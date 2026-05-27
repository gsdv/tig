//! Filesystem-level cloning, used to build new workspaces.
//!
//! The engine is platform-aware:
//!
//!   - **macOS / APFS:** `clonefile(2)` — one syscall, recursive,
//!     block-shared. Two workspaces from the same change end up sharing
//!     APFS extents at the block level. Editing one allocates new blocks
//!     on demand (copy-on-write); reads of unchanged data hit the same
//!     backing extents.
//!
//!   - **Anything else:** plain recursive copy. Slow and disk-greedy
//!     compared to clonefile, but correct everywhere. (Linux btrfs/xfs
//!     `FICLONE`, Windows ReFS `DUPLICATE_EXTENTS_TO_FILE`, etc. are
//!     sketched in `docs/ARCHITECTURE.md` §6.2 and are TODO.)
//!
//! `AutoClone` runs the primary engine and falls back to the copier on
//! ENOTSUP / EXDEV / etc. — so a tig user on macOS whose project sits on
//! an external non-APFS volume still gets a correct workspace, just
//! without the CoW speedup.

use std::fs;
use std::io;
use std::path::Path;

pub trait CloneEngine: Send + Sync {
    fn name(&self) -> &'static str;

    /// Materialize `src` (file, directory, or symlink) at `dst`. `dst`
    /// must not already exist; the engine creates it. For directories
    /// this is recursive.
    fn clone_path(&self, src: &Path, dst: &Path) -> io::Result<()>;
}

/// Detect the best available engine for the running platform. Always
/// returns *something* — at worst, a recursive `fs::copy` walker.
pub fn detect() -> Box<dyn CloneEngine> {
    #[cfg(target_os = "macos")]
    {
        return Box::new(AutoClone {
            primary: Box::new(ApfsClone),
            fallback: Box::new(CopyFallback),
        });
    }
    #[allow(unreachable_code)]
    Box::new(CopyFallback)
}

// --- AutoClone: primary with fallback ------------------------------------

pub struct AutoClone {
    pub primary: Box<dyn CloneEngine>,
    pub fallback: Box<dyn CloneEngine>,
}

impl CloneEngine for AutoClone {
    fn name(&self) -> &'static str {
        // The primary's name is the useful label — that's what the user
        // wanted to try. If we end up falling back, the log shows it.
        self.primary.name()
    }

    fn clone_path(&self, src: &Path, dst: &Path) -> io::Result<()> {
        match self.primary.clone_path(src, dst) {
            Ok(()) => Ok(()),
            Err(e) if is_fallback_eligible(&e) => {
                // The primary refused (e.g. non-APFS volume). Try the
                // fallback. If `dst` was partially created, clean it up
                // first so the fallback can start fresh.
                let _ = remove_dst(dst);
                self.fallback.clone_path(src, dst)
            }
            Err(e) => Err(e),
        }
    }
}

fn is_fallback_eligible(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    // ENOTSUP (Unsupported), EXDEV (cross-device), or "not supported on
    // this filesystem". We *don't* fall back on EEXIST/ENOENT — those
    // mean the caller passed bad inputs, not "wrong filesystem."
    matches!(e.kind(), Unsupported | CrossesDevices)
        || e.raw_os_error() == Some(libc_enotsup())
        || e.raw_os_error() == Some(libc_exdev())
}

fn remove_dst(dst: &Path) -> io::Result<()> {
    let meta = match fs::symlink_metadata(dst) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.is_dir() {
        fs::remove_dir_all(dst)
    } else {
        fs::remove_file(dst)
    }
}

// --- APFS clonefile (macOS) ---------------------------------------------

#[cfg(target_os = "macos")]
pub struct ApfsClone;

#[cfg(target_os = "macos")]
mod apfs {
    use std::ffi::CString;
    use std::io;
    use std::os::raw::{c_char, c_int};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    extern "C" {
        // int clonefile(const char *src, const char *dst, uint32_t flags);
        // We declare flags as c_int — it's a uint32_t in the header, but
        // `int` is also 32-bit on every macOS ABI we care about and Rust
        // doesn't otherwise care.
        pub fn clonefile(src: *const c_char, dst: *const c_char, flags: c_int) -> c_int;
    }

    /// `CLONE_NOFOLLOW = 0x0001` from `<sys/clonefile.h>`. Copy symlinks
    /// as symlinks rather than dereferencing them.
    pub const CLONE_NOFOLLOW: c_int = 0x0001;

    pub fn clone(src: &Path, dst: &Path) -> io::Result<()> {
        let src_c = CString::new(src.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let dst_c = CString::new(dst.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // SAFETY: the two C strings live for the duration of the call.
        // clonefile is a normal libc syscall — no special preconditions
        // beyond "the paths must be valid C strings."
        let ret = unsafe { clonefile(src_c.as_ptr(), dst_c.as_ptr(), CLONE_NOFOLLOW) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(target_os = "macos")]
impl CloneEngine for ApfsClone {
    fn name(&self) -> &'static str {
        "apfs-clonefile"
    }

    fn clone_path(&self, src: &Path, dst: &Path) -> io::Result<()> {
        apfs::clone(src, dst)
    }
}

#[cfg(not(target_os = "macos"))]
fn libc_enotsup() -> i32 {
    45 // common ENOTSUP value on Linux; harmless as a no-match elsewhere
}
#[cfg(target_os = "macos")]
fn libc_enotsup() -> i32 {
    45 // ENOTSUP on macOS
}

#[cfg(not(target_os = "macos"))]
fn libc_exdev() -> i32 {
    18
}
#[cfg(target_os = "macos")]
fn libc_exdev() -> i32 {
    18 // EXDEV
}

// --- Generic recursive copy ---------------------------------------------

pub struct CopyFallback;

impl CloneEngine for CopyFallback {
    fn name(&self) -> &'static str {
        "copy"
    }

    fn clone_path(&self, src: &Path, dst: &Path) -> io::Result<()> {
        copy_recursive(src, dst)
    }
}

fn copy_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(src)?;
    let ft = meta.file_type();

    if ft.is_dir() {
        fs::create_dir(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let name = entry.file_name();
            copy_recursive(&entry.path(), &dst.join(name))?;
        }
        Ok(())
    } else if ft.is_symlink() {
        let target = fs::read_link(src)?;
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, dst)?;
        }
        #[cfg(not(unix))]
        {
            // On Windows symlinks require a separate API. Out of scope
            // for milestone 1; surface a clear error.
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "symlink copy not yet supported on this platform: {}",
                    src.display()
                ),
            ));
        }
        Ok(())
    } else {
        fs::copy(src, dst).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn read(p: &Path) -> Vec<u8> {
        fs::read(p).unwrap()
    }

    fn engine_for_each_test() -> [(&'static str, Box<dyn CloneEngine>); 2] {
        [("auto", detect()), ("copy-only", Box::new(CopyFallback))]
    }

    #[test]
    fn clone_single_file() {
        for (label, eng) in engine_for_each_test() {
            let dir = tempdir().unwrap();
            let src = dir.path().join("a");
            let dst = dir.path().join("b");
            fs::write(&src, b"hello").unwrap();

            eng.clone_path(&src, &dst)
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(read(&dst), b"hello", "engine {label}");
        }
    }

    #[test]
    fn clone_directory_recursive() {
        for (label, eng) in engine_for_each_test() {
            let dir = tempdir().unwrap();
            let src = dir.path().join("src");
            fs::create_dir(&src).unwrap();
            fs::write(src.join("a.txt"), b"alpha").unwrap();
            fs::create_dir(src.join("sub")).unwrap();
            fs::write(src.join("sub/b.txt"), b"beta").unwrap();

            let dst = dir.path().join("dst");
            eng.clone_path(&src, &dst)
                .unwrap_or_else(|e| panic!("{label}: {e}"));

            assert_eq!(read(&dst.join("a.txt")), b"alpha", "engine {label}");
            assert_eq!(read(&dst.join("sub/b.txt")), b"beta", "engine {label}");
        }
    }

    #[test]
    fn clone_to_existing_destination_fails() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("a");
        let dst = dir.path().join("b");
        fs::write(&src, b"x").unwrap();
        fs::write(&dst, b"y").unwrap();

        let eng = detect();
        let err = eng.clone_path(&src, &dst).unwrap_err();
        // We don't pin the exact kind — APFS clonefile returns EEXIST,
        // the copy fallback returns AlreadyExists. Either is acceptable.
        let _ = err;
    }

    #[cfg(unix)]
    #[test]
    fn clone_preserves_symlinks_as_links() {
        for (label, eng) in engine_for_each_test() {
            let dir = tempdir().unwrap();
            let target = dir.path().join("target");
            fs::write(&target, b"contents").unwrap();
            let link_src = dir.path().join("link_src");
            std::os::unix::fs::symlink(&target, &link_src).unwrap();

            let link_dst = dir.path().join("link_dst");
            eng.clone_path(&link_src, &link_dst)
                .unwrap_or_else(|e| panic!("{label}: {e}"));

            let meta = fs::symlink_metadata(&link_dst).unwrap();
            assert!(
                meta.file_type().is_symlink(),
                "engine {label} dereferenced symlink"
            );
            assert_eq!(
                read(&link_dst),
                b"contents",
                "symlink target wrong, engine {label}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn apfs_clone_is_byte_exact() {
        // On macOS, the detect() engine should be ApfsClone-backed.
        // We won't *prove* CoW here (that requires fcntl(F_LOG2PHYS) and
        // is fragile in tests), but byte-exact roundtrip is the basic
        // correctness contract.
        let dir = tempdir().unwrap();
        let src = dir.path().join("big.bin");
        let payload: Vec<u8> = (0..(1 << 16)).map(|i| (i % 251) as u8).collect();
        fs::write(&src, &payload).unwrap();

        let dst = dir.path().join("clone.bin");
        ApfsClone.clone_path(&src, &dst).unwrap();
        assert_eq!(read(&dst), payload);
    }
}
