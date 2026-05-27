//! Build a fresh on-disk workspace from a Change.
//!
//! Two strategies, decided per call:
//!
//!   - **Clone path** (`materialize_from_workspace`): some existing
//!     workspace already has these files on disk. Use the platform CoW
//!     engine to clone its directory. One `clonefile(2)` on macOS APFS;
//!     a recursive copy elsewhere. The new workspace shares blocks with
//!     the donor and adds near-zero disk usage on supported filesystems.
//!
//!   - **Render path** (`materialize_change_into`): no donor exists, so
//!     we walk the change's `Tree` and write each `Blob` to disk from
//!     the object store. Slower, but the only option for arbitrary
//!     historical checkouts.
//!
//! Both leave a `.tig-workspace` marker out of scope — the caller (CLI
//! or test) writes the marker once it has decided the workspace id.

use crate::clone::CloneEngine;
use crate::{Error, Result};
use std::fs;
use std::path::Path;
use tig_core::{Blob, Encodable, EntryKind, Hash, Snapshot, Tree};
use tig_store::Repository;

#[derive(Clone, Debug)]
pub enum MaterializeOutcome {
    /// Used a donor workspace's existing on-disk tree.
    Cloned {
        engine: &'static str,
        donor: std::path::PathBuf,
    },
    /// Walked the object store and wrote everything from scratch.
    Rendered { files: usize, bytes: u64 },
}

/// Materialize the tree of `snapshot_hash` into `dst`. `dst` must not
/// exist; this function creates it.
pub fn materialize_change_into(
    repo: &Repository,
    snapshot_hash: &Hash,
    dst: &Path,
) -> Result<MaterializeOutcome> {
    if dst.exists() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("destination already exists: {}", dst.display()),
        )));
    }
    fs::create_dir_all(dst)?;

    let snap = Snapshot::decode(&repo.get(snapshot_hash)?).map_err(Error::Core)?;
    let mut stats = RenderStats::default();
    render_tree(repo, &snap.tree, dst, &mut stats)?;
    Ok(MaterializeOutcome::Rendered {
        files: stats.files,
        bytes: stats.bytes,
    })
}

/// Fast-path: clone an existing workspace's directory at `donor` to
/// `dst` using the supplied engine.
///
/// Implementation note: we don't call `engine.clone_path(donor, dst)`
/// directly because `dst` is commonly a *descendant* of `donor` (the
/// `.tig-worktrees/<name>/` layout). Recursive clonefile of a directory
/// into a path inside itself is a logical impossibility and APFS returns
/// EINVAL for it. Instead, we iterate the donor's top-level entries and
/// clone each one, skipping the repo metadata (`.tig`), the secondary-
/// workspace storage (`.tig-worktrees`), and any marker file. Each
/// surviving top-level entry is still cloned recursively in one syscall
/// on APFS — so the per-entry overhead is constant.
pub fn materialize_from_workspace(
    donor: &Path,
    dst: &Path,
    engine: &dyn CloneEngine,
) -> Result<MaterializeOutcome> {
    if dst.exists() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("destination already exists: {}", dst.display()),
        )));
    }
    fs::create_dir_all(dst)?;

    for entry in fs::read_dir(donor)? {
        let entry = entry?;
        let name_os = entry.file_name();
        let name = name_os.to_string_lossy();
        if is_workspace_internal(&name) {
            continue;
        }
        let src = entry.path();
        let dst_child = dst.join(&*name);
        engine.clone_path(&src, &dst_child).map_err(Error::Io)?;
    }

    Ok(MaterializeOutcome::Cloned {
        engine: engine.name(),
        donor: donor.to_path_buf(),
    })
}

fn is_workspace_internal(name: &str) -> bool {
    name == tig_store::TIG_DIR
        || name == tig_store::DEFAULT_WORKTREE_DIR
        || name == tig_store::MARKER_FILE
}

#[derive(Default, Clone, Copy, Debug)]
pub struct RenderStats {
    pub files: usize,
    pub bytes: u64,
}

/// Render `tree_hash` into `dst`, which must already exist. Public so
/// `restore` can call it after clearing a workdir in place.
pub fn render_tree_into(repo: &Repository, tree_hash: &Hash, dst: &Path) -> Result<RenderStats> {
    let mut stats = RenderStats::default();
    render_tree(repo, tree_hash, dst, &mut stats)?;
    Ok(stats)
}

/// Walk `tree_hash` and return every path that holds a `Sealed` entry.
/// Empty result means the tree is safe to render unconditionally —
/// the caller can then call `render_tree_into` without worrying about
/// crypto. Used by `restore` to refuse a half-finished render.
pub fn collect_sealed_paths(repo: &Repository, tree_hash: &Hash) -> Result<Vec<String>> {
    let mut out = Vec::new();
    walk_for_sealed(repo, tree_hash, "", &mut out)?;
    Ok(out)
}

fn walk_for_sealed(
    repo: &Repository,
    tree_hash: &Hash,
    prefix: &str,
    out: &mut Vec<String>,
) -> Result<()> {
    let tree = tig_core::Tree::decode(&repo.get(tree_hash)?).map_err(Error::Core)?;
    for entry in &tree.entries {
        let path = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{prefix}/{}", entry.name)
        };
        match entry.kind {
            tig_core::EntryKind::Sealed => out.push(path),
            tig_core::EntryKind::Tree => walk_for_sealed(repo, &entry.target, &path, out)?,
            _ => {}
        }
    }
    Ok(())
}

fn render_tree(
    repo: &Repository,
    tree_hash: &Hash,
    dst: &Path,
    stats: &mut RenderStats,
) -> Result<()> {
    let tree = Tree::decode(&repo.get(tree_hash)?).map_err(Error::Core)?;
    for entry in &tree.entries {
        let child = dst.join(&entry.name);
        match entry.kind {
            EntryKind::File => {
                let blob = Blob::decode(&repo.get(&entry.target)?).map_err(Error::Core)?;
                fs::write(&child, &blob.bytes)?;
                #[cfg(unix)]
                if entry.mode.is_executable() {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = fs::metadata(&child)?.permissions();
                    perms.set_mode(perms.mode() | 0o111);
                    fs::set_permissions(&child, perms)?;
                }
                stats.files += 1;
                stats.bytes += blob.bytes.len() as u64;
            }
            EntryKind::Tree => {
                fs::create_dir(&child)?;
                render_tree(repo, &entry.target, &child, stats)?;
            }
            EntryKind::Symlink => {
                let blob = Blob::decode(&repo.get(&entry.target)?).map_err(Error::Core)?;
                let target = std::str::from_utf8(&blob.bytes).map_err(|_| {
                    Error::Core(tig_core::Error::Decode(
                        "symlink target is not valid utf-8".into(),
                    ))
                })?;
                #[cfg(unix)]
                std::os::unix::fs::symlink(target, &child)?;
                #[cfg(not(unix))]
                {
                    let _ = target;
                    return Err(Error::UnsupportedFileKind {
                        path: child.display().to_string(),
                        kind: "symlink (non-unix)".into(),
                    });
                }
            }
            EntryKind::Sealed | EntryKind::Conflict | EntryKind::Submodule => {
                return Err(Error::UnsupportedFileKind {
                    path: child.display().to_string(),
                    kind: format!(
                        "{:?} (milestone 1 cannot materialize this kind)",
                        entry.kind
                    ),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{clone::CopyFallback, scan, snap::snap_now, ScanOptions, SnapOptions, SnapOutcome};
    use std::fs;
    use tempfile::tempdir;
    use tig_core::{PrincipalId, Snapshot};
    use tig_store::{OpLog, Repository, Workspace};

    fn fixture_with_files() -> (tempfile::TempDir, Repository, Hash) {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/b.txt"), b"beta beta beta").unwrap();

        let repo = Repository::init(dir.path()).unwrap();
        let mut log = OpLog::open(repo.root()).unwrap();
        let mut ws = Workspace::main_for(repo);
        let outcome = snap_now(
            &mut ws,
            &mut log,
            &SnapOptions {
                author: PrincipalId::local("t"),
                message: Some("seed".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let snapshot = match outcome {
            SnapOutcome::Snapped { snapshot, .. } => snapshot,
            other => panic!("expected Snapped, got {other:?}"),
        };
        (dir, ws.repo, snapshot)
    }

    #[test]
    fn render_path_produces_byte_exact_files() {
        let (dir, repo, snap) = fixture_with_files();
        let target = dir.path().join("rendered");
        let outcome = materialize_change_into(&repo, &snap, &target).unwrap();
        let MaterializeOutcome::Rendered { files, bytes } = outcome else {
            panic!("expected Rendered, got {outcome:?}");
        };
        assert_eq!(files, 2);
        assert_eq!(
            bytes,
            b"alpha".len() as u64 + b"beta beta beta".len() as u64
        );
        assert_eq!(fs::read(target.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(
            fs::read(target.join("sub/b.txt")).unwrap(),
            b"beta beta beta"
        );
    }

    #[test]
    fn clone_path_copies_workspace_files() {
        // Use CopyFallback so the test is portable. The APFS path is
        // covered by clone.rs's own apfs_clone_is_byte_exact test.
        let dir = tempdir().unwrap();
        let donor = dir.path().join("donor");
        fs::create_dir(&donor).unwrap();
        fs::write(donor.join("x.txt"), b"hi").unwrap();
        fs::create_dir(donor.join("sub")).unwrap();
        fs::write(donor.join("sub/y.txt"), b"there").unwrap();

        // Drop a fake marker + a sibling worktrees dir to test scrubbing.
        fs::write(donor.join(tig_store::MARKER_FILE), b"{}").unwrap();
        fs::create_dir(donor.join(tig_store::DEFAULT_WORKTREE_DIR)).unwrap();
        fs::write(
            donor.join(tig_store::DEFAULT_WORKTREE_DIR).join("junk"),
            b"orphan",
        )
        .unwrap();

        let dst = dir.path().join("clone");
        let outcome = materialize_from_workspace(&donor, &dst, &CopyFallback).unwrap();
        let MaterializeOutcome::Cloned { engine, donor: d } = outcome else {
            panic!("expected Cloned, got {outcome:?}");
        };
        assert_eq!(engine, "copy");
        assert_eq!(d, donor);

        assert_eq!(fs::read(dst.join("x.txt")).unwrap(), b"hi");
        assert_eq!(fs::read(dst.join("sub/y.txt")).unwrap(), b"there");
        assert!(
            !dst.join(tig_store::MARKER_FILE).exists(),
            "marker should be scrubbed"
        );
        assert!(
            !dst.join(tig_store::DEFAULT_WORKTREE_DIR).exists(),
            "sibling worktrees dir should be scrubbed"
        );
    }

    #[test]
    fn render_then_rescan_recovers_same_tree_hash() {
        let (dir, repo, snap) = fixture_with_files();
        let original_tree = Snapshot::decode(&repo.get(&snap).unwrap()).unwrap().tree;

        let target = dir.path().join("rendered");
        materialize_change_into(&repo, &snap, &target).unwrap();

        let rescanned = scan(&target, repo.objects(), &ScanOptions::default()).unwrap();
        assert_eq!(rescanned, original_tree);
    }

    #[test]
    fn materializing_into_existing_dst_errors() {
        let (dir, repo, snap) = fixture_with_files();
        let target = dir.path().join("rendered");
        fs::create_dir(&target).unwrap();
        let err = materialize_change_into(&repo, &snap, &target).unwrap_err();
        match err {
            Error::Io(io) => assert_eq!(io.kind(), std::io::ErrorKind::AlreadyExists),
            other => panic!("expected Io(AlreadyExists), got {other:?}"),
        }
    }
}
