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
//!
//! ## Sealed entries
//!
//! The render path can decrypt and write sealed entries to disk, but
//! only if the caller supplies an [`UnsealFn`] via
//! [`MaterializeOptions`]. The engine never holds keys itself — the
//! CLI/daemon assembles a closure wrapping `tig_vis::unseal` and
//! passes it down. Without an unsealer, encountering a sealed entry
//! fails the render (preserving the milestone-1 behaviour).
//!
//! **Round-trip caveat.** A decrypted sealed entry lands on disk as
//! plaintext. A subsequent `tig scan`/`tig snap` will reify it as a
//! regular `EntryKind::File` blob — the cryptographic binding is
//! gone. The user must re-seal the path (e.g. `tig seal path
//! --recipients ...`) before snapping if they want the next snapshot
//! to keep the contents sealed. A future milestone will detect this
//! at scan time and refuse with a clear message.

use crate::clone::CloneEngine;
use crate::{Error, Result};
use std::fs;
use std::path::Path;
use tig_core::{Blob, Encodable, EntryKind, Hash, Sealed, Snapshot, Tree};
use tig_store::Repository;

/// Caller-supplied decryption. Receives the [`Sealed`] object and the
/// AAD (which the engine sets to the entry's full tree path), returns
/// the plaintext bytes. A `String` error so the engine doesn't have to
/// know about `tig_vis::Error`.
///
/// The lifetime parameter lets the closure borrow from its
/// environment (e.g. a `SecretKey`). When you don't need a borrow,
/// `'static` works fine.
pub type UnsealFn<'a> =
    dyn Fn(&Sealed, &[u8]) -> std::result::Result<Vec<u8>, String> + Send + Sync + 'a;

/// What to do when the unsealer is configured but a specific sealed
/// entry can't be decrypted (e.g. caller isn't a recipient, AAD
/// mismatch, tampered ciphertext).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OnUnsealable {
    /// Abort the whole render. Safest default — partial materialization
    /// of a tree with secrets in it is rarely what the caller wants.
    #[default]
    Error,
    /// Skip the entry — the file simply isn't written. Stats record
    /// each skip so the caller can warn the user.
    Skip,
}

/// Knobs for the render path. Default is "render plain entries; refuse
/// on any sealed entry" — the milestone-1 behaviour.
#[derive(Default)]
pub struct MaterializeOptions<'a> {
    /// If present, sealed entries are decrypted at render time. If
    /// absent, encountering a sealed entry errors.
    pub unsealer: Option<&'a UnsealFn<'a>>,
    /// Behaviour when the unsealer is set but a given entry can't be
    /// decrypted (wrong identity, etc.). Ignored if `unsealer` is None.
    pub on_unsealable: OnUnsealable,
}

#[derive(Clone, Debug)]
pub enum MaterializeOutcome {
    /// Used a donor workspace's existing on-disk tree.
    Cloned {
        engine: &'static str,
        donor: std::path::PathBuf,
    },
    /// Walked the object store and wrote everything from scratch.
    Rendered {
        files: usize,
        bytes: u64,
        /// Sealed entries successfully decrypted + materialized. Zero
        /// when no unsealer was configured.
        sealed_unsealed: usize,
        /// Sealed entries skipped because the unsealer rejected them
        /// under [`OnUnsealable::Skip`]. Zero otherwise.
        sealed_skipped: usize,
    },
}

/// Materialize the tree of `snapshot_hash` into `dst`. `dst` must not
/// exist; this function creates it.
///
/// `opts` controls how sealed entries are handled — see
/// [`MaterializeOptions`]. The default refuses sealed entries (use a
/// fresh `MaterializeOptions::default()` if you don't need decryption).
pub fn materialize_change_into(
    repo: &Repository,
    snapshot_hash: &Hash,
    dst: &Path,
    opts: &MaterializeOptions<'_>,
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
    render_tree(repo, &snap.tree, dst, "", opts, &mut stats)?;
    Ok(MaterializeOutcome::Rendered {
        files: stats.files,
        bytes: stats.bytes,
        sealed_unsealed: stats.sealed_unsealed,
        sealed_skipped: stats.sealed_skipped,
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
    /// Sealed entries successfully decrypted + written as plaintext.
    pub sealed_unsealed: usize,
    /// Sealed entries the unsealer couldn't decrypt, skipped under
    /// [`OnUnsealable::Skip`]. Zero when policy is `Error`.
    pub sealed_skipped: usize,
}

/// Render `tree_hash` into `dst`, which must already exist. Public so
/// `restore` can call it after clearing a workdir in place.
pub fn render_tree_into(
    repo: &Repository,
    tree_hash: &Hash,
    dst: &Path,
    opts: &MaterializeOptions<'_>,
) -> Result<RenderStats> {
    let mut stats = RenderStats::default();
    render_tree(repo, tree_hash, dst, "", opts, &mut stats)?;
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
    path_prefix: &str,
    opts: &MaterializeOptions<'_>,
    stats: &mut RenderStats,
) -> Result<()> {
    let tree = Tree::decode(&repo.get(tree_hash)?).map_err(Error::Core)?;
    for entry in &tree.entries {
        let child = dst.join(&entry.name);
        let entry_path = if path_prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{path_prefix}/{}", entry.name)
        };
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
                render_tree(repo, &entry.target, &child, &entry_path, opts, stats)?;
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
            EntryKind::Sealed => {
                let Some(unsealer) = opts.unsealer else {
                    return Err(Error::UnsupportedFileKind {
                        path: entry_path,
                        kind: "sealed (no --as <identity> configured; pass an unsealer to \
                               materialize sealed entries)"
                            .into(),
                    });
                };
                let sealed = Sealed::decode(&repo.get(&entry.target)?).map_err(Error::Core)?;
                // AAD is the entry's full tree path, as set by `tig
                // seal`. If a different convention was used to seal,
                // this will fail with AuthFailure and the OnUnsealable
                // policy kicks in.
                match unsealer(&sealed, entry_path.as_bytes()) {
                    Ok(plaintext) => {
                        fs::write(&child, &plaintext)?;
                        #[cfg(unix)]
                        if entry.mode.is_executable() {
                            use std::os::unix::fs::PermissionsExt;
                            let mut perms = fs::metadata(&child)?.permissions();
                            perms.set_mode(perms.mode() | 0o111);
                            fs::set_permissions(&child, perms)?;
                        }
                        stats.sealed_unsealed += 1;
                        stats.bytes += plaintext.len() as u64;
                    }
                    Err(reason) => match opts.on_unsealable {
                        OnUnsealable::Error => {
                            return Err(Error::UnsupportedFileKind {
                                path: entry_path,
                                kind: format!("sealed (decrypt failed: {reason})"),
                            });
                        }
                        OnUnsealable::Skip => {
                            stats.sealed_skipped += 1;
                        }
                    },
                }
            }
            EntryKind::Conflict | EntryKind::Submodule => {
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
        let outcome =
            materialize_change_into(&repo, &snap, &target, &MaterializeOptions::default()).unwrap();
        let MaterializeOutcome::Rendered { files, bytes, .. } = outcome else {
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
        materialize_change_into(&repo, &snap, &target, &MaterializeOptions::default()).unwrap();

        let rescanned = scan(&target, repo.objects(), &ScanOptions::default()).unwrap();
        assert_eq!(rescanned, original_tree);
    }

    #[test]
    fn materializing_into_existing_dst_errors() {
        let (dir, repo, snap) = fixture_with_files();
        let target = dir.path().join("rendered");
        fs::create_dir(&target).unwrap();
        let err = materialize_change_into(&repo, &snap, &target, &MaterializeOptions::default())
            .unwrap_err();
        match err {
            Error::Io(io) => assert_eq!(io.kind(), std::io::ErrorKind::AlreadyExists),
            other => panic!("expected Io(AlreadyExists), got {other:?}"),
        }
    }

    // --- sealed-materialization tests ------------------------------------

    use std::sync::atomic::{AtomicUsize, Ordering};
    use tig_core::{
        Encodable, EntryKind, FileMode, RecipientWrap, SealAlgo, Sealed, Tree, TreeEntry,
    };

    /// Build a snapshot with one regular file `a` and one sealed entry
    /// `secret`. The Sealed object is a stub — we test rendering, not
    /// real crypto, so the unsealer closure just unconditionally
    /// returns whatever bytes we tell it to.
    fn fixture_with_sealed_entry(
        bytes_a: &[u8],
        sealed_aad: &[u8],
    ) -> (tempfile::TempDir, Repository, Hash) {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();

        let blob_a = repo
            .put(&Blob::new(bytes_a.to_vec()).encode().unwrap())
            .unwrap();
        let sealed = Sealed {
            algo: SealAlgo::X25519XChaCha20Poly1305,
            ephemeral_pk: vec![0u8; 32],
            recipients: vec![RecipientWrap {
                recipient_pk: vec![1u8; 32],
                wrapped_key: vec![2u8; 48],
                wrap_nonce: vec![3u8; 24],
            }],
            ciphertext: vec![9u8; 64],
            nonce: vec![4u8; 24],
            aad: sealed_aad.to_vec(),
        };
        let sealed_h = repo.put(&sealed.encode().unwrap()).unwrap();

        let tree = Tree::from_entries([
            TreeEntry {
                name: "a".into(),
                kind: EntryKind::File,
                target: blob_a,
                mode: FileMode::REGULAR,
                vis: None,
            },
            TreeEntry {
                name: "secret".into(),
                kind: EntryKind::Sealed,
                target: sealed_h,
                mode: FileMode::REGULAR,
                vis: None,
            },
        ])
        .unwrap();
        let tree_h = repo.put(&tree.encode().unwrap()).unwrap();
        let snap = Snapshot {
            parents: vec![],
            tree: tree_h,
            author: PrincipalId::local("t"),
            timestamp_ns: 1,
            message: None,
            op_id: None,
        };
        let snap_h = repo.put(&snap.encode().unwrap()).unwrap();
        (dir, repo, snap_h)
    }

    #[test]
    fn render_with_unsealer_writes_decrypted_plaintext() {
        let (dir, repo, snap) = fixture_with_sealed_entry(b"plain", b"secret");
        // Our fake unsealer returns this plaintext for every sealed
        // entry. Assert it gets called with the right AAD (the path).
        let observed_aad: AtomicUsize = AtomicUsize::new(0);
        let unsealer = |_s: &Sealed, aad: &[u8]| -> std::result::Result<Vec<u8>, String> {
            if aad == b"secret" {
                observed_aad.fetch_add(1, Ordering::SeqCst);
            }
            Ok(b"DATABASE_URL=postgres://x".to_vec())
        };
        let opts = MaterializeOptions {
            unsealer: Some(&unsealer),
            on_unsealable: OnUnsealable::Error,
        };

        let target = dir.path().join("rendered");
        let outcome = materialize_change_into(&repo, &snap, &target, &opts).unwrap();
        let MaterializeOutcome::Rendered {
            files,
            bytes,
            sealed_unsealed,
            sealed_skipped,
        } = outcome
        else {
            panic!("expected Rendered");
        };
        assert_eq!(files, 1, "the regular file");
        assert_eq!(sealed_unsealed, 1, "the sealed entry got decrypted");
        assert_eq!(sealed_skipped, 0);
        assert!(bytes > 0);

        assert_eq!(fs::read(target.join("a")).unwrap(), b"plain");
        assert_eq!(
            fs::read(target.join("secret")).unwrap(),
            b"DATABASE_URL=postgres://x"
        );
        assert_eq!(
            observed_aad.load(Ordering::SeqCst),
            1,
            "unsealer must be called with the entry's path as AAD"
        );
    }

    #[test]
    fn render_without_unsealer_errors_on_sealed_entry() {
        let (dir, repo, snap) = fixture_with_sealed_entry(b"plain", b"secret");
        let target = dir.path().join("rendered");
        let err = materialize_change_into(&repo, &snap, &target, &MaterializeOptions::default())
            .unwrap_err();
        match err {
            Error::UnsupportedFileKind { path, kind } => {
                assert_eq!(path, "secret");
                assert!(
                    kind.contains("sealed") && kind.contains("--as"),
                    "expected friendly sealed error, got: {kind}"
                );
            }
            other => panic!("expected UnsupportedFileKind, got {other:?}"),
        }
    }

    #[test]
    fn render_with_skip_policy_omits_unsealable_entries() {
        let (dir, repo, snap) = fixture_with_sealed_entry(b"plain", b"secret");
        // Unsealer always fails — pretend we're not a recipient.
        let unsealer = |_s: &Sealed, _aad: &[u8]| -> std::result::Result<Vec<u8>, String> {
            Err("not a recipient".into())
        };
        let opts = MaterializeOptions {
            unsealer: Some(&unsealer),
            on_unsealable: OnUnsealable::Skip,
        };

        let target = dir.path().join("rendered");
        let (files, _bytes, sealed_skipped) =
            match materialize_change_into(&repo, &snap, &target, &opts).unwrap() {
                MaterializeOutcome::Rendered {
                    files,
                    bytes,
                    sealed_skipped,
                    ..
                } => (files, bytes, sealed_skipped),
                other => panic!("expected Rendered, got {other:?}"),
            };
        assert_eq!(files, 1, "the regular file got written");
        assert_eq!(sealed_skipped, 1);
        // Regular file is there; sealed path is absent because we skipped.
        assert!(target.join("a").exists());
        assert!(
            !target.join("secret").exists(),
            "sealed path should be omitted under Skip"
        );
    }

    #[test]
    fn render_with_failing_unsealer_under_error_policy_aborts() {
        let (dir, repo, snap) = fixture_with_sealed_entry(b"plain", b"secret");
        let unsealer = |_s: &Sealed, _aad: &[u8]| -> std::result::Result<Vec<u8>, String> {
            Err("not a recipient".into())
        };
        let opts = MaterializeOptions {
            unsealer: Some(&unsealer),
            on_unsealable: OnUnsealable::Error,
        };
        let target = dir.path().join("rendered");
        let err = materialize_change_into(&repo, &snap, &target, &opts).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("decrypt failed") && msg.contains("not a recipient"),
            "got: {msg}"
        );
    }

    #[test]
    fn nested_sealed_entry_gets_aad_with_full_path() {
        // Put the sealed entry under sub/, confirm the AAD passed to
        // the unsealer is "sub/secret", matching how `tig seal` would
        // have signed it.
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let sealed = Sealed {
            algo: SealAlgo::X25519XChaCha20Poly1305,
            ephemeral_pk: vec![0u8; 32],
            recipients: vec![RecipientWrap {
                recipient_pk: vec![1u8; 32],
                wrapped_key: vec![2u8; 48],
                wrap_nonce: vec![3u8; 24],
            }],
            ciphertext: vec![9u8; 32],
            nonce: vec![4u8; 24],
            aad: b"sub/secret".to_vec(),
        };
        let sealed_h = repo.put(&sealed.encode().unwrap()).unwrap();
        let subtree = Tree::from_entries([TreeEntry {
            name: "secret".into(),
            kind: EntryKind::Sealed,
            target: sealed_h,
            mode: FileMode::REGULAR,
            vis: None,
        }])
        .unwrap();
        let subtree_h = repo.put(&subtree.encode().unwrap()).unwrap();
        let root = Tree::from_entries([TreeEntry {
            name: "sub".into(),
            kind: EntryKind::Tree,
            target: subtree_h,
            mode: FileMode::DIR,
            vis: None,
        }])
        .unwrap();
        let root_h = repo.put(&root.encode().unwrap()).unwrap();
        let snap = Snapshot {
            parents: vec![],
            tree: root_h,
            author: PrincipalId::local("t"),
            timestamp_ns: 1,
            message: None,
            op_id: None,
        };
        let snap_h = repo.put(&snap.encode().unwrap()).unwrap();

        let captured = std::sync::Mutex::new(Vec::<u8>::new());
        let unsealer = |_s: &Sealed, aad: &[u8]| -> std::result::Result<Vec<u8>, String> {
            *captured.lock().unwrap() = aad.to_vec();
            Ok(b"plaintext".to_vec())
        };
        let opts = MaterializeOptions {
            unsealer: Some(&unsealer),
            on_unsealable: OnUnsealable::Error,
        };
        let target = dir.path().join("rendered");
        materialize_change_into(&repo, &snap_h, &target, &opts).unwrap();
        assert_eq!(*captured.lock().unwrap(), b"sub/secret".to_vec());
        assert_eq!(fs::read(target.join("sub/secret")).unwrap(), b"plaintext");
    }
}
