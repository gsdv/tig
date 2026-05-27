//! Restore a workdir to match a chosen tree.
//!
//! Counterpart to `tig undo`. Undo rewinds the change pointer (a refs
//! operation). Restore brings the on-disk bytes back into alignment
//! with a chosen snapshot (a workdir operation). They're complementary:
//!
//!   - `tig undo` → change.current = previous snapshot; workdir unchanged.
//!   - `tig restore <snap>` → workdir contents = <snap>.tree; change advances
//!     with a new snapshot whose tree matches.
//!
//! Safety: by default `restore` refuses to run when the workdir doesn't
//! match the current snapshot's tree — i.e. when there are uncommitted
//! edits. Use `--force` to override.
//!
//! Sealed entries: the architecture spec says sealed reads happen
//! client-side with explicit identities. A blanket `tig restore` has no
//! identity context to decrypt with, so we refuse to render a tree
//! containing `Sealed` entries and ask the user to seal/unseal them
//! explicitly. (Future: `tig restore --as alice` could decrypt-as-it-renders.)

use crate::{
    materialize::{collect_sealed_paths, render_tree_into, RenderStats},
    scan, Error, Result, ScanOptions,
};
use std::fs;
use std::path::Path;
use tig_core::{Encodable, Hash, Snapshot};
use tig_store::Repository;

#[derive(Clone, Debug)]
#[derive(Default)]
pub struct RestoreOptions {
    /// Force the restore even if the workdir is dirty (has uncommitted
    /// changes vs. the current snapshot). Without this, restore refuses
    /// rather than silently overwriting work.
    pub force: bool,
}


#[derive(Clone, Debug)]
pub struct RestoreOutcome {
    /// The tree we restored to.
    pub tree: Hash,
    /// Render stats — how many files were written and total bytes.
    pub render: RenderStats,
    /// Number of top-level entries we removed from the workdir before
    /// rendering. Doesn't recurse — directory rms count as one.
    pub top_level_removed: usize,
}

/// Restore `workdir` to match the tree at `target_snapshot`.
///
/// Steps:
///   1. Walk the target tree; if it contains any `Sealed` entries,
///      refuse cleanly with the list of paths.
///   2. Compare the current workdir's tree-hash to the
///      `current_snapshot`'s tree-hash; if they differ and `force` is
///      off, refuse.
///   3. Remove every top-level entry in `workdir` except `.tig` and
///      `.tig-worktrees`.
///   4. Render the target tree into `workdir`.
///
/// Returns counts for the caller to display. Notably does **not**
/// touch refs or the oplog — that's the CLI/daemon's job, so the
/// engine stays composable.
pub fn restore_tree_into(
    repo: &Repository,
    target_snapshot: &Hash,
    workdir: &Path,
    current_snapshot: &Hash,
    opts: &RestoreOptions,
) -> Result<RestoreOutcome> {
    let target = Snapshot::decode(&repo.get(target_snapshot)?).map_err(Error::Core)?;

    // Step 1: refuse sealed entries up-front.
    let sealed = collect_sealed_paths(repo, &target.tree)?;
    if !sealed.is_empty() {
        return Err(Error::Core(tig_core::Error::Decode(format!(
            "refusing to restore: target tree contains {} sealed entr{}; \
             reveal them with `tig reveal` first or use a future `tig restore --as <id>`. \
             paths: {}",
            sealed.len(),
            if sealed.len() == 1 { "y" } else { "ies" },
            sealed.join(", ")
        ))));
    }

    // Step 2: dirty-check.
    if !opts.force {
        let mut scan_opts = ScanOptions::default();
        // Use the same default ignores as snap_now / tig snap.
        let current_workdir_tree = scan(workdir, repo.objects(), &scan_opts)?;
        scan_opts.ignore.clear(); // (silence "unused mut" without `let _ =`)
        let current_snap = Snapshot::decode(&repo.get(current_snapshot)?).map_err(Error::Core)?;
        if current_workdir_tree != current_snap.tree {
            return Err(Error::Core(tig_core::Error::Decode(format!(
                "workdir has uncommitted changes vs. current snapshot ({}); \
                 use --force to discard them, or snap first with `tig snap -m ...`",
                &current_snap.tree.to_hex()[..12]
            ))));
        }
    }

    // Step 3: clear the workdir of everything except protected entries.
    let removed = clear_workdir(workdir)?;

    // Step 4: render the target tree into the now-empty workdir.
    let render = render_tree_into(repo, &target.tree, workdir)?;

    Ok(RestoreOutcome {
        tree: target.tree,
        render,
        top_level_removed: removed,
    })
}

fn clear_workdir(workdir: &Path) -> Result<usize> {
    let mut removed = 0;
    for entry in fs::read_dir(workdir)? {
        let entry = entry?;
        let name_os = entry.file_name();
        let name = name_os.to_string_lossy();
        if name == tig_store::TIG_DIR
            || name == tig_store::DEFAULT_WORKTREE_DIR
            || name == tig_store::MARKER_FILE
        {
            continue;
        }
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
        removed += 1;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{snap_now, SnapOptions, SnapOutcome};
    use std::fs;
    use tempfile::tempdir;
    use tig_core::{
        Encodable, EntryKind, FileMode, PrincipalId, RecipientWrap, SealAlgo, Sealed, Tree,
        TreeEntry,
    };
    use tig_store::{ObjectStore, OpLog, Workspace};

    /// Set up a workspace with two snaps: v1 (single file "a"="alpha")
    /// then v2 ("a"="alpha", "b"="beta"). Returns the workspace, oplog,
    /// and both snapshot hashes.
    fn fixture_two_snaps() -> (
        tempfile::TempDir,
        Workspace,
        OpLog,
        Hash, // v1 snap hash
        Hash, // v2 snap hash
    ) {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let mut log = OpLog::open(repo.root()).unwrap();
        let mut ws = Workspace::main_for(repo);

        fs::write(dir.path().join("a"), b"alpha").unwrap();
        let opts = SnapOptions {
            author: PrincipalId::local("t"),
            message: Some("v1".into()),
            ..Default::default()
        };
        let v1 = match snap_now(&mut ws, &mut log, &opts).unwrap() {
            SnapOutcome::Snapped { snapshot, .. } => snapshot,
            _ => unreachable!(),
        };

        fs::write(dir.path().join("b"), b"beta").unwrap();
        let opts = SnapOptions {
            author: PrincipalId::local("t"),
            message: Some("v2".into()),
            ..Default::default()
        };
        let v2 = match snap_now(&mut ws, &mut log, &opts).unwrap() {
            SnapOutcome::Snapped { snapshot, .. } => snapshot,
            _ => unreachable!(),
        };

        (dir, ws, log, v1, v2)
    }

    #[test]
    fn restore_v1_removes_files_added_in_v2() {
        let (dir, ws, _log, v1, v2) = fixture_two_snaps();
        // Sanity: both files exist before.
        assert!(dir.path().join("a").exists());
        assert!(dir.path().join("b").exists());

        let outcome =
            restore_tree_into(&ws.repo, &v1, ws.workdir(), &v2, &RestoreOptions::default())
                .unwrap();
        assert_eq!(outcome.render.files, 1);
        assert_eq!(outcome.render.bytes, 5);

        assert!(dir.path().join("a").exists());
        assert!(
            !dir.path().join("b").exists(),
            "file added in v2 should be gone after restoring v1"
        );
    }

    #[test]
    fn restore_preserves_tig_directory() {
        let (dir, ws, _log, v1, v2) = fixture_two_snaps();
        let tig_dir = dir.path().join(".tig");
        assert!(tig_dir.is_dir());
        let _ = restore_tree_into(&ws.repo, &v1, ws.workdir(), &v2, &RestoreOptions::default())
            .unwrap();
        assert!(tig_dir.is_dir(), ".tig must survive a restore");
        // The store should still be functional.
        assert!(ws.repo.objects().has(&v1).unwrap());
    }

    #[test]
    fn restore_refuses_dirty_workdir_without_force() {
        let (dir, ws, _log, v1, v2) = fixture_two_snaps();
        // Make the workdir dirty: edit "a".
        fs::write(dir.path().join("a"), b"alpha-dirty").unwrap();

        let err = restore_tree_into(
            &ws.repo,
            &v1,
            ws.workdir(),
            &v2,
            &RestoreOptions { force: false },
        )
        .unwrap_err();
        assert!(err.to_string().contains("uncommitted"), "got: {err}");

        // The dirty edit must still be there — we refused before touching anything.
        assert_eq!(fs::read(dir.path().join("a")).unwrap(), b"alpha-dirty");
    }

    #[test]
    fn restore_with_force_overrides_dirty_check() {
        let (dir, ws, _log, v1, v2) = fixture_two_snaps();
        fs::write(dir.path().join("a"), b"alpha-dirty").unwrap();
        let _ = restore_tree_into(
            &ws.repo,
            &v1,
            ws.workdir(),
            &v2,
            &RestoreOptions { force: true },
        )
        .unwrap();
        assert_eq!(fs::read(dir.path().join("a")).unwrap(), b"alpha");
    }

    #[test]
    fn restore_refuses_tree_with_sealed_entries() {
        let (dir, ws, _log, _v1, v2) = fixture_two_snaps();

        // Hand-build a tree containing a Sealed entry, and a snapshot
        // pointing at it. This bypasses the CLI's seal command but
        // produces a valid Sealed object in the store.
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
            aad: b"secret".to_vec(),
        };
        let sealed_h = ws.repo.put(&sealed.encode().unwrap()).unwrap();
        let tree = Tree::from_entries([TreeEntry {
            name: "secret".into(),
            kind: EntryKind::Sealed,
            target: sealed_h,
            mode: FileMode::REGULAR,
            vis: None,
        }])
        .unwrap();
        let tree_h = ws.repo.put(&tree.encode().unwrap()).unwrap();
        let snap = Snapshot {
            parents: vec![v2],
            tree: tree_h,
            author: PrincipalId::local("t"),
            timestamp_ns: Snapshot::current_timestamp_ns(),
            message: Some("with-sealed".into()),
            op_id: None,
        };
        let snap_h = ws.repo.put(&snap.encode().unwrap()).unwrap();

        let err = restore_tree_into(
            &ws.repo,
            &snap_h,
            ws.workdir(),
            &v2,
            &RestoreOptions { force: true }, // force on, but sealed check fires first
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("sealed"), "got: {msg}");
        assert!(
            msg.contains("secret"),
            "expected the sealed path in the error, got: {msg}"
        );
        // The "a" file (from v2) must still be there — sealed check fired before clearing.
        assert!(dir.path().join("a").exists());
        assert!(dir.path().join("b").exists());
    }

    #[test]
    fn restore_then_rescan_recovers_same_tree_hash() {
        // Round-trip: snap v2, restore v1, scan — should equal v1's tree.
        let (_dir, ws, _log, v1, v2) = fixture_two_snaps();
        let _ = restore_tree_into(&ws.repo, &v1, ws.workdir(), &v2, &RestoreOptions::default())
            .unwrap();
        let scanned = scan(ws.workdir(), ws.repo.objects(), &ScanOptions::default()).unwrap();
        let v1_snap = Snapshot::decode(&ws.repo.get(&v1).unwrap()).unwrap();
        assert_eq!(scanned, v1_snap.tree);
    }
}
