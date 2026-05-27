//! Mark-and-sweep garbage collection over the content-addressed
//! object store.
//!
//! ## What gets kept
//!
//! Objects reachable from *any* reference live. References come from
//! two places:
//!
//!   1. **Live refs** — every [`Change`] record currently on disk
//!      (`refs/changes/<id>`). For each, `current` is a root snapshot
//!      hash and every entry in `history` is a root.
//!
//!   2. **Op-log captures** — every op that recorded a
//!      [`RefSnapshot::Change`] with a `Some(value)` payload, plus
//!      every [`OpKind::Snap`]'s `snapshot` hash. This is the critical
//!      bit that makes GC *undo-safe*: after `tig undo` deletes a
//!      change, its snapshots live on as long as the originating op
//!      remains in the log, so a future re-do can resurrect them.
//!
//! From each root snapshot we BFS through the object graph:
//!   `Snapshot.parents` → other snapshots
//!   `Snapshot.tree`    → root tree
//!   `Tree.entries[i].target` → sub-tree | blob | sealed | conflict
//!
//! Trees recurse. Blobs, Sealed, and Conflict objects are leaves —
//! their bytes are opaque to the GC.
//!
//! ## What gets removed
//!
//! Anything in `objects/` not reached during marking. Sweep walks the
//! whole store via [`FsObjectStore::iter_all`]; for each unreached
//! hash, [`FsObjectStore::remove`] deletes the file. The fanout
//! directory is left in place even when emptied — it's cheap and the
//! next `put` to that shard would recreate it anyway.
//!
//! ## Concurrency
//!
//! Caller is expected to hold [`Repository::lock_for_write`] for the
//! duration. Writers serialize behind us; readers don't take the lock
//! at all but they only fail if they cached an object hash that was
//! *already unreachable* before GC ran — i.e. a hash they shouldn't
//! have been able to obtain through any live ref. The contract:
//!
//!   * If you hold a hash you got from a live `Change`, it remains
//!     fetchable after GC.
//!   * If you hold a hash you got from an oplog op, it remains
//!     fetchable as long as that op stays in the log.
//!   * Hashes obtained any other way (e.g. cat-object output you
//!     stuffed in a sticky note) are not guaranteed.
//!
//! ## What this doesn't do
//!
//! Oplog compaction is a separate concern — we never drop ops, so we
//! never lose the references that protect their snapshots. A future
//! milestone may add a `min_age` filter so the GC only sweeps objects
//! older than N seconds, giving in-flight writers a safety margin.

use crate::{Repository, Result};
use std::collections::HashSet;
use tig_core::{Encodable, EntryKind, Hash, ObjectKind, Snapshot, Tree};

use crate::oplog::{OpKind, OpLog, RefSnapshot};
use crate::RefStore;

/// Knobs for a GC run.
#[derive(Clone, Debug)]
pub struct GcOptions {
    /// Walk + count what *would* be removed, but don't delete. Useful
    /// for "show me the damage first" UX.
    pub dry_run: bool,

    /// Walk the oplog and treat every op-captured Snapshot/Change as a
    /// root. **Default and recommended `true`**: skipping this breaks
    /// `tig undo` of `ChangeNew` (the deleted change's snapshots would
    /// be eligible for collection). Exposed mostly so destructive
    /// "wipe everything not in current refs" runs are possible.
    pub include_oplog_snapshots: bool,
}

impl Default for GcOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            include_oplog_snapshots: true,
        }
    }
}

/// What happened during a GC run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcSummary {
    /// Roots collected before marking — typically the count of unique
    /// snapshot hashes seen across live changes + oplog.
    pub roots: usize,
    /// Objects reachable from the root set (marked).
    pub kept: usize,
    /// Objects we removed (or *would* remove under `dry_run`).
    pub removed: usize,
    /// Total bytes freed (sum of file sizes of removed objects). For
    /// `dry_run`, this is the bytes that *would* be freed.
    pub bytes_freed: u64,
    /// True iff this was a dry run — no files were actually deleted.
    pub dry_run: bool,
}

/// Run GC against `repo`'s object store.
///
/// `log` is required because oplog-captured Change records are part of
/// the root set under default options. Pass a freshly-opened
/// [`OpLog`] (the daemon would normally hold one already and pass its
/// `&mut` after locking).
pub fn collect_garbage(repo: &Repository, log: &OpLog, opts: &GcOptions) -> Result<GcSummary> {
    let mut roots: HashSet<Hash> = HashSet::new();

    // (1) Live changes.
    for id in repo.refs().list_changes()? {
        let change = repo.refs().get_change(&id)?;
        roots.insert(change.current);
        for h in &change.history {
            roots.insert(*h);
        }
    }

    // (2) Op-log captures — only if asked. This is the undo-safety net.
    if opts.include_oplog_snapshots {
        for op in log.list()? {
            // Any Snap op directly names a snapshot.
            if let OpKind::Snap { snapshot, .. } = &op.kind {
                roots.insert(*snapshot);
            }
            // before/after may carry full Change records — pull their
            // snapshot hashes too.
            for snap in op.before.iter().chain(op.after.iter()) {
                if let RefSnapshot::Change { value: Some(c), .. } = snap {
                    roots.insert(c.current);
                    for h in &c.history {
                        roots.insert(*h);
                    }
                }
            }
        }
    }

    // Mark: BFS from roots through the object graph.
    let mut marked: HashSet<Hash> = HashSet::with_capacity(roots.len() * 4);
    let mut queue: Vec<Hash> = roots.iter().copied().collect();
    while let Some(h) = queue.pop() {
        if !marked.insert(h) {
            continue;
        }
        // The hash itself is in the marked set now. Pull its referents.
        let raw = match repo.get(&h) {
            Ok(r) => r,
            // A root pointing at a missing object is a corruption we
            // can't fix from here — leave it un-marked (nothing to
            // mark) and continue. The sweep will naturally not touch
            // anything keyed by a non-existent file.
            Err(crate::Error::NotFound(_)) => continue,
            Err(e) => return Err(e),
        };
        match raw.kind {
            ObjectKind::Snapshot => {
                let snap = Snapshot::decode(&raw)?;
                queue.push(snap.tree);
                for p in &snap.parents {
                    queue.push(*p);
                }
            }
            ObjectKind::Tree => {
                let tree = Tree::decode(&raw)?;
                for e in &tree.entries {
                    match e.kind {
                        // Both Tree and File/Sealed/Conflict targets
                        // are objects we need to keep. Trees push for
                        // recursion; leaves push so they end up in
                        // `marked` and survive the sweep.
                        EntryKind::Tree
                        | EntryKind::File
                        | EntryKind::Sealed
                        | EntryKind::Conflict => queue.push(e.target),
                        // Symlinks store their target inline in the
                        // entry (no object reference). Submodules
                        // point at an external repo's commit hash —
                        // not one of our objects. Both are leaves we
                        // don't need to chase.
                        EntryKind::Symlink | EntryKind::Submodule => {}
                    }
                }
            }
            // Leaves — no outgoing refs.
            ObjectKind::Blob | ObjectKind::Sealed | ObjectKind::Conflict => {}
        }
    }

    // Sweep: walk every object on disk, remove anything not marked.
    let mut summary = GcSummary {
        roots: roots.len(),
        kept: 0,
        removed: 0,
        bytes_freed: 0,
        dry_run: opts.dry_run,
    };
    let mut to_remove: Vec<(Hash, u64)> = Vec::new();
    repo.objects().iter_all(|h, size| {
        if marked.contains(&h) {
            summary.kept += 1;
        } else {
            to_remove.push((h, size));
        }
        Ok(())
    })?;
    for (h, size) in to_remove {
        if !opts.dry_run {
            repo.objects().remove(&h)?;
        }
        summary.removed += 1;
        summary.bytes_freed += size;
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObjectStore, OpInProgress, OpLog};
    use tempfile::tempdir;
    use tig_core::{
        Blob, Change, ChangeId, Encodable, EntryKind, FileMode, Hash, PrincipalId, RecipientWrap,
        SealAlgo, Sealed, Snapshot, Tree, TreeEntry,
    };

    fn fake_principal() -> PrincipalId {
        PrincipalId::local("tester")
    }

    /// Build a snap chain: empty-tree → tree-with-one-blob → tree-with-two-blobs,
    /// each snap parents the previous. Returns (change, [snap_hashes]).
    fn build_chain(repo: &Repository) -> (Change, Vec<Hash>) {
        let blob_a = repo
            .put(&Blob::new(b"alpha".to_vec()).encode().unwrap())
            .unwrap();
        let blob_b = repo
            .put(&Blob::new(b"beta".to_vec()).encode().unwrap())
            .unwrap();

        let empty_tree_h = repo.put(&Tree::new().encode().unwrap()).unwrap();
        let snap0 = Snapshot {
            parents: vec![],
            tree: empty_tree_h,
            author: fake_principal(),
            timestamp_ns: 1,
            message: Some("init".into()),
            op_id: None,
        };
        let s0 = repo.put(&snap0.encode().unwrap()).unwrap();

        let t1 = Tree::from_entries([TreeEntry {
            name: "a".into(),
            kind: EntryKind::File,
            target: blob_a,
            mode: FileMode::REGULAR,
            vis: None,
        }])
        .unwrap();
        let t1_h = repo.put(&t1.encode().unwrap()).unwrap();
        let snap1 = Snapshot {
            parents: vec![s0],
            tree: t1_h,
            author: fake_principal(),
            timestamp_ns: 2,
            message: Some("add a".into()),
            op_id: None,
        };
        let s1 = repo.put(&snap1.encode().unwrap()).unwrap();

        let t2 = Tree::from_entries([
            TreeEntry {
                name: "a".into(),
                kind: EntryKind::File,
                target: blob_a,
                mode: FileMode::REGULAR,
                vis: None,
            },
            TreeEntry {
                name: "b".into(),
                kind: EntryKind::File,
                target: blob_b,
                mode: FileMode::REGULAR,
                vis: None,
            },
        ])
        .unwrap();
        let t2_h = repo.put(&t2.encode().unwrap()).unwrap();
        let snap2 = Snapshot {
            parents: vec![s1],
            tree: t2_h,
            author: fake_principal(),
            timestamp_ns: 3,
            message: Some("add b".into()),
            op_id: None,
        };
        let s2 = repo.put(&snap2.encode().unwrap()).unwrap();

        let mut change = Change::new("the work", fake_principal(), s0);
        change.advance(s1);
        change.advance(s2);
        repo.put_change(&change).unwrap();

        (change, vec![s0, s1, s2])
    }

    #[test]
    fn unreachable_blob_is_removed() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let log = OpLog::open(repo.root()).unwrap();

        // Build a chain we'll keep alive via the Change record.
        let (_change, _snaps) = build_chain(&repo);

        // And a stray blob nobody references.
        let stray = repo
            .put(&Blob::new(b"orphan".to_vec()).encode().unwrap())
            .unwrap();
        assert!(repo.objects().has(&stray).unwrap());

        let summary = collect_garbage(
            &repo,
            &log,
            &GcOptions {
                include_oplog_snapshots: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            !repo.objects().has(&stray).unwrap(),
            "orphan blob survived GC"
        );
        assert_eq!(summary.removed, 1);
        assert!(summary.bytes_freed > 0);
    }

    #[test]
    fn reachable_chain_survives() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let log = OpLog::open(repo.root()).unwrap();
        let (change, snaps) = build_chain(&repo);

        // GC should keep all three snaps + their trees + both blobs.
        let summary = collect_garbage(&repo, &log, &GcOptions::default()).unwrap();
        assert_eq!(
            summary.removed, 0,
            "GC removed reachable objects: {summary:?}"
        );
        for h in &snaps {
            assert!(
                repo.objects().has(h).unwrap(),
                "snap {} got swept",
                h.to_hex()
            );
        }
        // Spot-check: walk into the latest tree and verify the blob is there.
        let snap2 = Snapshot::decode(&repo.get(&change.current).unwrap()).unwrap();
        let t2 = Tree::decode(&repo.get(&snap2.tree).unwrap()).unwrap();
        for e in t2.entries {
            assert!(repo.objects().has(&e.target).unwrap());
        }
    }

    #[test]
    fn deleted_change_snapshots_kept_via_oplog() {
        // Scenario: we create a Change + a Snap op, then delete the
        // Change record from refs (mimicking what `tig undo` does for
        // a ChangeNew). With include_oplog_snapshots=true (the
        // default), the snapshot stays — its hash is captured in the
        // op-log entry.
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let mut log = OpLog::open(repo.root()).unwrap();

        let blob = repo
            .put(&Blob::new(b"alive".to_vec()).encode().unwrap())
            .unwrap();
        let tree = Tree::from_entries([TreeEntry {
            name: "f".into(),
            kind: EntryKind::File,
            target: blob,
            mode: FileMode::REGULAR,
            vis: None,
        }])
        .unwrap();
        let tree_h = repo.put(&tree.encode().unwrap()).unwrap();
        let snap = Snapshot {
            parents: vec![],
            tree: tree_h,
            author: fake_principal(),
            timestamp_ns: 1,
            message: Some("x".into()),
            op_id: None,
        };
        let snap_h = repo.put(&snap.encode().unwrap()).unwrap();
        let change = Change::new("c", fake_principal(), snap_h);
        repo.put_change(&change).unwrap();

        // Record an op whose `after` carries the full Change record.
        log.append(OpInProgress {
            actor: fake_principal(),
            kind: OpKind::ChangeNew {
                change_id: change.id.clone(),
                description: change.description.clone(),
            },
            before: vec![RefSnapshot::Change {
                id: change.id.clone(),
                value: None,
            }],
            after: vec![RefSnapshot::Change {
                id: change.id.clone(),
                value: Some(change.clone()),
            }],
        })
        .unwrap();

        // Delete the live change record (simulating `tig undo`).
        repo.refs().delete_change(&change.id).unwrap();

        // GC with oplog captures enabled: snapshot must survive.
        let summary = collect_garbage(&repo, &log, &GcOptions::default()).unwrap();
        assert!(
            repo.objects().has(&snap_h).unwrap(),
            "snapshot lost; oplog capture didn't protect it"
        );
        assert!(repo.objects().has(&blob).unwrap(), "blob also gone");
        assert_eq!(
            summary.removed, 0,
            "expected nothing removed, got {summary:?}"
        );

        // Now run again with oplog captures disabled: snapshot goes.
        let summary = collect_garbage(
            &repo,
            &log,
            &GcOptions {
                include_oplog_snapshots: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!repo.objects().has(&snap_h).unwrap());
        assert!(!repo.objects().has(&blob).unwrap());
        assert_eq!(summary.removed, 3, "snap + tree + blob"); // snap, tree, blob
    }

    #[test]
    fn dry_run_doesnt_delete() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let log = OpLog::open(repo.root()).unwrap();
        let _ = build_chain(&repo);
        let stray = repo
            .put(&Blob::new(b"to-be-collected".to_vec()).encode().unwrap())
            .unwrap();

        let summary = collect_garbage(
            &repo,
            &log,
            &GcOptions {
                dry_run: true,
                include_oplog_snapshots: false,
            },
        )
        .unwrap();
        assert!(summary.dry_run);
        assert_eq!(summary.removed, 1);
        // The file is still there.
        assert!(repo.objects().has(&stray).unwrap(), "dry-run removed file!");
    }

    #[test]
    fn sealed_objects_referenced_by_tree_survive() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let log = OpLog::open(repo.root()).unwrap();

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
            aad: b"path/x".to_vec(),
        };
        let sealed_h = repo.put(&sealed.encode().unwrap()).unwrap();
        let tree = Tree::from_entries([TreeEntry {
            name: "secret".into(),
            kind: EntryKind::Sealed,
            target: sealed_h,
            mode: FileMode::REGULAR,
            vis: None,
        }])
        .unwrap();
        let tree_h = repo.put(&tree.encode().unwrap()).unwrap();
        let snap = Snapshot {
            parents: vec![],
            tree: tree_h,
            author: fake_principal(),
            timestamp_ns: 1,
            message: None,
            op_id: None,
        };
        let snap_h = repo.put(&snap.encode().unwrap()).unwrap();
        let change = Change::new("c", fake_principal(), snap_h);
        repo.put_change(&change).unwrap();

        let _ = collect_garbage(&repo, &log, &GcOptions::default()).unwrap();
        assert!(repo.objects().has(&sealed_h).unwrap(), "sealed entry lost");
    }

    #[test]
    fn nested_subtree_objects_survive() {
        // A two-level tree: root → subdir/ → file.
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let log = OpLog::open(repo.root()).unwrap();

        let blob = repo
            .put(&Blob::new(b"buried".to_vec()).encode().unwrap())
            .unwrap();
        let subdir = Tree::from_entries([TreeEntry {
            name: "buried.txt".into(),
            kind: EntryKind::File,
            target: blob,
            mode: FileMode::REGULAR,
            vis: None,
        }])
        .unwrap();
        let subdir_h = repo.put(&subdir.encode().unwrap()).unwrap();
        let root_tree = Tree::from_entries([TreeEntry {
            name: "sub".into(),
            kind: EntryKind::Tree,
            target: subdir_h,
            mode: FileMode::DIR,
            vis: None,
        }])
        .unwrap();
        let root_h = repo.put(&root_tree.encode().unwrap()).unwrap();
        let snap = Snapshot {
            parents: vec![],
            tree: root_h,
            author: fake_principal(),
            timestamp_ns: 1,
            message: None,
            op_id: None,
        };
        let snap_h = repo.put(&snap.encode().unwrap()).unwrap();
        let change = Change::new("c", fake_principal(), snap_h);
        repo.put_change(&change).unwrap();

        let summary = collect_garbage(&repo, &log, &GcOptions::default()).unwrap();
        assert_eq!(summary.removed, 0, "swept nested tree object: {summary:?}");
        assert!(repo.objects().has(&blob).unwrap());
        assert!(repo.objects().has(&subdir_h).unwrap());
    }

    #[test]
    fn empty_repo_gc_is_a_no_op() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let log = OpLog::open(repo.root()).unwrap();
        let summary = collect_garbage(&repo, &log, &GcOptions::default()).unwrap();
        assert_eq!(summary.removed, 0);
        assert_eq!(summary.kept, 0);
        assert_eq!(summary.bytes_freed, 0);
    }

    #[test]
    fn snapshot_parents_keep_old_snaps_alive_via_one_change() {
        // We only point the Change at the *current* snap (no history).
        // The parent chain still survives because we walk
        // snapshot.parents during marking.
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let log = OpLog::open(repo.root()).unwrap();

        let tree_h = repo.put(&Tree::new().encode().unwrap()).unwrap();
        let s0 = repo
            .put(
                &Snapshot {
                    parents: vec![],
                    tree: tree_h,
                    author: fake_principal(),
                    timestamp_ns: 1,
                    message: None,
                    op_id: None,
                }
                .encode()
                .unwrap(),
            )
            .unwrap();
        let s1 = repo
            .put(
                &Snapshot {
                    parents: vec![s0],
                    tree: tree_h,
                    author: fake_principal(),
                    timestamp_ns: 2,
                    message: None,
                    op_id: None,
                }
                .encode()
                .unwrap(),
            )
            .unwrap();

        // Change records s1 as current but does NOT carry s0 in history.
        // Construct directly so we control history.
        let change = Change {
            id: ChangeId::new(),
            current: s1,
            bookmark: None,
            description: "x".into(),
            state: tig_core::ChangeState::Working,
            history: vec![s1],
            author: fake_principal(),
            visibility: tig_core::VisLabel::default(),
        };
        repo.put_change(&change).unwrap();

        let summary = collect_garbage(
            &repo,
            &log,
            &GcOptions {
                include_oplog_snapshots: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(summary.removed, 0, "parent snap swept: {summary:?}");
        assert!(repo.objects().has(&s0).unwrap(), "parent snap removed");
    }
}
