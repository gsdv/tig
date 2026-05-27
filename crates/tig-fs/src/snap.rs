//! Take a snapshot of a workspace's working copy.
//!
//! The engine behind both `tig snap` and the file-system watcher (see
//! `tig-fs::watch`). One implementation, two callers — so the watcher
//! doesn't drift away from the CLI's notion of what a snap means.
//!
//! Steps:
//!   1. Scan the workspace's working directory into the object store,
//!      producing a root `Tree` hash. (`tig-fs::scan`.)
//!   2. Look up the workspace's current change. If none, this is the
//!      bootstrap snap and we will invent one.
//!   3. If the new tree matches the previous snapshot's tree AND no
//!      message was supplied AND `force` is off, return `Unchanged`.
//!   4. Otherwise, build and store a `Snapshot`, advance the `Change`,
//!      update the workspace's current change pointer, and return
//!      `Snapped`.
//!
//! Note the singular pointer: HEAD (for the main workspace) or the
//! workspace manifest's `change_id` (for secondaries). The engine
//! doesn't care which — `Workspace::set_current_change_id` routes it.

use crate::{scan, Error, Result, ScanOptions};
use tig_core::ChangeId;
use tig_core::{Change, Encodable, Hash, PrincipalId, Snapshot};
use tig_store::{OpInProgress, OpKind, OpLog, RefSnapshot, Repository, Workspace, WorkspaceKind};

#[derive(Clone, Debug)]
pub struct SnapOptions {
    pub author: PrincipalId,
    pub message: Option<String>,
    pub force: bool,
    pub initial_description: String,
    pub extra_ignores: Vec<String>,
}

impl Default for SnapOptions {
    fn default() -> Self {
        Self {
            author: PrincipalId::local("anonymous"),
            message: None,
            force: false,
            initial_description: "initial work".into(),
            extra_ignores: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum SnapOutcome {
    Snapped {
        snapshot: Hash,
        tree: Hash,
        change: Change,
        fresh_change: bool,
    },
    Unchanged {
        change: Change,
    },
}

impl SnapOutcome {
    pub fn change(&self) -> &Change {
        match self {
            SnapOutcome::Snapped { change, .. } | SnapOutcome::Unchanged { change } => change,
        }
    }
}

pub fn snap_now(
    workspace: &mut Workspace,
    log: &mut OpLog,
    opts: &SnapOptions,
) -> Result<SnapOutcome> {
    let mut scan_opts = ScanOptions::default();
    scan_opts.ignore.extend(opts.extra_ignores.iter().cloned());

    let workdir = workspace.workdir().to_path_buf();
    let tree_hash = scan(&workdir, workspace.repo.objects(), &scan_opts)?;

    let current = workspace.current_change_id()?;
    let (mut change, parents, fresh, change_before) = match current {
        Some(id) => {
            let c = workspace.repo.get_change(&id)?;
            let parents = vec![c.current];
            (c.clone(), parents, false, Some(c))
        }
        None => (
            Change::new(
                &opts.initial_description,
                opts.author.clone(),
                placeholder_hash(),
            ),
            Vec::new(),
            true,
            None,
        ),
    };

    if !fresh {
        let prev_snap =
            Snapshot::decode(&workspace.repo.get(&change.current)?).map_err(Error::Core)?;
        if prev_snap.tree == tree_hash && opts.message.is_none() && !opts.force {
            return Ok(SnapOutcome::Unchanged { change });
        }
    }

    // Capture the "before" refs we'll need for undo before any mutation.
    let workspace_ref_before = capture_workspace_ref(workspace);
    let change_ref_before = RefSnapshot::Change {
        id: change.id.clone(),
        value: change_before,
    };

    let snap = Snapshot {
        parents,
        tree: tree_hash,
        author: opts.author.clone(),
        timestamp_ns: Snapshot::current_timestamp_ns(),
        message: opts.message.clone(),
        op_id: None,
    };
    let snap_hash = workspace.repo.put(&snap.encode().map_err(Error::Core)?)?;

    if fresh {
        change.current = snap_hash;
        change.history = vec![snap_hash];
    } else {
        change.advance(snap_hash);
    }
    workspace.repo.put_change(&change)?;
    if fresh {
        workspace.set_current_change_id(&change.id)?;
    }

    let workspace_ref_after = capture_workspace_ref(workspace);
    let change_ref_after = RefSnapshot::Change {
        id: change.id.clone(),
        value: Some(change.clone()),
    };
    log.append(OpInProgress {
        actor: opts.author.clone(),
        kind: OpKind::Snap {
            snapshot: snap_hash,
            message: opts.message.clone(),
        },
        before: vec![workspace_ref_before, change_ref_before],
        after: vec![workspace_ref_after, change_ref_after],
    })?;

    Ok(SnapOutcome::Snapped {
        snapshot: snap_hash,
        tree: tree_hash,
        change,
        fresh_change: fresh,
    })
}

/// Snapshot whichever ref points at "what's checked out here" — HEAD for
/// the main workspace, the manifest for a secondary. Read fresh from
/// disk each call so it captures whatever was *just* written.
fn capture_workspace_ref(ws: &Workspace) -> RefSnapshot {
    match &ws.kind {
        WorkspaceKind::Main => {
            let head = ws.repo.head().ok().flatten();
            RefSnapshot::Head(head)
        }
        WorkspaceKind::Secondary(_) => {
            // The manifest in memory may be stale after a mutation; re-read.
            let store = match tig_store::WorkspaceStore::open(ws.repo.root()) {
                Ok(s) => s,
                Err(_) => return RefSnapshot::Head(None), // unreachable in practice
            };
            let id = match ws.workspace_id() {
                Some(id) => id.clone(),
                None => return RefSnapshot::Head(None),
            };
            let value = store.get(&id).ok();
            RefSnapshot::Workspace { id, value }
        }
    }
}

fn placeholder_hash() -> Hash {
    Hash::compute(tig_core::ObjectKind::Snapshot, b"tig:placeholder")
}

/// Snap a Change without a working directory.
///
/// Used by `tigd` (and any other no-FS caller, e.g. a WASM agent) when a
/// new tree hash has already been built by tree-editing primitives. The
/// snapshot becomes a child of the change's current snapshot. No HEAD
/// or workspace manifest is touched — those belong to specific
/// materializations, and this caller has none.
///
/// If `new_tree` matches the current snapshot's tree AND no message was
/// supplied AND `force` is off, returns `Unchanged` and writes no op.
pub fn snap_change_directly(
    repo: &Repository,
    log: &mut OpLog,
    change_id: &ChangeId,
    new_tree: Hash,
    opts: &SnapOptions,
) -> Result<SnapOutcome> {
    let mut change = repo.get_change(change_id)?;
    let change_before = change.clone();

    let prev_snap = Snapshot::decode(&repo.get(&change.current)?).map_err(Error::Core)?;
    if prev_snap.tree == new_tree && opts.message.is_none() && !opts.force {
        return Ok(SnapOutcome::Unchanged { change });
    }

    let snap = Snapshot {
        parents: vec![change.current],
        tree: new_tree,
        author: opts.author.clone(),
        timestamp_ns: Snapshot::current_timestamp_ns(),
        message: opts.message.clone(),
        op_id: None,
    };
    let snap_hash = repo.put(&snap.encode().map_err(Error::Core)?)?;

    change.advance(snap_hash);
    repo.put_change(&change)?;

    log.append(OpInProgress {
        actor: opts.author.clone(),
        kind: OpKind::Snap {
            snapshot: snap_hash,
            message: opts.message.clone(),
        },
        before: vec![RefSnapshot::Change {
            id: change_id.clone(),
            value: Some(change_before),
        }],
        after: vec![RefSnapshot::Change {
            id: change_id.clone(),
            value: Some(change.clone()),
        }],
    })?;

    Ok(SnapOutcome::Snapped {
        snapshot: snap_hash,
        tree: new_tree,
        change,
        fresh_change: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use tig_core::Tree;
    use tig_store::{ObjectStore, Repository, Workspace};

    fn fixture() -> (tempfile::TempDir, Workspace, OpLog) {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let log = OpLog::open(repo.root()).unwrap();
        let ws = Workspace::main_for(repo);
        (dir, ws, log)
    }

    fn opts() -> SnapOptions {
        SnapOptions {
            author: PrincipalId::local("tester"),
            ..Default::default()
        }
    }

    fn snap_messaged(msg: &str) -> SnapOptions {
        SnapOptions {
            message: Some(msg.into()),
            ..opts()
        }
    }

    #[test]
    fn first_snap_bootstraps_head() {
        let (dir, mut ws, mut log) = fixture();
        fs::write(dir.path().join("hello.txt"), b"hi").unwrap();

        let outcome = snap_now(&mut ws, &mut log, &snap_messaged("init")).unwrap();
        let head_change_id = match &outcome {
            SnapOutcome::Snapped {
                fresh_change,
                change,
                ..
            } => {
                assert!(*fresh_change);
                assert_eq!(change.history.len(), 1);
                assert_eq!(change.history[0], change.current);
                change.id.clone()
            }
            other => panic!("expected Snapped, got {other:?}"),
        };
        assert_eq!(ws.current_change_id().unwrap(), Some(head_change_id));
    }

    #[test]
    fn unchanged_tree_returns_unchanged() {
        let (dir, mut ws, mut log) = fixture();
        fs::write(dir.path().join("a.txt"), b"x").unwrap();
        snap_now(&mut ws, &mut log, &snap_messaged("first")).unwrap();

        let outcome = snap_now(&mut ws, &mut log, &opts()).unwrap();
        assert!(matches!(outcome, SnapOutcome::Unchanged { .. }));
        // Unchanged should NOT have recorded an op — nothing happened.
        assert_eq!(
            log.list().unwrap().len(),
            1,
            "Unchanged should not append an op"
        );
    }

    #[test]
    fn message_forces_snap_even_when_unchanged() {
        let (dir, mut ws, mut log) = fixture();
        fs::write(dir.path().join("a.txt"), b"x").unwrap();
        snap_now(&mut ws, &mut log, &snap_messaged("first")).unwrap();

        let outcome = snap_now(&mut ws, &mut log, &snap_messaged("second take")).unwrap();
        let SnapOutcome::Snapped { change, .. } = outcome else {
            panic!("a fresh message should always anchor a new snapshot");
        };
        assert_eq!(change.history.len(), 2);
    }

    #[test]
    fn edit_then_auto_snap_advances_history() {
        let (dir, mut ws, mut log) = fixture();
        fs::write(dir.path().join("a.txt"), b"v1").unwrap();
        snap_now(&mut ws, &mut log, &snap_messaged("first")).unwrap();

        fs::write(dir.path().join("a.txt"), b"v2").unwrap();
        let outcome = snap_now(&mut ws, &mut log, &opts()).unwrap();
        let SnapOutcome::Snapped {
            change, snapshot, ..
        } = outcome
        else {
            panic!("an edit should produce a fresh snapshot");
        };
        assert_eq!(change.history.len(), 2);
        assert_eq!(change.current, snapshot);

        let snap = Snapshot::decode(&ws.repo.get(&snapshot).unwrap()).unwrap();
        assert!(snap.message.is_none());
    }

    #[test]
    fn force_flag_snaps_unchanged_tree() {
        let (dir, mut ws, mut log) = fixture();
        fs::write(dir.path().join("a.txt"), b"x").unwrap();
        snap_now(&mut ws, &mut log, &snap_messaged("first")).unwrap();

        let outcome = snap_now(
            &mut ws,
            &mut log,
            &SnapOptions {
                force: true,
                ..opts()
            },
        )
        .unwrap();
        assert!(matches!(outcome, SnapOutcome::Snapped { .. }));
    }

    #[test]
    fn placeholder_never_lands_in_store() {
        let (dir, mut ws, mut log) = fixture();
        fs::write(dir.path().join("a.txt"), b"x").unwrap();
        snap_now(&mut ws, &mut log, &snap_messaged("first")).unwrap();
        assert!(!ws.repo.objects().has(&placeholder_hash()).unwrap());
    }

    #[test]
    fn empty_workdir_still_snapshots_an_empty_tree() {
        let (_dir, mut ws, mut log) = fixture();
        let outcome = snap_now(&mut ws, &mut log, &snap_messaged("init")).unwrap();
        let SnapOutcome::Snapped { tree, .. } = outcome else {
            panic!("first snap should always materialize");
        };
        let empty_tree_hash = Tree::new().hash().unwrap();
        assert_eq!(tree, empty_tree_hash);
    }

    #[test]
    fn each_snap_appends_one_op_with_correct_before_after() {
        let (dir, mut ws, mut log) = fixture();
        fs::write(dir.path().join("a.txt"), b"v1").unwrap();
        snap_now(&mut ws, &mut log, &snap_messaged("first")).unwrap();
        fs::write(dir.path().join("a.txt"), b"v2").unwrap();
        snap_now(&mut ws, &mut log, &snap_messaged("second")).unwrap();

        let ops = log.list().unwrap();
        assert_eq!(ops.len(), 2);

        // First op: HEAD goes from None → Some(change_id).
        let op0 = &ops[0];
        assert!(matches!(op0.before[0], RefSnapshot::Head(None)));
        let head_after = match &op0.after[0] {
            RefSnapshot::Head(Some(id)) => id.clone(),
            other => panic!("expected Head(Some), got {other:?}"),
        };

        // Second op's before-Head matches first op's after-Head — i.e.
        // the log is consistent across operations.
        match &ops[1].before[0] {
            RefSnapshot::Head(Some(id)) => assert_eq!(id, &head_after),
            other => panic!("expected Head(Some), got {other:?}"),
        }
    }
}
