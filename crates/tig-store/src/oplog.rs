//! Per-repo operation log.
//!
//! Every state-changing operation appends one `Op` here. `tig undo` is
//! literally "find the most recent op that hasn't been undone yet, walk
//! its `before` list, restore each `RefSnapshot`." That's the whole
//! undo story — see ARCHITECTURE.md §P7 and §2.5.
//!
//! File format (V1): a single file `oplog/000000.log`, append-only,
//! framed records:
//!
//! ```text
//! [u32 BE: record length] [N bytes: CBOR(Op)]
//! [u32 BE: record length] [N bytes: CBOR(Op)]
//! ...
//! ```
//!
//! Reading: open the file, read u32, read that many bytes, decode,
//! repeat until EOF. We scan the whole log to compute `next_id` on open,
//! which is O(n) — acceptable for milestone 2; an LMDB sidecar index is
//! sketched in ARCHITECTURE.md §3 for when n gets big.
//!
//! The `InMemory` variant is for tests and the rare caller that wants
//! the engine API without persistence.

use crate::{Error, Result, WorkspaceId, WorkspaceManifest};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tig_core::{Change, ChangeId, ChangeState, Hash, OpId, PrincipalId, VisLabel};

const OPLOG_DIR: &str = "oplog";
const PRIMARY_FILE: &str = "000000.log";

/// A single, fully-formed record in the oplog. Has an id.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Op {
    pub id: OpId,
    pub ts_ns: u64,
    pub actor: PrincipalId,
    pub kind: OpKind,
    pub before: Vec<RefSnapshot>,
    pub after: Vec<RefSnapshot>,
}

/// A new op being staged — id and timestamp are assigned by `append`.
#[derive(Clone, Debug)]
pub struct OpInProgress {
    pub actor: PrincipalId,
    pub kind: OpKind,
    pub before: Vec<RefSnapshot>,
    pub after: Vec<RefSnapshot>,
}

/// What kind of operation this op recorded. Discriminates for display
/// and for the undo skip-pairing algorithm (`Undo` is the only variant
/// that gets special handling).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum OpKind {
    /// Took a snapshot of a workspace's working copy.
    Snap {
        snapshot: Hash,
        message: Option<String>,
    },
    /// Created a new Change record.
    ChangeNew {
        change_id: ChangeId,
        description: String,
    },
    /// Created a secondary workspace.
    WtMake {
        workspace_id: WorkspaceId,
        name: String,
    },
    /// Dropped a secondary workspace.
    WtDrop {
        workspace_id: WorkspaceId,
        name: String,
    },
    /// Flipped a change's state and/or visibility. Both old and new
    /// values are captured for display; the actual restore goes through
    /// `before`/`after` like every other op.
    ChangeTransition {
        change_id: ChangeId,
        from_state: ChangeState,
        to_state: ChangeState,
        from_vis: VisLabel,
        to_vis: VisLabel,
    },
    /// Undid another op. `undone_op` is that op's id, kept for audit
    /// and so `pick_op_to_undo` can balance regular ops against undos.
    Undo { undone_op: OpId },
}

impl OpKind {
    pub fn one_line(&self) -> String {
        match self {
            OpKind::Snap { snapshot, message } => {
                let label = message.as_deref().unwrap_or("(auto)");
                format!("Snap {}  {label}", &snapshot.to_hex()[..12])
            }
            OpKind::ChangeNew {
                change_id,
                description,
            } => {
                format!("ChangeNew {change_id}  {description}")
            }
            OpKind::WtMake { workspace_id, name } => {
                format!("WtMake {name} ({workspace_id})")
            }
            OpKind::WtDrop { workspace_id, name } => {
                format!("WtDrop {name} ({workspace_id})")
            }
            OpKind::ChangeTransition {
                change_id,
                from_state,
                to_state,
                from_vis,
                to_vis,
            } => format!(
                "ChangeTransition {change_id}  {:?}/{} → {:?}/{}",
                from_state,
                from_vis.name(),
                to_state,
                to_vis.name(),
            ),
            OpKind::Undo { undone_op } => format!("Undo of {undone_op}"),
        }
    }
}

/// A single mutated ref captured at one point in time.
///
/// `None` payloads represent "the ref did not exist." This is how we
/// represent creation (before=None, after=Some) and deletion
/// (before=Some, after=None) symmetrically.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RefSnapshot {
    /// The main workspace's HEAD pointer.
    Head(Option<ChangeId>),
    /// A `Change` record by id. We capture the entire record because its
    /// `history` field grows on every snap and must be restored exactly.
    Change { id: ChangeId, value: Option<Change> },
    /// A secondary workspace's manifest.
    Workspace {
        id: WorkspaceId,
        value: Option<WorkspaceManifest>,
    },
    /// A bookmark by name. The payload is its target ChangeId.
    Bookmark {
        name: String,
        value: Option<ChangeId>,
    },
}

// --- the log ----------------------------------------------------------

/// Append-only log of every state-changing operation. Two backends —
/// file-backed for real repos, in-memory for tests.
pub enum OpLog {
    File(FileLog),
    InMemory(MemLog),
}

pub struct FileLog {
    path: PathBuf,
    next_id: u64,
}

#[derive(Default)]
pub struct MemLog {
    next_id: u64,
    ops: Vec<Op>,
}

impl OpLog {
    /// Open (or create) the oplog rooted at `<repo_root>/oplog/`.
    pub fn open(repo_root: &Path) -> Result<Self> {
        let dir = repo_root.join(OPLOG_DIR);
        fs::create_dir_all(&dir)?;
        let path = dir.join(PRIMARY_FILE);
        // Touch the file so subsequent reads don't fail with NotFound.
        if !path.exists() {
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
        }
        let next_id = compute_next_id(&path)?;
        Ok(OpLog::File(FileLog { path, next_id }))
    }

    pub fn in_memory() -> Self {
        OpLog::InMemory(MemLog::default())
    }

    /// Append an op. Assigns id + timestamp. Returns the finalized `Op`.
    pub fn append(&mut self, op: OpInProgress) -> Result<Op> {
        match self {
            OpLog::File(log) => log.append(op),
            OpLog::InMemory(log) => log.append(op),
        }
    }

    /// Read all ops in order. O(n) — acceptable for small logs;
    /// pagination/indexes come later.
    pub fn list(&self) -> Result<Vec<Op>> {
        match self {
            OpLog::File(log) => read_all(&log.path),
            OpLog::InMemory(log) => Ok(log.ops.clone()),
        }
    }

    /// The most recent op, if any.
    pub fn last(&self) -> Result<Option<Op>> {
        Ok(self.list()?.into_iter().last())
    }

    pub fn next_id(&self) -> OpId {
        OpId(match self {
            OpLog::File(log) => log.next_id,
            OpLog::InMemory(log) => log.next_id,
        })
    }
}

impl FileLog {
    fn append(&mut self, op: OpInProgress) -> Result<Op> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let finalized = Op {
            id: OpId(self.next_id),
            ts_ns: now,
            actor: op.actor,
            kind: op.kind,
            before: op.before,
            after: op.after,
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&finalized, &mut bytes)
            .map_err(|e| Error::Corrupt(format!("oplog encode: {e}")))?;
        let len: u32 = bytes
            .len()
            .try_into()
            .map_err(|_| Error::Corrupt("oplog record too large".into()))?;

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&len.to_be_bytes())?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        self.next_id += 1;
        Ok(finalized)
    }
}

impl MemLog {
    fn append(&mut self, op: OpInProgress) -> Result<Op> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let finalized = Op {
            id: OpId(self.next_id),
            ts_ns: now,
            actor: op.actor,
            kind: op.kind,
            before: op.before,
            after: op.after,
        };
        self.next_id += 1;
        self.ops.push(finalized.clone());
        Ok(finalized)
    }
}

fn compute_next_id(path: &Path) -> Result<u64> {
    let mut max: i64 = -1;
    for op in read_all(path)? {
        if op.id.0 as i64 > max {
            max = op.id.0 as i64;
        }
    }
    Ok((max + 1) as u64)
}

fn read_all(path: &Path) -> Result<Vec<Op>> {
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(e)),
    };
    let total = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(0))?;

    let mut out = Vec::new();
    let mut pos: u64 = 0;
    let mut len_buf = [0u8; 4];
    while pos < total {
        if total - pos < 4 {
            return Err(Error::Corrupt(format!(
                "oplog truncated header at byte {pos}"
            )));
        }
        file.read_exact(&mut len_buf)?;
        pos += 4;
        let len = u32::from_be_bytes(len_buf) as u64;
        if total - pos < len {
            return Err(Error::Corrupt(format!(
                "oplog truncated payload at byte {pos} (need {len})"
            )));
        }
        let mut payload = vec![0u8; len as usize];
        file.read_exact(&mut payload)?;
        pos += len;
        let op: Op = ciborium::de::from_reader(payload.as_slice())
            .map_err(|e| Error::Corrupt(format!("oplog decode at {pos}: {e}")))?;
        out.push(op);
    }
    Ok(out)
}

impl RefSnapshot {
    /// Read whatever the named ref currently points at, returning a
    /// fresh `RefSnapshot` of the same discriminator. The variant's
    /// `value` (or `Option<ChangeId>`) is filled in from disk.
    ///
    /// Used by `undo_once` to capture "what we're about to overwrite"
    /// so the undo itself becomes auditable + redoable.
    pub fn read_current(
        &self,
        repo: &crate::Repository,
        workspaces: &crate::WorkspaceStore,
    ) -> Result<RefSnapshot> {
        use crate::RefStore;
        match self {
            RefSnapshot::Head(_) => Ok(RefSnapshot::Head(repo.head()?)),
            RefSnapshot::Change { id, .. } => match repo.get_change(id) {
                Ok(c) => Ok(RefSnapshot::Change {
                    id: id.clone(),
                    value: Some(c),
                }),
                Err(Error::NotFound(_)) => Ok(RefSnapshot::Change {
                    id: id.clone(),
                    value: None,
                }),
                Err(e) => Err(e),
            },
            RefSnapshot::Workspace { id, .. } => match workspaces.get(id) {
                Ok(m) => Ok(RefSnapshot::Workspace {
                    id: id.clone(),
                    value: Some(m),
                }),
                Err(Error::NotFound(_)) => Ok(RefSnapshot::Workspace {
                    id: id.clone(),
                    value: None,
                }),
                Err(e) => Err(e),
            },
            RefSnapshot::Bookmark { name, .. } => Ok(RefSnapshot::Bookmark {
                name: name.clone(),
                value: repo.refs().get_bookmark(name)?,
            }),
        }
    }
}

/// Capture the current value of whichever ref `tig snap` would mutate
/// in this workspace — HEAD for main, the workspace manifest for a
/// secondary. Used by every command that wants to record a workspace-
/// advancing op.
pub fn workspace_ref_snapshot(ws: &crate::Workspace) -> Result<RefSnapshot> {
    use crate::WorkspaceKind;
    match &ws.kind {
        WorkspaceKind::Main => Ok(RefSnapshot::Head(ws.repo.head()?)),
        WorkspaceKind::Secondary(_) => {
            let store = crate::WorkspaceStore::open(ws.repo.root())?;
            let id = ws
                .workspace_id()
                .expect("secondary workspace always has an id")
                .clone();
            let value = match store.get(&id) {
                Ok(m) => Some(m),
                Err(Error::NotFound(_)) => None,
                Err(e) => return Err(e),
            };
            Ok(RefSnapshot::Workspace { id, value })
        }
    }
}

/// Result of a successful `undo_once`.
#[derive(Clone, Debug)]
pub struct UndoOutcome {
    /// The op we rolled back.
    pub undone: Op,
    /// The Undo op we appended to record this action.
    pub recorded: Op,
}

/// Roll back one operation. Returns `None` if every prior op is already
/// undone (i.e. the log only contains balanced regular/undo pairs).
///
/// Steps:
///   1. Walk the log, find the most recent op not yet undone (see
///      `pick_op_to_undo`).
///   2. Read each ref's *current* state — this is the "after-undo"
///      target's `before` from our perspective, which we'll record so a
///      future redo can put us back.
///   3. Apply `target.before` to each ref via `restore_ref`.
///   4. Append a new `OpKind::Undo` op.
pub fn undo_once(
    repo: &crate::Repository,
    log: &mut OpLog,
    actor: &PrincipalId,
) -> Result<Option<UndoOutcome>> {
    let ops = log.list()?;
    let target = match pick_op_to_undo(&ops) {
        Some(op) => op.clone(),
        None => return Ok(None),
    };
    let workspaces = crate::WorkspaceStore::open(repo.root())?;

    // Snapshot the live state of each ref the target touched. This is
    // what we're about to overwrite, so we record it as `before_undo`
    // — i.e. the state to which a `redo` (not yet implemented) would
    // restore us.
    let mut before_undo: Vec<RefSnapshot> = Vec::with_capacity(target.before.len());
    for snap in &target.before {
        before_undo.push(snap.read_current(repo, &workspaces)?);
    }

    // Apply the inverse — write the target's recorded "before" state.
    for snap in &target.before {
        restore_ref(snap, repo, &workspaces)?;
    }

    let recorded = log.append(OpInProgress {
        actor: actor.clone(),
        kind: OpKind::Undo {
            undone_op: target.id,
        },
        before: before_undo,
        after: target.before.clone(),
    })?;

    Ok(Some(UndoOutcome {
        undone: target,
        recorded,
    }))
}

/// Apply a `RefSnapshot` — write its value into the repo so the named
/// ref ends up matching this captured state. Used by `tig undo`.
///
/// Missing-target handling: `Change::delete` and friends already treat
/// "ref doesn't exist" as a no-op, so restoring `None` is idempotent.
pub fn restore_ref(
    snapshot: &RefSnapshot,
    repo: &crate::Repository,
    workspaces: &crate::WorkspaceStore,
) -> Result<()> {
    use crate::RefStore;
    match snapshot {
        RefSnapshot::Head(value) => match value {
            Some(id) => repo.refs().set_head(id),
            None => repo.refs().clear_head(),
        },
        RefSnapshot::Change { id, value } => match value {
            Some(c) => repo.refs().put_change(c),
            None => repo.refs().delete_change(id),
        },
        RefSnapshot::Workspace { id, value } => match value {
            Some(m) => workspaces.put(m),
            None => match workspaces.delete(id) {
                Ok(()) => Ok(()),
                Err(Error::NotFound(_)) => Ok(()),
                Err(e) => Err(e),
            },
        },
        RefSnapshot::Bookmark { name, value } => match value {
            Some(c) => repo.refs().set_bookmark(name, c),
            None => repo.refs().delete_bookmark(name),
        },
    }
}

/// Find the most recent op that hasn't already been undone.
///
/// Algorithm: walk backward; each `Undo` increments a counter, each
/// non-`Undo` decrements it if positive (it's already accounted for).
/// The first non-`Undo` to find the counter at zero is what we should
/// undo next.
pub fn pick_op_to_undo(ops: &[Op]) -> Option<&Op> {
    let mut undo_depth: i64 = 0;
    for op in ops.iter().rev() {
        match &op.kind {
            OpKind::Undo { .. } => undo_depth += 1,
            _ if undo_depth > 0 => undo_depth -= 1,
            _ => return Some(op),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tig_core::{Change, ChangeId, Hash, ObjectKind};

    fn fake_change(desc: &str) -> Change {
        let h = Hash::compute(ObjectKind::Snapshot, desc.as_bytes());
        Change::new(desc, PrincipalId::local("t"), h)
    }

    fn snap_op() -> OpInProgress {
        OpInProgress {
            actor: PrincipalId::local("tester"),
            kind: OpKind::Snap {
                snapshot: Hash::compute(ObjectKind::Snapshot, b"x"),
                message: Some("test".into()),
            },
            before: vec![RefSnapshot::Head(None)],
            after: vec![RefSnapshot::Head(Some(ChangeId::new()))],
        }
    }

    #[test]
    fn empty_log_returns_no_ops() {
        let dir = tempdir().unwrap();
        let log = OpLog::open(dir.path()).unwrap();
        assert!(log.list().unwrap().is_empty());
        assert!(log.last().unwrap().is_none());
        assert_eq!(log.next_id(), OpId(0));
    }

    #[test]
    fn append_assigns_monotonic_ids() {
        let dir = tempdir().unwrap();
        let mut log = OpLog::open(dir.path()).unwrap();
        let a = log.append(snap_op()).unwrap();
        let b = log.append(snap_op()).unwrap();
        let c = log.append(snap_op()).unwrap();
        assert_eq!(a.id, OpId(0));
        assert_eq!(b.id, OpId(1));
        assert_eq!(c.id, OpId(2));
        assert_eq!(log.list().unwrap().len(), 3);
        assert_eq!(log.last().unwrap().unwrap().id, c.id);
    }

    #[test]
    fn ids_resume_after_reopen() {
        let dir = tempdir().unwrap();
        let mut log = OpLog::open(dir.path()).unwrap();
        log.append(snap_op()).unwrap();
        log.append(snap_op()).unwrap();
        drop(log);
        let mut log = OpLog::open(dir.path()).unwrap();
        let next = log.append(snap_op()).unwrap();
        assert_eq!(next.id, OpId(2));
    }

    #[test]
    fn ref_snapshot_with_change_record_roundtrips() {
        let dir = tempdir().unwrap();
        let mut log = OpLog::open(dir.path()).unwrap();
        let change = fake_change("the work");
        log.append(OpInProgress {
            actor: PrincipalId::local("t"),
            kind: OpKind::ChangeNew {
                change_id: change.id.clone(),
                description: change.description.clone(),
            },
            before: vec![
                RefSnapshot::Head(None),
                RefSnapshot::Change {
                    id: change.id.clone(),
                    value: None,
                },
            ],
            after: vec![
                RefSnapshot::Head(Some(change.id.clone())),
                RefSnapshot::Change {
                    id: change.id.clone(),
                    value: Some(change.clone()),
                },
            ],
        })
        .unwrap();

        let ops = log.list().unwrap();
        assert_eq!(ops.len(), 1);
        let op = &ops[0];
        // After contains the change record by value:
        match &op.after[1] {
            RefSnapshot::Change { value: Some(c), .. } => {
                assert_eq!(c, &change);
            }
            other => panic!("expected Change(Some), got {other:?}"),
        }
    }

    #[test]
    fn corrupt_oplog_is_reported_not_silently_ignored() {
        let dir = tempdir().unwrap();
        let mut log = OpLog::open(dir.path()).unwrap();
        log.append(snap_op()).unwrap();
        let path = dir.path().join(OPLOG_DIR).join(PRIMARY_FILE);

        // Truncate mid-record.
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..bytes.len() - 4]).unwrap();
        match OpLog::open(dir.path()) {
            Err(Error::Corrupt(_)) => {}
            Ok(_) => panic!("expected Corrupt, got Ok"),
            Err(other) => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn pick_op_to_undo_skips_balanced_undo_pairs() {
        let mut ops: Vec<Op> = Vec::new();
        let mk = |id: u64, kind: OpKind| Op {
            id: OpId(id),
            ts_ns: id,
            actor: PrincipalId::local("t"),
            kind,
            before: vec![],
            after: vec![],
        };

        // op#0: ChangeNew
        // op#1: Snap
        // op#2: Snap
        // op#3: Undo of op#2     ← cancels op#2
        // op#4: Undo of op#1     ← cancels op#1
        // pick_op_to_undo → op#0
        ops.push(mk(
            0,
            OpKind::ChangeNew {
                change_id: ChangeId::new(),
                description: "x".into(),
            },
        ));
        ops.push(mk(
            1,
            OpKind::Snap {
                snapshot: Hash::compute(ObjectKind::Snapshot, b"a"),
                message: None,
            },
        ));
        ops.push(mk(
            2,
            OpKind::Snap {
                snapshot: Hash::compute(ObjectKind::Snapshot, b"b"),
                message: None,
            },
        ));
        ops.push(mk(3, OpKind::Undo { undone_op: OpId(2) }));
        ops.push(mk(4, OpKind::Undo { undone_op: OpId(1) }));

        let picked = pick_op_to_undo(&ops).expect("should pick something");
        assert_eq!(picked.id, OpId(0));
    }

    #[test]
    fn pick_op_to_undo_returns_none_when_everything_is_undone() {
        let mk = |id: u64, kind: OpKind| Op {
            id: OpId(id),
            ts_ns: id,
            actor: PrincipalId::local("t"),
            kind,
            before: vec![],
            after: vec![],
        };
        let ops = vec![
            mk(
                0,
                OpKind::Snap {
                    snapshot: Hash::compute(ObjectKind::Snapshot, b"a"),
                    message: None,
                },
            ),
            mk(1, OpKind::Undo { undone_op: OpId(0) }),
        ];
        assert!(pick_op_to_undo(&ops).is_none());
    }

    #[test]
    fn in_memory_log_is_functional() {
        let mut log = OpLog::in_memory();
        log.append(snap_op()).unwrap();
        log.append(snap_op()).unwrap();
        assert_eq!(log.list().unwrap().len(), 2);
    }

    // --- integration tests: undo against a real Repository ---

    use crate::{Repository, WorkspaceStore};

    fn fresh_repo() -> (tempfile::TempDir, Repository) {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        (dir, repo)
    }

    #[test]
    fn undo_restores_head_after_create() {
        // Scenario:
        //   - HEAD starts None.
        //   - We "create change A" — set HEAD = Some(A.id) and put A.
        //   - undo_once should put HEAD back to None and remove A.

        let (_dir, repo) = fresh_repo();
        let mut log = OpLog::open(repo.root()).unwrap();

        let change = fake_change("first work");
        let change_id = change.id.clone();

        // Apply the mutation.
        repo.put_change(&change).unwrap();
        repo.set_head(&change_id).unwrap();
        // Record the op.
        log.append(OpInProgress {
            actor: PrincipalId::local("t"),
            kind: OpKind::ChangeNew {
                change_id: change_id.clone(),
                description: change.description.clone(),
            },
            before: vec![
                RefSnapshot::Head(None),
                RefSnapshot::Change {
                    id: change_id.clone(),
                    value: None,
                },
            ],
            after: vec![
                RefSnapshot::Head(Some(change_id.clone())),
                RefSnapshot::Change {
                    id: change_id.clone(),
                    value: Some(change.clone()),
                },
            ],
        })
        .unwrap();

        // Undo.
        let actor = PrincipalId::local("undoer");
        let outcome = undo_once(&repo, &mut log, &actor).unwrap().unwrap();
        assert!(matches!(outcome.undone.kind, OpKind::ChangeNew { .. }));
        assert!(matches!(outcome.recorded.kind, OpKind::Undo { .. }));

        // HEAD cleared.
        assert!(repo.head().unwrap().is_none());
        // Change deleted.
        assert!(matches!(
            repo.get_change(&change_id),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn undo_handles_workspace_creation() {
        let (_dir, repo) = fresh_repo();
        let workspaces = WorkspaceStore::open(repo.root()).unwrap();
        let mut log = OpLog::open(repo.root()).unwrap();

        let manifest = WorkspaceManifest {
            id: WorkspaceId::new(),
            name: "feat".into(),
            location: repo.workdir().join("ws"),
            change_id: ChangeId::new(),
            created_ns: 0,
        };
        workspaces.put(&manifest).unwrap();

        log.append(OpInProgress {
            actor: PrincipalId::local("t"),
            kind: OpKind::WtMake {
                workspace_id: manifest.id.clone(),
                name: manifest.name.clone(),
            },
            before: vec![RefSnapshot::Workspace {
                id: manifest.id.clone(),
                value: None,
            }],
            after: vec![RefSnapshot::Workspace {
                id: manifest.id.clone(),
                value: Some(manifest.clone()),
            }],
        })
        .unwrap();

        let outcome = undo_once(&repo, &mut log, &PrincipalId::local("t"))
            .unwrap()
            .unwrap();
        assert!(matches!(outcome.undone.kind, OpKind::WtMake { .. }));
        assert!(matches!(
            workspaces.get(&manifest.id),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn undo_twice_walks_back_two_real_ops() {
        let (_dir, repo) = fresh_repo();
        let mut log = OpLog::open(repo.root()).unwrap();

        // Op A: change-new for A.
        let change_a = fake_change("a");
        repo.put_change(&change_a).unwrap();
        repo.set_head(&change_a.id).unwrap();
        log.append(OpInProgress {
            actor: PrincipalId::local("t"),
            kind: OpKind::ChangeNew {
                change_id: change_a.id.clone(),
                description: "a".into(),
            },
            before: vec![
                RefSnapshot::Head(None),
                RefSnapshot::Change {
                    id: change_a.id.clone(),
                    value: None,
                },
            ],
            after: vec![
                RefSnapshot::Head(Some(change_a.id.clone())),
                RefSnapshot::Change {
                    id: change_a.id.clone(),
                    value: Some(change_a.clone()),
                },
            ],
        })
        .unwrap();

        // Op B: change-new for B (HEAD now points at B).
        let change_b = fake_change("b");
        repo.put_change(&change_b).unwrap();
        repo.set_head(&change_b.id).unwrap();
        log.append(OpInProgress {
            actor: PrincipalId::local("t"),
            kind: OpKind::ChangeNew {
                change_id: change_b.id.clone(),
                description: "b".into(),
            },
            before: vec![
                RefSnapshot::Head(Some(change_a.id.clone())),
                RefSnapshot::Change {
                    id: change_b.id.clone(),
                    value: None,
                },
            ],
            after: vec![
                RefSnapshot::Head(Some(change_b.id.clone())),
                RefSnapshot::Change {
                    id: change_b.id.clone(),
                    value: Some(change_b.clone()),
                },
            ],
        })
        .unwrap();

        // First undo → walks back op B; HEAD back to A, B's change gone.
        undo_once(&repo, &mut log, &PrincipalId::local("u"))
            .unwrap()
            .unwrap();
        assert_eq!(repo.head().unwrap(), Some(change_a.id.clone()));
        assert!(matches!(
            repo.get_change(&change_b.id),
            Err(Error::NotFound(_))
        ));

        // Second undo → walks back op A; HEAD None, A's change gone.
        undo_once(&repo, &mut log, &PrincipalId::local("u"))
            .unwrap()
            .unwrap();
        assert!(repo.head().unwrap().is_none());
        assert!(matches!(
            repo.get_change(&change_a.id),
            Err(Error::NotFound(_))
        ));

        // Third undo finds nothing.
        assert!(undo_once(&repo, &mut log, &PrincipalId::local("u"))
            .unwrap()
            .is_none());
    }
}
