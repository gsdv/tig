//! On-disk persistence for tig.
//!
//! Two stores live side-by-side under `.tig/`:
//!
//!   - `objects/`  → content-addressed, immutable blobs/trees/snapshots
//!   - `refs/`     → small mutable JSON records (Changes, bookmarks)
//!
//! Anything content-addressed goes through `ObjectStore`. Anything that
//! moves over time goes through `RefStore`. The two have no shared
//! invariants — they are independent on purpose so they can have
//! different durability strategies later (object writes are append-only;
//! ref writes are CAS).

pub mod error;
pub mod objects;
pub mod oplog;
pub mod refs;
pub mod repo;
pub mod workspace;

pub use error::Error;
pub use objects::{FsObjectStore, ObjectStore};
pub use oplog::{
    pick_op_to_undo, restore_ref, undo_once, workspace_ref_snapshot, Op, OpInProgress,
    OpKind, OpLog, RefSnapshot, UndoOutcome,
};
pub use refs::{FsRefStore, RefStore};
pub use repo::{Repository, TIG_DIR};
pub use workspace::{
    read_marker, write_marker, Workspace, WorkspaceId, WorkspaceKind, WorkspaceManifest,
    WorkspaceMarker, WorkspaceStore, DEFAULT_WORKTREE_DIR, MARKER_FILE,
};

pub type Result<T> = std::result::Result<T, Error>;
