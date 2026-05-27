//! Working-copy I/O for tig.
//!
//! Right now: one operation — `scan`. Given a working directory and a
//! place to put objects, walk the tree, hash everything, and return the
//! root `Tree`'s hash. This is the operation that turns "what's on disk
//! right now" into a snapshot's tree.
//!
//! Future additions documented in `docs/ARCHITECTURE.md`:
//!   - `materialize` — render a Tree back to disk via CoW (§6.2)
//!   - `watch` — fsevents/inotify-driven auto-snap (§5.1)
//!   - `workspace` — multi-checkout management (§6)

pub mod clone;
pub mod diff;
pub mod error;
pub mod materialize;
pub mod restore;
pub mod scan;
pub mod snap;
pub mod tree_edit;
pub mod watch;

#[cfg(target_os = "macos")]
pub use clone::ApfsClone;
pub use clone::{detect as detect_clone_engine, AutoClone, CloneEngine, CopyFallback};
pub use diff::{
    blob_diff_hunks, diff_trees, is_binary, ChangeKind, DiffOptions, FileDiff, Hunk, HunkLine,
};
pub use error::Error;
pub use materialize::{
    collect_sealed_paths, materialize_change_into, materialize_from_workspace, render_tree_into,
    MaterializeOutcome, RenderStats,
};
pub use restore::{restore_tree_into, RestoreOptions, RestoreOutcome};
pub use scan::{scan, ScanOptions};
pub use snap::{snap_change_directly, snap_now, SnapOptions, SnapOutcome};
pub use tree_edit::{
    delete_at_path, list_tree, lookup_entry, read_blob_at_path, write_blob_at_path,
    write_sealed_at_path,
};
pub use watch::{watch_and_snap, WatchEvent, WatchOptions};

pub type Result<T> = std::result::Result<T, Error>;
