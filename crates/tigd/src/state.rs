//! Daemon-wide state: the open repo and the single oplog handle.
//!
//! We hold the `OpLog` behind a `Mutex` so writes serialize, since the
//! file is append-only and the in-memory `next_id` must advance
//! monotonically. The `Repository` itself is `&self`-only and safe to
//! share via `Arc`; we keep `OpLog` separate so reads on the change/
//! object stores don't have to take the oplog lock.

use std::path::PathBuf;
use std::sync::Arc;

use tig_store::{OpLog, Repository};
use tokio::sync::Mutex;

pub struct AppState {
    pub repo: Arc<Repository>,
    pub log: Mutex<OpLog>,
    pub repo_root: PathBuf,
}

impl AppState {
    pub fn open(repo_root: PathBuf) -> anyhow::Result<Self> {
        let repo =
            Repository::open_at_tig_dir(&repo_root).or_else(|_| Repository::open(&repo_root))?;
        let log = OpLog::open(repo.root())?;
        Ok(Self {
            repo: Arc::new(repo),
            log: Mutex::new(log),
            repo_root,
        })
    }
}
