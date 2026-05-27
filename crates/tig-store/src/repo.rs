//! The `Repository` — the bundle a CLI command typically holds.
//!
//! Owns:
//!   - `.tig/` root path
//!   - an `ObjectStore` (`objects/`)
//!   - a `RefStore`     (`refs/`)
//!
//! Higher layers should prefer methods on `Repository` over reaching into
//! the stores directly, so that lifecycle (locking, validation, op-log
//! recording) can be added in one place.

use crate::{Error, FsObjectStore, FsRefStore, ObjectStore, RefStore, Result};
use fs4::fs_std::FileExt;
use std::fs;
use std::path::{Path, PathBuf};
use tig_core::{Change, ChangeId, Hash, RawObject};

pub const TIG_DIR: &str = ".tig";
pub const LOCK_FILE: &str = "lock";

pub struct Repository {
    root: PathBuf,
    objects: FsObjectStore,
    refs: FsRefStore,
}

/// RAII guard for the per-repo write lock. Acquired by
/// [`Repository::lock_for_write`]; released when dropped.
///
/// Behind the scenes this is an exclusive `flock(2)` on `<repo>/lock`
/// (`LockFileEx` on Windows, via `fs4`). The OS releases the lock if
/// the holding process dies — so a crashed writer doesn't deadlock
/// future writers. Advisory locking applies per-FD: threads of the
/// same process don't block each other on the same lock file, but
/// separate processes do.
pub struct WriteGuard {
    // Holding the File alive keeps the flock held. Drop releases it.
    _file: fs::File,
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        // fs4 releases the lock when the File is closed (drop). We
        // could call `unlock()` explicitly but the implicit release on
        // drop is equivalent and avoids a fallible step in Drop.
    }
}

impl Repository {
    /// Initialize a new tig repo rooted at `workdir`. Fails if `.tig`
    /// already exists.
    pub fn init(workdir: impl AsRef<Path>) -> Result<Self> {
        let tig_dir = workdir.as_ref().join(TIG_DIR);
        if tig_dir.exists() {
            return Err(Error::AlreadyExists(tig_dir.display().to_string()));
        }
        fs::create_dir_all(&tig_dir)?;

        let objects = FsObjectStore::open(tig_dir.join("store").join("objects"))?;
        let refs = FsRefStore::open(tig_dir.join("refs"))?;
        Ok(Self {
            root: tig_dir,
            objects,
            refs,
        })
    }

    /// Open an existing tig repo. Looks for `.tig/` in `workdir` only
    /// (no upward walk yet — added in a follow-up).
    pub fn open(workdir: impl AsRef<Path>) -> Result<Self> {
        let tig_dir = workdir.as_ref().join(TIG_DIR);
        if !tig_dir.exists() {
            return Err(Error::NotFound(format!(
                "no .tig directory at {}",
                workdir.as_ref().display()
            )));
        }
        Self::open_at_tig_dir(&tig_dir)
    }

    /// Open a repo when you already have the absolute path to its `.tig/`
    /// directory. Used by the workspace marker layer where the workdir is
    /// arbitrary but the repo is pinned.
    pub fn open_at_tig_dir(tig_dir: impl AsRef<Path>) -> Result<Self> {
        let tig_dir = tig_dir.as_ref().to_path_buf();
        if !tig_dir.is_dir() {
            return Err(Error::NotFound(format!(
                "not a tig directory: {}",
                tig_dir.display()
            )));
        }
        let objects = FsObjectStore::open(tig_dir.join("store").join("objects"))?;
        let refs = FsRefStore::open(tig_dir.join("refs"))?;
        Ok(Self {
            root: tig_dir,
            objects,
            refs,
        })
    }

    /// Walk upward from `start` looking for a `.tig/` directory.
    pub fn discover(start: impl AsRef<Path>) -> Result<Self> {
        let mut cur = start.as_ref().canonicalize()?;
        loop {
            if cur.join(TIG_DIR).is_dir() {
                return Self::open(&cur);
            }
            if !cur.pop() {
                return Err(Error::NotFound(format!(
                    "no .tig directory in {} or any parent",
                    start.as_ref().display()
                )));
            }
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The working directory — the parent of `.tig/`. Every `Repository`
    /// must have one (we always create `.tig/` under a real directory).
    pub fn workdir(&self) -> &Path {
        self.root
            .parent()
            .expect("Repository::root always has a parent directory")
    }

    pub fn objects(&self) -> &FsObjectStore {
        &self.objects
    }

    pub fn refs(&self) -> &FsRefStore {
        &self.refs
    }

    // --- convenience passthroughs -------------------------------------

    pub fn put(&self, obj: &RawObject) -> Result<Hash> {
        self.objects.put(obj)
    }

    pub fn get(&self, hash: &Hash) -> Result<RawObject> {
        self.objects.get(hash)
    }

    /// Resolve a hex prefix (≥ 4 chars) to a full content hash. Errors
    /// on ambiguous or missing prefixes — see `FsObjectStore::resolve_prefix`.
    pub fn resolve_hash_prefix(&self, prefix: &str) -> Result<Hash> {
        self.objects.resolve_prefix(prefix)
    }

    pub fn put_change(&self, change: &Change) -> Result<()> {
        self.refs.put_change(change)
    }

    pub fn get_change(&self, id: &ChangeId) -> Result<Change> {
        self.refs.get_change(id)
    }

    pub fn head(&self) -> Result<Option<ChangeId>> {
        self.refs.head()
    }

    pub fn set_head(&self, id: &ChangeId) -> Result<()> {
        self.refs.set_head(id)
    }

    // --- multi-process write locking ----------------------------------

    fn lock_file_path(&self) -> PathBuf {
        self.root.join(LOCK_FILE)
    }

    /// Acquire the per-repo exclusive write lock, blocking until
    /// available. Hold the returned guard for the duration of any
    /// state-changing operation — snap, change creation, transition,
    /// undo, workspace make/drop, sealed-value writes.
    ///
    /// The lock serializes writers across processes; without it, two
    /// concurrent `tig snap` invocations can produce torn op-log
    /// records or duplicate op ids. Reads don't take this lock;
    /// individual writes are atomic via tempfile-rename, so readers
    /// either see the old or new state but never a half-written one.
    pub fn lock_for_write(&self) -> Result<WriteGuard> {
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.lock_file_path())?;
        file.lock_exclusive()?;
        Ok(WriteGuard { _file: file })
    }

    /// Non-blocking variant. Returns `Ok(None)` if another process
    /// already holds the lock. Useful for "is anyone else writing
    /// right now?" probes; the daemon doesn't use this — it always
    /// wants to wait.
    pub fn try_lock_for_write(&self) -> Result<Option<WriteGuard>> {
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.lock_file_path())?;
        match file.try_lock_exclusive() {
            Ok(true) => Ok(Some(WriteGuard { _file: file })),
            Ok(false) => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tig_core::{Blob, Encodable, PrincipalId, Snapshot, Tree};

    #[test]
    fn init_then_open_finds_same_repo() {
        let dir = tempdir().unwrap();
        Repository::init(dir.path()).unwrap();
        let repo = Repository::open(dir.path()).unwrap();
        // The repo's root path's final component should be ".tig".
        assert_eq!(
            repo.root().file_name().and_then(|n| n.to_str()),
            Some(".tig"),
        );
    }

    #[test]
    fn init_twice_fails() {
        let dir = tempdir().unwrap();
        Repository::init(dir.path()).unwrap();
        match Repository::init(dir.path()) {
            Err(Error::AlreadyExists(_)) => {}
            other => panic!("expected AlreadyExists, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn full_object_chain_persists() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();

        let blob_h = repo
            .put(&Blob::new(b"hi".to_vec()).encode().unwrap())
            .unwrap();
        let tree_h = repo.put(&Tree::new().encode().unwrap()).unwrap();
        let snap = Snapshot {
            parents: vec![],
            tree: tree_h,
            author: PrincipalId::local("t"),
            timestamp_ns: 1,
            message: Some("initial".into()),
            op_id: None,
        };
        let snap_h = repo.put(&snap.encode().unwrap()).unwrap();

        let change = Change::new("first work", PrincipalId::local("t"), snap_h);
        repo.put_change(&change).unwrap();
        repo.set_head(&change.id).unwrap();

        // Re-open and re-read
        let repo = Repository::open(dir.path()).unwrap();
        assert_eq!(repo.head().unwrap(), Some(change.id.clone()));
        let back = repo.get_change(&change.id).unwrap();
        assert_eq!(back, change);
        assert!(repo.objects.has(&blob_h).unwrap());
    }
}
