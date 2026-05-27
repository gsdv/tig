//! Workspaces: independently materialized projections of a `Change`.
//!
//! A single repository can have many workspaces. Each is a real directory
//! containing the files of some `Change` at some point in time. Edits in
//! a workspace advance *that workspace's* change — they do not silently
//! cross-contaminate.
//!
//! Two kinds:
//!
//!   - **Main** — the workspace whose `.tig/` directory holds the actual
//!     repo. There is exactly one main workspace per repo. Its "current
//!     change" lives in `refs/HEAD` (same as before this module existed).
//!
//!   - **Secondary** — created by `tig wt make`. Lives in a different
//!     directory and contains a small `.tig-workspace` marker pointing
//!     back at the repo. Its current change lives in the manifest under
//!     `<repo>/workspaces/<id>.json`.
//!
//! This split keeps the existing single-workspace behavior unchanged —
//! tests that read `repo.head()` keep working. Secondary workspaces are
//! purely additive.

use crate::{Error, Repository, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tig_core::ChangeId;

/// Filename of the marker dropped at the root of every secondary
/// workspace. Holds an absolute path back to the repo and the
/// workspace's id.
pub const MARKER_FILE: &str = ".tig-workspace";

/// Where secondary workspaces live by default, relative to the main
/// workdir. The scanner adds this to its ignore list so the main
/// workspace doesn't try to snapshot its own siblings.
pub const DEFAULT_WORKTREE_DIR: &str = ".tig-worktrees";

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct WorkspaceId(pub String);

impl WorkspaceId {
    pub fn new() -> Self {
        WorkspaceId(ulid::Ulid::new().to_string())
    }
}

impl Default for WorkspaceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for WorkspaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The on-disk record of a secondary workspace. Stored at
/// `<repo>/workspaces/<id>.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceManifest {
    pub id: WorkspaceId,
    pub name: String,
    /// Absolute path to the directory holding this workspace's files.
    pub location: PathBuf,
    /// The change currently checked out here.
    pub change_id: ChangeId,
    /// Unix ns. Display-only.
    pub created_ns: u64,
}

/// The small marker file at `<workspace>/.tig-workspace`. Points back at
/// the owning repo so the CLI can resolve a stray `cd` into a workspace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceMarker {
    /// Absolute path to the repo's `.tig/` directory.
    pub repo: PathBuf,
    pub workspace_id: WorkspaceId,
}

/// CRUD over the workspace manifest registry under `<repo>/workspaces/`.
pub struct WorkspaceStore {
    dir: PathBuf,
}

impl WorkspaceStore {
    pub fn open(repo_dir: &Path) -> Result<Self> {
        let dir = repo_dir.join("workspaces");
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn put(&self, manifest: &WorkspaceManifest) -> Result<()> {
        let path = self.dir.join(format!("{}.json", manifest.id.0));
        let bytes = serde_json::to_vec_pretty(manifest)?;
        atomic_write(&path, &bytes)
    }

    pub fn get(&self, id: &WorkspaceId) -> Result<WorkspaceManifest> {
        let path = self.dir.join(format!("{}.json", id.0));
        let bytes = fs::read(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::NotFound(format!("workspace {}", id.0)),
            _ => Error::Io(e),
        })?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn list(&self) -> Result<Vec<WorkspaceManifest>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if !s.ends_with(".json") || s.starts_with('.') {
                continue;
            }
            let bytes = fs::read(entry.path())?;
            let manifest: WorkspaceManifest = serde_json::from_slice(&bytes)?;
            out.push(manifest);
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    pub fn find_by_name(&self, name: &str) -> Result<Option<WorkspaceManifest>> {
        for m in self.list()? {
            if m.name == name {
                return Ok(Some(m));
            }
        }
        Ok(None)
    }

    pub fn delete(&self, id: &WorkspaceId) -> Result<()> {
        let path = self.dir.join(format!("{}.json", id.0));
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::NotFound(format!("workspace {}", id.0)))
            }
            Err(e) => Err(Error::Io(e)),
        }
    }
}

/// Read a `.tig-workspace` marker if one exists in `dir`.
pub fn read_marker(dir: &Path) -> Result<Option<WorkspaceMarker>> {
    let path = dir.join(MARKER_FILE);
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io(e)),
    }
}

pub fn write_marker(dir: &Path, marker: &WorkspaceMarker) -> Result<()> {
    let path = dir.join(MARKER_FILE);
    let bytes = serde_json::to_vec_pretty(marker)?;
    atomic_write(&path, &bytes)
}

/// A handle representing "which workspace are we currently operating in?"
///
/// Carries the owning `Repository` plus the discriminator. Most engine
/// functions (`snap_now`, `watch_and_snap`) take `&Workspace` so they
/// don't have to know whether they're operating on the main workspace or
/// a secondary.
pub struct Workspace {
    pub repo: Repository,
    pub kind: WorkspaceKind,
}

pub enum WorkspaceKind {
    Main,
    Secondary(WorkspaceManifest),
}

impl Workspace {
    /// Wrap an open `Repository` as the main workspace. Convenience for
    /// callers that already have a `Repository`.
    pub fn main_for(repo: Repository) -> Self {
        Self { repo, kind: WorkspaceKind::Main }
    }

    /// Wrap a manifest as a secondary workspace. The repo must already be
    /// open and refer to the repo named by the manifest.
    pub fn secondary(repo: Repository, manifest: WorkspaceManifest) -> Self {
        Self { repo, kind: WorkspaceKind::Secondary(manifest) }
    }

    /// Discover the workspace containing `start`. Algorithm:
    ///   1. Walk upward looking for `.tig-workspace` first. If found,
    ///      load the marker and open the repo it points at; return a
    ///      Secondary workspace.
    ///   2. Otherwise walk upward looking for `.tig/`. If found, return
    ///      a Main workspace.
    ///
    /// The marker takes priority over `.tig/` to handle the legal case
    /// where a marker lives inside a directory tree that also contains a
    /// `.tig/` (e.g. nested checkouts).
    pub fn discover(start: impl AsRef<Path>) -> Result<Self> {
        let start = start.as_ref().canonicalize()?;
        let mut cur: &Path = &start;
        loop {
            if cur.join(MARKER_FILE).is_file() {
                let marker = read_marker(cur)?.ok_or_else(|| {
                    Error::Corrupt(format!(
                        "marker exists but cannot be read at {}",
                        cur.display()
                    ))
                })?;
                let repo = Repository::open_at_tig_dir(&marker.repo)?;
                let store = WorkspaceStore::open(repo.root())?;
                let manifest = store.get(&marker.workspace_id)?;
                return Ok(Workspace::secondary(repo, manifest));
            }
            if cur.join(super::repo::TIG_DIR).is_dir() {
                let repo = Repository::open(cur)?;
                return Ok(Workspace::main_for(repo));
            }
            match cur.parent() {
                Some(p) => cur = p,
                None => {
                    return Err(Error::NotFound(format!(
                        "no .tig or .tig-workspace anywhere above {}",
                        start.display()
                    )));
                }
            }
        }
    }

    pub fn workdir(&self) -> &Path {
        match &self.kind {
            WorkspaceKind::Main => self.repo.workdir(),
            WorkspaceKind::Secondary(m) => &m.location,
        }
    }

    pub fn current_change_id(&self) -> Result<Option<ChangeId>> {
        match &self.kind {
            WorkspaceKind::Main => self.repo.head(),
            WorkspaceKind::Secondary(m) => Ok(Some(m.change_id.clone())),
        }
    }

    /// Update what's checked out here. For Main, advances HEAD. For
    /// Secondary, rewrites the manifest. Either way it persists.
    pub fn set_current_change_id(&mut self, id: &ChangeId) -> Result<()> {
        match &mut self.kind {
            WorkspaceKind::Main => self.repo.set_head(id),
            WorkspaceKind::Secondary(m) => {
                m.change_id = id.clone();
                let store = WorkspaceStore::open(self.repo.root())?;
                store.put(m)
            }
        }
    }

    pub fn id_for_display(&self) -> String {
        match &self.kind {
            WorkspaceKind::Main => "(main)".to_string(),
            WorkspaceKind::Secondary(m) => m.name.clone(),
        }
    }

    pub fn workspace_id(&self) -> Option<&WorkspaceId> {
        match &self.kind {
            WorkspaceKind::Main => None,
            WorkspaceKind::Secondary(m) => Some(&m.id),
        }
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().expect("workspace path has a parent");
    fs::create_dir_all(dir)?;
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("workspace");
    let tmp = dir.join(format!(".tmp-{file_name}"));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tig_core::Hash;

    fn fake_change_id() -> ChangeId {
        ChangeId::new()
    }

    fn manifest(name: &str, loc: &Path) -> WorkspaceManifest {
        WorkspaceManifest {
            id: WorkspaceId::new(),
            name: name.into(),
            location: loc.to_path_buf(),
            change_id: fake_change_id(),
            created_ns: 0,
        }
    }

    #[test]
    fn manifest_roundtrips_via_store() {
        let dir = tempdir().unwrap();
        let store = WorkspaceStore::open(dir.path()).unwrap();
        let m = manifest("feature", dir.path());
        store.put(&m).unwrap();
        let back = store.get(&m.id).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn list_and_find_by_name() {
        let dir = tempdir().unwrap();
        let store = WorkspaceStore::open(dir.path()).unwrap();
        let m1 = manifest("feat", dir.path());
        let m2 = manifest("bug", dir.path());
        store.put(&m1).unwrap();
        store.put(&m2).unwrap();
        assert_eq!(store.list().unwrap().len(), 2);
        assert_eq!(store.find_by_name("feat").unwrap(), Some(m1.clone()));
        assert_eq!(store.find_by_name("nope").unwrap(), None);
    }

    #[test]
    fn delete_removes_manifest() {
        let dir = tempdir().unwrap();
        let store = WorkspaceStore::open(dir.path()).unwrap();
        let m = manifest("x", dir.path());
        store.put(&m).unwrap();
        store.delete(&m.id).unwrap();
        assert!(matches!(store.get(&m.id), Err(Error::NotFound(_))));
    }

    #[test]
    fn marker_roundtrips() {
        let dir = tempdir().unwrap();
        let marker = WorkspaceMarker {
            repo: PathBuf::from("/tmp/x/.tig"),
            workspace_id: WorkspaceId::new(),
        };
        write_marker(dir.path(), &marker).unwrap();
        let back = read_marker(dir.path()).unwrap().unwrap();
        assert_eq!(back.repo, marker.repo);
        assert_eq!(back.workspace_id, marker.workspace_id);
    }

    #[test]
    fn discover_main_workspace_from_workdir() {
        let dir = tempdir().unwrap();
        let _repo = Repository::init(dir.path()).unwrap();

        let ws = Workspace::discover(dir.path()).unwrap();
        assert!(matches!(ws.kind, WorkspaceKind::Main));
        assert_eq!(ws.workdir().canonicalize().unwrap(), dir.path().canonicalize().unwrap());
    }

    #[test]
    fn discover_secondary_workspace_via_marker() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let repo_dir = repo.root().to_path_buf();

        let secondary = dir.path().join("elsewhere");
        fs::create_dir(&secondary).unwrap();

        let store = WorkspaceStore::open(&repo_dir).unwrap();
        let m = WorkspaceManifest {
            id: WorkspaceId::new(),
            name: "elsewhere".into(),
            location: secondary.canonicalize().unwrap(),
            change_id: fake_change_id(),
            created_ns: 1,
        };
        store.put(&m).unwrap();

        write_marker(
            &secondary,
            &WorkspaceMarker { repo: repo_dir, workspace_id: m.id.clone() },
        )
        .unwrap();

        let ws = Workspace::discover(&secondary).unwrap();
        let WorkspaceKind::Secondary(found) = &ws.kind else {
            panic!("expected secondary, got main");
        };
        assert_eq!(found.id, m.id);
        assert_eq!(ws.workdir().canonicalize().unwrap(), secondary.canonicalize().unwrap());
    }

    #[test]
    fn secondary_workspace_updates_its_own_change() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let secondary = dir.path().join("e");
        fs::create_dir(&secondary).unwrap();

        let store = WorkspaceStore::open(repo.root()).unwrap();
        let m = WorkspaceManifest {
            id: WorkspaceId::new(),
            name: "e".into(),
            location: secondary.canonicalize().unwrap(),
            change_id: fake_change_id(),
            created_ns: 0,
        };
        store.put(&m).unwrap();
        write_marker(
            &secondary,
            &WorkspaceMarker {
                repo: repo.root().to_path_buf(),
                workspace_id: m.id.clone(),
            },
        )
        .unwrap();

        let mut ws = Workspace::discover(&secondary).unwrap();
        let new_change = ChangeId::new();
        ws.set_current_change_id(&new_change).unwrap();

        // Re-load; manifest should reflect the new change.
        let store = WorkspaceStore::open(ws.repo.root()).unwrap();
        let back = store.get(&m.id).unwrap();
        assert_eq!(back.change_id, new_change);

        // Make sure HEAD was *not* touched — secondaries are independent.
        assert!(ws.repo.head().unwrap().is_none());

        // Pull the silently-unused hash into the test surface so the compiler
        // doesn't flag the helper as dead.
        let _h: Hash = Hash::compute(tig_core::ObjectKind::Blob, b"unused");
    }
}
