//! Mutable refs: Changes and bookmarks.
//!
//! Stored as small JSON files. Writes are atomic via tempfile+rename.
//! No CAS yet — milestone 0 is single-process. The trait shape lets us
//! add CAS or remote refs later without touching call sites.

use crate::{Error, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tig_core::{Change, ChangeId};

pub trait RefStore {
    fn put_change(&self, change: &Change) -> Result<()>;
    fn get_change(&self, id: &ChangeId) -> Result<Change>;
    fn list_changes(&self) -> Result<Vec<ChangeId>>;
    /// Remove a Change record. Used by `tig undo` to roll back creation.
    /// Missing changes are a no-op (rolling back a roll-back).
    fn delete_change(&self, id: &ChangeId) -> Result<()>;

    fn set_bookmark(&self, name: &str, change: &ChangeId) -> Result<()>;
    fn get_bookmark(&self, name: &str) -> Result<Option<ChangeId>>;
    fn list_bookmarks(&self) -> Result<Vec<(String, ChangeId)>>;
    fn delete_bookmark(&self, name: &str) -> Result<()>;

    /// The "current" Change for a working copy — what `tig snap` advances.
    /// Stored at `refs/HEAD`. Optional because a fresh repo has none.
    fn head(&self) -> Result<Option<ChangeId>>;
    fn set_head(&self, change: &ChangeId) -> Result<()>;
    /// Remove the HEAD pointer entirely. Missing HEAD is a no-op.
    fn clear_head(&self) -> Result<()>;
}

pub struct FsRefStore {
    root: PathBuf,
}

impl FsRefStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("changes"))?;
        fs::create_dir_all(root.join("bookmarks"))?;
        Ok(Self { root })
    }

    fn change_path(&self, id: &ChangeId) -> PathBuf {
        self.root.join("changes").join(&id.0)
    }

    fn bookmark_path(&self, name: &str) -> PathBuf {
        self.root.join("bookmarks").join(name)
    }

    fn head_path(&self) -> PathBuf {
        self.root.join("HEAD")
    }

    fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
        let dir = path.parent().expect("ref path has a parent");
        fs::create_dir_all(dir)?;
        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("ref");
        let tmp = dir.join(format!(".tmp-{file_name}"));
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(contents)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

impl RefStore for FsRefStore {
    fn put_change(&self, change: &Change) -> Result<()> {
        let path = self.change_path(&change.id);
        let bytes = serde_json::to_vec_pretty(change)?;
        Self::atomic_write(&path, &bytes)
    }

    fn get_change(&self, id: &ChangeId) -> Result<Change> {
        let path = self.change_path(id);
        let bytes = fs::read(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::NotFound(format!("change {}", id.0)),
            _ => Error::Io(e),
        })?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn list_changes(&self) -> Result<Vec<ChangeId>> {
        let dir = self.root.join("changes");
        let mut out = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if s.starts_with('.') {
                continue;
            }
            out.push(ChangeId(s.into_owned()));
        }
        out.sort();
        Ok(out)
    }

    fn set_bookmark(&self, name: &str, change: &ChangeId) -> Result<()> {
        if name.is_empty() || name.contains('/') || name.contains('\0') {
            return Err(Error::Corrupt(format!("invalid bookmark name: {name}")));
        }
        Self::atomic_write(&self.bookmark_path(name), change.0.as_bytes())
    }

    fn get_bookmark(&self, name: &str) -> Result<Option<ChangeId>> {
        let path = self.bookmark_path(name);
        match fs::read_to_string(&path) {
            Ok(s) => Ok(Some(ChangeId(s.trim().to_string()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn list_bookmarks(&self) -> Result<Vec<(String, ChangeId)>> {
        let dir = self.root.join("bookmarks");
        let mut out = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            let id_text = fs::read_to_string(entry.path())?;
            out.push((name, ChangeId(id_text.trim().to_string())));
        }
        out.sort();
        Ok(out)
    }

    fn head(&self) -> Result<Option<ChangeId>> {
        match fs::read_to_string(self.head_path()) {
            Ok(s) => Ok(Some(ChangeId(s.trim().to_string()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn set_head(&self, change: &ChangeId) -> Result<()> {
        Self::atomic_write(&self.head_path(), change.0.as_bytes())
    }

    fn clear_head(&self) -> Result<()> {
        match fs::remove_file(self.head_path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn delete_change(&self, id: &ChangeId) -> Result<()> {
        match fs::remove_file(self.change_path(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn delete_bookmark(&self, name: &str) -> Result<()> {
        match fs::remove_file(self.bookmark_path(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tig_core::{Hash, ObjectKind};

    fn refs() -> (tempfile::TempDir, FsRefStore) {
        let dir = tempdir().unwrap();
        let r = FsRefStore::open(dir.path().join("refs")).unwrap();
        (dir, r)
    }

    fn fake_snap_hash() -> Hash {
        Hash::compute(ObjectKind::Snapshot, b"x")
    }

    #[test]
    fn change_roundtrip() {
        let (_d, r) = refs();
        let c = Change::new(
            "the work",
            tig_core::PrincipalId::local("t"),
            fake_snap_hash(),
        );
        r.put_change(&c).unwrap();
        let back = r.get_change(&c.id).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn list_changes_finds_all_written() {
        let (_d, r) = refs();
        let h = fake_snap_hash();
        let author = tig_core::PrincipalId::local("t");
        let c1 = Change::new("a", author.clone(), h);
        let c2 = Change::new("b", author, h);
        r.put_change(&c1).unwrap();
        r.put_change(&c2).unwrap();
        let listed = r.list_changes().unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&c1.id));
        assert!(listed.contains(&c2.id));
    }

    #[test]
    fn bookmark_and_head() {
        let (_d, r) = refs();
        let c = Change::new("a", tig_core::PrincipalId::local("t"), fake_snap_hash());
        r.put_change(&c).unwrap();
        r.set_bookmark("main", &c.id).unwrap();
        r.set_head(&c.id).unwrap();
        assert_eq!(r.get_bookmark("main").unwrap(), Some(c.id.clone()));
        assert_eq!(r.head().unwrap(), Some(c.id));
    }

    #[test]
    fn missing_bookmark_returns_none_not_error() {
        let (_d, r) = refs();
        assert_eq!(r.get_bookmark("nothing").unwrap(), None);
    }
}
