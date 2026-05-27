//! Recursive working-copy → Tree conversion.
//!
//! Algorithm: directory recursion, depth-first. For each entry:
//!   - regular file → read bytes → `Blob` → `ObjectStore::put` → `TreeEntry { kind: File }`
//!   - directory    → recurse → `Tree` → `ObjectStore::put` → `TreeEntry { kind: Tree }`
//!   - symlink      → read link target → `Blob(target_bytes)` → `TreeEntry { kind: Symlink }`
//!   - other        → error (sockets, fifos, devices)
//!
//! The `.tig/` directory itself is always skipped, regardless of ignores.
//!
//! This implementation is straightforward, not yet performance-tuned. It
//! reads every file every time. The auto-snap watcher in a future
//! milestone will diff against the last-scan stat cache to avoid that.

use crate::{Error, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use tig_core::{
    Blob, Encodable, EntryKind, FileMode, Hash, Tree, TreeEntry,
};
use tig_store::ObjectStore;

#[derive(Clone, Debug)]
pub struct ScanOptions {
    /// Path components, relative to workdir, to skip entirely. Always
    /// includes `.tig`.
    pub ignore: Vec<String>,
    /// Follow symlinks instead of recording them. Off by default — that
    /// would let a file outside the workdir become tracked content.
    pub follow_symlinks: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            ignore: vec![
                ".tig".to_string(),
                // Secondary workspaces created via `tig wt make` land
                // here by default. They have their own change-tracking,
                // so the main workspace must not snapshot them.
                tig_store::DEFAULT_WORKTREE_DIR.to_string(),
            ],
            follow_symlinks: false,
        }
    }
}

/// Scan `workdir`, write every blob and tree object into `store`, return
/// the hash of the root `Tree`.
pub fn scan<S: ObjectStore>(workdir: &Path, store: &S, opts: &ScanOptions) -> Result<Hash> {
    let workdir = workdir.canonicalize()?;
    scan_dir(&workdir, store, opts)
}

fn scan_dir<S: ObjectStore>(
    dir: &Path,
    store: &S,
    opts: &ScanOptions,
) -> Result<Hash> {
    // Collect children first so we can sort and detect duplicates before
    // committing any objects. Helps make the error path clean.
    let mut children: BTreeMap<String, PathBuf> = BTreeMap::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|os| Error::Core(tig_core::Error::InvalidPathComponent(
                os.to_string_lossy().into_owned(),
            )))?;
        if opts.ignore.iter().any(|i| i == &name) {
            continue;
        }
        children.insert(name, entry.path());
    }

    let mut tree = Tree::new();
    for (name, path) in children {
        let entry = build_entry(&name, &path, store, opts)?;
        tree.insert(entry).map_err(Error::Core)?;
    }

    let raw = tree.encode().map_err(Error::Core)?;
    Ok(store.put(&raw)?)
}

fn build_entry<S: ObjectStore>(
    name: &str,
    path: &Path,
    store: &S,
    opts: &ScanOptions,
) -> Result<TreeEntry> {
    let metadata = if opts.follow_symlinks {
        fs::metadata(path)?
    } else {
        fs::symlink_metadata(path)?
    };
    let file_type = metadata.file_type();

    if file_type.is_dir() {
        let target = scan_dir(path, store, opts)?;
        Ok(TreeEntry {
            name: name.to_string(),
            kind: EntryKind::Tree,
            target,
            mode: FileMode::DIR,
            vis: None,
        })
    } else if file_type.is_file() {
        let bytes = fs::read(path)?;
        let blob = Blob::new(bytes);
        let target = store.put(&blob.encode().map_err(Error::Core)?)?;
        let mode = unix_mode(&metadata, false);
        Ok(TreeEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            target,
            mode,
            vis: None,
        })
    } else if file_type.is_symlink() {
        // Store the link's *target string* as a blob's payload. This is
        // what git does and it makes symlinks portable across filesystems.
        let link_target = fs::read_link(path)?;
        let link_bytes = link_target.to_string_lossy().into_owned().into_bytes();
        let blob = Blob::new(link_bytes);
        let target = store.put(&blob.encode().map_err(Error::Core)?)?;
        Ok(TreeEntry {
            name: name.to_string(),
            kind: EntryKind::Symlink,
            target,
            mode: FileMode::SYMLINK,
            vis: None,
        })
    } else {
        Err(Error::UnsupportedFileKind {
            path: path.display().to_string(),
            kind: format!("{file_type:?}"),
        })
    }
}

#[cfg(unix)]
fn unix_mode(meta: &fs::Metadata, _is_symlink: bool) -> FileMode {
    use std::os::unix::fs::PermissionsExt;
    let raw = meta.permissions().mode();
    if raw & 0o111 != 0 {
        FileMode::EXEC
    } else {
        FileMode::REGULAR
    }
}

#[cfg(not(unix))]
fn unix_mode(_meta: &fs::Metadata, _is_symlink: bool) -> FileMode {
    FileMode::REGULAR
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tig_core::{Encodable, EntryKind, Tree};
    use tig_store::{FsObjectStore, ObjectStore};

    fn setup() -> (tempfile::TempDir, FsObjectStore) {
        let dir = tempdir().unwrap();
        let store = FsObjectStore::open(dir.path().join("objects")).unwrap();
        (dir, store)
    }

    #[test]
    fn scans_a_flat_directory() {
        let (dir, store) = setup();
        let work = dir.path().join("work");
        fs::create_dir(&work).unwrap();
        fs::write(work.join("a.txt"), b"hello").unwrap();
        fs::write(work.join("b.txt"), b"world").unwrap();

        let root_hash = scan(&work, &store, &ScanOptions::default()).unwrap();
        let root = Tree::decode(&store.get(&root_hash).unwrap()).unwrap();
        assert_eq!(root.len(), 2);

        let a = root.get("a.txt").expect("a.txt missing");
        assert_eq!(a.kind, EntryKind::File);
        let a_blob = tig_core::Blob::decode(&store.get(&a.target).unwrap()).unwrap();
        assert_eq!(a_blob.bytes, b"hello");
    }

    #[test]
    fn scans_recursively() {
        let (dir, store) = setup();
        let work = dir.path().join("work");
        fs::create_dir_all(work.join("sub/deeper")).unwrap();
        fs::write(work.join("top.txt"), b"top").unwrap();
        fs::write(work.join("sub/mid.txt"), b"mid").unwrap();
        fs::write(work.join("sub/deeper/leaf.txt"), b"leaf").unwrap();

        let root_h = scan(&work, &store, &ScanOptions::default()).unwrap();
        let root = Tree::decode(&store.get(&root_h).unwrap()).unwrap();

        let sub = root.get("sub").unwrap();
        assert_eq!(sub.kind, EntryKind::Tree);
        let sub_tree = Tree::decode(&store.get(&sub.target).unwrap()).unwrap();
        let deeper = sub_tree.get("deeper").unwrap();
        let deeper_tree = Tree::decode(&store.get(&deeper.target).unwrap()).unwrap();
        let leaf = deeper_tree.get("leaf.txt").unwrap();
        let leaf_blob = tig_core::Blob::decode(&store.get(&leaf.target).unwrap()).unwrap();
        assert_eq!(leaf_blob.bytes, b"leaf");
    }

    #[test]
    fn skips_dot_tig_directory() {
        let (dir, store) = setup();
        let work = dir.path().join("work");
        fs::create_dir_all(work.join(".tig/store")).unwrap();
        fs::write(work.join(".tig/store/something"), b"nope").unwrap();
        fs::write(work.join("real.txt"), b"yes").unwrap();

        let root_h = scan(&work, &store, &ScanOptions::default()).unwrap();
        let root = Tree::decode(&store.get(&root_h).unwrap()).unwrap();
        assert_eq!(root.len(), 1);
        assert!(root.get(".tig").is_none());
        assert!(root.get("real.txt").is_some());
    }

    #[test]
    fn identical_content_dedupes() {
        let (dir, store) = setup();
        let work = dir.path().join("work");
        fs::create_dir(&work).unwrap();
        fs::write(work.join("a.txt"), b"same").unwrap();
        fs::write(work.join("b.txt"), b"same").unwrap();

        let root_h = scan(&work, &store, &ScanOptions::default()).unwrap();
        let root = Tree::decode(&store.get(&root_h).unwrap()).unwrap();
        let a = root.get("a.txt").unwrap();
        let b = root.get("b.txt").unwrap();
        assert_eq!(a.target, b.target, "identical content should share a blob");
    }

    #[test]
    fn repeat_scan_produces_same_root_hash() {
        let (dir, store) = setup();
        let work = dir.path().join("work");
        fs::create_dir_all(work.join("x")).unwrap();
        fs::write(work.join("x/a"), b"1").unwrap();
        fs::write(work.join("x/b"), b"2").unwrap();
        fs::write(work.join("c"), b"3").unwrap();

        let h1 = scan(&work, &store, &ScanOptions::default()).unwrap();
        let h2 = scan(&work, &store, &ScanOptions::default()).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn empty_dir_produces_empty_tree() {
        let (dir, store) = setup();
        let work = dir.path().join("work");
        fs::create_dir(&work).unwrap();
        let h = scan(&work, &store, &ScanOptions::default()).unwrap();
        let t = Tree::decode(&store.get(&h).unwrap()).unwrap();
        assert!(t.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn executable_bit_recorded() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, store) = setup();
        let work = dir.path().join("work");
        fs::create_dir(&work).unwrap();
        let p = work.join("script.sh");
        fs::write(&p, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();

        let h = scan(&work, &store, &ScanOptions::default()).unwrap();
        let root = Tree::decode(&store.get(&h).unwrap()).unwrap();
        let entry = root.get("script.sh").unwrap();
        assert!(entry.mode.is_executable());
    }
}
