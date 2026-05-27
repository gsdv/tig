//! A directory snapshot.
//!
//! Trees hold *one level* of directory contents. Subdirectories are
//! recursive: a `TreeEntry { kind: Tree, target: <hash> }` points at
//! another `Tree` object.
//!
//! Entries are kept sorted by `name` so the serialized form is canonical.
//! That sort happens in `Tree::sorted` / `Tree::insert`; callers should
//! prefer those over `entries.push(...)`.

use crate::{Encodable, Error, Hash, ObjectKind, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    File,
    Tree,
    Symlink,
    Sealed,
    Conflict,
    Submodule,
}

/// Unix-ish mode bits. We keep the executable bit and that's about it for
/// milestone 0; ACLs and xattrs are out of scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMode(pub u32);

impl FileMode {
    pub const REGULAR: FileMode = FileMode(0o100_644);
    pub const EXEC: FileMode = FileMode(0o100_755);
    pub const SYMLINK: FileMode = FileMode(0o120_000);
    pub const DIR: FileMode = FileMode(0o040_000);

    pub fn is_executable(self) -> bool {
        self.0 & 0o111 != 0
    }
}

/// Placeholder for the visibility tag (see ARCHITECTURE.md §4).
///
/// Milestone 0 ships the wire shape but no enforcement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VisTag(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntry {
    pub name: String,
    pub kind: EntryKind,
    pub target: Hash,
    pub mode: FileMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vis: Option<VisTag>,
}

impl TreeEntry {
    fn validate_name(name: &str) -> Result<()> {
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.contains('\0')
        {
            return Err(Error::InvalidPathComponent(name.to_string()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Tree {
    /// Sorted ascending by `name`. The invariant is upheld by all
    /// constructors and mutators on this type. Direct field access is
    /// public for reading; modify via `insert`/`remove` instead.
    pub entries: Vec<TreeEntry>,
}

impl Tree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a tree from an unsorted iterator. Validates names and sorts.
    pub fn from_entries<I: IntoIterator<Item = TreeEntry>>(iter: I) -> Result<Self> {
        let mut entries: Vec<TreeEntry> = iter.into_iter().collect();
        for e in &entries {
            TreeEntry::validate_name(&e.name)?;
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        // Reject duplicates — a directory can't hold two entries with the same name.
        for pair in entries.windows(2) {
            if pair[0].name == pair[1].name {
                return Err(Error::InvalidPathComponent(format!(
                    "duplicate entry: {}",
                    pair[0].name
                )));
            }
        }
        Ok(Tree { entries })
    }

    pub fn insert(&mut self, entry: TreeEntry) -> Result<()> {
        TreeEntry::validate_name(&entry.name)?;
        match self.entries.binary_search_by(|e| e.name.cmp(&entry.name)) {
            Ok(idx) => self.entries[idx] = entry,
            Err(idx) => self.entries.insert(idx, entry),
        }
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&TreeEntry> {
        match self.entries.binary_search_by(|e| e.name.as_str().cmp(name)) {
            Ok(idx) => Some(&self.entries[idx]),
            Err(_) => None,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Encodable for Tree {
    const KIND: ObjectKind = ObjectKind::Tree;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str) -> TreeEntry {
        TreeEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            target: Hash::compute(ObjectKind::Blob, name.as_bytes()),
            mode: FileMode::REGULAR,
            vis: None,
        }
    }

    #[test]
    fn entries_are_sorted_on_construction() {
        let t = Tree::from_entries([entry("zeta"), entry("alpha"), entry("mu")]).unwrap();
        let names: Vec<&str> = t.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "mu", "zeta"]);
    }

    #[test]
    fn duplicate_names_rejected() {
        let r = Tree::from_entries([entry("a"), entry("a")]);
        assert!(r.is_err());
    }

    #[test]
    fn invalid_components_rejected() {
        let bad = TreeEntry {
            name: "a/b".into(),
            ..entry("placeholder")
        };
        let r = Tree::from_entries([bad]);
        assert!(r.is_err());

        let dotdot = TreeEntry {
            name: "..".into(),
            ..entry("placeholder")
        };
        let r = Tree::from_entries([dotdot]);
        assert!(r.is_err());
    }

    #[test]
    fn roundtrip_preserves_hash() {
        let t = Tree::from_entries([entry("a"), entry("b"), entry("c")]).unwrap();
        let h1 = t.hash().unwrap();
        let raw = t.encode().unwrap();
        let t2 = Tree::decode(&raw).unwrap();
        assert_eq!(t, t2);
        assert_eq!(h1, t2.hash().unwrap());
    }

    #[test]
    fn insertion_order_does_not_change_hash() {
        let a = Tree::from_entries([entry("a"), entry("b"), entry("c")]).unwrap();
        let b = Tree::from_entries([entry("c"), entry("a"), entry("b")]).unwrap();
        assert_eq!(a.hash().unwrap(), b.hash().unwrap());
    }

    #[test]
    fn insert_upserts() {
        let mut t = Tree::new();
        t.insert(entry("x")).unwrap();
        t.insert(entry("y")).unwrap();
        let mut replacement = entry("x");
        replacement.mode = FileMode::EXEC;
        t.insert(replacement.clone()).unwrap();
        assert_eq!(t.get("x"), Some(&replacement));
        assert_eq!(t.len(), 2);
    }
}
