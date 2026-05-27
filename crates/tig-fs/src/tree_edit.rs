//! Edit a `Tree` purely through the object store — no working copy.
//!
//! This is the engine behind every daemon mutation. An HTTP `PATCH
//! /v1/changes/:id/tree/src/main.rs` arrives, we read the change's
//! current snapshot's tree hash, call [`write_blob_at_path`] to compute
//! a new root tree hash, then ask `snap_change_directly` to build a
//! `Snapshot` and advance the `Change`. No file ever touches disk
//! outside `<repo>/.tig/store/objects/`.
//!
//! Why this matters: an agent in a 50 MB lambda or a browser tab has no
//! working directory. With these primitives, source control becomes a
//! sequence of HTTP calls + object-store writes — exactly the "OS-
//! optional" requirement from ARCHITECTURE.md §P4 and §7.2.
//!
//! Path semantics: forward-slash-separated, no leading slash, no empty
//! components, no `.` or `..`. Each component is validated through the
//! same rules that apply to `TreeEntry::name`.

use crate::{Error, Result};
use tig_core::{Blob, Encodable, EntryKind, FileMode, Hash, Sealed, Tree, TreeEntry};
use tig_store::Repository;

/// Compute the new root tree hash that results from writing `bytes` at
/// `path` in the tree rooted at `root_tree`. Stores the new blob and
/// every rewritten ancestor tree in the object store.
pub fn write_blob_at_path(
    repo: &Repository,
    root_tree: Hash,
    path: &str,
    bytes: Vec<u8>,
) -> Result<Hash> {
    let parts = split_path(path)?;
    let blob = Blob::new(bytes);
    let blob_hash = repo.put(&blob.encode().map_err(Error::Core)?)?;
    rewrite_insert(repo, &root_tree, &parts, blob_hash, EntryKind::File, FileMode::REGULAR)
}

/// Same as [`write_blob_at_path`] but writes a `Sealed` object and tags
/// the tree entry as [`EntryKind::Sealed`]. Used by `tig seal`.
pub fn write_sealed_at_path(
    repo: &Repository,
    root_tree: Hash,
    path: &str,
    sealed: Sealed,
) -> Result<Hash> {
    let parts = split_path(path)?;
    let sealed_hash = repo.put(&sealed.encode().map_err(Error::Core)?)?;
    rewrite_insert(repo, &root_tree, &parts, sealed_hash, EntryKind::Sealed, FileMode::REGULAR)
}

/// Read the raw bytes of the blob at `path`. Fails if `path` resolves
/// to a tree, symlink, or anything other than a regular file.
pub fn read_blob_at_path(repo: &Repository, root_tree: Hash, path: &str) -> Result<Vec<u8>> {
    let parts = split_path(path)?;
    let entry = lookup_entry(repo, &root_tree, &parts)?;
    if entry.kind != EntryKind::File {
        return Err(Error::Core(tig_core::Error::Decode(format!(
            "path {path:?} is a {:?}, not a file",
            entry.kind
        ))));
    }
    let blob = Blob::decode(&repo.get(&entry.target)?).map_err(Error::Core)?;
    Ok(blob.bytes)
}

/// Look up the `TreeEntry` at `path` without decoding its content.
/// Useful for `GET /tree/:path` callers that want to know if it's a
/// file vs a directory before fetching.
pub fn lookup_entry(repo: &Repository, root_tree: &Hash, parts: &[String]) -> Result<TreeEntry> {
    if parts.is_empty() {
        return Err(Error::Core(tig_core::Error::Decode(
            "empty path has no entry".into(),
        )));
    }
    let mut tree = Tree::decode(&repo.get(root_tree)?).map_err(Error::Core)?;
    for (i, part) in parts.iter().enumerate() {
        let entry = tree.get(part).cloned().ok_or_else(|| {
            Error::Core(tig_core::Error::Decode(format!(
                "no entry {part:?} at /{}",
                parts[..i].join("/")
            )))
        })?;
        if i + 1 == parts.len() {
            return Ok(entry);
        }
        if entry.kind != EntryKind::Tree {
            return Err(Error::Core(tig_core::Error::Decode(format!(
                "path traverses {:?} at /{}/{part}",
                entry.kind,
                parts[..i].join("/")
            ))));
        }
        tree = Tree::decode(&repo.get(&entry.target)?).map_err(Error::Core)?;
    }
    unreachable!("loop body returns on the last iteration")
}

/// Compute the new root tree hash that results from removing whatever is
/// at `path`. If removing a file leaves its containing subtree empty,
/// the subtree is also removed (transitively), unless that would remove
/// the root tree itself — the root always exists, just possibly empty.
pub fn delete_at_path(repo: &Repository, root_tree: Hash, path: &str) -> Result<Hash> {
    let parts = split_path(path)?;
    rewrite_remove(repo, &root_tree, &parts)
}

/// List the entries of the (sub)tree at `path`. Pass an empty string for
/// the root.
pub fn list_tree(repo: &Repository, root_tree: Hash, path: &str) -> Result<Tree> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Tree::decode(&repo.get(&root_tree)?).map_err(Error::Core);
    }
    let parts = split_path(trimmed)?;
    let entry = lookup_entry(repo, &root_tree, &parts)?;
    if entry.kind != EntryKind::Tree {
        return Err(Error::Core(tig_core::Error::Decode(format!(
            "path {path:?} is a {:?}, not a tree",
            entry.kind
        ))));
    }
    Tree::decode(&repo.get(&entry.target)?).map_err(Error::Core)
}

// --- internals -------------------------------------------------------------

fn split_path(path: &str) -> Result<Vec<String>> {
    let parts: Vec<String> = path
        .split('/')
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect();
    if parts.is_empty() {
        return Err(Error::Core(tig_core::Error::InvalidPathComponent(
            "(empty path)".into(),
        )));
    }
    for p in &parts {
        if p == "." || p == ".." || p.contains('\0') {
            return Err(Error::Core(tig_core::Error::InvalidPathComponent(p.clone())));
        }
    }
    Ok(parts)
}

fn rewrite_insert(
    repo: &Repository,
    tree_hash: &Hash,
    parts: &[String],
    target: Hash,
    kind: EntryKind,
    mode: FileMode,
) -> Result<Hash> {
    let mut tree = Tree::decode(&repo.get(tree_hash)?).map_err(Error::Core)?;

    if parts.len() == 1 {
        tree.insert(TreeEntry {
            name: parts[0].clone(),
            kind,
            target,
            mode,
            vis: None,
        })
        .map_err(Error::Core)?;
    } else {
        let head = &parts[0];
        let rest = &parts[1..];
        let sub_hash = match tree.get(head) {
            Some(e) if e.kind == EntryKind::Tree => e.target,
            Some(e) => {
                return Err(Error::Core(tig_core::Error::Decode(format!(
                    "cannot descend into {:?} at {head:?}",
                    e.kind
                ))));
            }
            None => {
                // Create an empty subtree on the way down.
                let empty = Tree::new();
                repo.put(&empty.encode().map_err(Error::Core)?)?
            }
        };
        let new_sub = rewrite_insert(repo, &sub_hash, rest, target, kind, mode)?;
        tree.insert(TreeEntry {
            name: head.clone(),
            kind: EntryKind::Tree,
            target: new_sub,
            mode: FileMode::DIR,
            vis: None,
        })
        .map_err(Error::Core)?;
    }

    repo.put(&tree.encode().map_err(Error::Core)?).map_err(Error::Store)
}

fn rewrite_remove(
    repo: &Repository,
    tree_hash: &Hash,
    parts: &[String],
) -> Result<Hash> {
    let mut tree = Tree::decode(&repo.get(tree_hash)?).map_err(Error::Core)?;

    if parts.len() == 1 {
        let head = &parts[0];
        let pos = tree.entries.iter().position(|e| &e.name == head);
        match pos {
            Some(idx) => {
                tree.entries.remove(idx);
            }
            None => {
                return Err(Error::Core(tig_core::Error::Decode(format!(
                    "no entry {head:?} to delete"
                ))));
            }
        }
    } else {
        let head = &parts[0];
        let rest = &parts[1..];
        let entry = tree.get(head).cloned().ok_or_else(|| {
            Error::Core(tig_core::Error::Decode(format!(
                "no entry {head:?} on the way to deleting"
            )))
        })?;
        if entry.kind != EntryKind::Tree {
            return Err(Error::Core(tig_core::Error::Decode(format!(
                "cannot descend into {:?} at {head:?}",
                entry.kind
            ))));
        }
        let new_sub_hash = rewrite_remove(repo, &entry.target, rest)?;
        let new_sub = Tree::decode(&repo.get(&new_sub_hash)?).map_err(Error::Core)?;
        if new_sub.is_empty() {
            // Prune empty subtrees so the resulting tree matches what a
            // fresh scan would produce.
            let pos = tree.entries.iter().position(|e| &e.name == head).unwrap();
            tree.entries.remove(pos);
        } else {
            tree.insert(TreeEntry {
                name: head.clone(),
                kind: EntryKind::Tree,
                target: new_sub_hash,
                mode: FileMode::DIR,
                vis: None,
            })
            .map_err(Error::Core)?;
        }
    }

    repo.put(&tree.encode().map_err(Error::Core)?).map_err(Error::Store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tig_core::Tree;
    use tig_store::Repository;

    fn empty_repo() -> (tempfile::TempDir, Repository, Hash) {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let empty_tree_hash = repo.put(&Tree::new().encode().unwrap()).unwrap();
        (dir, repo, empty_tree_hash)
    }

    #[test]
    fn write_then_read_top_level_file() {
        let (_d, repo, root) = empty_repo();
        let new_root = write_blob_at_path(&repo, root, "hello.txt", b"hi".to_vec()).unwrap();
        let bytes = read_blob_at_path(&repo, new_root, "hello.txt").unwrap();
        assert_eq!(bytes, b"hi");
    }

    #[test]
    fn write_creates_intermediate_subtrees() {
        let (_d, repo, root) = empty_repo();
        let new_root =
            write_blob_at_path(&repo, root, "src/sub/deep/leaf.rs", b"contents".to_vec())
                .unwrap();
        assert_eq!(
            read_blob_at_path(&repo, new_root, "src/sub/deep/leaf.rs").unwrap(),
            b"contents"
        );
    }

    #[test]
    fn write_overwrites_existing_file() {
        let (_d, repo, root) = empty_repo();
        let r1 = write_blob_at_path(&repo, root, "a.txt", b"v1".to_vec()).unwrap();
        let r2 = write_blob_at_path(&repo, r1, "a.txt", b"v2".to_vec()).unwrap();
        assert_eq!(read_blob_at_path(&repo, r2, "a.txt").unwrap(), b"v2");
    }

    #[test]
    fn delete_removes_file_and_empty_subtree() {
        let (_d, repo, root) = empty_repo();
        let r1 = write_blob_at_path(&repo, root, "src/main.rs", b"x".to_vec()).unwrap();
        let r2 = write_blob_at_path(&repo, r1, "README.md", b"y".to_vec()).unwrap();

        let r3 = delete_at_path(&repo, r2, "src/main.rs").unwrap();
        let listing = list_tree(&repo, r3, "").unwrap();
        // src/ should be pruned (it became empty); only README.md remains.
        assert_eq!(listing.len(), 1);
        assert!(listing.get("README.md").is_some());
        assert!(listing.get("src").is_none());
    }

    #[test]
    fn delete_keeps_subtree_if_other_siblings_remain() {
        let (_d, repo, root) = empty_repo();
        let r1 = write_blob_at_path(&repo, root, "src/main.rs", b"x".to_vec()).unwrap();
        let r2 = write_blob_at_path(&repo, r1, "src/lib.rs", b"y".to_vec()).unwrap();
        let r3 = delete_at_path(&repo, r2, "src/main.rs").unwrap();

        let src = list_tree(&repo, r3, "src").unwrap();
        assert_eq!(src.len(), 1);
        assert!(src.get("lib.rs").is_some());
    }

    #[test]
    fn read_nonexistent_path_errors() {
        let (_d, repo, root) = empty_repo();
        let result = read_blob_at_path(&repo, root, "missing.txt");
        assert!(result.is_err());
    }

    #[test]
    fn writing_through_a_file_errors() {
        let (_d, repo, root) = empty_repo();
        let r1 = write_blob_at_path(&repo, root, "a", b"x".to_vec()).unwrap();
        // 'a' is a file; trying to put a child under it must fail.
        let err = write_blob_at_path(&repo, r1, "a/child", b"y".to_vec()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cannot descend"), "got error: {msg}");
    }

    #[test]
    fn empty_paths_are_rejected() {
        let (_d, repo, root) = empty_repo();
        assert!(write_blob_at_path(&repo, root, "", b"x".to_vec()).is_err());
        assert!(write_blob_at_path(&repo, root, "/", b"x".to_vec()).is_err());
        assert!(write_blob_at_path(&repo, root, "..", b"x".to_vec()).is_err());
        assert!(write_blob_at_path(&repo, root, "a/../b", b"x".to_vec()).is_err());
    }

    #[test]
    fn list_tree_works_at_root_and_subdir() {
        let (_d, repo, root) = empty_repo();
        let r1 = write_blob_at_path(&repo, root, "src/a.rs", b"x".to_vec()).unwrap();
        let r2 = write_blob_at_path(&repo, r1, "src/b.rs", b"y".to_vec()).unwrap();
        let r3 = write_blob_at_path(&repo, r2, "README.md", b"z".to_vec()).unwrap();

        let root_listing = list_tree(&repo, r3, "").unwrap();
        let names: Vec<&str> = root_listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["README.md", "src"]);

        let src_listing = list_tree(&repo, r3, "src").unwrap();
        let names: Vec<&str> = src_listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a.rs", "b.rs"]);
    }

    #[test]
    fn idempotent_writes_dedupe_in_store() {
        // Same bytes at the same path twice produces the same root hash.
        let (_d, repo, root) = empty_repo();
        let r1 = write_blob_at_path(&repo, root, "x", b"hello".to_vec()).unwrap();
        let r2 = write_blob_at_path(&repo, root, "x", b"hello".to_vec()).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn sealed_entries_are_tagged_as_sealed_in_the_tree() {
        let (_d, repo, root) = empty_repo();
        let sealed = Sealed {
            algo: tig_core::SealAlgo::X25519XChaCha20Poly1305,
            ephemeral_pk: vec![0u8; 32],
            recipients: vec![tig_core::RecipientWrap {
                recipient_pk: vec![1u8; 32],
                wrapped_key: vec![2u8; 48],
                wrap_nonce: vec![3u8; 24],
            }],
            ciphertext: vec![4u8; 16],
            nonce: vec![5u8; 24],
            aad: b"config/secret.env".to_vec(),
        };
        let new_root =
            write_sealed_at_path(&repo, root, "config/secret.env", sealed.clone()).unwrap();
        let entry = lookup_entry(
            &repo,
            &new_root,
            &["config".to_string(), "secret.env".to_string()],
        )
        .unwrap();
        assert_eq!(entry.kind, EntryKind::Sealed);

        // Round-trip the Sealed object out of the store.
        let raw = repo.get(&entry.target).unwrap();
        assert_eq!(raw.kind, tig_core::ObjectKind::Sealed);
        let back = Sealed::decode(&raw).unwrap();
        assert_eq!(back, sealed);
    }
}
