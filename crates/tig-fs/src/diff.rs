//! Tree-vs-tree diff.
//!
//! Two passes, both in this file:
//!
//!   - [`diff_trees`] walks two trees in lockstep and emits one
//!     [`FileDiff`] per path that differs. Equal subtree hashes prune
//!     the entire subtree — the whole point of content addressing is
//!     that we can compare hashes instead of contents.
//!
//!   - [`blob_diff_hunks`] reads two blobs and produces unified hunks
//!     via the `similar` crate. Detects binary files by looking for a
//!     NUL byte in the first 8 KiB (matches git's heuristic).
//!
//! The CLI renders the result in git's familiar unified-diff format.
//! The daemon serializes [`FileDiff`] as JSON ([`tig_protocol::FileDiffView`]).
//!
//! Sealed entries and conflict entries are rendered without hunks —
//! the diff lists their existence but doesn't try to decrypt or
//! resolve. That's the right behaviour for milestone scope; future
//! work could add a `--as <identity>` flag that decrypts as it diffs.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tig_core::{Blob, Encodable, EntryKind, Hash, Tree, TreeEntry};
use tig_store::Repository;

/// Per-file change. The semantics:
///   - `Added`:        path didn't exist in `from`, exists in `to`.
///   - `Removed`:      path existed in `from`, doesn't in `to`.
///   - `Modified`:     same path, same kind, different `target` hash.
///   - `TypeChanged`:  same path, different `kind` (e.g. File → Symlink).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
    TypeChanged { from: EntryKind, to: EntryKind },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDiff {
    pub path: String,
    pub kind: ChangeKind,
    /// Entry kind for display: for `Removed`, the `from` kind. For
    /// `Added`, the `to` kind. For others, the `to` kind (post-change).
    pub entry_kind: EntryKind,
    pub from_target: Option<Hash>,
    pub to_target: Option<Hash>,
    /// True if either side was detected as binary. Hunks omitted in
    /// that case.
    pub binary: bool,
    /// Optional unified hunks. Populated for `Added`/`Removed`/`Modified`
    /// on text blobs; `None` for trees, symlinks, sealed entries, and
    /// binary blobs.
    pub hunks: Option<Vec<Hunk>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hunk {
    /// 1-indexed; 0 if the side is empty (whole-file add/remove).
    pub from_start: usize,
    pub from_len: usize,
    pub to_start: usize,
    pub to_len: usize,
    pub lines: Vec<HunkLine>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HunkLine {
    Context(String),
    Add(String),
    Remove(String),
}

#[derive(Clone, Debug, Default)]
pub struct DiffOptions {
    /// Skip hunk generation; report only the file-level change list.
    pub no_hunks: bool,
    /// Only include diffs whose path starts with one of these prefixes.
    /// Empty = no filter.
    pub paths: Vec<String>,
    /// Lines of context for unified diff hunks. Defaults to 3 (git's default).
    pub context_lines: usize,
}

impl DiffOptions {
    pub fn with_paths(mut self, paths: Vec<String>) -> Self {
        self.paths = paths;
        self
    }
}

/// Compute the diff between two trees.
pub fn diff_trees(
    repo: &Repository,
    from: &Hash,
    to: &Hash,
    opts: &DiffOptions,
) -> Result<Vec<FileDiff>> {
    let mut out = Vec::new();
    if from == to {
        // Same root tree — no diff at any depth. Single-hash prune.
        return Ok(out);
    }
    diff_subtree(repo, Some(from), Some(to), "", opts, &mut out)?;
    Ok(out)
}

fn diff_subtree(
    repo: &Repository,
    from: Option<&Hash>,
    to: Option<&Hash>,
    prefix: &str,
    opts: &DiffOptions,
    out: &mut Vec<FileDiff>,
) -> Result<()> {
    // Hash equality short-circuits both sides exist.
    if let (Some(f), Some(t)) = (from, to) {
        if f == t {
            return Ok(());
        }
    }

    let from_entries: BTreeMap<String, TreeEntry> = match from {
        Some(h) => Tree::decode(&repo.get(h)?)
            .map_err(Error::Core)?
            .entries
            .into_iter()
            .map(|e| (e.name.clone(), e))
            .collect(),
        None => BTreeMap::new(),
    };
    let to_entries: BTreeMap<String, TreeEntry> = match to {
        Some(h) => Tree::decode(&repo.get(h)?)
            .map_err(Error::Core)?
            .entries
            .into_iter()
            .map(|e| (e.name.clone(), e))
            .collect(),
        None => BTreeMap::new(),
    };

    // Union of names, sorted (BTreeMap iteration is already sorted).
    let mut names: Vec<&String> = from_entries.keys().chain(to_entries.keys()).collect();
    names.sort();
    names.dedup();

    for name in names {
        let f = from_entries.get(name);
        let t = to_entries.get(name);
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };

        if !opts.paths.is_empty()
            && !opts
                .paths
                .iter()
                .any(|p| path.starts_with(p.as_str()) || p.starts_with(&path))
        {
            // Path filter: include if the diff path starts with a
            // filter (the filter is an ancestor of the path) OR if a
            // filter starts with the path (the path is an ancestor of
            // the filter, so we need to recurse into it).
            continue;
        }

        match (f, t) {
            (Some(f), Some(t)) if f.target == t.target && f.kind == t.kind => {
                // Identical entries; prune.
            }
            (Some(f), Some(t)) if f.kind == EntryKind::Tree && t.kind == EntryKind::Tree => {
                diff_subtree(repo, Some(&f.target), Some(&t.target), &path, opts, out)?;
            }
            (Some(f), Some(t)) if f.kind != t.kind => {
                out.push(emit_change(
                    repo,
                    &path,
                    ChangeKind::TypeChanged { from: f.kind, to: t.kind },
                    Some(f),
                    Some(t),
                    opts,
                )?);
            }
            (Some(f), Some(t)) => {
                // Same kind, different target.
                if f.kind == EntryKind::Tree {
                    // Already handled above; the guard's redundant but explicit.
                    diff_subtree(repo, Some(&f.target), Some(&t.target), &path, opts, out)?;
                } else {
                    out.push(emit_change(
                        repo,
                        &path,
                        ChangeKind::Modified,
                        Some(f),
                        Some(t),
                        opts,
                    )?);
                }
            }
            (Some(f), None) => {
                if f.kind == EntryKind::Tree {
                    diff_subtree(repo, Some(&f.target), None, &path, opts, out)?;
                } else {
                    out.push(emit_change(
                        repo,
                        &path,
                        ChangeKind::Removed,
                        Some(f),
                        None,
                        opts,
                    )?);
                }
            }
            (None, Some(t)) => {
                if t.kind == EntryKind::Tree {
                    diff_subtree(repo, None, Some(&t.target), &path, opts, out)?;
                } else {
                    out.push(emit_change(
                        repo,
                        &path,
                        ChangeKind::Added,
                        None,
                        Some(t),
                        opts,
                    )?);
                }
            }
            (None, None) => unreachable!("name came from at least one side"),
        }
    }
    Ok(())
}

fn emit_change(
    repo: &Repository,
    path: &str,
    kind: ChangeKind,
    f: Option<&TreeEntry>,
    t: Option<&TreeEntry>,
    opts: &DiffOptions,
) -> Result<FileDiff> {
    let entry_kind = match (&kind, f, t) {
        (ChangeKind::Removed, Some(f), _) => f.kind,
        (ChangeKind::Added, _, Some(t)) => t.kind,
        (_, _, Some(t)) => t.kind,
        (_, Some(f), _) => f.kind,
        _ => EntryKind::File, // unreachable in practice
    };
    let from_target = f.map(|e| e.target);
    let to_target = t.map(|e| e.target);

    let mut binary = false;
    let mut hunks = None;

    let is_file_diffable = matches!(
        (&kind, entry_kind),
        (ChangeKind::Added | ChangeKind::Removed | ChangeKind::Modified, EntryKind::File)
    );

    if is_file_diffable && !opts.no_hunks {
        let (from_bytes, to_bytes) = (
            match from_target {
                Some(h) => Blob::decode(&repo.get(&h)?).map_err(Error::Core)?.bytes,
                None => Vec::new(),
            },
            match to_target {
                Some(h) => Blob::decode(&repo.get(&h)?).map_err(Error::Core)?.bytes,
                None => Vec::new(),
            },
        );
        if is_binary(&from_bytes) || is_binary(&to_bytes) {
            binary = true;
        } else {
            let from_text = String::from_utf8_lossy(&from_bytes);
            let to_text = String::from_utf8_lossy(&to_bytes);
            hunks = Some(blob_diff_hunks(&from_text, &to_text, opts.context_lines.max(1)));
        }
    }

    Ok(FileDiff { path: path.to_string(), kind, entry_kind, from_target, to_target, binary, hunks })
}

/// Git-style binary detection: NUL byte in the first ~8 KiB.
pub fn is_binary(bytes: &[u8]) -> bool {
    let window = &bytes[..bytes.len().min(8192)];
    window.contains(&0)
}

/// Compute unified hunks between two text blobs.
///
/// We don't use `similar`'s `UnifiedDiff::iter_hunks()` ranges directly
/// because the internal range type isn't publicly accessible. Instead
/// we iterate each hunk's changes, read `Change::old_index()` /
/// `Change::new_index()` (both `Option<usize>`), and derive
/// `(start, len)` ourselves. Same answer, smaller API surface.
pub fn blob_diff_hunks(from: &str, to: &str, context: usize) -> Vec<Hunk> {
    use similar::{ChangeTag, TextDiff};
    let diff = TextDiff::from_lines(from, to);
    let mut binding = diff.unified_diff();
    let unified = binding.context_radius(context.max(1));
    let mut hunks = Vec::new();
    for h in unified.iter_hunks() {
        let mut lines = Vec::new();
        let mut from_start: Option<usize> = None;
        let mut to_start: Option<usize> = None;
        let mut from_len: usize = 0;
        let mut to_len: usize = 0;

        for change in h.iter_changes() {
            // Track ranges: first index seen on each side becomes the
            // start; counts come from however many lines on each side
            // appear in the hunk.
            if let Some(idx) = change.old_index() {
                if from_start.is_none() {
                    from_start = Some(idx);
                }
                from_len += 1;
            }
            if let Some(idx) = change.new_index() {
                if to_start.is_none() {
                    to_start = Some(idx);
                }
                to_len += 1;
            }

            let mut s = change.value().to_string();
            // similar yields lines including trailing '\n'; strip so
            // serialized hunks aren't ambiguous about line boundaries.
            if s.ends_with('\n') {
                s.pop();
            }
            if s.ends_with('\r') {
                s.pop();
            }
            let line = match change.tag() {
                ChangeTag::Equal => HunkLine::Context(s),
                ChangeTag::Insert => HunkLine::Add(s),
                ChangeTag::Delete => HunkLine::Remove(s),
            };
            lines.push(line);
        }

        hunks.push(Hunk {
            // 0-indexed line indices → 1-indexed for unified-diff display.
            // If a side is empty (whole-file add or remove), `*_start`
            // stays at `None` and we report 0 — the git convention.
            from_start: from_start.map(|i| i + 1).unwrap_or(0),
            from_len,
            to_start: to_start.map(|i| i + 1).unwrap_or(0),
            to_len,
            lines,
        });
    }
    hunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::write_blob_at_path;
    use tempfile::tempdir;
    use tig_core::{Encodable, Tree};
    use tig_store::Repository;

    fn empty_repo() -> (tempfile::TempDir, Repository, Hash) {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let empty = repo.put(&Tree::new().encode().unwrap()).unwrap();
        (dir, repo, empty)
    }

    #[test]
    fn same_tree_yields_empty_diff() {
        let (_d, repo, root) = empty_repo();
        let r1 = write_blob_at_path(&repo, root, "a.txt", b"hello".to_vec()).unwrap();
        let diff = diff_trees(&repo, &r1, &r1, &DiffOptions::default()).unwrap();
        assert!(diff.is_empty());
    }

    #[test]
    fn added_file_shows_as_added() {
        let (_d, repo, root) = empty_repo();
        let r1 = write_blob_at_path(&repo, root, "a.txt", b"v1\nv2\n".to_vec()).unwrap();
        let diff = diff_trees(&repo, &root, &r1, &DiffOptions::default()).unwrap();
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].path, "a.txt");
        assert_eq!(diff[0].kind, ChangeKind::Added);
        let hunks = diff[0].hunks.as_ref().expect("hunks for added text file");
        assert_eq!(hunks.len(), 1);
        let inserts: usize = hunks[0]
            .lines
            .iter()
            .filter(|l| matches!(l, HunkLine::Add(_)))
            .count();
        assert_eq!(inserts, 2, "expected two inserted lines");
    }

    #[test]
    fn removed_file_shows_as_removed() {
        let (_d, repo, root) = empty_repo();
        let r1 = write_blob_at_path(&repo, root, "a.txt", b"v1\nv2\n".to_vec()).unwrap();
        let diff = diff_trees(&repo, &r1, &root, &DiffOptions::default()).unwrap();
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].kind, ChangeKind::Removed);
        let hunks = diff[0].hunks.as_ref().unwrap();
        let removes: usize = hunks[0]
            .lines
            .iter()
            .filter(|l| matches!(l, HunkLine::Remove(_)))
            .count();
        assert_eq!(removes, 2);
    }

    #[test]
    fn modified_file_shows_unified_hunks() {
        let (_d, repo, root) = empty_repo();
        let r1 = write_blob_at_path(
            &repo,
            root,
            "a.txt",
            b"line one\nline two\nline three\n".to_vec(),
        )
        .unwrap();
        let r2 = write_blob_at_path(
            &repo,
            r1,
            "a.txt",
            b"line one\nline TWO\nline three\n".to_vec(),
        )
        .unwrap();
        let diff = diff_trees(&repo, &r1, &r2, &DiffOptions::default()).unwrap();
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].kind, ChangeKind::Modified);
        let hunks = diff[0].hunks.as_ref().unwrap();
        assert_eq!(hunks.len(), 1);

        let h = &hunks[0];
        assert!(h
            .lines
            .iter()
            .any(|l| matches!(l, HunkLine::Remove(s) if s == "line two")));
        assert!(h
            .lines
            .iter()
            .any(|l| matches!(l, HunkLine::Add(s) if s == "line TWO")));
        // The unchanged lines should appear as context.
        assert!(h
            .lines
            .iter()
            .any(|l| matches!(l, HunkLine::Context(s) if s == "line one")));
    }

    #[test]
    fn equal_subtree_pruned_no_redundant_walk() {
        // Both sides have a deep `src/sub/` subtree with identical
        // content. Add a top-level file that differs. The diff should
        // contain only the top-level entry — no entries inside src/sub.
        let (_d, repo, root) = empty_repo();
        let r1 = write_blob_at_path(&repo, root, "src/sub/a.rs", b"a".to_vec()).unwrap();
        let r1 = write_blob_at_path(&repo, r1, "src/sub/b.rs", b"b".to_vec()).unwrap();
        let r2 = write_blob_at_path(&repo, r1, "top.txt", b"new top\n".to_vec()).unwrap();

        let diff = diff_trees(&repo, &r1, &r2, &DiffOptions::default()).unwrap();
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].path, "top.txt");
        assert_eq!(diff[0].kind, ChangeKind::Added);
    }

    #[test]
    fn binary_file_marked_binary_no_hunks() {
        let (_d, repo, root) = empty_repo();
        // 0x00 byte makes it binary.
        let payload = vec![0xff, 0x00, 0x01, 0x02];
        let r1 = write_blob_at_path(&repo, root, "img.bin", payload.clone()).unwrap();
        let mut payload2 = payload;
        payload2.push(0x42);
        let r2 = write_blob_at_path(&repo, r1, "img.bin", payload2).unwrap();
        let diff = diff_trees(&repo, &r1, &r2, &DiffOptions::default()).unwrap();
        assert_eq!(diff.len(), 1);
        assert!(diff[0].binary);
        assert!(diff[0].hunks.is_none());
    }

    #[test]
    fn no_hunks_option_skips_hunk_generation() {
        let (_d, repo, root) = empty_repo();
        let r1 = write_blob_at_path(&repo, root, "a.txt", b"hi\n".to_vec()).unwrap();
        let r2 = write_blob_at_path(&repo, r1, "a.txt", b"bye\n".to_vec()).unwrap();
        let opts = DiffOptions { no_hunks: true, ..Default::default() };
        let diff = diff_trees(&repo, &r1, &r2, &opts).unwrap();
        assert_eq!(diff.len(), 1);
        assert!(diff[0].hunks.is_none());
    }

    #[test]
    fn path_filter_restricts_to_subtree() {
        let (_d, repo, root) = empty_repo();
        let r1 = write_blob_at_path(&repo, root, "src/a.rs", b"a".to_vec()).unwrap();
        let r2 = write_blob_at_path(&repo, r1, "src/a.rs", b"AA".to_vec()).unwrap();
        let r2 = write_blob_at_path(&repo, r2, "docs/readme.md", b"hi".to_vec()).unwrap();

        let opts = DiffOptions::default().with_paths(vec!["src".into()]);
        let diff = diff_trees(&repo, &r1, &r2, &opts).unwrap();
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].path, "src/a.rs");
    }

    #[test]
    fn deleting_a_directory_emits_per_file_removed() {
        // Removing src/ should produce one Removed per leaf, not one
        // for the directory itself.
        let (_d, repo, root) = empty_repo();
        let r1 = write_blob_at_path(&repo, root, "src/a.rs", b"a".to_vec()).unwrap();
        let r1 = write_blob_at_path(&repo, r1, "src/b.rs", b"b".to_vec()).unwrap();
        let r2 = write_blob_at_path(&repo, root, "README.md", b"x".to_vec()).unwrap();
        // r2 has README.md only; r1 has src/{a,b}.rs. Diff r1 → r2 =
        // removed src/a.rs, removed src/b.rs, added README.md.
        let diff = diff_trees(&repo, &r1, &r2, &DiffOptions::default()).unwrap();
        let removed: Vec<&str> = diff
            .iter()
            .filter(|d| d.kind == ChangeKind::Removed)
            .map(|d| d.path.as_str())
            .collect();
        let added: Vec<&str> = diff
            .iter()
            .filter(|d| d.kind == ChangeKind::Added)
            .map(|d| d.path.as_str())
            .collect();
        assert_eq!(removed, vec!["src/a.rs", "src/b.rs"]);
        assert_eq!(added, vec!["README.md"]);
    }

    #[test]
    fn diff_against_empty_tree_is_added_everywhere() {
        let (_d, repo, root) = empty_repo();
        let r = write_blob_at_path(&repo, root, "a", b"x".to_vec()).unwrap();
        let r = write_blob_at_path(&repo, r, "b/c", b"y".to_vec()).unwrap();
        let diff = diff_trees(&repo, &root, &r, &DiffOptions::default()).unwrap();
        let paths: Vec<&str> = diff.iter().map(|d| d.path.as_str()).collect();
        assert_eq!(paths, vec!["a", "b/c"]);
        assert!(diff.iter().all(|d| d.kind == ChangeKind::Added));
    }
}
