//! Per-line authorship attribution — `tig blame`.
//!
//! Given a path and a starting snapshot, attribute each line of the
//! file to the snap that last introduced or modified it. This is the
//! same shape git blame has, computed via tree-diff machinery already
//! present in [`crate::diff`].
//!
//! Algorithm (recursive, walking parent-first):
//!
//!   1. Read the file at the target snap. These are the lines we
//!      ultimately attribute.
//!   2. If the snap has no parent, *or* the parent doesn't contain the
//!      file at this path, attribute every line to this snap.
//!   3. Otherwise, blame the parent recursively to get the parent's
//!      attribution map.
//!   4. Run a line-diff between parent's file and current's file.
//!      `Equal` lines inherit the parent's attribution at their
//!      original index. `Insert` lines (new in current) get attributed
//!      to the current snap. `Delete` lines (removed from parent) are
//!      ignored — they're not in the output.
//!
//! Refuses binary files (the line-diff doesn't apply). Refuses sealed
//! entries (decryption needs an identity, which the engine doesn't
//! currently have access to).
//!
//! Complexity: O(N × L) where N is the snap-history depth and L is
//! the file's line count. The diff at each step is dominated by
//! similar's Myers diff (effectively O(L²) worst case but linear for
//! small edits). For typical files and history depths this is fine;
//! caching per-snap blame would help for very long histories — left as
//! a future optimisation.

use crate::{is_binary, try_read_blob_at_path, Error, Result};
use serde::{Deserialize, Serialize};
use tig_core::{Encodable, Hash, PrincipalId, Snapshot};
use tig_store::Repository;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlameLine {
    /// The line text, without a trailing newline.
    pub line: String,
    /// The snapshot that last introduced or modified this line.
    pub snap: Hash,
    pub author: PrincipalId,
    pub timestamp_ns: u64,
    /// The snap's commit message, if any. Useful for display.
    pub message: Option<String>,
}

/// Attribute every line of `path` at `target_snap`. See module docs
/// for the algorithm.
pub fn blame_at(repo: &Repository, path: &str, target_snap: &Hash) -> Result<Vec<BlameLine>> {
    let snap = Snapshot::decode(&repo.get(target_snap)?).map_err(Error::Core)?;

    let current_bytes = match try_read_blob_at_path(repo, snap.tree, path)? {
        Some(b) => b,
        None => {
            return Err(Error::Core(tig_core::Error::Decode(format!(
                "path {path:?} does not exist as a regular file at snapshot {}",
                &target_snap.to_hex()[..12]
            ))))
        }
    };

    if is_binary(&current_bytes) {
        return Err(Error::Core(tig_core::Error::Decode(format!(
            "path {path:?} is a binary file; blame doesn't apply"
        ))));
    }

    let current_text = String::from_utf8_lossy(&current_bytes).into_owned();
    let current_lines = split_lines(&current_text);

    // Base case: root snap or file-new-in-snap → everything attributed here.
    let parent_hash = match snap.parents.first() {
        Some(h) => *h,
        None => return Ok(make_lines_from(current_lines, target_snap, &snap)),
    };

    let parent_snap_obj = Snapshot::decode(&repo.get(&parent_hash)?).map_err(Error::Core)?;
    let parent_bytes = match try_read_blob_at_path(repo, parent_snap_obj.tree, path)? {
        Some(b) => b,
        // File didn't exist in parent. Created in this snap.
        None => return Ok(make_lines_from(current_lines, target_snap, &snap)),
    };
    if is_binary(&parent_bytes) {
        // Parent was binary; treat as if the file is new in current —
        // we can't meaningfully diff binary against text.
        return Ok(make_lines_from(current_lines, target_snap, &snap));
    }

    // Recurse to get parent's attribution.
    let parent_attrs = blame_at(repo, path, &parent_hash)?;

    // Diff parent → current. similar's Change::old_index() points into
    // the parent's lines (i.e. into parent_attrs); new_index() points
    // into current's. We walk all changes in order and emit one
    // `BlameLine` per `Equal` or `Insert` — `Delete` contributes
    // nothing to the output because it's gone.
    use similar::{ChangeTag, TextDiff};
    let parent_text = String::from_utf8_lossy(&parent_bytes).into_owned();
    let diff = TextDiff::from_lines(parent_text.as_str(), current_text.as_str());

    let mut out: Vec<BlameLine> = Vec::with_capacity(current_lines.len());
    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Equal => {
                let parent_idx = change.old_index().expect("Equal must have an old_index");
                // Defensive: the parent_attrs vec should have an entry
                // at parent_idx because parent_attrs is one-per-parent-line.
                let inherited = parent_attrs.get(parent_idx).cloned().unwrap_or_else(|| {
                    // Fallback: shouldn't happen unless similar
                    // disagrees with our line split. Attribute to
                    // current to fail safe — we *over-credit*
                    // current rather than under-credit.
                    synthesize_line(strip_eol(change.value()), target_snap, &snap)
                });
                out.push(inherited);
            }
            ChangeTag::Insert => {
                out.push(synthesize_line(
                    strip_eol(change.value()),
                    target_snap,
                    &snap,
                ));
            }
            ChangeTag::Delete => {
                // Line removed from parent; not in output.
            }
        }
    }
    Ok(out)
}

fn make_lines_from(lines: Vec<&str>, snap_hash: &Hash, snap: &Snapshot) -> Vec<BlameLine> {
    lines
        .into_iter()
        .map(|l| synthesize_line(l.to_string(), snap_hash, snap))
        .collect()
}

fn synthesize_line(line: impl Into<String>, snap_hash: &Hash, snap: &Snapshot) -> BlameLine {
    BlameLine {
        line: line.into(),
        snap: *snap_hash,
        author: snap.author.clone(),
        timestamp_ns: snap.timestamp_ns,
        message: snap.message.clone(),
    }
}

/// Split text into lines, dropping the trailing `\n` (and `\r` if
/// present). Matches what the diff inheritance will see — `similar`
/// yields lines including the trailing newline; we strip on emit.
fn split_lines(s: &str) -> Vec<&str> {
    // `str::lines` drops the trailing newline already, and handles
    // CRLF. It's the simplest correct thing.
    s.lines().collect()
}

fn strip_eol(s: &str) -> String {
    let mut s = s.to_string();
    if s.ends_with('\n') {
        s.pop();
    }
    if s.ends_with('\r') {
        s.pop();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{snap_now, write_blob_at_path, SnapOptions, SnapOutcome};
    use std::fs;
    use tempfile::tempdir;
    use tig_store::{OpLog, Repository, Workspace};

    /// Initialize a repo, then write the given `(filename, contents,
    /// author, message)` tuples one snap at a time. Returns the
    /// workspace, the oplog, and the snapshot hash produced by each
    /// step in order.
    fn snap_sequence(
        seq: &[(&str, &str, &str, &str)],
    ) -> (tempfile::TempDir, Workspace, OpLog, Vec<Hash>) {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let mut log = OpLog::open(repo.root()).unwrap();
        let mut ws = Workspace::main_for(repo);
        let mut snaps = Vec::new();
        for (filename, contents, author, msg) in seq {
            fs::write(dir.path().join(filename), contents.as_bytes()).unwrap();
            let opts = SnapOptions {
                author: PrincipalId::local(author),
                message: Some((*msg).to_string()),
                ..Default::default()
            };
            let out = snap_now(&mut ws, &mut log, &opts).unwrap();
            let h = match out {
                SnapOutcome::Snapped { snapshot, .. } => snapshot,
                _ => unreachable!(),
            };
            snaps.push(h);
        }
        (dir, ws, log, snaps)
    }

    #[test]
    fn single_snap_attributes_everything_to_that_snap() {
        let (_d, ws, _log, snaps) =
            snap_sequence(&[("a.txt", "first\nsecond\nthird\n", "alice", "initial")]);
        let blame = blame_at(&ws.repo, "a.txt", &snaps[0]).unwrap();
        assert_eq!(blame.len(), 3);
        let authors: Vec<&str> = blame.iter().map(|l| l.author.0.as_str()).collect();
        assert_eq!(authors, vec!["local:alice", "local:alice", "local:alice"]);
        let lines: Vec<&str> = blame.iter().map(|l| l.line.as_str()).collect();
        assert_eq!(lines, vec!["first", "second", "third"]);
        assert!(blame.iter().all(|l| l.snap == snaps[0]));
    }

    #[test]
    fn mid_file_edit_attributes_only_changed_line() {
        // Alice writes 5 lines. Bob edits line 3. Lines 1,2,4,5 should
        // still be alice's; line 3 attributed to bob.
        let (_d, ws, _log, snaps) = snap_sequence(&[
            (
                "src.rs",
                "fn main() {\n    let x = 1;\n    println!(\"hi\");\n    drop(x);\n}\n",
                "alice",
                "v1",
            ),
            (
                "src.rs",
                "fn main() {\n    let x = 1;\n    println!(\"hello, world\");\n    drop(x);\n}\n",
                "bob",
                "v2",
            ),
        ]);
        let blame = blame_at(&ws.repo, "src.rs", &snaps[1]).unwrap();
        assert_eq!(blame.len(), 5);

        let by_idx = |i: usize| (blame[i].author.0.as_str(), blame[i].line.as_str());
        assert_eq!(by_idx(0), ("local:alice", "fn main() {"));
        assert_eq!(by_idx(1), ("local:alice", "    let x = 1;"));
        assert_eq!(by_idx(2), ("local:bob", "    println!(\"hello, world\");"));
        assert_eq!(by_idx(3), ("local:alice", "    drop(x);"));
        assert_eq!(by_idx(4), ("local:alice", "}"));

        // The bob line should point at the bob snap, the alice lines at the alice snap.
        assert_eq!(blame[0].snap, snaps[0]);
        assert_eq!(blame[2].snap, snaps[1]);
    }

    #[test]
    fn file_new_in_snap_attributes_all_to_that_snap() {
        // Alice creates an unrelated file in v1. Bob creates "new.txt"
        // in v2. blame of new.txt should attribute everything to v2.
        let (_d, ws, _log, snaps) = snap_sequence(&[
            ("other.txt", "unrelated\n", "alice", "v1: unrelated"),
            (
                "new.txt",
                "line A\nline B\n",
                "bob",
                "v2: introduce new.txt",
            ),
        ]);
        let blame = blame_at(&ws.repo, "new.txt", &snaps[1]).unwrap();
        assert_eq!(blame.len(), 2);
        assert!(blame.iter().all(|l| l.author.0 == "local:bob"));
        assert!(blame.iter().all(|l| l.snap == snaps[1]));
    }

    #[test]
    fn lines_added_in_middle_attributed_to_inserter() {
        let (_d, ws, _log, snaps) = snap_sequence(&[
            ("notes.md", "A\nB\nC\n", "alice", "v1"),
            ("notes.md", "A\nB1\nB2\nC\n", "bob", "v2: insert"),
        ]);
        let blame = blame_at(&ws.repo, "notes.md", &snaps[1]).unwrap();
        assert_eq!(blame.len(), 4);
        assert_eq!(blame[0].author.0, "local:alice");
        assert_eq!(blame[1].author.0, "local:bob");
        assert_eq!(blame[2].author.0, "local:bob");
        assert_eq!(blame[3].author.0, "local:alice");
    }

    #[test]
    fn deletions_dont_appear_in_output() {
        // Alice writes 5 lines; bob removes line 3. Output should be 4
        // lines, all alice's.
        let (_d, ws, _log, snaps) = snap_sequence(&[
            ("x.txt", "a\nb\nc\nd\ne\n", "alice", "v1"),
            ("x.txt", "a\nb\nd\ne\n", "bob", "v2: drop c"),
        ]);
        let blame = blame_at(&ws.repo, "x.txt", &snaps[1]).unwrap();
        assert_eq!(blame.len(), 4);
        let lines: Vec<&str> = blame.iter().map(|l| l.line.as_str()).collect();
        assert_eq!(lines, vec!["a", "b", "d", "e"]);
        assert!(blame.iter().all(|l| l.author.0 == "local:alice"));
    }

    #[test]
    fn three_author_chain_attributes_correctly() {
        let (_d, ws, _log, snaps) = snap_sequence(&[
            ("f", "x\ny\nz\n", "alice", "v1"),
            ("f", "x\nyy\nz\n", "bob", "v2"),
            ("f", "x\nyy\nzz\n", "carol", "v3"),
        ]);
        let blame = blame_at(&ws.repo, "f", &snaps[2]).unwrap();
        assert_eq!(blame.len(), 3);
        assert_eq!(blame[0].author.0, "local:alice");
        assert_eq!(blame[1].author.0, "local:bob");
        assert_eq!(blame[2].author.0, "local:carol");
    }

    #[test]
    fn binary_file_refuses_with_clear_error() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();

        // Build a tree+snap holding a binary blob by hand (the scan
        // path treats arbitrary bytes the same way).
        let root = repo.put(&tig_core::Tree::new().encode().unwrap()).unwrap();
        let bin = vec![0xff, 0x00, 0xfe, 0x01];
        let new_root = write_blob_at_path(&repo, root, "img.bin", bin).unwrap();
        let snap = Snapshot {
            parents: vec![],
            tree: new_root,
            author: PrincipalId::local("t"),
            timestamp_ns: 0,
            message: Some("binary".into()),
            op_id: None,
        };
        let snap_hash = repo.put(&snap.encode().unwrap()).unwrap();

        let err = blame_at(&repo, "img.bin", &snap_hash).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("binary"), "got: {msg}");
    }

    #[test]
    fn missing_path_returns_clear_error() {
        let (_d, ws, _log, snaps) = snap_sequence(&[("exists.txt", "hello\n", "alice", "v1")]);
        let err = blame_at(&ws.repo, "missing.txt", &snaps[0]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("does not exist"),
            "expected missing-path message, got: {msg}"
        );
    }
}
