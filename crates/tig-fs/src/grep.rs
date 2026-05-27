//! `tig grep` — pattern search across a snapshot's tree.
//!
//! Walks `tree_hash` recursively, reads each [`EntryKind::File`] blob
//! from the object store, and reports every line matching the
//! configured pattern. Output is `grep`-shaped (path, line number,
//! line text); the engine returns structured values and lets the CLI
//! / daemon format them.
//!
//! ## What gets searched
//!
//! Only regular files. Sealed, conflict, submodule, and symlink
//! entries are skipped silently — sealed reads need an identity
//! (separate concern; the user has `tig reveal`), and the others
//! don't have searchable text in the snapshot's view.
//!
//! Binary files are skipped via [`crate::is_binary`] — the same
//! heuristic [`crate::blame`] uses. A future flag could let the
//! caller force-include binaries (`grep -a`), but the milestone
//! default is "skip, no message" to keep output focused.
//!
//! ## Pattern semantics
//!
//! Default is literal substring match — predictable, no escape
//! gotchas. Set [`GrepOptions::regex`] for full Rust-`regex` regex
//! support. `ignore_case` works for both — in literal mode it
//! lowercases both sides; in regex mode it sets the case-insensitive
//! flag on compile.
//!
//! ## Path filtering
//!
//! `paths` is a list of path *prefixes*. An entry is searched iff
//! its full tree path starts with at least one prefix, *or* the
//! list is empty (no filter). Same shape `/diff` already uses.
//!
//! ## Bounded output
//!
//! `max_matches_per_file` and `max_total_matches` cap pathological
//! greps (e.g. searching for `e` in a corpus). When the global cap is
//! hit, walking stops cleanly — no exception, no partial-file
//! ambiguity, just "here's what we found before the cap".

use crate::{is_binary, Error, Result};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use tig_core::{Blob, Encodable, EntryKind, Hash, Tree};
use tig_store::Repository;

/// One matched line in one file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrepMatch {
    /// Full tree path, slash-separated.
    pub path: String,
    /// 1-based line number, matching what every editor + `grep`
    /// itself uses.
    pub line_number: usize,
    /// The full matching line, without a trailing newline.
    pub line: String,
}

/// Knobs for a `grep_tree` call.
#[derive(Clone, Debug, Default)]
pub struct GrepOptions {
    /// Treat `pattern` as a Rust-`regex` regular expression. Default
    /// is literal substring match.
    pub regex: bool,
    /// Case-insensitive match. Honored for both literal and regex
    /// modes.
    pub ignore_case: bool,
    /// Path-prefix allowlist. Empty = no filter.
    pub paths: Vec<String>,
    /// Cap matches per file. None = no cap.
    pub max_matches_per_file: Option<usize>,
    /// Cap total matches across the whole tree. None = no cap. When
    /// hit, the walk stops cleanly.
    pub max_total_matches: Option<usize>,
}

/// Search every regular file under `tree_hash` for lines matching
/// `pattern`. Returns matches in tree-traversal order (alphabetical
/// within a directory, since [`Tree::entries`] is sorted by name).
pub fn grep_tree(
    repo: &Repository,
    tree_hash: &Hash,
    pattern: &str,
    opts: &GrepOptions,
) -> Result<Vec<GrepMatch>> {
    if pattern.is_empty() {
        return Err(Error::Core(tig_core::Error::Decode(
            "grep pattern must be non-empty".into(),
        )));
    }
    let matcher = Matcher::compile(pattern, opts)?;
    let mut out = Vec::new();
    walk(repo, tree_hash, "", opts, &matcher, &mut out)?;
    Ok(out)
}

// --- impl ------------------------------------------------------------

enum Matcher {
    Literal {
        needle: String,
        // Pre-lowercased needle for ignore-case; haystack is
        // lowercased per-line at scan time.
        ignore_case: bool,
    },
    Regex(Regex),
}

impl Matcher {
    fn compile(pattern: &str, opts: &GrepOptions) -> Result<Self> {
        if opts.regex {
            let re = RegexBuilder::new(pattern)
                .case_insensitive(opts.ignore_case)
                .build()
                .map_err(|e| {
                    Error::Core(tig_core::Error::Decode(format!(
                        "invalid regex {pattern:?}: {e}"
                    )))
                })?;
            Ok(Matcher::Regex(re))
        } else {
            let needle = if opts.ignore_case {
                pattern.to_lowercase()
            } else {
                pattern.to_string()
            };
            Ok(Matcher::Literal {
                needle,
                ignore_case: opts.ignore_case,
            })
        }
    }

    fn matches(&self, line: &str) -> bool {
        match self {
            Matcher::Literal {
                needle,
                ignore_case,
            } => {
                if *ignore_case {
                    // Allocation per line — fine for milestone; the
                    // dominant cost is decoding blobs anyway.
                    line.to_lowercase().contains(needle)
                } else {
                    line.contains(needle.as_str())
                }
            }
            Matcher::Regex(re) => re.is_match(line),
        }
    }
}

fn path_passes_filter(path: &str, paths: &[String]) -> bool {
    if paths.is_empty() {
        return true;
    }
    paths.iter().any(|p| path.starts_with(p))
}

/// Whether walking can stop because we've hit the global cap.
fn at_global_cap(opts: &GrepOptions, out: &[GrepMatch]) -> bool {
    opts.max_total_matches
        .map(|cap| out.len() >= cap)
        .unwrap_or(false)
}

fn walk(
    repo: &Repository,
    tree_hash: &Hash,
    prefix: &str,
    opts: &GrepOptions,
    matcher: &Matcher,
    out: &mut Vec<GrepMatch>,
) -> Result<()> {
    let tree = Tree::decode(&repo.get(tree_hash)?).map_err(Error::Core)?;
    for entry in &tree.entries {
        if at_global_cap(opts, out) {
            return Ok(());
        }
        let path = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{prefix}/{}", entry.name)
        };
        match entry.kind {
            EntryKind::File => {
                if !path_passes_filter(&path, &opts.paths) {
                    continue;
                }
                let blob = Blob::decode(&repo.get(&entry.target)?).map_err(Error::Core)?;
                if is_binary(&blob.bytes) {
                    continue;
                }
                // Treat the file as utf-8-ish. `from_utf8_lossy`
                // preserves byte offsets up to the first invalid
                // sequence by substituting U+FFFD; for typical source
                // code this is a no-op.
                let text = String::from_utf8_lossy(&blob.bytes);
                let mut per_file = 0usize;
                for (i, line) in text.lines().enumerate() {
                    if matcher.matches(line) {
                        out.push(GrepMatch {
                            path: path.clone(),
                            line_number: i + 1,
                            line: line.to_string(),
                        });
                        per_file += 1;
                        if let Some(cap) = opts.max_matches_per_file {
                            if per_file >= cap {
                                break;
                            }
                        }
                        if at_global_cap(opts, out) {
                            return Ok(());
                        }
                    }
                }
            }
            EntryKind::Tree => {
                // Don't apply the path filter at the tree level — a
                // path prefix like "src/" should let us descend into
                // src/, but the entries inside are what get checked
                // against the prefix. (`path_passes_filter` is
                // prefix-only, so `"src/x.rs".starts_with("src/")`
                // matches; we just don't gate the recursion.)
                walk(repo, &entry.target, &path, opts, matcher, out)?;
            }
            // Sealed: would require an identity (not in scope here).
            // Conflict / Submodule / Symlink: nothing useful to grep.
            EntryKind::Sealed | EntryKind::Conflict | EntryKind::Submodule | EntryKind::Symlink => {
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tig_core::{FileMode, Snapshot, Tree, TreeEntry};
    use tig_store::Repository;

    fn put_blob(repo: &Repository, bytes: &[u8]) -> Hash {
        repo.put(&Blob::new(bytes.to_vec()).encode().unwrap())
            .unwrap()
    }

    fn put_tree<I: IntoIterator<Item = TreeEntry>>(repo: &Repository, entries: I) -> Hash {
        let t = Tree::from_entries(entries).unwrap();
        repo.put(&t.encode().unwrap()).unwrap()
    }

    fn file_entry(name: &str, hash: Hash) -> TreeEntry {
        TreeEntry {
            name: name.into(),
            kind: EntryKind::File,
            target: hash,
            mode: FileMode::REGULAR,
            vis: None,
        }
    }

    fn dir_entry(name: &str, hash: Hash) -> TreeEntry {
        TreeEntry {
            name: name.into(),
            kind: EntryKind::Tree,
            target: hash,
            mode: FileMode::DIR,
            vis: None,
        }
    }

    /// Build a tree:
    ///   /README       "hello\nworld\nHello again\n"
    ///   /src/main.rs  "fn main() {\n    println!(\"hi\");\n}\n"
    ///   /src/util.rs  "fn util() {}\n"
    ///   /bin.dat      "\x00\x01\x02" (binary — should be skipped)
    fn fixture() -> (tempfile::TempDir, Repository, Hash) {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let readme = put_blob(&repo, b"hello\nworld\nHello again\n");
        let main_rs = put_blob(&repo, b"fn main() {\n    println!(\"hi\");\n}\n");
        let util_rs = put_blob(&repo, b"fn util() {}\n");
        let bin = put_blob(&repo, &[0u8, 1, 2, 3, 4]);

        let src_tree = put_tree(
            &repo,
            [
                file_entry("main.rs", main_rs),
                file_entry("util.rs", util_rs),
            ],
        );
        let root_tree = put_tree(
            &repo,
            [
                file_entry("README", readme),
                file_entry("bin.dat", bin),
                dir_entry("src", src_tree),
            ],
        );
        (dir, repo, root_tree)
    }

    #[test]
    fn literal_match_finds_substring() {
        let (_dir, repo, root) = fixture();
        let hits = grep_tree(&repo, &root, "hello", &GrepOptions::default()).unwrap();
        // Case-sensitive default — finds only lowercase "hello", not "Hello again".
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "README");
        assert_eq!(hits[0].line_number, 1);
        assert_eq!(hits[0].line, "hello");
    }

    #[test]
    fn ignore_case_matches_both() {
        let (_dir, repo, root) = fixture();
        let opts = GrepOptions {
            ignore_case: true,
            ..Default::default()
        };
        let hits = grep_tree(&repo, &root, "hello", &opts).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].line_number, 1);
        assert_eq!(hits[1].line_number, 3);
    }

    #[test]
    fn regex_mode_compiles_pattern() {
        let (_dir, repo, root) = fixture();
        let opts = GrepOptions {
            regex: true,
            ..Default::default()
        };
        // Match function definitions in any .rs file.
        let hits = grep_tree(&repo, &root, r"^fn \w+\(", &opts).unwrap();
        let paths: Vec<_> = hits.iter().map(|h| h.path.as_str()).collect();
        assert!(paths.contains(&"src/main.rs"));
        assert!(paths.contains(&"src/util.rs"));
    }

    #[test]
    fn invalid_regex_returns_decode_error() {
        let (_dir, repo, root) = fixture();
        let opts = GrepOptions {
            regex: true,
            ..Default::default()
        };
        let err = grep_tree(&repo, &root, "(unclosed", &opts).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid regex"), "got: {msg}");
    }

    #[test]
    fn empty_pattern_is_rejected() {
        let (_dir, repo, root) = fixture();
        let err = grep_tree(&repo, &root, "", &GrepOptions::default()).unwrap_err();
        assert!(err.to_string().contains("non-empty"));
    }

    #[test]
    fn binary_files_are_skipped() {
        let (_dir, repo, root) = fixture();
        // Pattern that would trivially match any non-empty file —
        // any single byte. The binary file must not appear in
        // results.
        let opts = GrepOptions {
            regex: true,
            ..Default::default()
        };
        let hits = grep_tree(&repo, &root, ".", &opts).unwrap();
        for h in &hits {
            assert_ne!(h.path, "bin.dat", "binary file leaked into results");
        }
    }

    #[test]
    fn sealed_and_other_kinds_are_skipped() {
        // Put a sealed entry in the tree; grep must skip silently.
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let plain = put_blob(&repo, b"alpha\n");
        // Sealed needs a Sealed object in the store; build a stub.
        use tig_core::{RecipientWrap, SealAlgo, Sealed};
        let sealed = Sealed {
            algo: SealAlgo::X25519XChaCha20Poly1305,
            ephemeral_pk: vec![0u8; 32],
            recipients: vec![RecipientWrap {
                recipient_pk: vec![1u8; 32],
                wrapped_key: vec![2u8; 48],
                wrap_nonce: vec![3u8; 24],
            }],
            ciphertext: vec![9u8; 32],
            nonce: vec![4u8; 24],
            aad: b"secret".to_vec(),
        };
        let sealed_h = repo.put(&sealed.encode().unwrap()).unwrap();
        let root = put_tree(
            &repo,
            [
                file_entry("plain.txt", plain),
                TreeEntry {
                    name: "secret".into(),
                    kind: EntryKind::Sealed,
                    target: sealed_h,
                    mode: FileMode::REGULAR,
                    vis: None,
                },
            ],
        );

        let hits = grep_tree(&repo, &root, "alpha", &GrepOptions::default()).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "plain.txt");
    }

    #[test]
    fn path_filter_excludes_non_matching_files() {
        let (_dir, repo, root) = fixture();
        let opts = GrepOptions {
            paths: vec!["src/".into()],
            ..Default::default()
        };
        // README has "hello" but is filtered out by the prefix.
        let hits = grep_tree(&repo, &root, "fn", &opts).unwrap();
        for h in &hits {
            assert!(h.path.starts_with("src/"), "leak: {}", h.path);
        }
        assert!(!hits.is_empty());
    }

    #[test]
    fn max_per_file_caps_results() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        // Five matching lines.
        let h = put_blob(&repo, b"x\nx\nx\nx\nx\n");
        let root = put_tree(&repo, [file_entry("f", h)]);

        let opts = GrepOptions {
            max_matches_per_file: Some(2),
            ..Default::default()
        };
        let hits = grep_tree(&repo, &root, "x", &opts).unwrap();
        assert_eq!(hits.len(), 2);
        // Order preserved.
        assert_eq!(hits[0].line_number, 1);
        assert_eq!(hits[1].line_number, 2);
    }

    #[test]
    fn max_total_stops_walking() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let h1 = put_blob(&repo, b"x\nx\nx\n");
        let h2 = put_blob(&repo, b"x\nx\nx\n");
        // Two files, three matches each = 6 total. Cap at 4.
        let root = put_tree(&repo, [file_entry("a", h1), file_entry("b", h2)]);

        let opts = GrepOptions {
            max_total_matches: Some(4),
            ..Default::default()
        };
        let hits = grep_tree(&repo, &root, "x", &opts).unwrap();
        assert_eq!(hits.len(), 4);
        // First file fully exhausted, second only partially.
        let by_path = (
            hits.iter().filter(|h| h.path == "a").count(),
            hits.iter().filter(|h| h.path == "b").count(),
        );
        assert_eq!(by_path, (3, 1));
    }

    #[test]
    fn line_numbers_are_one_based() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let h = put_blob(&repo, b"first\nsecond\nthird\n");
        let root = put_tree(&repo, [file_entry("f", h)]);
        let hits = grep_tree(&repo, &root, "third", &GrepOptions::default()).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line_number, 3);
    }

    #[test]
    fn empty_tree_returns_no_matches() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let root = put_tree(&repo, std::iter::empty::<TreeEntry>());
        let hits = grep_tree(&repo, &root, "anything", &GrepOptions::default()).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn searches_actual_snapshot_tree_via_helper() {
        // Sanity: grep_tree against a hash derived from a real
        // Snapshot object behaves identically (it always took a tree
        // hash, but make sure callers can drive it that way).
        let (dir, repo, root) = fixture();
        let snap = Snapshot {
            parents: vec![],
            tree: root,
            author: tig_core::PrincipalId::local("t"),
            timestamp_ns: 1,
            message: None,
            op_id: None,
        };
        let snap_h = repo.put(&snap.encode().unwrap()).unwrap();
        let snap_back = Snapshot::decode(&repo.get(&snap_h).unwrap()).unwrap();
        let hits = grep_tree(&repo, &snap_back.tree, "world", &GrepOptions::default()).unwrap();
        assert_eq!(hits.len(), 1);
        let _ = dir;
    }
}
