//! A `Change` — the mutable label that floats forward as work progresses.
//!
//! Conceptually replaces git's `branch` + `HEAD` combination. A Change has
//! a stable `id` (a ULID), an optional human `bookmark` name, and a
//! `current` pointer to a Snapshot that updates on every save.
//!
//! Unlike snapshots, Changes are **not** content-addressed. They live in
//! `.tig/refs/changes/<id>` and are read/written as small JSON records.
//! That's why this file doesn't implement `Encodable`.

use crate::{ChangeId, Hash, PrincipalId, VisLabel};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeState {
    /// Author is still editing. Snapshots accumulate freely.
    Working,
    /// Author has paused; visible only to themself (see ARCHITECTURE.md §4.3).
    Draft,
    /// Open for review. Bookmark advances are gated.
    Review,
    /// Merged into a published bookmark. Effectively frozen.
    Landed,
    /// Author gave up. Snapshots remain in store for the GC interval.
    Abandoned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub id: ChangeId,

    /// The snapshot this Change currently points at. Advances on each snap.
    pub current: Hash,

    /// Optional human name. Two Changes can share a bookmark only if one
    /// is `Landed` (history). Milestone 0 does not yet enforce that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bookmark: Option<String>,

    pub description: String,

    pub state: ChangeState,

    /// Every snapshot this Change has ever pointed at, oldest first.
    /// Lets `tig undo` rewind without consulting the global oplog.
    pub history: Vec<Hash>,

    /// Who created this change. Drives the visibility policy — the
    /// author can always see + mutate; others depend on `visibility`.
    /// Defaulted so older serialized changes deserialize cleanly.
    #[serde(default = "default_anonymous_author")]
    pub author: PrincipalId,

    /// Who can see this change. Defaults to `Public`. Combined with
    /// `state == Draft`, a `Private` change is invisible to anyone but
    /// its author until they publish — the "hidden in-flight PRs"
    /// from Theo's §1.
    #[serde(default)]
    pub visibility: VisLabel,
}

fn default_anonymous_author() -> PrincipalId {
    PrincipalId("local:anonymous".into())
}

impl Change {
    pub fn new(
        description: impl Into<String>,
        author: PrincipalId,
        initial_snapshot: Hash,
    ) -> Self {
        Self {
            id: ChangeId::new(),
            current: initial_snapshot,
            bookmark: None,
            description: description.into(),
            state: ChangeState::Working,
            history: vec![initial_snapshot],
            author,
            visibility: VisLabel::default(),
        }
    }

    /// Construct a fresh change in `Draft` + `Private` state. The common
    /// "in-flight, not for anyone else's eyes yet" combination.
    pub fn new_private_draft(
        description: impl Into<String>,
        author: PrincipalId,
        initial_snapshot: Hash,
    ) -> Self {
        let mut c = Self::new(description, author, initial_snapshot);
        c.state = ChangeState::Draft;
        c.visibility = VisLabel::Private;
        c
    }

    pub fn advance(&mut self, new_snapshot: Hash) {
        if self.current != new_snapshot {
            self.current = new_snapshot;
            self.history.push(new_snapshot);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObjectKind, hash::Hash as H};

    fn fake_hash(b: &[u8]) -> Hash {
        H::compute(ObjectKind::Snapshot, b)
    }

    fn alice() -> PrincipalId {
        PrincipalId("alice".into())
    }

    #[test]
    fn advance_appends_to_history_and_dedupes() {
        let s0 = fake_hash(b"0");
        let s1 = fake_hash(b"1");
        let mut c = Change::new("desc", alice(), s0);
        c.advance(s1);
        c.advance(s1); // same snap again: history should not grow
        assert_eq!(c.history, vec![s0, s1]);
        assert_eq!(c.current, s1);
    }

    #[test]
    fn json_roundtrip() {
        let s0 = fake_hash(b"x");
        let c = Change::new("the work", alice(), s0);
        let s = serde_json::to_string(&c).unwrap();
        let back: Change = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn new_change_defaults_to_public_working() {
        let c = Change::new("x", alice(), fake_hash(b"x"));
        assert_eq!(c.state, ChangeState::Working);
        assert_eq!(c.visibility, VisLabel::Public);
    }

    #[test]
    fn new_private_draft_sets_both_fields() {
        let c = Change::new_private_draft("x", alice(), fake_hash(b"x"));
        assert_eq!(c.state, ChangeState::Draft);
        assert_eq!(c.visibility, VisLabel::Private);
    }

    #[test]
    fn legacy_change_without_author_or_visibility_deserializes_with_defaults() {
        // Migration: a Change record written before this milestone has
        // no `author` or `visibility` fields. Simulate by serializing a
        // current Change, stripping those two fields from the JSON, and
        // round-tripping back through serde — should produce defaults.
        let full = Change::new("legacy", alice(), fake_hash(b"snap"));
        let mut v: serde_json::Value = serde_json::to_value(&full).unwrap();
        let obj = v.as_object_mut().unwrap();
        obj.remove("author");
        obj.remove("visibility");
        let bytes = serde_json::to_vec(&v).unwrap();
        let back: Change = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.author, default_anonymous_author());
        assert_eq!(back.visibility, VisLabel::Public);
        assert_eq!(back.description, "legacy");
    }
}
