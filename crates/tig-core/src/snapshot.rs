//! Immutable point in history. Replaces git's `commit`.
//!
//! A snapshot's hash binds *everything you'd ever check against*: tree,
//! parents, author, message, timestamp. Signatures are layered on in a
//! later milestone (see ARCHITECTURE.md §8); the encoding leaves room.

use crate::{Encodable, Hash, ObjectKind, OpId, PrincipalId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Empty for the root snapshot. Two parents = merge. More = octopus
    /// merges, supported by the data model but not the CLI yet.
    pub parents: Vec<Hash>,

    /// The root `Tree` of this snapshot.
    pub tree: Hash,

    pub author: PrincipalId,

    /// Wall-clock unix nanoseconds, for ordering and display. Not part of
    /// any consensus — content addressing makes the snapshot's identity
    /// independent of timestamp games.
    pub timestamp_ns: u64,

    /// Optional human-meaningful message. `tig log` (default view) hides
    /// snapshots without one — see ARCHITECTURE.md §5.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// The op that produced this snapshot, if any. None for synthesized
    /// snapshots (imports, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_id: Option<OpId>,
}

impl Snapshot {
    pub fn current_timestamp_ns() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

impl Encodable for Snapshot {
    const KIND: ObjectKind = ObjectKind::Snapshot;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Blob, Tree};

    #[test]
    fn snapshot_roundtrip_preserves_hash() {
        let tree_hash = Tree::new().hash().unwrap();
        let snap = Snapshot {
            parents: vec![],
            tree: tree_hash,
            author: PrincipalId::local("tester"),
            timestamp_ns: 1_700_000_000_000_000_000,
            message: Some("initial".into()),
            op_id: None,
        };
        let raw = snap.encode().unwrap();
        let back = Snapshot::decode(&raw).unwrap();
        assert_eq!(snap, back);
        assert_eq!(snap.hash().unwrap(), back.hash().unwrap());
    }

    #[test]
    fn parents_affect_hash() {
        let tree_hash = Tree::new().hash().unwrap();
        let blob_hash = Blob::new(b"x".to_vec()).hash().unwrap();
        let a = Snapshot {
            parents: vec![],
            tree: tree_hash,
            author: PrincipalId::local("t"),
            timestamp_ns: 0,
            message: None,
            op_id: None,
        };
        let b = Snapshot {
            parents: vec![blob_hash],
            ..a.clone()
        };
        assert_ne!(a.hash().unwrap(), b.hash().unwrap());
    }
}
