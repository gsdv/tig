//! Stable identifiers for non-content-addressed records.
//!
//! Hashes identify *content*. These identify *records that change* —
//! Changes that float forward as their snapshot advances, ops in the
//! operation log, principals that author snapshots.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A Change's stable identity. ULID — lexicographically sortable, time-
/// prefixed, 26 chars in Crockford base32.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ChangeId(pub String);

impl ChangeId {
    pub fn new() -> Self {
        ChangeId(ulid::Ulid::new().to_string())
    }
}

impl Default for ChangeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ChangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Monotonic operation id within a repo. Assigned by the oplog writer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct OpId(pub u64);

impl fmt::Display for OpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "op#{}", self.0)
    }
}

/// An author identity. Milestone 0: opaque string ("local:alice",
/// "agent:claude-code"). Future milestones will key this to public keys
/// and signatures (see ARCHITECTURE.md §8).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrincipalId(pub String);

impl PrincipalId {
    pub fn local(name: &str) -> Self {
        PrincipalId(format!("local:{name}"))
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_ids_are_unique_and_sortable() {
        let a = ChangeId::new();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = ChangeId::new();
        assert_ne!(a, b);
        assert!(a < b, "ULIDs should sort by time");
    }
}
