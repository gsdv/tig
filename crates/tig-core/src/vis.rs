//! Visibility labels — who can see what.
//!
//! This module names the labels; *enforcement* lives at the daemon
//! boundary. A `VisLabel` attached to a `Change` (or, later, a `Tree`
//! entry or `Snapshot`) tells the daemon what audience the object is
//! intended for. When a request arrives, the daemon resolves the
//! caller's principal and decides — see `tigd::vis` for the policy
//! engine.
//!
//! Milestone 7 ships `Public` and `Private`. The enum has explicit
//! room for `Org` and `Team`; those land when there's a real
//! membership registry. (`Sealed` is *not* a label here — sealed
//! payloads use the `Sealed` *object kind* instead, with crypto
//! enforcing access.)

use crate::PrincipalId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum VisLabel {
    /// Anyone (including no principal claim at all) can see this.
    #[default]
    Public,
    /// Only the object's author can see it.
    Private,
    /// (Future) Members of the named organisation.
    Org(String),
    /// (Future) Members of the named team.
    Team(String),
    /// (Future) Exactly one named principal (in addition to the author).
    Principal(PrincipalId),
}

impl VisLabel {
    pub fn name(&self) -> &'static str {
        match self {
            VisLabel::Public => "public",
            VisLabel::Private => "private",
            VisLabel::Org(_) => "org",
            VisLabel::Team(_) => "team",
            VisLabel::Principal(_) => "principal",
        }
    }
}

/// The minimal policy decision: given an object's `(visibility, author)`
/// and a (possibly absent) caller principal, may the caller see it?
///
/// This function is the **single source of truth** for read access.
/// The daemon's list, fetch, and snapshot endpoints all call through
/// here. Mutation gating is a stricter check — see `can_mutate`.
pub fn can_see(
    visibility: &VisLabel,
    author: &PrincipalId,
    caller: Option<&PrincipalId>,
) -> bool {
    match visibility {
        VisLabel::Public => true,
        VisLabel::Private => caller.map(|c| c == author).unwrap_or(false),
        // Until membership exists, treat group labels as "author only".
        // This is the safer failure mode (deny by default).
        VisLabel::Org(_) | VisLabel::Team(_) => {
            caller.map(|c| c == author).unwrap_or(false)
        }
        VisLabel::Principal(allowed) => {
            caller.map(|c| c == author || c == allowed).unwrap_or(false)
        }
    }
}

/// Mutation requires being the author. Read access alone is not enough.
/// A future "collaborative draft" feature would extend this.
pub fn can_mutate(author: &PrincipalId, caller: Option<&PrincipalId>) -> bool {
    caller.map(|c| c == author).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> PrincipalId {
        PrincipalId("alice".into())
    }
    fn bob() -> PrincipalId {
        PrincipalId("bob".into())
    }

    #[test]
    fn public_is_visible_to_anyone() {
        assert!(can_see(&VisLabel::Public, &alice(), None));
        assert!(can_see(&VisLabel::Public, &alice(), Some(&bob())));
        assert!(can_see(&VisLabel::Public, &alice(), Some(&alice())));
    }

    #[test]
    fn private_is_visible_only_to_author() {
        assert!(can_see(&VisLabel::Private, &alice(), Some(&alice())));
        assert!(!can_see(&VisLabel::Private, &alice(), Some(&bob())));
        assert!(!can_see(&VisLabel::Private, &alice(), None));
    }

    #[test]
    fn principal_label_extends_visibility_to_a_named_other() {
        let label = VisLabel::Principal(bob());
        assert!(can_see(&label, &alice(), Some(&alice())));
        assert!(can_see(&label, &alice(), Some(&bob())));
        let carol = PrincipalId("carol".into());
        assert!(!can_see(&label, &alice(), Some(&carol)));
    }

    #[test]
    fn group_labels_deny_until_membership_registry_exists() {
        // Documented behaviour: until we have orgs/teams, group labels
        // collapse to "author only". This is the safer default.
        let label = VisLabel::Org("eng".into());
        assert!(can_see(&label, &alice(), Some(&alice())));
        assert!(!can_see(&label, &alice(), Some(&bob())));
    }

    #[test]
    fn mutation_requires_being_the_author() {
        assert!(can_mutate(&alice(), Some(&alice())));
        assert!(!can_mutate(&alice(), Some(&bob())));
        assert!(!can_mutate(&alice(), None));
    }
}
