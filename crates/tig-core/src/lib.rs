//! `tig-core` — the pure data model.
//!
//! This crate has zero I/O. It defines the objects that make up a tig
//! repository (Blob, Tree, Snapshot, Change, …), their canonical encoding,
//! and their content-addressed identity (BLAKE3-256, kind-prefixed).
//!
//! Storage, networking, working copies, and the CLI all sit *above* this
//! crate. They are free to evolve their representations as long as they
//! preserve the object hashes computed here.
//!
//! Design references: see `docs/ARCHITECTURE.md` §2 for the object model
//! and §11 for milestone-0 scope.

pub mod blob;
pub mod canonical;
pub mod change;
pub mod error;
pub mod hash;
pub mod id;
pub mod object;
pub mod sealed;
pub mod snapshot;
pub mod tree;
pub mod vis;

pub use blob::Blob;
pub use canonical::canonical_encode;
pub use change::{Change, ChangeState};
pub use error::Error;
pub use hash::Hash;
pub use id::{ChangeId, OpId, PrincipalId};
pub use object::{Encodable, ObjectKind, RawObject};
pub use sealed::{RecipientWrap, SealAlgo, Sealed};
pub use snapshot::Snapshot;
pub use tree::{EntryKind, FileMode, Tree, TreeEntry, VisTag};
pub use vis::{can_mutate, can_see, VisLabel};

pub type Result<T> = std::result::Result<T, Error>;
