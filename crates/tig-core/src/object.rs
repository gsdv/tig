//! Object kinds and the encode/decode contract.
//!
//! Every persisted tig object is a `RawObject`: a `(kind, bytes)` pair
//! where `bytes` is the canonical CBOR encoding of the typed object.
//!
//! Higher layers (tig-store, tig-net) only ever see `RawObject`. They
//! don't need to know whether a blob, a tree, or a snapshot is inside.
//!
//! NB: ciborium does not promise a strictly canonical encoding (no fixed
//! integer width, etc.). For milestone 0 we accept this: hashes are
//! stable round-trip in our own implementation. A future milestone will
//! switch to a canonical CBOR profile (or a hand-rolled encoder) before
//! external compatibility is promised.

use crate::{Error, Hash, Result};
use serde::{de::DeserializeOwned, Serialize};

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObjectKind {
    Blob = 1,
    Tree = 2,
    Snapshot = 3,
    Sealed = 4,
    Conflict = 5,
}

impl ObjectKind {
    pub fn from_tag(b: u8) -> Result<Self> {
        Ok(match b {
            1 => Self::Blob,
            2 => Self::Tree,
            3 => Self::Snapshot,
            4 => Self::Sealed,
            5 => Self::Conflict,
            other => return Err(Error::InvalidKind(other)),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
            Self::Snapshot => "snapshot",
            Self::Sealed => "sealed",
            Self::Conflict => "conflict",
        }
    }
}

/// A persisted-form object: kind + canonical bytes.
#[derive(Clone, Debug)]
pub struct RawObject {
    pub kind: ObjectKind,
    pub bytes: Vec<u8>,
}

impl RawObject {
    pub fn hash(&self) -> Hash {
        Hash::compute(self.kind, &self.bytes)
    }

    /// Verify that an externally-asserted hash matches our content.
    /// Use when reading from untrusted sources (network, disk cache).
    pub fn verify(&self, claimed: &Hash) -> Result<()> {
        let actual = self.hash();
        if &actual == claimed {
            Ok(())
        } else {
            Err(Error::HashMismatch {
                expected: claimed.to_hex(),
                actual: actual.to_hex(),
            })
        }
    }
}

/// A typed tig object. Implementations declare their `KIND` so we never
/// have to guess what's inside a blob of bytes.
pub trait Encodable: Sized + Serialize + DeserializeOwned {
    const KIND: ObjectKind;

    fn encode(&self) -> Result<RawObject> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(self, &mut bytes).map_err(|e| Error::Encode(e.to_string()))?;
        Ok(RawObject {
            kind: Self::KIND,
            bytes,
        })
    }

    fn decode(raw: &RawObject) -> Result<Self> {
        if raw.kind != Self::KIND {
            return Err(Error::Decode(format!(
                "expected kind {}, got {}",
                Self::KIND.name(),
                raw.kind.name()
            )));
        }
        ciborium::de::from_reader(raw.bytes.as_slice()).map_err(|e| Error::Decode(e.to_string()))
    }

    fn hash(&self) -> Result<Hash> {
        Ok(self.encode()?.hash())
    }
}
