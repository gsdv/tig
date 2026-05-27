//! Content-addressed hashes.
//!
//! tig uses BLAKE3-256. Each hash is computed over the byte concatenation
//! of `[kind_tag, canonical_payload]`, which prevents a blob's bytes from
//! ever colliding with a tree's bytes even if they happen to be identical.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::object::ObjectKind;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub(crate) [u8; 32]);

impl Hash {
    /// Hash a kind-tagged payload. Always go through this — never hash
    /// payloads directly, or you'll lose cross-kind collision resistance.
    pub fn compute(kind: ObjectKind, payload: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(&[kind as u8]);
        h.update(payload);
        Hash(*h.finalize().as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(Error::Decode(format!(
                "expected 32-byte hash, got {} bytes",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Hash(out))
    }

    /// First two hex chars — used for object-store fan-out directory.
    pub fn fanout(&self) -> String {
        hex::encode(&self.0[..1])
    }

    /// Remaining 62 hex chars after the fanout prefix.
    pub fn rest(&self) -> String {
        hex::encode(&self.0[1..])
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", &self.to_hex()[..12])
    }
}

impl Serialize for Hash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        // bytes form on the wire — compact and exact
        serde_bytes::Bytes::new(&self.0).serialize(s)
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let bytes: serde_bytes::ByteBuf = Deserialize::deserialize(d)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "Hash must be exactly 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Hash(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_prefix_separates_collisions() {
        // identical payload, different kind tag → different hash
        let a = Hash::compute(ObjectKind::Blob, b"hello");
        let b = Hash::compute(ObjectKind::Tree, b"hello");
        assert_ne!(a, b);
    }

    #[test]
    fn hex_roundtrip() {
        let h = Hash::compute(ObjectKind::Blob, b"xyz");
        let s = h.to_hex();
        assert_eq!(s.len(), 64);
        let back = Hash::from_hex(&s).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn fanout_and_rest_concatenate_to_hex() {
        let h = Hash::compute(ObjectKind::Blob, b"q");
        let joined = format!("{}{}", h.fanout(), h.rest());
        assert_eq!(joined, h.to_hex());
        assert_eq!(h.fanout().len(), 2);
        assert_eq!(h.rest().len(), 62);
    }
}
