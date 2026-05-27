use crate::{Encodable, ObjectKind};
use serde::{Deserialize, Serialize};

/// Opaque file bytes. The unit of file content in tig.
///
/// Blobs are *byte-exact* — line ending normalization, CRLF tricks, and
/// other "helpful" mangling have no place here. If two files differ by a
/// single byte, they have different hashes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blob {
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

impl Blob {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Encodable for Blob {
    const KIND: ObjectKind = ObjectKind::Blob;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let b = Blob::new(b"hello world".to_vec());
        let raw = b.encode().unwrap();
        let back = Blob::decode(&raw).unwrap();
        assert_eq!(b, back);
        assert_eq!(raw.kind, ObjectKind::Blob);
    }

    #[test]
    fn empty_blob_hashes() {
        let b = Blob::new(Vec::new());
        let h = b.hash().unwrap();
        // re-hashing the same content yields the same hash
        assert_eq!(h, Blob::new(Vec::new()).hash().unwrap());
    }

    #[test]
    fn different_bytes_different_hashes() {
        let a = Blob::new(b"a".to_vec()).hash().unwrap();
        let b = Blob::new(b"b".to_vec()).hash().unwrap();
        assert_ne!(a, b);
    }

    /// Pin the exact hash of a known fixture under the canonical
    /// encoder. If this ever changes, the on-disk format silently
    /// diverged — every stored object's hash would be invalidated
    /// across versions. This test is the canary.
    #[test]
    fn blob_hash_is_stable_across_versions() {
        let empty = Blob::new(Vec::new()).hash().unwrap();
        assert_eq!(
            empty.to_hex(),
            "542b1ad8f8d11112b689b61edb6f597fe9cdfd6aa888be9654938eb91385595c",
            "empty-blob hash drifted; canonical encoding changed under us",
        );
        let hello = Blob::new(b"hello".to_vec()).hash().unwrap();
        assert_eq!(
            hello.to_hex(),
            "05f6c41d2f5ea325dee96d79ca96a71d0aa8a1b393a31c051435ac08a87f373a",
            "non-empty-blob hash drifted; canonical encoding changed under us",
        );
    }
}
