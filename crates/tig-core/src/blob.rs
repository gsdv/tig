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
}
