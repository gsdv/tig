//! Sealed objects — encrypted payloads with explicit recipient lists.
//!
//! The architecture's §2.6 type, expressed exactly. Crypto lives in
//! `tig-vis`; this module only defines the wire shape so the
//! object-store layer can store and address sealed bytes the same way
//! it stores blobs and trees. The hash is over the ciphertext, so the
//! object store doesn't need any keys to dedupe.
//!
//! Field-by-field:
//!   - `algo` — which seal recipe was used. Today only one.
//!   - `ephemeral_pk` — sender's per-seal X25519 public key. Recipients
//!     ECDH against this to derive their wrap key.
//!   - `recipients` — one wrap entry per recipient; each entry binds a
//!     recipient pubkey to the encrypted-with-wrap-key data key.
//!   - `ciphertext` — the payload, encrypted with the data key under
//!     XChaCha20-Poly1305.
//!   - `nonce` — 24-byte XChaCha20 nonce. Random per seal.
//!   - `aad` — additional authenticated data, typically the tree path
//!     so a ciphertext bound to one location can't be moved to another.

use crate::{Encodable, ObjectKind};
use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SealAlgo {
    /// X25519 ECDH → HKDF-SHA256-derived wrap key → XChaCha20-Poly1305
    /// over the data key, with a fresh per-seal data key + 24-byte
    /// nonce. The data key encrypts the actual payload under the same
    /// AEAD with `aad` as the path binding.
    X25519XChaCha20Poly1305 = 1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientWrap {
    /// 32-byte X25519 public key identifying the recipient.
    #[serde(with = "serde_bytes")]
    pub recipient_pk: Vec<u8>,
    /// Wrapped 32-byte data key (32 bytes ciphertext + 16-byte Poly1305 tag = 48 bytes).
    #[serde(with = "serde_bytes")]
    pub wrapped_key: Vec<u8>,
    /// 24-byte XChaCha20 nonce for the wrap operation.
    #[serde(with = "serde_bytes")]
    pub wrap_nonce: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub algo: SealAlgo,

    /// Sender's per-seal ephemeral X25519 public key. 32 bytes.
    #[serde(with = "serde_bytes")]
    pub ephemeral_pk: Vec<u8>,

    pub recipients: Vec<RecipientWrap>,

    /// Encrypted payload (the actual file bytes).
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,

    /// 24-byte nonce for the payload encryption.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,

    /// Additional authenticated data — typically the tree path the
    /// sealed entry lives at. Recipients must supply matching AAD on
    /// decrypt.
    #[serde(with = "serde_bytes")]
    pub aad: Vec<u8>,
}

impl Sealed {
    pub fn recipient_for(&self, pk: &[u8]) -> Option<&RecipientWrap> {
        self.recipients.iter().find(|r| r.recipient_pk == pk)
    }
}

impl Encodable for Sealed {
    const KIND: ObjectKind = ObjectKind::Sealed;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_sealed() -> Sealed {
        Sealed {
            algo: SealAlgo::X25519XChaCha20Poly1305,
            ephemeral_pk: vec![0u8; 32],
            recipients: vec![RecipientWrap {
                recipient_pk: vec![1u8; 32],
                wrapped_key: vec![2u8; 48],
                wrap_nonce: vec![3u8; 24],
            }],
            ciphertext: vec![9u8; 64],
            nonce: vec![4u8; 24],
            aad: b"config/prod.env".to_vec(),
        }
    }

    #[test]
    fn roundtrips_through_encode_decode() {
        let s = dummy_sealed();
        let raw = s.encode().unwrap();
        let back = Sealed::decode(&raw).unwrap();
        assert_eq!(s, back);
        assert_eq!(raw.kind, ObjectKind::Sealed);
    }

    #[test]
    fn hash_changes_with_payload() {
        let mut s1 = dummy_sealed();
        let h1 = s1.hash().unwrap();
        s1.ciphertext.push(0xff);
        let h2 = s1.hash().unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn recipient_for_finds_by_pubkey() {
        let s = dummy_sealed();
        assert!(s.recipient_for(&[1u8; 32]).is_some());
        assert!(s.recipient_for(&[0u8; 32]).is_none());
    }
}
