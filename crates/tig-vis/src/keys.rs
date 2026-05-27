//! Typed wrappers around X25519 key material.
//!
//! Wraps `x25519_dalek` types so the rest of the crate stays clean and
//! we can swap implementations later (e.g. signing keys would land
//! here too). Keys are serialized as 32-byte values, displayed as hex.

use crate::Error;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

/// 32-byte X25519 public key. Hex on the wire.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(Error::Crypto(format!(
                "expected 32-byte X25519 key, got {} bytes",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(PublicKey(out))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", &self.to_hex()[..16])
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_hex().serialize(s)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        PublicKey::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// 32-byte X25519 secret key. The secret never touches the wire;
/// disk persistence handles its own access control.
pub struct SecretKey(pub(crate) StaticSecret);

impl SecretKey {
    pub fn public(&self) -> PublicKey {
        let xpub: XPublicKey = (&self.0).into();
        PublicKey(*xpub.as_bytes())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0.to_bytes())
    }

    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(Error::Crypto(format!(
                "expected 32-byte secret, got {} bytes",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(SecretKey(StaticSecret::from(out)))
    }

    /// ECDH: shared secret with the named peer's public key. The
    /// `x25519_dalek` API returns a 32-byte `SharedSecret`; we expose
    /// raw bytes for the KDF.
    pub fn dh(&self, peer: &PublicKey) -> [u8; 32] {
        let xpub = XPublicKey::from(peer.0);
        let shared = self.0.diffie_hellman(&xpub);
        *shared.as_bytes()
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't print the bytes — leaking secrets via Debug is a classic.
        write!(
            f,
            "SecretKey(<redacted>, pub={})",
            &self.public().to_hex()[..16]
        )
    }
}

pub struct KeyPair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl KeyPair {
    /// Generate a fresh keypair using the OS RNG.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_x: XPublicKey = (&secret).into();
        let public = PublicKey(*public_x.as_bytes());
        KeyPair {
            secret: SecretKey(secret),
            public,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_generates_matching_public() {
        let kp = KeyPair::generate();
        assert_eq!(kp.public, kp.secret.public());
    }

    #[test]
    fn dh_is_commutative() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let shared_ab = a.secret.dh(&b.public);
        let shared_ba = b.secret.dh(&a.public);
        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let kp = KeyPair::generate();
        let s = kp.public.to_hex();
        assert_eq!(s.len(), 64);
        let back = PublicKey::from_hex(&s).unwrap();
        assert_eq!(kp.public, back);
    }

    #[test]
    fn secret_key_hex_roundtrip_preserves_dh() {
        let kp = KeyPair::generate();
        let peer = KeyPair::generate();
        let s = kp.secret.to_hex();
        let restored = SecretKey::from_hex(&s).unwrap();
        assert_eq!(kp.secret.dh(&peer.public), restored.dh(&peer.public));
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let kp = KeyPair::generate();
        let s = format!("{:?}", kp.secret);
        assert!(s.contains("redacted"));
        assert!(!s.contains(&kp.secret.to_hex()));
    }
}
