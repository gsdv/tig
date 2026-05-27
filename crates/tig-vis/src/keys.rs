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

// --- Ed25519 signing keys -------------------------------------------------
//
// Distinct from the X25519 keys above. X25519 is for sealing (ECDH +
// AEAD). Ed25519 is for signing — specifically, the daemon's signed
// bearer tokens (see `tig-vis::tokens`). Each Principal owns both
// keypairs; nothing today derives one from the other (a future
// optimization could collapse them via the standard Ed25519 →
// X25519 conversion).

/// 32-byte Ed25519 public key. Hex on the wire.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SignPublicKey(pub [u8; 32]);

impl SignPublicKey {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(Error::Crypto(format!(
                "expected 32-byte Ed25519 public key, got {} bytes",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(SignPublicKey(out))
    }

    /// Verify `sig` against `msg`. Returns true iff the signature
    /// was produced by the matching `SignSecretKey`.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        use ed25519_dalek::Verifier;
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        let ed_sig = ed25519_dalek::Signature::from_bytes(&sig.0);
        vk.verify(msg, &ed_sig).is_ok()
    }
}

impl std::fmt::Debug for SignPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SignPublicKey({})", &self.to_hex()[..16])
    }
}

impl std::fmt::Display for SignPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for SignPublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_hex().serialize(s)
    }
}

impl<'de> Deserialize<'de> for SignPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        SignPublicKey::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// 32-byte Ed25519 secret seed. Derived public key via `.public()`.
/// Like its X25519 sibling, the bytes never serialize through this
/// type; only the on-disk principal store stores them, hex-encoded.
pub struct SignSecretKey(ed25519_dalek::SigningKey);

impl SignSecretKey {
    pub fn public(&self) -> SignPublicKey {
        SignPublicKey(self.0.verifying_key().to_bytes())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0.to_bytes())
    }

    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(Error::Crypto(format!(
                "expected 32-byte Ed25519 secret seed, got {} bytes",
                bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(SignSecretKey(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }

    /// Produce an Ed25519 signature over `msg`.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        use ed25519_dalek::Signer;
        let s = self.0.sign(msg);
        Signature(s.to_bytes())
    }
}

impl std::fmt::Debug for SignSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SignSecretKey(<redacted>, pub={})",
            &self.public().to_hex()[..16]
        )
    }
}

/// 64-byte Ed25519 signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 64 {
            return Err(Error::Crypto(format!(
                "expected 64-byte Ed25519 signature, got {} bytes",
                bytes.len()
            )));
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(Signature(out))
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({}…)", &self.to_hex()[..16])
    }
}

pub struct SignKeyPair {
    pub secret: SignSecretKey,
    pub public: SignPublicKey,
}

impl SignKeyPair {
    /// Generate a fresh Ed25519 keypair using the OS RNG.
    pub fn generate() -> Self {
        let signing = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let public = SignPublicKey(signing.verifying_key().to_bytes());
        SignKeyPair {
            secret: SignSecretKey(signing),
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

    // --- Ed25519 sign/verify tests --------------------------------------

    #[test]
    fn sign_keypair_signs_and_verifies() {
        let kp = SignKeyPair::generate();
        let msg = b"hello, world";
        let sig = kp.secret.sign(msg);
        assert!(kp.public.verify(msg, &sig));
    }

    #[test]
    fn sign_signature_rejects_wrong_message() {
        let kp = SignKeyPair::generate();
        let sig = kp.secret.sign(b"original");
        assert!(!kp.public.verify(b"tampered", &sig));
    }

    #[test]
    fn sign_signature_rejects_wrong_key() {
        let alice = SignKeyPair::generate();
        let bob = SignKeyPair::generate();
        let sig = alice.secret.sign(b"x");
        assert!(!bob.public.verify(b"x", &sig));
    }

    #[test]
    fn sign_secret_hex_roundtrip_preserves_signatures() {
        let kp = SignKeyPair::generate();
        let restored = SignSecretKey::from_hex(&kp.secret.to_hex()).unwrap();
        let msg = b"x";
        assert_eq!(kp.secret.sign(msg).0, restored.sign(msg).0);
    }

    #[test]
    fn sign_debug_does_not_leak_secret() {
        let kp = SignKeyPair::generate();
        let s = format!("{:?}", kp.secret);
        assert!(s.contains("redacted"));
        assert!(!s.contains(&kp.secret.to_hex()));
    }
}
