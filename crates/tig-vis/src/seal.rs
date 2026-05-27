//! Seal and unseal — multi-recipient authenticated encryption.
//!
//! Construction (matches the architecture's §2.6 `Sealed` shape):
//!
//! 1. Generate an ephemeral X25519 keypair `(eph_sk, eph_pk)`.
//! 2. Generate a fresh 32-byte symmetric `data_key`.
//! 3. For each recipient public key `R`:
//!      a. `shared = X25519(eph_sk, R)`
//!      b. `wrap_key = HKDF-SHA256(shared, info="tig-seal:wrap:v1")`
//!      c. `wrap_nonce = random 24 bytes`
//!      d. `wrap_aad = aad || R`  ← binds each wrap to (path, recipient)
//!      e. `wrapped = XChaCha20Poly1305(wrap_key, wrap_nonce).encrypt(data_key, wrap_aad)`
//!      f. Record `RecipientWrap { R, wrapped, wrap_nonce }`
//! 4. Encrypt the payload:
//!      `nonce = random 24 bytes`
//!      `ciphertext = XChaCha20Poly1305(data_key, nonce).encrypt(plaintext, aad)`
//!
//! On decrypt the recipient:
//! 1. Finds its wrap entry by matching pubkey.
//! 2. Computes `shared = X25519(my_sk, eph_pk)` → same `wrap_key`.
//! 3. Unwraps `data_key` with `wrap_aad = aad || my_pk`.
//! 4. Decrypts `ciphertext` with `data_key` and `aad`.
//!
//! Properties:
//! - **AAD path binding.** Moving a sealed entry to a different tree
//!   path breaks decryption — Poly1305 tag invalidates.
//! - **Recipient binding.** Swapping wrap entries between recipients
//!   breaks decryption — each wrap is authenticated against its
//!   intended recipient's pubkey.
//! - **Forward secrecy at rest.** Ephemeral X25519 keys means a compromised
//!   recipient secret only reveals what they were a recipient of, not the
//!   sender's other seals.
//!
//! Constants:
//! - HKDF salt is empty (we're inside one cryptosystem with consistent
//!   `info` strings; salt rotation is a future story).
//! - Algo tag is `SealAlgo::X25519XChaCha20Poly1305` — the only variant
//!   today. Field is there so future algorithms can negotiate.

use crate::{Error, PublicKey, Result, SecretKey};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use tig_core::{RecipientWrap, SealAlgo, Sealed};

const HKDF_INFO: &[u8] = b"tig-seal:wrap:v1";

/// Encrypt `plaintext` so each recipient (and only each recipient) can
/// decrypt. The `aad` should be the tree path the sealed entry lives
/// at — this binds the ciphertext to its location.
pub fn seal(plaintext: &[u8], recipients: &[PublicKey], aad: &[u8]) -> Result<Sealed> {
    if recipients.is_empty() {
        return Err(Error::Crypto(
            "at least one recipient is required to seal".into(),
        ));
    }

    // Step 1: ephemeral keypair.
    let eph = crate::KeyPair::generate();
    let eph_pk_bytes = eph.public.0.to_vec();

    // Step 2: data key (32 random bytes).
    let mut data_key = [0u8; 32];
    OsRng.fill_bytes(&mut data_key);

    // Step 3: per-recipient wraps.
    let mut wraps: Vec<RecipientWrap> = Vec::with_capacity(recipients.len());
    for rpk in recipients {
        let shared = eph.secret.dh(rpk);
        let wrap_key = derive_wrap_key(&shared)?;
        let cipher = XChaCha20Poly1305::new(wrap_key.as_slice().into());
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        // Bind each wrap to its intended recipient: AAD includes their pubkey.
        let mut wrap_aad = Vec::with_capacity(aad.len() + 32);
        wrap_aad.extend_from_slice(aad);
        wrap_aad.extend_from_slice(&rpk.0);

        let wrapped = cipher
            .encrypt(
                nonce,
                Payload { msg: &data_key, aad: &wrap_aad },
            )
            .map_err(|e| Error::Crypto(format!("wrap encryption: {e}")))?;

        wraps.push(RecipientWrap {
            recipient_pk: rpk.0.to_vec(),
            wrapped_key: wrapped,
            wrap_nonce: nonce_bytes.to_vec(),
        });
    }

    // Step 4: payload encryption.
    let payload_cipher = XChaCha20Poly1305::new(data_key.as_slice().into());
    let mut payload_nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut payload_nonce_bytes);
    let payload_nonce = XNonce::from_slice(&payload_nonce_bytes);
    let ciphertext = payload_cipher
        .encrypt(payload_nonce, Payload { msg: plaintext, aad })
        .map_err(|e| Error::Crypto(format!("payload encryption: {e}")))?;

    Ok(Sealed {
        algo: SealAlgo::X25519XChaCha20Poly1305,
        ephemeral_pk: eph_pk_bytes,
        recipients: wraps,
        ciphertext,
        nonce: payload_nonce_bytes.to_vec(),
        aad: aad.to_vec(),
    })
}

/// Decrypt a `Sealed` payload as the holder of `my_secret`. The `aad`
/// must match the value passed to `seal` — typically the tree path.
pub fn unseal(sealed: &Sealed, my_secret: &SecretKey, aad: &[u8]) -> Result<Vec<u8>> {
    if !matches!(sealed.algo, SealAlgo::X25519XChaCha20Poly1305) {
        return Err(Error::UnsupportedAlgo);
    }
    if sealed.ephemeral_pk.len() != 32 {
        return Err(Error::MalformedSealed(format!(
            "ephemeral_pk must be 32 bytes, got {}",
            sealed.ephemeral_pk.len()
        )));
    }
    if sealed.nonce.len() != 24 {
        return Err(Error::MalformedSealed(format!(
            "payload nonce must be 24 bytes, got {}",
            sealed.nonce.len()
        )));
    }
    if sealed.aad != aad {
        // The aad is authenticated, but giving a clear error here helps
        // distinguish "wrong path" from "tampered ciphertext."
        return Err(Error::AuthFailure);
    }

    let my_pub = my_secret.public();
    let wrap = sealed
        .recipient_for(my_pub.as_bytes())
        .ok_or(Error::NotARecipient)?;

    if wrap.wrap_nonce.len() != 24 {
        return Err(Error::MalformedSealed("wrap_nonce must be 24 bytes".into()));
    }

    // Recreate the wrap key.
    let mut eph_pk_arr = [0u8; 32];
    eph_pk_arr.copy_from_slice(&sealed.ephemeral_pk);
    let eph_pk = PublicKey(eph_pk_arr);
    let shared = my_secret.dh(&eph_pk);
    let wrap_key = derive_wrap_key(&shared)?;

    let wrap_cipher = XChaCha20Poly1305::new(wrap_key.as_slice().into());
    let wrap_nonce = XNonce::from_slice(&wrap.wrap_nonce);
    let mut wrap_aad = Vec::with_capacity(aad.len() + 32);
    wrap_aad.extend_from_slice(aad);
    wrap_aad.extend_from_slice(&my_pub.0);
    let data_key = wrap_cipher
        .decrypt(
            wrap_nonce,
            Payload { msg: &wrap.wrapped_key, aad: &wrap_aad },
        )
        .map_err(|_| Error::AuthFailure)?;

    if data_key.len() != 32 {
        return Err(Error::MalformedSealed(format!(
            "unwrapped data key has wrong length: {}",
            data_key.len()
        )));
    }

    // Decrypt the payload.
    let payload_cipher = XChaCha20Poly1305::new(data_key.as_slice().into());
    let payload_nonce = XNonce::from_slice(&sealed.nonce);
    let plaintext = payload_cipher
        .decrypt(
            payload_nonce,
            Payload { msg: &sealed.ciphertext, aad },
        )
        .map_err(|_| Error::AuthFailure)?;

    Ok(plaintext)
}

fn derive_wrap_key(shared: &[u8; 32]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut out = [0u8; 32];
    hk.expand(HKDF_INFO, &mut out)
        .map_err(|e| Error::Crypto(format!("HKDF: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;
    use tig_core::Encodable;

    #[test]
    fn single_recipient_roundtrip() {
        let alice = KeyPair::generate();
        let plaintext = b"DATABASE_URL=postgres://host/db";
        let aad = b"config/prod.env";

        let sealed = seal(plaintext, &[alice.public.clone()], aad).unwrap();
        let back = unseal(&sealed, &alice.secret, aad).unwrap();
        assert_eq!(back, plaintext);
    }

    #[test]
    fn multi_recipient_each_can_decrypt() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let plaintext = b"SHARED_SECRET";
        let aad = b"path";

        let sealed = seal(
            plaintext,
            &[alice.public.clone(), bob.public.clone()],
            aad,
        )
        .unwrap();

        assert_eq!(unseal(&sealed, &alice.secret, aad).unwrap(), plaintext);
        assert_eq!(unseal(&sealed, &bob.secret, aad).unwrap(), plaintext);
    }

    #[test]
    fn non_recipient_cannot_decrypt() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let carol = KeyPair::generate();
        let sealed = seal(b"top secret", &[alice.public, bob.public], b"path").unwrap();
        match unseal(&sealed, &carol.secret, b"path") {
            Err(Error::NotARecipient) => {}
            other => panic!("expected NotARecipient, got {other:?}"),
        }
    }

    #[test]
    fn wrong_aad_fails() {
        let alice = KeyPair::generate();
        let sealed = seal(b"x", &[alice.public.clone()], b"correct/path").unwrap();
        match unseal(&sealed, &alice.secret, b"wrong/path") {
            Err(Error::AuthFailure) => {}
            other => panic!("expected AuthFailure, got {other:?}"),
        }
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let alice = KeyPair::generate();
        let mut sealed = seal(b"hello", &[alice.public.clone()], b"p").unwrap();
        let last = sealed.ciphertext.last_mut().unwrap();
        *last ^= 0xff;
        match unseal(&sealed, &alice.secret, b"p") {
            Err(Error::AuthFailure) => {}
            other => panic!("expected AuthFailure, got {other:?}"),
        }
    }

    #[test]
    fn swapping_wraps_between_recipients_fails() {
        // Recipient binding: if I tamper by swapping bob's wrap entry
        // for alice's recipient_pk, alice can't decrypt because the
        // wrap_aad includes the recipient pubkey.
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let mut sealed = seal(
            b"x",
            &[alice.public.clone(), bob.public.clone()],
            b"p",
        )
        .unwrap();
        // Re-label bob's wrap as alice's: keep alice's wrap entry intact
        // but copy bob's wrapped_key+wrap_nonce on top of alice's pubkey.
        let bob_wrap = sealed
            .recipients
            .iter()
            .find(|r| r.recipient_pk == bob.public.0.to_vec())
            .unwrap()
            .clone();
        let alice_idx = sealed
            .recipients
            .iter()
            .position(|r| r.recipient_pk == alice.public.0.to_vec())
            .unwrap();
        sealed.recipients[alice_idx].wrapped_key = bob_wrap.wrapped_key;
        sealed.recipients[alice_idx].wrap_nonce = bob_wrap.wrap_nonce;

        match unseal(&sealed, &alice.secret, b"p") {
            Err(Error::AuthFailure) => {}
            other => panic!("expected AuthFailure after wrap swap, got {other:?}"),
        }
    }

    #[test]
    fn sealed_object_roundtrips_through_object_store_encoding() {
        // Belt-and-suspenders: encode → decode → unseal still works.
        let alice = KeyPair::generate();
        let sealed = seal(b"hi", &[alice.public.clone()], b"a/b").unwrap();
        let raw = sealed.encode().unwrap();
        let back = Sealed::decode(&raw).unwrap();
        assert_eq!(unseal(&back, &alice.secret, b"a/b").unwrap(), b"hi");
    }
}
