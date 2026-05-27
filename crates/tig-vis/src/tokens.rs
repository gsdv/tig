//! Ed25519-signed bearer tokens.
//!
//! Wire format: `<base64url(payload_json)>.<base64url(signature)>`.
//! Lightly JWT-shaped, no header — alg is fixed (Ed25519), and
//! everything else fits in the payload.
//!
//! Payload (JSON):
//! ```json
//! {"sub": "alice", "exp": 1700000000}
//! ```
//! - `sub` is the principal's local id (matches the daemon's
//!   PrincipalStore lookup key).
//! - `exp` is the unix-seconds expiration.
//!
//! The signature covers the **base64url-encoded payload bytes** —
//! the same bytes that appear before the `.` on the wire. Verifying
//! over the already-encoded form means there's exactly one canonical
//! payload representation per request; no JSON-canonicalization
//! questions arise.
//!
//! What this milestone explicitly does NOT do:
//!   - No nonce / one-time use. Two requests with the same token
//!     succeed. Adding nonce tracking is a future hardening.
//!   - No audience field. Tokens are repo-wide; the daemon doesn't
//!     verify they were minted for "this repo." A future
//!     deployment-scoped audience would close that.
//!   - No key rotation. If an identity's signing secret leaks,
//!     revocation means re-issuing the identity entirely.

use crate::{Error, SignPublicKey, SignSecretKey, Signature};
use base64::Engine;
use serde::{Deserialize, Serialize};

/// Token payload — the claims signed by the principal's Ed25519 key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// Principal id, matching `Principal::id` in the registry.
    pub sub: String,
    /// Unix-seconds expiration. The daemon rejects tokens past `exp`.
    pub exp: u64,
}

impl Claims {
    pub fn is_expired(&self, now_unix_seconds: u64) -> bool {
        now_unix_seconds >= self.exp
    }
}

/// Mint a bearer token for `claims`, signed by `secret`. The
/// resulting string can be sent to the daemon as
/// `Authorization: Bearer <token>`.
pub fn sign_token(claims: &Claims, secret: &SignSecretKey) -> Result<String, Error> {
    let payload_json = serde_json::to_vec(claims)?;
    let payload_b64 = b64url_encode(&payload_json);
    let sig = secret.sign(payload_b64.as_bytes());
    let sig_b64 = b64url_encode(&sig.0);
    Ok(format!("{payload_b64}.{sig_b64}"))
}

/// Decode and validate a bearer token. Returns the claims iff:
///   1. the token is well-formed (`<payload>.<sig>`),
///   2. the signature verifies against `pubkey`,
///   3. the token hasn't expired by `now_unix_seconds`.
///
/// Each failure mode produces a distinct `Error` variant so callers
/// can render the right HTTP status (401 for auth failure, 401 for
/// expired, 400 for malformed).
pub fn verify_token(
    token: &str,
    pubkey: &SignPublicKey,
    now_unix_seconds: u64,
) -> Result<Claims, Error> {
    let (payload_b64, sig_b64) = split_once_dot(token)?;
    let sig_bytes = b64url_decode(sig_b64)?;
    if sig_bytes.len() != 64 {
        return Err(Error::Crypto(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature(sig_arr);

    // Signature covers the base64url-encoded payload bytes, not the
    // raw JSON. Verifying over the already-encoded form makes the
    // canonical representation question disappear.
    if !pubkey.verify(payload_b64.as_bytes(), &sig) {
        return Err(Error::AuthFailure);
    }

    let payload_bytes = b64url_decode(payload_b64)?;
    let claims: Claims = serde_json::from_slice(&payload_bytes)?;
    if claims.is_expired(now_unix_seconds) {
        return Err(Error::Crypto(format!(
            "token expired at {} (now {})",
            claims.exp, now_unix_seconds
        )));
    }
    Ok(claims)
}

/// Decode a token's payload without verifying the signature. Useful
/// for daemon-side principal lookup — we need to know `sub` to find
/// the right pubkey before we can verify. Always combine with
/// `verify_token`; never trust the result of this alone.
pub fn peek_claims(token: &str) -> Result<Claims, Error> {
    let (payload_b64, _sig) = split_once_dot(token)?;
    let payload_bytes = b64url_decode(payload_b64)?;
    let claims: Claims = serde_json::from_slice(&payload_bytes)?;
    Ok(claims)
}

// --- helpers -------------------------------------------------------------

fn split_once_dot(token: &str) -> Result<(&str, &str), Error> {
    let mut parts = token.splitn(2, '.');
    let payload = parts.next().ok_or_else(malformed)?;
    let sig = parts.next().ok_or_else(malformed)?;
    if payload.is_empty() || sig.is_empty() {
        return Err(malformed());
    }
    Ok((payload, sig))
}

fn malformed() -> Error {
    Error::Crypto("malformed token (expected payload.signature)".into())
}

fn b64url_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, Error> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| Error::Crypto(format!("base64url: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SignKeyPair;

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn roundtrip_valid_token_verifies() {
        let kp = SignKeyPair::generate();
        let claims = Claims {
            sub: "alice".into(),
            exp: now() + 60,
        };
        let token = sign_token(&claims, &kp.secret).unwrap();
        let back = verify_token(&token, &kp.public, now()).unwrap();
        assert_eq!(back, claims);
    }

    #[test]
    fn tampered_payload_fails() {
        let kp = SignKeyPair::generate();
        let claims = Claims {
            sub: "alice".into(),
            exp: now() + 60,
        };
        let token = sign_token(&claims, &kp.secret).unwrap();
        // Flip a byte in the payload. Locate the '.' delimiter.
        let dot = token.find('.').unwrap();
        let mut bytes = token.as_bytes().to_vec();
        bytes[dot - 1] ^= 0x01;
        let tampered = String::from_utf8(bytes).unwrap();
        match verify_token(&tampered, &kp.public, now()) {
            Err(Error::AuthFailure) => {}
            other => panic!("expected AuthFailure, got {other:?}"),
        }
    }

    #[test]
    fn wrong_key_fails() {
        let alice = SignKeyPair::generate();
        let bob = SignKeyPair::generate();
        let claims = Claims {
            sub: "alice".into(),
            exp: now() + 60,
        };
        let token = sign_token(&claims, &alice.secret).unwrap();
        match verify_token(&token, &bob.public, now()) {
            Err(Error::AuthFailure) => {}
            other => panic!("expected AuthFailure when verifying with wrong key, got {other:?}"),
        }
    }

    #[test]
    fn expired_token_fails() {
        let kp = SignKeyPair::generate();
        let claims = Claims {
            sub: "alice".into(),
            exp: now().saturating_sub(60), // already expired
        };
        let token = sign_token(&claims, &kp.secret).unwrap();
        let err = verify_token(&token, &kp.public, now()).unwrap_err();
        assert!(err.to_string().contains("expired"), "got: {err}");
    }

    #[test]
    fn malformed_token_fails() {
        let kp = SignKeyPair::generate();
        let err = verify_token("nope-no-dots", &kp.public, now()).unwrap_err();
        assert!(err.to_string().contains("malformed"), "got: {err}");
    }

    #[test]
    fn peek_claims_returns_sub_without_verifying() {
        let alice = SignKeyPair::generate();
        let claims = Claims {
            sub: "alice".into(),
            exp: now() + 60,
        };
        let token = sign_token(&claims, &alice.secret).unwrap();
        let peeked = peek_claims(&token).unwrap();
        assert_eq!(peeked.sub, "alice");
        // peek_claims explicitly does NOT verify; a tampered token
        // can still peek cleanly. (The point is to let the daemon
        // *find* the right pubkey to verify against.)
    }
}
