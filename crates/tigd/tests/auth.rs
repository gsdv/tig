//! Integration tests for Ed25519-signed bearer tokens.
//!
//! These exercise the daemon's full auth path: a token signed by the
//! correct principal's Ed25519 key is accepted; bad signatures,
//! expired tokens, unknown subjects, and the missing-pubkey corner
//! all return 401. The X-Tig-Principal fallback continues to work
//! when no Authorization header is set.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::json;
use tempfile::tempdir;
use tig_protocol::ChangeView;
use tig_store::Repository;
use tig_vis::{sign_token, Claims, KeyPair, Principal, PrincipalKind, PrincipalStore, SignKeyPair};
use tigd::{build_app, AppState};
use tower::ServiceExt;

/// Set up a daemon with two registered local identities: alice (full
/// keys) and bob (full keys). Returns the app and the secrets we
/// generated so tests can mint tokens client-side.
struct Fixture {
    app: axum::Router,
    _dir: tempfile::TempDir,
    alice_sign: SignKeyPair,
    bob_sign: SignKeyPair,
}

fn fixture() -> Fixture {
    let dir = tempdir().unwrap();
    let repo = Repository::init(dir.path()).unwrap();

    // Pre-register alice and bob in the principal store, populating
    // both X25519 (sealing) and Ed25519 (signing) keypairs.
    let store = PrincipalStore::open(repo.root()).unwrap();

    let alice_seal = KeyPair::generate();
    let alice_sign = SignKeyPair::generate();
    let alice_sign_public_for_record = alice_sign.public.clone();
    let alice_sign_for_record = SignKeyPair {
        secret: tig_vis::SignSecretKey::from_hex(&alice_sign.secret.to_hex()).unwrap(),
        public: alice_sign.public.clone(),
    };
    store
        .put_new(&Principal::new_local_full(
            "alice",
            PrincipalKind::User,
            alice_seal,
            alice_sign_for_record,
        ))
        .unwrap();
    let _ = alice_sign_public_for_record;

    let bob_seal = KeyPair::generate();
    let bob_sign = SignKeyPair::generate();
    let bob_sign_for_record = SignKeyPair {
        secret: tig_vis::SignSecretKey::from_hex(&bob_sign.secret.to_hex()).unwrap(),
        public: bob_sign.public.clone(),
    };
    store
        .put_new(&Principal::new_local_full(
            "bob",
            PrincipalKind::User,
            bob_seal,
            bob_sign_for_record,
        ))
        .unwrap();

    let state = Arc::new(AppState::open(repo.root().to_path_buf()).unwrap());
    drop(repo);
    let app = build_app(state);
    Fixture {
        app,
        _dir: dir,
        alice_sign,
        bob_sign,
    }
}

async fn json_body<T: serde::de::DeserializeOwned>(resp: axum::response::Response) -> T {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "failed to decode JSON: {e}\nbody: {}",
            String::from_utf8_lossy(&bytes)
        )
    })
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn token_for(sub: &str, ttl_secs: u64, signer: &tig_vis::SignSecretKey) -> String {
    let claims = Claims {
        sub: sub.to_string(),
        exp: now() + ttl_secs,
    };
    sign_token(&claims, signer).unwrap()
}

fn post_change_with_auth(token: &str, who_says: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/changes")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(json!({ "description": who_says }).to_string()))
        .unwrap()
}

#[tokio::test]
async fn valid_bearer_token_authenticates() {
    let fx = fixture();
    let token = token_for("alice", 60, &fx.alice_sign.secret);

    let resp = fx
        .app
        .clone()
        .oneshot(post_change_with_auth(&token, "alice signed this"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let change: ChangeView = json_body(resp).await;
    assert_eq!(change.author, "alice");
    assert_eq!(change.description, "alice signed this");
}

#[tokio::test]
async fn token_signed_by_wrong_key_is_rejected() {
    // Alice claims to be alice, but the token was signed by bob's key.
    // Daemon looks up alice's pubkey (correct), verifies → fail.
    let fx = fixture();
    let bad_token = token_for("alice", 60, &fx.bob_sign.secret);

    let resp = fx
        .app
        .clone()
        .oneshot(post_change_with_auth(&bad_token, "impersonation"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let fx = fixture();
    let claims = Claims {
        sub: "alice".into(),
        exp: now().saturating_sub(60), // already expired
    };
    let token = sign_token(&claims, &fx.alice_sign.secret).unwrap();
    let resp = fx
        .app
        .clone()
        .oneshot(post_change_with_auth(&token, "stale"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_for_unknown_principal_is_rejected() {
    let fx = fixture();
    // carol isn't registered.
    let claims = Claims {
        sub: "carol".into(),
        exp: now() + 60,
    };
    // We can mint with any key — server can't verify because the
    // principal doesn't exist (so we never get to verify); 401 with
    // an "unknown principal" reason.
    let token = sign_token(&claims, &fx.alice_sign.secret).unwrap();
    let resp = fx
        .app
        .clone()
        .oneshot(post_change_with_auth(&token, "carol who?"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_token_is_400_not_401() {
    // Malformed (not even bearer-shaped) is a client error in
    // request construction, not an auth failure. Returns 400 so the
    // caller can distinguish "your token is broken" from "your token
    // is wrong."
    let fx = fixture();
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/changes")
                .header("content-type", "application/json")
                .header("authorization", "Bearer not-a-real-token")
                .body(Body::from(json!({"description": "x"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn bearer_prefix_is_required() {
    let fx = fixture();
    let token = token_for("alice", 60, &fx.alice_sign.secret);
    // Missing "Bearer " prefix.
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/changes")
                .header("content-type", "application/json")
                .header("authorization", token)
                .body(Body::from(json!({"description": "x"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn x_tig_principal_fallback_still_works_when_no_authorization() {
    // The legacy trust-by-name path is preserved for backward compat
    // and the local CLI's existing flow. With no Authorization
    // header, X-Tig-Principal is honored as before.
    let fx = fixture();
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/changes")
                .header("content-type", "application/json")
                .header("x-tig-principal", "alice")
                .body(Body::from(
                    json!({"description": "via fallback"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let change: ChangeView = json_body(resp).await;
    assert_eq!(change.author, "alice");
}

#[tokio::test]
async fn token_takes_precedence_over_x_tig_principal() {
    // If both headers are present, the signed token wins. The
    // trust-by-name header is silently ignored — there's no path
    // where the lesser-trust header overrides a valid signed claim.
    let fx = fixture();
    let alice_token = token_for("alice", 60, &fx.alice_sign.secret);
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/changes")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {alice_token}"))
                .header("x-tig-principal", "bob")
                .body(Body::from(json!({"description": "both"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let change: ChangeView = json_body(resp).await;
    assert_eq!(
        change.author, "alice",
        "signed token must take precedence over X-Tig-Principal"
    );
}
