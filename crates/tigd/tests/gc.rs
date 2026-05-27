//! Integration tests for `POST /v1/gc`.
//!
//! We drive the axum router in-process. The fixture mirrors `auth.rs`
//! since the gc endpoint requires a signed Bearer token.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::json;
use tempfile::tempdir;
use tig_core::{Blob, Encodable};
use tig_protocol::GcView;
use tig_store::{ObjectStore, Repository};
use tig_vis::{sign_token, Claims, KeyPair, Principal, PrincipalKind, PrincipalStore, SignKeyPair};
use tigd::{build_app, AppState};
use tower::ServiceExt;

struct Fixture {
    app: axum::Router,
    repo: Repository, // kept for direct store inspection in tests
    _dir: tempfile::TempDir,
    alice_sign: SignKeyPair,
}

fn fixture() -> Fixture {
    let dir = tempdir().unwrap();
    let repo = Repository::init(dir.path()).unwrap();

    let store = PrincipalStore::open(repo.root()).unwrap();
    let alice_seal = KeyPair::generate();
    let alice_sign = SignKeyPair::generate();
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

    let state = Arc::new(AppState::open(repo.root().to_path_buf()).unwrap());
    // Reopen a separate Repository handle for test-side inspection;
    // AppState already has its own copy.
    let inspect = Repository::open_at_tig_dir(repo.root()).unwrap();
    drop(repo);
    let app = build_app(state);
    Fixture {
        app,
        repo: inspect,
        _dir: dir,
        alice_sign,
    }
}

fn token_for(sub: &str, ttl_secs: u64, signer: &tig_vis::SignSecretKey) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = Claims {
        sub: sub.to_string(),
        exp: now + ttl_secs,
    };
    sign_token(&claims, signer).unwrap()
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

fn post_gc(token: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/gc")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn gc_requires_bearer_token() {
    // No Authorization header → 401. The trust-by-name fallback is
    // explicitly rejected on the gc endpoint, so even with
    // X-Tig-Principal we should be denied.
    let fx = fixture();
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/gc")
                .header("content-type", "application/json")
                .header("x-tig-principal", "alice")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn gc_sweeps_orphan_blobs() {
    let fx = fixture();
    // Stash an orphan blob directly via the store.
    let orphan_hash = fx
        .repo
        .put(&Blob::new(b"orphan-payload".to_vec()).encode().unwrap())
        .unwrap();
    assert!(fx.repo.objects().has(&orphan_hash).unwrap());

    let token = token_for("alice", 60, &fx.alice_sign.secret);
    let resp = fx
        .app
        .clone()
        .oneshot(post_gc(&token, json!({"ignore_oplog": true})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let view: GcView = json_body(resp).await;
    assert!(view.removed >= 1, "expected ≥1 removal, got {view:?}");
    assert!(!view.dry_run);
    assert!(view.bytes_freed > 0);
    assert!(
        !fx.repo.objects().has(&orphan_hash).unwrap(),
        "orphan survived"
    );
}

#[tokio::test]
async fn gc_dry_run_reports_but_doesnt_delete() {
    let fx = fixture();
    let orphan_hash = fx
        .repo
        .put(&Blob::new(b"keep-me-for-now".to_vec()).encode().unwrap())
        .unwrap();

    let token = token_for("alice", 60, &fx.alice_sign.secret);
    let resp = fx
        .app
        .clone()
        .oneshot(post_gc(
            &token,
            json!({"dry_run": true, "ignore_oplog": true}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let view: GcView = json_body(resp).await;
    assert!(view.dry_run);
    assert!(view.removed >= 1);
    assert!(
        fx.repo.objects().has(&orphan_hash).unwrap(),
        "dry-run deleted the file"
    );
}

#[tokio::test]
async fn gc_with_empty_body_uses_defaults() {
    // No body at all — daemon should treat as default GcReq
    // (dry_run=false, ignore_oplog=false). Should succeed and report.
    let fx = fixture();
    let token = token_for("alice", 60, &fx.alice_sign.secret);
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/gc")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let view: GcView = json_body(resp).await;
    assert!(!view.dry_run);
    // Fresh repo, no orphans, nothing to do.
    assert_eq!(view.removed, 0);
}

#[tokio::test]
async fn gc_preserves_objects_referenced_via_http_created_change() {
    // Create a change through the daemon's own API; PATCH a file into
    // its tree; run GC. The blob and tree must survive — they're
    // reachable through the live Change record.
    let fx = fixture();
    let token = token_for("alice", 60, &fx.alice_sign.secret);

    // Create a change.
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/changes")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(json!({"description": "for gc"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let change: serde_json::Value = json_body(resp).await;
    let cid = change["id"].as_str().unwrap().to_string();

    // PATCH a file.
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/v1/changes/{cid}/tree/notes.txt"))
                .header("content-type", "application/octet-stream")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from("important content".as_bytes().to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Sanity check: file can be fetched.
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/changes/{cid}/tree/notes.txt"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"important content");

    // Run GC (default opts: includes oplog, not dry-run).
    let resp = fx
        .app
        .clone()
        .oneshot(post_gc(&token, json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let view: GcView = json_body(resp).await;
    assert_eq!(view.removed, 0, "GC nuked something reachable: {view:?}");

    // File still fetchable post-GC.
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/changes/{cid}/tree/notes.txt"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"important content");
}

#[tokio::test]
async fn gc_unknown_token_principal_is_unauthorized() {
    // Token for a principal not in the store → 401, no GC happens.
    let fx = fixture();
    // Mint a token claiming to be "ghost" — alice's signing key,
    // but the daemon will look up "ghost" in the principal store
    // and fail.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let bad = sign_token(
        &Claims {
            sub: "ghost".into(),
            exp: now + 60,
        },
        &fx.alice_sign.secret,
    )
    .unwrap();
    let resp = fx
        .app
        .clone()
        .oneshot(post_gc(&bad, json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
