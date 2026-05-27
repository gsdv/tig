//! Integration tests for the tigd HTTP surface.
//!
//! We drive the axum `Router` directly via `tower::ServiceExt::oneshot`
//! — no network, no port allocation, no flakiness. Each test gets a
//! tempdir-scoped repo and a fresh AppState.
//!
//! What we're proving:
//!   1. The "OS-optional" loop works: create a change, PATCH a file,
//!      GET it back, snap it, undo it — entirely over HTTP, with no
//!      working copy ever materialized to disk.
//!   2. Errors map to the right status codes (404, 400, 409).
//!   3. The op log reflects every state-changing call.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::json;
use tempfile::tempdir;
use tig_protocol::{
    ChangeView, HealthView, OpView, SnapResp, SnapshotView, TreeView, UndoResp,
};
use tig_store::Repository;
use tigd::{build_app, AppState};
use tower::ServiceExt;

/// Spin up an axum app over a fresh empty repo. Returns the app and the
/// tempdir (must be held to keep the repo on disk for the test's
/// lifetime).
fn fixture() -> (axum::Router, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let repo = Repository::init(dir.path()).unwrap();
    let state = Arc::new(AppState::open(repo.root().to_path_buf()).unwrap());
    drop(repo); // AppState reopens it
    let app = build_app(state);
    (app, dir)
}

async fn json_body<T: serde::de::DeserializeOwned>(resp: axum::response::Response) -> T {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!("failed to decode JSON: {e}\nbody: {}", String::from_utf8_lossy(&bytes))
    })
}

async fn raw_body(resp: axum::response::Response) -> Vec<u8> {
    to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()
}

fn get(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

fn post_json(path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn patch_bytes(path: &str, bytes: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(path)
        .header("content-type", "application/octet-stream")
        .body(Body::from(bytes))
        .unwrap()
}

fn delete(path: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn health_returns_ok_and_version() {
    let (app, _dir) = fixture();
    let resp = app.oneshot(get("/v1/health")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: HealthView = json_body(resp).await;
    assert!(body.ok);
    assert!(!body.version.is_empty());
}

#[tokio::test]
async fn full_lifecycle_over_http() {
    let (app, _dir) = fixture();

    // 1. List changes — empty.
    let resp = app.clone().oneshot(get("/v1/changes")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let listed: Vec<ChangeView> = json_body(resp).await;
    assert_eq!(listed.len(), 0);

    // 2. Create a change.
    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/changes",
            json!({ "description": "first agent work" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let change: ChangeView = json_body(resp).await;
    assert_eq!(change.description, "first agent work");
    let change_id = change.id.clone();

    // 3. PATCH a file.
    let resp = app
        .clone()
        .oneshot(patch_bytes(
            &format!("/v1/changes/{change_id}/tree/src/main.rs"),
            b"fn main() { println!(\"agent wrote me\"); }".to_vec(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let change_after_patch: ChangeView = json_body(resp).await;
    assert_eq!(
        change_after_patch.history.len(),
        2,
        "PATCH should have appended a snapshot"
    );

    // 4. GET the file back.
    let resp = app
        .clone()
        .oneshot(get(&format!(
            "/v1/changes/{change_id}/tree/src/main.rs"
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = raw_body(resp).await;
    assert_eq!(body, b"fn main() { println!(\"agent wrote me\"); }");

    // 5. GET the root tree listing.
    let resp = app
        .clone()
        .oneshot(get(&format!("/v1/changes/{change_id}/tree")))
        .await
        .unwrap();
    let tree: TreeView = json_body(resp).await;
    assert_eq!(tree.entries.len(), 1);
    assert_eq!(tree.entries[0].name, "src");

    // 6. Anchored snap with a message.
    let resp = app
        .clone()
        .oneshot(post_json(
            &format!("/v1/changes/{change_id}/snap"),
            json!({ "message": "wrote main.rs", "author": "agent:claude" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let snap: SnapResp = json_body(resp).await;
    assert_eq!(snap.outcome, "snapped");
    let snap_hash = snap.snapshot.as_ref().unwrap().hash.clone();

    // 7. GET that snapshot back.
    let resp = app
        .clone()
        .oneshot(get(&format!("/v1/snapshots/{snap_hash}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let snap_view: SnapshotView = json_body(resp).await;
    assert_eq!(snap_view.message.as_deref(), Some("wrote main.rs"));
    assert_eq!(snap_view.author, "agent:claude");

    // 8. Op log shows our actions.
    let resp = app.clone().oneshot(get("/v1/oplog")).await.unwrap();
    let ops: Vec<OpView> = json_body(resp).await;
    let kinds: Vec<&str> = ops.iter().map(|o| o.kind.as_str()).collect();
    assert_eq!(kinds, vec!["ChangeNew", "Snap", "Snap"]);

    // 9. Undo the anchored snap.
    let resp = app
        .clone()
        .oneshot(post_json("/v1/oplog/undo", json!({})))
        .await
        .unwrap();
    let undo: UndoResp = json_body(resp).await;
    let kind = undo.undone_kind.as_deref().unwrap_or_default();
    assert!(kind.starts_with("Snap"), "expected Snap, got {kind:?}");
    assert!(kind.contains("wrote main.rs"), "expected message, got {kind:?}");

    // 10. Op log now has a recorded Undo.
    let resp = app.clone().oneshot(get("/v1/oplog")).await.unwrap();
    let ops: Vec<OpView> = json_body(resp).await;
    let kinds: Vec<&str> = ops.iter().map(|o| o.kind.as_str()).collect();
    assert_eq!(kinds, vec!["ChangeNew", "Snap", "Snap", "Undo"]);
}

#[tokio::test]
async fn patch_then_delete_then_listing_is_empty() {
    let (app, _dir) = fixture();

    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/changes",
            json!({ "description": "x" }),
        ))
        .await
        .unwrap();
    let change: ChangeView = json_body(resp).await;
    let id = change.id;

    // PATCH then DELETE.
    let _ = app
        .clone()
        .oneshot(patch_bytes(
            &format!("/v1/changes/{id}/tree/junk.txt"),
            b"goodbye".to_vec(),
        ))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(delete(&format!("/v1/changes/{id}/tree/junk.txt")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Root tree is empty.
    let resp = app
        .clone()
        .oneshot(get(&format!("/v1/changes/{id}/tree")))
        .await
        .unwrap();
    let tree: TreeView = json_body(resp).await;
    assert!(tree.entries.is_empty());
}

#[tokio::test]
async fn unknown_change_returns_404() {
    let (app, _dir) = fixture();
    let resp = app
        .clone()
        .oneshot(get("/v1/changes/01NONEXISTENT"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_hash_returns_400() {
    let (app, _dir) = fixture();
    let resp = app
        .clone()
        .oneshot(get("/v1/snapshots/not-hex"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn patch_traversing_a_file_returns_400() {
    let (app, _dir) = fixture();
    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/changes",
            json!({ "description": "x" }),
        ))
        .await
        .unwrap();
    let change: ChangeView = json_body(resp).await;
    let id = change.id;

    // Create a file, then try to write a child under it — illegal.
    let _ = app
        .clone()
        .oneshot(patch_bytes(
            &format!("/v1/changes/{id}/tree/a"),
            b"x".to_vec(),
        ))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(patch_bytes(
            &format!("/v1/changes/{id}/tree/a/b"),
            b"y".to_vec(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn two_patches_show_up_as_three_ops_total() {
    // ChangeNew + Snap + Snap. Verifies that PATCH always creates a Snap
    // op, not a custom kind, so undo / op log are uniform.
    let (app, _dir) = fixture();
    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/changes",
            json!({ "description": "x" }),
        ))
        .await
        .unwrap();
    let id: ChangeView = json_body(resp).await;
    let id = id.id;
    let _ = app
        .clone()
        .oneshot(patch_bytes(
            &format!("/v1/changes/{id}/tree/a.txt"),
            b"1".to_vec(),
        ))
        .await
        .unwrap();
    let _ = app
        .clone()
        .oneshot(patch_bytes(
            &format!("/v1/changes/{id}/tree/b.txt"),
            b"2".to_vec(),
        ))
        .await
        .unwrap();

    let ops: Vec<OpView> = json_body(app.clone().oneshot(get("/v1/oplog")).await.unwrap()).await;
    assert_eq!(ops.len(), 3);
    assert_eq!(ops[0].kind, "ChangeNew");
    assert_eq!(ops[1].kind, "Snap");
    assert_eq!(ops[2].kind, "Snap");
}

#[tokio::test]
async fn snap_with_unchanged_tree_returns_unchanged() {
    let (app, _dir) = fixture();
    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/changes",
            json!({ "description": "x" }),
        ))
        .await
        .unwrap();
    let id: ChangeView = json_body(resp).await;
    let id = id.id;

    // Snap without writing anything, no message → unchanged.
    let resp = app
        .clone()
        .oneshot(post_json(
            &format!("/v1/changes/{id}/snap"),
            json!({}),
        ))
        .await
        .unwrap();
    let snap: SnapResp = json_body(resp).await;
    assert_eq!(snap.outcome, "unchanged");
}
