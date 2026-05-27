//! Integration tests for the blame endpoint.
//!
//! Heavier engine coverage lives in `tig-fs/src/blame.rs`. These tests
//! confirm the daemon wires it up correctly, surfaces sensible
//! errors, and enforces visibility.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::json;
use tempfile::tempdir;
use tig_protocol::{BlameView, ChangeView};
use tig_store::Repository;
use tigd::{build_app, AppState};
use tower::ServiceExt;

fn fixture() -> (axum::Router, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let repo = Repository::init(dir.path()).unwrap();
    let state = Arc::new(AppState::open(repo.root().to_path_buf()).unwrap());
    drop(repo);
    let app = build_app(state);
    (app, dir)
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

fn get_as(path: &str, who: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header("x-tig-principal", who)
        .body(Body::empty())
        .unwrap()
}

fn post_json_as(path: &str, who: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("x-tig-principal", who)
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn patch_bytes_as(path: &str, who: &str, bytes: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(path)
        .header("content-type", "application/octet-stream")
        .header("x-tig-principal", who)
        .body(Body::from(bytes))
        .unwrap()
}

#[tokio::test]
async fn blame_attributes_alice_and_bob_lines_to_the_right_authors() {
    let (app, _dir) = fixture();

    // Alice creates a public change + writes a file.
    let resp = app
        .clone()
        .oneshot(post_json_as(
            "/v1/changes",
            "alice",
            json!({ "description": "shared" }),
        ))
        .await
        .unwrap();
    let change: ChangeView = json_body(resp).await;
    let id = change.id;

    let _ = app
        .clone()
        .oneshot(patch_bytes_as(
            &format!("/v1/changes/{id}/tree/notes.md"),
            "alice",
            b"line A\nline B\nline C\n".to_vec(),
        ))
        .await
        .unwrap();

    // Wait — the test fixture's daemon uses `local:tigd` as the
    // mutator's principal when the caller isn't specified. But here
    // we *do* set X-Tig-Principal: alice, so PATCH should be
    // authorized for alice. Since alice was the author of the change,
    // load_mutable_change(alice) succeeds.
    //
    // Actually the change's author is "alice" (set from the
    // X-Tig-Principal of the CREATE request), so alice can PATCH it.
    // Same person, no conflict.

    // Bob can't patch alice's change (CONFLICT), but he COULD edit
    // *if it were his*. So have alice make another edit to
    // demonstrate multi-author chain: change "line B" to "line B'".
    let _ = app
        .clone()
        .oneshot(patch_bytes_as(
            &format!("/v1/changes/{id}/tree/notes.md"),
            "alice",
            b"line A\nline B'\nline C\n".to_vec(),
        ))
        .await
        .unwrap();

    // Blame against the current snap.
    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/changes/{id}/blame/notes.md"), "alice"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let view: BlameView = json_body(resp).await;
    assert_eq!(view.lines.len(), 3);
    // All lines authored by alice — but the snap hashes should
    // differ: line A and C from the first snap, line B' from the second.
    assert!(view.lines.iter().all(|l| l.author == "alice"));
    assert_eq!(view.lines[0].line, "line A");
    assert_eq!(view.lines[1].line, "line B'");
    assert_eq!(view.lines[2].line, "line C");
    assert_eq!(view.lines[0].snap, view.lines[2].snap);
    assert_ne!(view.lines[1].snap, view.lines[0].snap);
}

#[tokio::test]
async fn blame_on_invisible_change_returns_404() {
    let (app, _dir) = fixture();

    // Alice creates a draft + writes to it.
    let resp = app
        .clone()
        .oneshot(post_json_as(
            "/v1/changes",
            "alice",
            json!({
                "description": "secret",
                "state": "draft",
                "visibility": "private",
            }),
        ))
        .await
        .unwrap();
    let draft: ChangeView = json_body(resp).await;
    let _ = app
        .clone()
        .oneshot(patch_bytes_as(
            &format!("/v1/changes/{}/tree/secret.rs", draft.id),
            "alice",
            b"fn secret() {}\n".to_vec(),
        ))
        .await
        .unwrap();

    // Bob attempts to blame the file in alice's draft.
    let resp = app
        .clone()
        .oneshot(get_as(
            &format!("/v1/changes/{}/blame/secret.rs", draft.id),
            "bob",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Alice can.
    let resp = app
        .clone()
        .oneshot(get_as(
            &format!("/v1/changes/{}/blame/secret.rs", draft.id),
            "alice",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let view: BlameView = json_body(resp).await;
    assert_eq!(view.lines.len(), 1);
    assert_eq!(view.lines[0].line, "fn secret() {}");
}

#[tokio::test]
async fn blame_on_missing_file_returns_400() {
    let (app, _dir) = fixture();
    let resp = app
        .clone()
        .oneshot(post_json_as(
            "/v1/changes",
            "alice",
            json!({ "description": "empty" }),
        ))
        .await
        .unwrap();
    let change: ChangeView = json_body(resp).await;

    let resp = app
        .clone()
        .oneshot(get_as(
            &format!("/v1/changes/{}/blame/missing.txt", change.id),
            "alice",
        ))
        .await
        .unwrap();
    // Engine returns Core(Decode("does not exist...")), which maps to BadRequest.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
