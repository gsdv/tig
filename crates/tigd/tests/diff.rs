//! Integration tests for the diff endpoint.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::json;
use tempfile::tempdir;
use tig_protocol::{ChangeView, DiffView};
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

fn get(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

fn get_as(path: &str, who: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header("x-tig-principal", who)
        .body(Body::empty())
        .unwrap()
}

fn post_json(path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
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

fn patch_bytes(path: &str, bytes: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(path)
        .header("content-type", "application/octet-stream")
        .body(Body::from(bytes))
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
async fn diff_defaults_to_parent_of_current() {
    let (app, _dir) = fixture();
    // Create a change, write a file (auto-snap), modify it (another snap).
    let resp = app
        .clone()
        .oneshot(post_json("/v1/changes", json!({"description": "x"})))
        .await
        .unwrap();
    let change: ChangeView = json_body(resp).await;
    let id = change.id;

    let _ = app
        .clone()
        .oneshot(patch_bytes(
            &format!("/v1/changes/{id}/tree/a.txt"),
            b"line1\nline2\n".to_vec(),
        ))
        .await
        .unwrap();
    let _ = app
        .clone()
        .oneshot(patch_bytes(
            &format!("/v1/changes/{id}/tree/a.txt"),
            b"line1\nLINE2\n".to_vec(),
        ))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(get(&format!("/v1/changes/{id}/diff")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let diff: DiffView = json_body(resp).await;
    assert_eq!(diff.files.len(), 1);
    assert_eq!(diff.files[0].path, "a.txt");
    assert_eq!(diff.files[0].kind, "Modified");
    let hunks = diff.files[0]
        .hunks
        .as_ref()
        .expect("text file should have hunks");
    let any_add = hunks.iter().any(|h| {
        h.lines
            .iter()
            .any(|l| serde_json::to_string(l).unwrap().contains("\"Add\""))
    });
    let any_remove = hunks.iter().any(|h| {
        h.lines
            .iter()
            .any(|l| serde_json::to_string(l).unwrap().contains("\"Remove\""))
    });
    assert!(any_add && any_remove);
}

#[tokio::test]
async fn diff_explicit_range_uses_supplied_hashes() {
    let (app, _dir) = fixture();
    let resp = app
        .clone()
        .oneshot(post_json("/v1/changes", json!({"description": "x"})))
        .await
        .unwrap();
    let change: ChangeView = json_body(resp).await;
    let id = change.id;

    // Three snaps: v1, v2, v3.
    let _ = app
        .clone()
        .oneshot(patch_bytes(
            &format!("/v1/changes/{id}/tree/a.txt"),
            b"v1\n".to_vec(),
        ))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(get(&format!("/v1/changes/{id}")))
        .await
        .unwrap();
    let after_v1: ChangeView = json_body(resp).await;
    let v1 = after_v1.current;

    let _ = app
        .clone()
        .oneshot(patch_bytes(
            &format!("/v1/changes/{id}/tree/a.txt"),
            b"v2\n".to_vec(),
        ))
        .await
        .unwrap();
    let _ = app
        .clone()
        .oneshot(patch_bytes(
            &format!("/v1/changes/{id}/tree/a.txt"),
            b"v3\n".to_vec(),
        ))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(get(&format!("/v1/changes/{id}")))
        .await
        .unwrap();
    let after_v3: ChangeView = json_body(resp).await;
    let v3 = after_v3.current;

    // Diff v1..v3 should show v1 → v3 (skipping v2).
    let resp = app
        .clone()
        .oneshot(get(&format!("/v1/changes/{id}/diff?from={v1}&to={v3}")))
        .await
        .unwrap();
    let diff: DiffView = json_body(resp).await;
    let hunks = diff.files[0].hunks.as_ref().unwrap();
    let removed: Vec<String> = hunks
        .iter()
        .flat_map(|h| {
            h.lines.iter().filter_map(|l| match l {
                tig_protocol::HunkLineView::Remove(s) => Some(s.clone()),
                _ => None,
            })
        })
        .collect();
    let added: Vec<String> = hunks
        .iter()
        .flat_map(|h| {
            h.lines.iter().filter_map(|l| match l {
                tig_protocol::HunkLineView::Add(s) => Some(s.clone()),
                _ => None,
            })
        })
        .collect();
    assert_eq!(removed, vec!["v1"]);
    assert_eq!(added, vec!["v3"]);
}

#[tokio::test]
async fn diff_on_invisible_change_returns_404() {
    let (app, _dir) = fixture();
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
            &format!("/v1/changes/{}/tree/x.txt", draft.id),
            "alice",
            b"hush\n".to_vec(),
        ))
        .await
        .unwrap();

    // Bob can't diff alice's draft.
    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/changes/{}/diff", draft.id), "bob"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Alice can.
    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/changes/{}/diff", draft.id), "alice"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn diff_with_unreachable_hash_returns_404() {
    // If a caller supplies a `from` hash that exists in the store but
    // is not reachable from any change visible to them, the daemon
    // must refuse — otherwise it'd be a sidechannel into hidden state.

    let (app, _dir) = fixture();

    // Alice creates a draft and patches a file (produces a draft-only snap).
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
            b"top secret\n".to_vec(),
        ))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/changes/{}", draft.id), "alice"))
        .await
        .unwrap();
    let after: ChangeView = json_body(resp).await;
    let draft_snap = after.current;

    // Bob creates his own change and tries to diff using alice's hash.
    let resp = app
        .clone()
        .oneshot(post_json_as(
            "/v1/changes",
            "bob",
            json!({ "description": "bob's work" }),
        ))
        .await
        .unwrap();
    let bobs_change: ChangeView = json_body(resp).await;
    // Bob writes a file so his change has its own snap.
    let _ = app
        .clone()
        .oneshot(patch_bytes_as(
            &format!("/v1/changes/{}/tree/b.txt", bobs_change.id),
            "bob",
            b"hi\n".to_vec(),
        ))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/changes/{}", bobs_change.id), "bob"))
        .await
        .unwrap();
    let bob_now: ChangeView = json_body(resp).await;
    let bob_snap = bob_now.current;

    // Bob asks: diff bob_snap → alice's draft_snap. Daemon must 404.
    let resp = app
        .clone()
        .oneshot(get_as(
            &format!(
                "/v1/changes/{}/diff?from={}&to={}",
                bobs_change.id, bob_snap, draft_snap
            ),
            "bob",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn diff_with_no_hunks_omits_hunks() {
    let (app, _dir) = fixture();
    let resp = app
        .clone()
        .oneshot(post_json("/v1/changes", json!({"description": "x"})))
        .await
        .unwrap();
    let change: ChangeView = json_body(resp).await;
    let id = change.id;
    let _ = app
        .clone()
        .oneshot(patch_bytes(
            &format!("/v1/changes/{id}/tree/a.txt"),
            b"hi\n".to_vec(),
        ))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(get(&format!("/v1/changes/{id}/diff?no_hunks=true")))
        .await
        .unwrap();
    let diff: DiffView = json_body(resp).await;
    assert!(diff.files.iter().all(|f| f.hunks.is_none()));
}
