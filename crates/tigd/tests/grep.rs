//! Integration tests for the grep endpoint.
//!
//! Heavy engine coverage lives in `tig-fs/src/grep.rs`. These tests
//! confirm the daemon wires it up correctly, parses query params,
//! and enforces visibility.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::json;
use tempfile::tempdir;
use tig_protocol::{ChangeView, GrepView};
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

async fn create_change_with_files(
    app: &axum::Router,
    who: &str,
    extra: serde_json::Value,
    files: &[(&str, &[u8])],
) -> String {
    let resp = app
        .clone()
        .oneshot(post_json_as("/v1/changes", who, extra))
        .await
        .unwrap();
    let change: ChangeView = json_body(resp).await;
    for (path, bytes) in files {
        let resp = app
            .clone()
            .oneshot(patch_bytes_as(
                &format!("/v1/changes/{}/tree/{path}", change.id),
                who,
                bytes.to_vec(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PATCH failed for {path}: {:?}",
            resp.status()
        );
    }
    change.id
}

#[tokio::test]
async fn grep_returns_matches_with_path_line_and_text() {
    let (app, _dir) = fixture();
    let id = create_change_with_files(
        &app,
        "alice",
        json!({"description": "demo"}),
        &[
            ("README.md", b"hello world\nfoobar\n"),
            ("src/main.rs", b"fn main() {\n    println!(\"hello\");\n}\n"),
        ],
    )
    .await;

    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/changes/{id}/grep?q=hello"), "alice"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let view: GrepView = json_body(resp).await;
    let mut hits: Vec<(String, usize, String)> = view
        .matches
        .into_iter()
        .map(|m| (m.path, m.line_number, m.line))
        .collect();
    hits.sort();
    assert_eq!(
        hits,
        vec![
            ("README.md".into(), 1, "hello world".into()),
            ("src/main.rs".into(), 2, "    println!(\"hello\");".into(),),
        ]
    );
    assert_eq!(view.at.len(), 64);
}

#[tokio::test]
async fn grep_regex_flag_compiles_pattern() {
    let (app, _dir) = fixture();
    let id = create_change_with_files(
        &app,
        "alice",
        json!({"description": "demo"}),
        &[("a.rs", b"fn foo() {}\nfn bar() {}\nstruct X;\n")],
    )
    .await;

    // Match function definitions.
    let resp = app
        .clone()
        .oneshot(get_as(
            &format!("/v1/changes/{id}/grep?q=^fn%20%5Cw%2B%5C(&regex=true"),
            "alice",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let view: GrepView = json_body(resp).await;
    assert_eq!(view.matches.len(), 2);
    assert!(view.matches.iter().all(|m| m.path == "a.rs"));
}

#[tokio::test]
async fn grep_ignore_case_matches_both() {
    let (app, _dir) = fixture();
    let id = create_change_with_files(
        &app,
        "alice",
        json!({"description": "demo"}),
        &[("notes.txt", b"hello\nHELLO\nworld\n")],
    )
    .await;

    let resp = app
        .clone()
        .oneshot(get_as(
            &format!("/v1/changes/{id}/grep?q=hello&ignore_case=true"),
            "alice",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let view: GrepView = json_body(resp).await;
    assert_eq!(view.matches.len(), 2);
}

#[tokio::test]
async fn grep_path_filter_scopes_search() {
    let (app, _dir) = fixture();
    let id = create_change_with_files(
        &app,
        "alice",
        json!({"description": "demo"}),
        &[
            ("README.md", b"hello world\n"),
            ("src/main.rs", b"fn main() { /* hello */ }\n"),
        ],
    )
    .await;

    // `paths` is a comma-separated string on the wire (axum's
    // `Query<T>` via `serde_urlencoded` doesn't decode `Vec<T>`).
    let resp = app
        .clone()
        .oneshot(get_as(
            &format!("/v1/changes/{id}/grep?q=hello&paths=src%2F"),
            "alice",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let view: GrepView = json_body(resp).await;
    assert_eq!(view.matches.len(), 1);
    assert_eq!(view.matches[0].path, "src/main.rs");
}

#[tokio::test]
async fn grep_on_invisible_change_returns_404() {
    let (app, _dir) = fixture();
    let id = create_change_with_files(
        &app,
        "alice",
        json!({
            "description": "secret",
            "state": "draft",
            "visibility": "private",
        }),
        &[("secrets.env", b"DATABASE_URL=postgres://prod\n")],
    )
    .await;

    // Bob can't see alice's private draft.
    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/changes/{id}/grep?q=DATABASE"), "bob"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Alice can.
    let resp = app
        .clone()
        .oneshot(get_as(
            &format!("/v1/changes/{id}/grep?q=DATABASE"),
            "alice",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let view: GrepView = json_body(resp).await;
    assert_eq!(view.matches.len(), 1);
    assert_eq!(view.matches[0].line, "DATABASE_URL=postgres://prod");
}

#[tokio::test]
async fn grep_with_snap_from_invisible_change_is_refused() {
    // Reachability gate: a snap hash leaked from a hidden draft
    // mustn't grant grep access. We give bob alice's draft snap and
    // confirm the daemon refuses.
    let (app, _dir) = fixture();

    // Alice creates a private draft.
    let alice_draft = create_change_with_files(
        &app,
        "alice",
        json!({
            "description": "secret",
            "state": "draft",
            "visibility": "private",
        }),
        &[("s.txt", b"hello secret\n")],
    )
    .await;
    // Pull the snap hex out by reading alice's change.
    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/changes/{alice_draft}"), "alice"))
        .await
        .unwrap();
    let alice_view: ChangeView = json_body(resp).await;
    let alice_snap = alice_view.current;

    // Bob creates a public change so he has *some* change id of his
    // own — needed to address the grep endpoint.
    let bob_change = create_change_with_files(
        &app,
        "bob",
        json!({"description": "mine"}),
        &[("ok.txt", b"hi\n")],
    )
    .await;

    // Bob tries to grep with `?snap=<alice_snap>` — refused.
    let resp = app
        .clone()
        .oneshot(get_as(
            &format!("/v1/changes/{bob_change}/grep?q=hello&snap={alice_snap}"),
            "bob",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn grep_invalid_regex_returns_400() {
    let (app, _dir) = fixture();
    let id = create_change_with_files(
        &app,
        "alice",
        json!({"description": "demo"}),
        &[("a.txt", b"hi\n")],
    )
    .await;

    let resp = app
        .clone()
        .oneshot(get_as(
            &format!("/v1/changes/{id}/grep?q=(unclosed&regex=true"),
            "alice",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn grep_max_total_caps_results() {
    let (app, _dir) = fixture();
    let id = create_change_with_files(
        &app,
        "alice",
        json!({"description": "demo"}),
        &[("a.txt", b"x\nx\nx\nx\nx\n")],
    )
    .await;

    let resp = app
        .clone()
        .oneshot(get_as(
            &format!("/v1/changes/{id}/grep?q=x&max_total=2"),
            "alice",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let view: GrepView = json_body(resp).await;
    assert_eq!(view.matches.len(), 2);
}

#[tokio::test]
async fn grep_empty_pattern_is_400() {
    let (app, _dir) = fixture();
    let id = create_change_with_files(
        &app,
        "alice",
        json!({"description": "demo"}),
        &[("a.txt", b"hi\n")],
    )
    .await;

    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/changes/{id}/grep?q="), "alice"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
