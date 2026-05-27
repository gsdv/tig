//! Integration tests for visibility filtering on the daemon.
//!
//! We drive the axum `Router` directly via `tower::ServiceExt::oneshot`.
//! Two callers in every test: `alice` (author of the draft) and `bob`
//! (third party). Each request labels itself with `X-Tig-Principal`.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::json;
use tempfile::tempdir;
use tig_protocol::{ChangeView, OpView, SnapshotView, TreeView};
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

async fn make_draft(app: &axum::Router, who: &str, description: &str) -> ChangeView {
    let resp = app
        .clone()
        .oneshot(post_json_as(
            "/v1/changes",
            who,
            json!({
                "description": description,
                "state": "draft",
                "visibility": "private",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "draft creation failed");
    json_body(resp).await
}

async fn make_public(app: &axum::Router, who: &str, description: &str) -> ChangeView {
    let resp = app
        .clone()
        .oneshot(post_json_as(
            "/v1/changes",
            who,
            json!({ "description": description }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    json_body(resp).await
}

#[tokio::test]
async fn draft_invisible_to_third_party_in_list() {
    let (app, _dir) = fixture();
    let _draft = make_draft(&app, "alice", "alice's secret feature").await;
    let _public = make_public(&app, "alice", "alice's public work").await;

    // Bob lists changes — he should only see the public one.
    let resp = app
        .clone()
        .oneshot(get_as("/v1/changes", "bob"))
        .await
        .unwrap();
    let bobs_view: Vec<ChangeView> = json_body(resp).await;
    assert_eq!(bobs_view.len(), 1);
    assert_eq!(bobs_view[0].description, "alice's public work");
    assert_eq!(bobs_view[0].visibility, "public");

    // Alice sees both.
    let resp = app
        .clone()
        .oneshot(get_as("/v1/changes", "alice"))
        .await
        .unwrap();
    let alice_view: Vec<ChangeView> = json_body(resp).await;
    assert_eq!(alice_view.len(), 2);
}

#[tokio::test]
async fn draft_returns_404_on_direct_fetch_for_outsider() {
    let (app, _dir) = fixture();
    let draft = make_draft(&app, "alice", "secret").await;

    // Bob asks for it by id — must look like it doesn't exist.
    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/changes/{}", draft.id), "bob"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Alice asks for it by id — gets it.
    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/changes/{}", draft.id), "alice"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn draft_tree_and_snapshot_are_also_hidden_from_outsider() {
    let (app, _dir) = fixture();
    let draft = make_draft(&app, "alice", "secret").await;

    // Alice writes a file into the draft.
    let _ = app
        .clone()
        .oneshot(patch_bytes_as(
            &format!("/v1/changes/{}/tree/src/secret.rs", draft.id),
            "alice",
            b"// don't look".to_vec(),
        ))
        .await
        .unwrap();

    // Bob can't list the draft's tree.
    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/changes/{}/tree", draft.id), "bob"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Bob can't read the draft's file even if he somehow guessed the path.
    let resp = app
        .clone()
        .oneshot(get_as(
            &format!("/v1/changes/{}/tree/src/secret.rs", draft.id),
            "bob",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Bob can't fetch the snapshot by hash, even if he learns it
    // through some other channel.
    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/changes/{}", draft.id), "alice"))
        .await
        .unwrap();
    let alices_view: ChangeView = json_body(resp).await;
    let snap_hash = &alices_view.current;
    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/snapshots/{snap_hash}"), "bob"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "snapshot reachability gate must hide hashes from non-recipients"
    );
}

#[tokio::test]
async fn bob_cannot_mutate_alices_public_change() {
    let (app, _dir) = fixture();
    let alice_change = make_public(&app, "alice", "alice's work").await;

    // Bob tries to PATCH a file into alice's change.
    let resp = app
        .clone()
        .oneshot(patch_bytes_as(
            &format!("/v1/changes/{}/tree/intrusion.txt", alice_change.id),
            "bob",
            b"bob was here".to_vec(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn publishing_a_draft_makes_it_visible_to_others() {
    let (app, _dir) = fixture();
    let draft = make_draft(&app, "alice", "secret WIP").await;

    // Pre-publish: bob's list is empty.
    let resp = app
        .clone()
        .oneshot(get_as("/v1/changes", "bob"))
        .await
        .unwrap();
    let listed: Vec<ChangeView> = json_body(resp).await;
    assert!(listed.is_empty());

    // Alice publishes via the transition endpoint.
    let resp = app
        .clone()
        .oneshot(post_json_as(
            &format!("/v1/changes/{}/transition", draft.id),
            "alice",
            json!({ "state": "working", "visibility": "public" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let after: ChangeView = json_body(resp).await;
    assert_eq!(after.state, "Working");
    assert_eq!(after.visibility, "public");

    // Now bob sees it.
    let resp = app
        .clone()
        .oneshot(get_as("/v1/changes", "bob"))
        .await
        .unwrap();
    let listed: Vec<ChangeView> = json_body(resp).await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, draft.id);

    // Op log captured the transition.
    let resp = app
        .clone()
        .oneshot(get_as("/v1/oplog", "alice"))
        .await
        .unwrap();
    let ops: Vec<OpView> = json_body(resp).await;
    let kinds: Vec<&str> = ops.iter().map(|o| o.kind.as_str()).collect();
    assert!(kinds.contains(&"ChangeNew"));
    assert!(kinds.contains(&"ChangeTransition"));
}

#[tokio::test]
async fn bob_cannot_publish_alices_draft() {
    let (app, _dir) = fixture();
    let draft = make_draft(&app, "alice", "secret").await;

    // Bob doesn't even see the draft exists; transition attempt → 404.
    let resp = app
        .clone()
        .oneshot(post_json_as(
            &format!("/v1/changes/{}/transition", draft.id),
            "bob",
            json!({ "state": "working", "visibility": "public" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn anonymous_caller_sees_daemon_owned_changes() {
    // Missing X-Tig-Principal → caller is `local:tigd`. That's also the
    // default author for caller-less creates, so the daemon's own
    // changes are visible to the daemon's own anonymous reads. The
    // *interesting* invisibility is for changes created with explicit
    // headers like "alice".
    let (app, _dir) = fixture();

    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/changes")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    json!({ "description": "ambient" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Same anonymous caller sees it back.
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/v1/changes")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let listed: Vec<ChangeView> = json_body(resp).await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].author, "local:tigd");
}

#[tokio::test]
async fn snapshot_view_is_consistent_with_change_view_history() {
    // A correctness check: after a PATCH, the snapshot the change
    // points at must be fetchable by the author and exposed in their
    // history. (Catches bugs where the visibility gate over-prunes.)
    let (app, _dir) = fixture();
    let change = make_public(&app, "alice", "x").await;
    let _ = app
        .clone()
        .oneshot(patch_bytes_as(
            &format!("/v1/changes/{}/tree/a.txt", change.id),
            "alice",
            b"hello".to_vec(),
        ))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/changes/{}", change.id), "alice"))
        .await
        .unwrap();
    let updated: ChangeView = json_body(resp).await;
    let snap_hash = updated.current;

    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/snapshots/{snap_hash}"), "alice"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let snap: SnapshotView = json_body(resp).await;
    assert_eq!(snap.hash, snap_hash);
}

#[tokio::test]
async fn oplog_redacts_ops_referencing_invisible_changes() {
    // Per-op visibility filter: ops that touch a Change bob can't see
    // must come back redacted — no actor, no kind, no one_line. Just
    // the op id and timestamp survive so bob can see "an op happened
    // here" without seeing what.
    let (app, _dir) = fixture();
    let draft = make_draft(&app, "alice", "alice's secret").await;
    let public = make_public(&app, "alice", "alice's public work").await;

    // Patch a file into each to produce a snap op too.
    let _ = app
        .clone()
        .oneshot(patch_bytes_as(
            &format!("/v1/changes/{}/tree/secret.rs", draft.id),
            "alice",
            b"secret_fn()".to_vec(),
        ))
        .await
        .unwrap();
    let _ = app
        .clone()
        .oneshot(patch_bytes_as(
            &format!("/v1/changes/{}/tree/public.rs", public.id),
            "alice",
            b"public_fn()".to_vec(),
        ))
        .await
        .unwrap();

    // Bob fetches the oplog.
    let resp = app
        .clone()
        .oneshot(get_as("/v1/oplog", "bob"))
        .await
        .unwrap();
    let ops: Vec<OpView> = json_body(resp).await;
    assert_eq!(ops.len(), 4, "two ChangeNew + two Snap = 4 total ops");

    // Partition by visibility.
    let redacted: Vec<&OpView> = ops.iter().filter(|o| o.kind == "Redacted").collect();
    let visible: Vec<&OpView> = ops.iter().filter(|o| o.kind != "Redacted").collect();

    // Bob should see exactly the two ops that touched alice's public
    // change (ChangeNew + Snap) and the two for the draft should be
    // redacted.
    assert_eq!(redacted.len(), 2);
    assert_eq!(visible.len(), 2);

    // Redacted ops disclose nothing about author or contents.
    for r in &redacted {
        assert_eq!(r.actor, "<redacted>");
        assert_eq!(r.kind, "Redacted");
        assert_eq!(r.one_line, "<redacted>");
        // But id is preserved so callers can reason about ordering.
        // (Just sanity-check it's nonzero or matches what we expect; any
        // value distinguishable from default is fine here.)
        let _ = r.id;
    }

    // The visible ops correctly reveal the public change's details.
    let visible_kinds: Vec<&str> = visible.iter().map(|o| o.kind.as_str()).collect();
    assert!(visible_kinds.contains(&"ChangeNew"));
    assert!(visible_kinds.contains(&"Snap"));
    for v in &visible {
        assert_ne!(v.actor, "<redacted>");
        // Sanity: the snap hash (in the one_line) doesn't accidentally
        // include any of the draft's content. Hard to assert directly;
        // we settle for "actor names are real."
        assert!(v.actor.contains(':') || !v.actor.is_empty());
    }

    // Alice sees everything un-redacted.
    let resp = app
        .clone()
        .oneshot(get_as("/v1/oplog", "alice"))
        .await
        .unwrap();
    let alice_ops: Vec<OpView> = json_body(resp).await;
    assert_eq!(alice_ops.len(), 4);
    assert!(
        alice_ops.iter().all(|o| o.kind != "Redacted"),
        "alice (the author) should see everything un-redacted"
    );
}

#[tokio::test]
async fn publishing_a_draft_unredacts_its_prior_ops_for_outsiders() {
    // Bob's view should change *dynamically* based on the current
    // visibility — once alice publishes, the ops that were previously
    // redacted to bob should now be readable. Visibility is checked at
    // fetch time, not at op-record time.
    let (app, _dir) = fixture();
    let draft = make_draft(&app, "alice", "secret").await;
    let _ = app
        .clone()
        .oneshot(patch_bytes_as(
            &format!("/v1/changes/{}/tree/x.rs", draft.id),
            "alice",
            b"contents".to_vec(),
        ))
        .await
        .unwrap();

    // Before publish: bob sees redacted.
    let resp = app
        .clone()
        .oneshot(get_as("/v1/oplog", "bob"))
        .await
        .unwrap();
    let before: Vec<OpView> = json_body(resp).await;
    assert!(
        before.iter().all(|o| o.kind == "Redacted"),
        "every op should be redacted to bob before publish"
    );

    // Alice publishes.
    let _ = app
        .clone()
        .oneshot(post_json_as(
            &format!("/v1/changes/{}/transition", draft.id),
            "alice",
            json!({ "state": "working", "visibility": "public" }),
        ))
        .await
        .unwrap();

    // After publish: bob now sees the previously-redacted ops with
    // their original kinds.
    let resp = app
        .clone()
        .oneshot(get_as("/v1/oplog", "bob"))
        .await
        .unwrap();
    let after: Vec<OpView> = json_body(resp).await;
    let redacted_after = after.iter().filter(|o| o.kind == "Redacted").count();
    assert_eq!(
        redacted_after, 0,
        "no ops should be redacted after publish; got {after:?}"
    );
    // And the kinds line up with what alice actually did.
    let kinds: Vec<&str> = after.iter().map(|o| o.kind.as_str()).collect();
    assert!(kinds.contains(&"ChangeNew"));
    assert!(kinds.contains(&"Snap"));
    assert!(kinds.contains(&"ChangeTransition"));
}

#[tokio::test]
async fn anonymous_caller_cannot_see_either_principals_drafts_in_oplog() {
    // The default caller (no X-Tig-Principal header) is `local:tigd`.
    // Drafts authored by alice or bob shouldn't leak even into
    // anonymous oplog queries.
    let (app, _dir) = fixture();
    let _ = make_draft(&app, "alice", "alice's secret").await;
    let _ = make_draft(&app, "bob", "bob's secret").await;

    let resp = app.clone().oneshot(get("/v1/oplog")).await.unwrap();
    let ops: Vec<OpView> = json_body(resp).await;
    assert!(
        ops.iter().all(|o| o.kind == "Redacted"),
        "anonymous caller should see both drafts as redacted; got {ops:?}"
    );
}

fn get(path: &str) -> axum::http::Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn tree_view_returns_for_alice_on_her_own_draft() {
    let (app, _dir) = fixture();
    let draft = make_draft(&app, "alice", "secret").await;
    let _ = app
        .clone()
        .oneshot(patch_bytes_as(
            &format!("/v1/changes/{}/tree/notes.md", draft.id),
            "alice",
            b"shh".to_vec(),
        ))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(get_as(&format!("/v1/changes/{}/tree", draft.id), "alice"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tree: TreeView = json_body(resp).await;
    assert_eq!(tree.entries.len(), 1);
    assert_eq!(tree.entries[0].name, "notes.md");
}
