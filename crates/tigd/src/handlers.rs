//! Request handlers.
//!
//! Each is a thin shim: parse params, take the oplog lock if needed,
//! call into a tig-fs or tig-store engine function, convert the result
//! to a DTO. Business logic lives in the engine — handlers are wiring.
//!
//! Naming: every handler that mutates state takes the oplog lock and
//! holds it for the duration of its critical section. Reads that don't
//! need the lock skip it entirely.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bytes::Bytes;
use serde::Deserialize;
use tig_core::{
    can_mutate, can_see, Blob, Change, ChangeId, Encodable, Hash, ObjectKind, PrincipalId,
    Sealed, Snapshot, Tree, VisLabel,
};
use tig_fs::{
    delete_at_path, list_tree, lookup_entry, read_blob_at_path, snap_change_directly,
    write_blob_at_path, SnapOptions, SnapOutcome,
};
use tig_protocol::{
    ChangeView, CreateChangeReq, ErrorResp, HealthView, OpView, SealedView, SnapReq, SnapResp,
    SnapshotView, TransitionReq, TreeView, UndoReq, UndoResp,
};
use tig_store::{
    undo_once, OpInProgress, OpKind, RefSnapshot,
};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Header the daemon honours as the caller's identity claim. Trust-by-
/// name: we don't verify a signature in this milestone (see ARCHITECTURE.md
/// §8 + the milestone scoping conversation). Future: require a signed
/// challenge instead.
pub const PRINCIPAL_HEADER: &str = "x-tig-principal";

fn default_actor() -> PrincipalId {
    PrincipalId::local("tigd")
}

/// Extract the caller's claimed principal. Missing or empty header →
/// the daemon's own ambient principal (`local:tigd`). This means "no
/// auth" mode behaves as if every call were issued by the daemon itself
/// — read everything tigd authored, mutate it freely. Opting *into* a
/// different identity is the explicit act of sending the header.
fn caller_from(headers: &HeaderMap) -> PrincipalId {
    headers
        .get(PRINCIPAL_HEADER)
        .and_then(|h| h.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| PrincipalId(s.to_string()))
        .unwrap_or_else(default_actor)
}

/// Look up a change and apply the read-visibility check in one step.
/// Returns 404 (not 403) for invisible changes so the daemon doesn't
/// leak existence to callers without access — this is the same
/// behaviour the architecture spec describes in §4.2.
fn load_visible_change(
    state: &AppState,
    id: &ChangeId,
    caller: &PrincipalId,
) -> ApiResult<Change> {
    let change = state
        .repo
        .get_change(id)
        .map_err(|_| ApiError::NotFound(format!("change {}", id.0)))?;
    if !can_see(&change.visibility, &change.author, Some(caller)) {
        return Err(ApiError::NotFound(format!("change {}", id.0)));
    }
    Ok(change)
}

/// Stricter check for mutating endpoints. Returns 409 when the change
/// is *visible* but not mutable (someone else's public change), and 404
/// when even the existence is hidden.
fn load_mutable_change(
    state: &AppState,
    id: &ChangeId,
    caller: &PrincipalId,
) -> ApiResult<Change> {
    let change = load_visible_change(state, id, caller)?;
    if !can_mutate(&change.author, Some(caller)) {
        return Err(ApiError::Conflict(format!(
            "change {} is owned by {}; only the author can mutate it",
            id.0, change.author
        )));
    }
    Ok(change)
}

/// Build the set of snapshot hashes reachable from any change visible
/// to `caller`. Used to gate raw snapshot fetches so a leaked hash
/// can't be used to recover bytes from a hidden draft.
fn visible_snapshot_set(
    state: &AppState,
    caller: &PrincipalId,
) -> ApiResult<std::collections::HashSet<Hash>> {
    use tig_store::RefStore;
    let mut out = std::collections::HashSet::new();
    for id in state.repo.refs().list_changes()? {
        let change = state.repo.get_change(&id)?;
        if !can_see(&change.visibility, &change.author, Some(caller)) {
            continue;
        }
        for h in &change.history {
            out.insert(*h);
        }
    }
    Ok(out)
}

fn parse_change_id(s: &str) -> ApiResult<ChangeId> {
    if s.is_empty() {
        return Err(ApiError::BadRequest("empty change id".into()));
    }
    Ok(ChangeId(s.to_string()))
}

fn parse_hash(s: &str) -> ApiResult<Hash> {
    Hash::from_hex(s).map_err(|e| ApiError::BadRequest(format!("invalid hash: {e}")))
}

// --- health --------------------------------------------------------------

pub async fn health() -> Json<HealthView> {
    Json(HealthView { ok: true, version: DAEMON_VERSION.to_string() })
}

// --- changes -------------------------------------------------------------

pub async fn list_changes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<ChangeView>>> {
    use tig_store::RefStore;
    let caller = caller_from(&headers);
    let mut out = Vec::new();
    for id in state.repo.refs().list_changes()? {
        let c = state.repo.get_change(&id)?;
        if !can_see(&c.visibility, &c.author, Some(&caller)) {
            continue;
        }
        out.push(ChangeView::from_core(&c));
    }
    Ok(Json(out))
}

pub async fn get_change(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ChangeView>> {
    let id = parse_change_id(&id)?;
    let caller = caller_from(&headers);
    let change = load_visible_change(&state, &id, &caller)?;
    Ok(Json(ChangeView::from_core(&change)))
}

pub async fn create_change(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateChangeReq>,
) -> ApiResult<(StatusCode, Json<ChangeView>)> {
    let caller = caller_from(&headers);

    // Determine the parent snapshot for the new change.
    let parent_snap = if let Some(from_str) = &req.from_change {
        let parent_id = parse_change_id(from_str)?;
        // The parent must also be visible to the caller; otherwise
        // we'd let them branch off a hidden draft they don't know about.
        let parent = load_visible_change(&state, &parent_id, &caller)?;
        parent.current
    } else {
        // Empty tree → empty bootstrap snapshot. This produces a stable
        // hash, so multiple calls without `from_change` all branch from
        // the same starting point.
        let tree_h = state
            .repo
            .put(&Tree::new().encode().map_err(ApiError::from)?)?;
        let snap = Snapshot {
            parents: vec![],
            tree: tree_h,
            author: caller.clone(),
            timestamp_ns: Snapshot::current_timestamp_ns(),
            message: Some("(empty)".into()),
            op_id: None,
        };
        state
            .repo
            .put(&snap.encode().map_err(ApiError::from)?)?
    };

    let mut change = Change::new(req.description.clone(), caller.clone(), parent_snap);
    if let Some(vis_str) = req.visibility.as_deref() {
        change.visibility = parse_vis_label(vis_str)?;
    }
    if let Some(state_str) = req.state.as_deref() {
        change.state = parse_change_state(state_str)?;
    }
    state.repo.put_change(&change)?;

    // Record the op.
    let mut log = state.log.lock().await;
    log.append(OpInProgress {
        actor: caller.clone(),
        kind: OpKind::ChangeNew {
            change_id: change.id.clone(),
            description: req.description.clone(),
        },
        before: vec![RefSnapshot::Change {
            id: change.id.clone(),
            value: None,
        }],
        after: vec![RefSnapshot::Change {
            id: change.id.clone(),
            value: Some(change.clone()),
        }],
    })?;

    Ok((StatusCode::CREATED, Json(ChangeView::from_core(&change))))
}

fn parse_vis_label(s: &str) -> ApiResult<VisLabel> {
    match s {
        "public" => Ok(VisLabel::Public),
        "private" => Ok(VisLabel::Private),
        other => Err(ApiError::BadRequest(format!(
            "unknown visibility {other:?} (try \"public\" or \"private\")"
        ))),
    }
}

fn parse_change_state(s: &str) -> ApiResult<tig_core::ChangeState> {
    use tig_core::ChangeState;
    match s.to_lowercase().as_str() {
        "working" => Ok(ChangeState::Working),
        "draft" => Ok(ChangeState::Draft),
        "review" => Ok(ChangeState::Review),
        "landed" => Ok(ChangeState::Landed),
        "abandoned" => Ok(ChangeState::Abandoned),
        other => Err(ApiError::BadRequest(format!("unknown state {other:?}"))),
    }
}

// --- tree ----------------------------------------------------------------

pub async fn get_tree_root(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<TreeView>> {
    let id = parse_change_id(&id)?;
    let caller = caller_from(&headers);
    let change = load_visible_change(&state, &id, &caller)?;
    let snap = Snapshot::decode(&state.repo.get(&change.current)?)
        .map_err(ApiError::from)?;
    let tree = Tree::decode(&state.repo.get(&snap.tree)?).map_err(ApiError::from)?;
    Ok(Json(TreeView::from_core(Some(snap.tree), &tree)))
}

/// `GET /v1/changes/{id}/tree/{*path}`:
///   - If `path` resolves to a file → response body is the raw bytes,
///     `Content-Type: application/octet-stream`.
///   - If `path` resolves to a directory → response is JSON
///     `TreeView` listing.
pub async fn get_tree_path(
    State(state): State<Arc<AppState>>,
    Path((id, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    use tig_core::EntryKind;

    let id = parse_change_id(&id)?;
    let caller = caller_from(&headers);
    let change = load_visible_change(&state, &id, &caller)?;
    let snap = Snapshot::decode(&state.repo.get(&change.current)?)
        .map_err(ApiError::from)?;

    let parts = path_parts(&path)?;
    let entry = lookup_entry(&state.repo, &snap.tree, &parts).map_err(ApiError::from)?;

    match entry.kind {
        EntryKind::File => {
            let bytes = read_blob_at_path(&state.repo, snap.tree, &path)?;
            Ok((
                StatusCode::OK,
                [
                    (axum::http::header::CONTENT_TYPE, "application/octet-stream"),
                    (axum::http::header::ETAG, &format!("\"{}\"", entry.target.to_hex())),
                ],
                bytes,
            )
                .into_response())
        }
        EntryKind::Tree => {
            let t = list_tree(&state.repo, snap.tree, &path)?;
            Ok(Json(TreeView::from_core(Some(entry.target), &t)).into_response())
        }
        EntryKind::Sealed => {
            // Sealed entries are returned as JSON so the client can
            // decrypt locally. The daemon never holds principal secrets
            // and never sees the plaintext.
            let sealed = Sealed::decode(&state.repo.get(&entry.target)?)
                .map_err(ApiError::from)?;
            Ok((
                StatusCode::OK,
                [(
                    axum::http::header::CONTENT_TYPE,
                    "application/vnd.tig.sealed+json",
                )],
                Json(SealedView::from_core(&sealed)),
            )
                .into_response())
        }
        other => Err(ApiError::BadRequest(format!(
            "path {path:?} is a {:?}; GET only supports File, Tree, and Sealed",
            other
        ))),
    }
}

pub async fn patch_tree_path(
    State(state): State<Arc<AppState>>,
    Path((id, path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<ChangeView>> {
    let id = parse_change_id(&id)?;
    let caller = caller_from(&headers);
    let change = load_mutable_change(&state, &id, &caller)?;
    let snap = Snapshot::decode(&state.repo.get(&change.current)?)
        .map_err(ApiError::from)?;

    let new_tree = write_blob_at_path(&state.repo, snap.tree, &path, body.to_vec())?;
    let mut log = state.log.lock().await;
    let outcome = snap_change_directly(
        &state.repo,
        &mut log,
        &id,
        new_tree,
        &SnapOptions {
            author: caller.clone(),
            message: None,
            ..Default::default()
        },
    )?;
    Ok(Json(ChangeView::from_core(outcome.change())))
}

pub async fn delete_tree_path(
    State(state): State<Arc<AppState>>,
    Path((id, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<ChangeView>> {
    let id = parse_change_id(&id)?;
    let caller = caller_from(&headers);
    let change = load_mutable_change(&state, &id, &caller)?;
    let snap = Snapshot::decode(&state.repo.get(&change.current)?)
        .map_err(ApiError::from)?;

    let new_tree = delete_at_path(&state.repo, snap.tree, &path)?;
    let mut log = state.log.lock().await;
    let outcome = snap_change_directly(
        &state.repo,
        &mut log,
        &id,
        new_tree,
        &SnapOptions {
            author: caller.clone(),
            message: None,
            ..Default::default()
        },
    )?;
    Ok(Json(ChangeView::from_core(outcome.change())))
}

// --- snap ----------------------------------------------------------------

pub async fn snap_change(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<SnapReq>,
) -> ApiResult<Json<SnapResp>> {
    let id = parse_change_id(&id)?;
    let caller = caller_from(&headers);
    let change = load_mutable_change(&state, &id, &caller)?;
    let snap = Snapshot::decode(&state.repo.get(&change.current)?)
        .map_err(ApiError::from)?;

    // `author` on a snap can either echo the caller or be explicitly
    // overridden by the request (useful when an agent-on-behalf-of
    // wants to label the snap with the upstream identity).
    let author = req.author.map(PrincipalId).unwrap_or(caller);

    let mut log = state.log.lock().await;
    let outcome = snap_change_directly(
        &state.repo,
        &mut log,
        &id,
        snap.tree, // same tree → with a message this still anchors (force-via-message)
        &SnapOptions {
            author,
            message: req.message.clone(),
            force: req.force.unwrap_or(false),
            ..Default::default()
        },
    )?;

    Ok(Json(match outcome {
        SnapOutcome::Snapped { snapshot, change, .. } => {
            let s = Snapshot::decode(&state.repo.get(&snapshot).unwrap()).unwrap();
            SnapResp {
                outcome: "snapped".into(),
                change: ChangeView::from_core(&change),
                snapshot: Some(SnapshotView::from_core(snapshot, &s)),
            }
        }
        SnapOutcome::Unchanged { change } => SnapResp {
            outcome: "unchanged".into(),
            change: ChangeView::from_core(&change),
            snapshot: None,
        },
    }))
}

/// `POST /v1/changes/{id}/transition` — flip state and/or visibility.
/// The author can move freely; nobody else can.
pub async fn transition_change(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<TransitionReq>,
) -> ApiResult<Json<ChangeView>> {
    let id = parse_change_id(&id)?;
    let caller = caller_from(&headers);
    let mut change = load_mutable_change(&state, &id, &caller)?;
    let before = change.clone();

    if let Some(s) = req.state.as_deref() {
        change.state = parse_change_state(s)?;
    }
    if let Some(v) = req.visibility.as_deref() {
        change.visibility = parse_vis_label(v)?;
    }
    state.repo.put_change(&change)?;

    // Record the transition so `tig undo` can roll it back.
    let mut log = state.log.lock().await;
    log.append(OpInProgress {
        actor: caller,
        kind: OpKind::ChangeTransition {
            change_id: change.id.clone(),
            from_state: before.state,
            to_state: change.state,
            from_vis: before.visibility.clone(),
            to_vis: change.visibility.clone(),
        },
        before: vec![RefSnapshot::Change {
            id: change.id.clone(),
            value: Some(before),
        }],
        after: vec![RefSnapshot::Change {
            id: change.id.clone(),
            value: Some(change.clone()),
        }],
    })?;

    Ok(Json(ChangeView::from_core(&change)))
}

// --- snapshots -----------------------------------------------------------

pub async fn get_snapshot(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<SnapshotView>> {
    let h = parse_hash(&hash)?;
    let caller = caller_from(&headers);

    // Reachability gate: the snapshot must be reachable from at least
    // one change visible to the caller. A leaked hash from a hidden
    // draft must not let you fetch its bytes. This is O(N changes) on
    // every request; an index lands when we need it (see ARCHITECTURE.md §3).
    let visible = visible_snapshot_set(&state, &caller)?;
    if !visible.contains(&h) {
        return Err(ApiError::NotFound(format!("snapshot {}", hash)));
    }

    let raw = state.repo.get(&h)?;
    if raw.kind != ObjectKind::Snapshot {
        return Err(ApiError::BadRequest(format!(
            "object {hash} is a {}, not a snapshot",
            raw.kind.name()
        )));
    }
    let snap = Snapshot::decode(&raw).map_err(ApiError::from)?;
    Ok(Json(SnapshotView::from_core(h, &snap)))
}

// --- oplog ---------------------------------------------------------------

#[derive(Deserialize)]
pub struct OplogQuery {
    pub limit: Option<usize>,
}

pub async fn list_oplog(
    State(state): State<Arc<AppState>>,
    Query(q): Query<OplogQuery>,
) -> ApiResult<Json<Vec<OpView>>> {
    let log = state.log.lock().await;
    let mut ops = log.list()?;
    if let Some(limit) = q.limit {
        // Return the most recent `limit` ops, but in chronological order
        // (oldest first within the window).
        let total = ops.len();
        if total > limit {
            ops.drain(..total - limit);
        }
    }
    Ok(Json(ops.iter().map(OpView::from_core).collect()))
}

pub async fn undo(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UndoReq>,
) -> ApiResult<Json<UndoResp>> {
    let actor = req
        .author
        .map(|a| PrincipalId(a))
        .unwrap_or_else(default_actor);
    let mut log = state.log.lock().await;
    let outcome = undo_once(&state.repo, &mut log, &actor)?;
    Ok(Json(match outcome {
        Some(out) => UndoResp {
            undone_op_id: Some(out.undone.id.0),
            undone_kind: Some(out.undone.kind.one_line()),
            recorded_op_id: Some(out.recorded.id.0),
            message: format!("undid op#{}", out.undone.id.0),
        },
        None => UndoResp {
            undone_op_id: None,
            undone_kind: None,
            recorded_op_id: None,
            message: "nothing to undo".into(),
        },
    }))
}

// --- helpers -------------------------------------------------------------

fn path_parts(path: &str) -> ApiResult<Vec<String>> {
    let parts: Vec<String> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    if parts.is_empty() {
        return Err(ApiError::BadRequest("empty path".into()));
    }
    for p in &parts {
        if p == "." || p == ".." || p.contains('\0') {
            return Err(ApiError::BadRequest(format!("invalid path component: {p}")));
        }
    }
    Ok(parts)
}

// silence lint on unused imports we may want to reach for from tests
#[allow(unused_imports)]
use Blob as _;
#[allow(unused_imports)]
use ErrorResp as _;
