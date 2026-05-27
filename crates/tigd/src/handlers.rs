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
    can_mutate, can_see, Blob, Change, ChangeId, Encodable, Hash, ObjectKind, PrincipalId, Sealed,
    Snapshot, Tree, VisLabel,
};
use tig_fs::{
    blame_at, delete_at_path, diff_trees, list_tree, lookup_entry, read_blob_at_path,
    snap_change_directly, write_blob_at_path, BlameLine, ChangeKind as FsChangeKind, DiffOptions,
    FileDiff, Hunk, HunkLine, SnapOptions, SnapOutcome,
};
use tig_protocol::{
    BlameLineView, BlameQuery, BlameView, ChangeView, CreateChangeReq, DiffQuery, DiffView,
    ErrorResp, FileDiffView, GcReq, GcView, HealthView, HunkLineView, HunkView, OpView, SealedView,
    SnapReq, SnapResp, SnapshotView, TransitionReq, TreeView, UndoReq, UndoResp,
};
use tig_store::{collect_garbage, undo_once, GcOptions, Op, OpInProgress, OpKind, RefSnapshot};
use tig_vis::{peek_claims, verify_token, PrincipalStore};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Trust-by-name fallback header. Honored only when no `Authorization`
/// header is present. Real deployments configure `require_signed_tokens
/// = true` (future work) to disable this fallback entirely; for now
/// the local CLI and many tests still rely on it.
pub const PRINCIPAL_HEADER: &str = "x-tig-principal";

/// Standard HTTP Authorization header — `Bearer <signed-token>`. The
/// token format is defined by `tig_vis::tokens` (Ed25519-signed JWT-
/// style payload).
pub const AUTH_HEADER: &str = "authorization";

fn default_actor() -> PrincipalId {
    PrincipalId::local("tigd")
}

fn now_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolve the caller's principal from request headers, with this
/// precedence:
///
///   1. `Authorization: Bearer <token>` — verify the Ed25519
///      signature against the principal's pubkey from the registry.
///      Any failure (malformed, bad signature, expired, unknown
///      subject) returns `401 Unauthorized` — we never silently
///      fall through to a weaker mode when a token is *present*.
///   2. `X-Tig-Principal: <name>` — trust-by-name fallback. Honored
///      only when no Authorization header is set.
///   3. Neither header → the daemon's ambient principal
///      (`local:tigd`).
fn caller_from(state: &AppState, headers: &HeaderMap) -> ApiResult<PrincipalId> {
    if let Some(auth) = headers.get(AUTH_HEADER).and_then(|h| h.to_str().ok()) {
        let token = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "));
        let Some(token) = token else {
            return Err(ApiError::BadRequest(format!(
                "{AUTH_HEADER} header must be `Bearer <token>`"
            )));
        };
        // Peek the claims to find the right pubkey, then verify.
        let claims = peek_claims(token)
            .map_err(|e| ApiError::BadRequest(format!("malformed bearer token: {e}")))?;
        let principal_store = PrincipalStore::open(state.repo.root())
            .map_err(|e| ApiError::Internal(format!("principal store: {e}")))?;
        let principal = principal_store
            .get(&claims.sub)
            .map_err(|_| ApiError::Unauthorized(format!("unknown principal: {}", claims.sub)))?;
        let pubkey = principal.sign_pubkey().map_err(|_| {
            ApiError::Unauthorized(format!(
                "principal {:?} has no signing pubkey on file",
                claims.sub
            ))
        })?;
        let claims = verify_token(token, &pubkey, now_unix_seconds()).map_err(|e| {
            // All verify failures collapse to 401; the body carries
            // the specific reason for debugging.
            ApiError::Unauthorized(format!("token rejected: {e}"))
        })?;
        return Ok(PrincipalId(claims.sub));
    }

    Ok(headers
        .get(PRINCIPAL_HEADER)
        .and_then(|h| h.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| PrincipalId(s.to_string()))
        .unwrap_or_else(default_actor))
}

/// Look up a change and apply the read-visibility check in one step.
/// Returns 404 (not 403) for invisible changes so the daemon doesn't
/// leak existence to callers without access — this is the same
/// behaviour the architecture spec describes in §4.2.
fn load_visible_change(state: &AppState, id: &ChangeId, caller: &PrincipalId) -> ApiResult<Change> {
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
fn load_mutable_change(state: &AppState, id: &ChangeId, caller: &PrincipalId) -> ApiResult<Change> {
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

/// Pull every `ChangeId` an op references — via its `Head`, `Change`,
/// or `Workspace`-with-manifest RefSnapshots in before+after. Used by
/// `is_op_visible` to decide whether the op leaks anything the caller
/// shouldn't see.
///
/// Note: `Workspace` refs reference a change indirectly through their
/// manifest's `change_id`. A WtMake/WtDrop op for a workspace targeting
/// a hidden draft must itself be redacted, since the manifest's
/// `change_id` is otherwise leakable through the RefSnapshot.
fn referenced_change_ids(op: &Op) -> Vec<tig_core::ChangeId> {
    let mut out = Vec::new();
    for snap in op.before.iter().chain(op.after.iter()) {
        match snap {
            RefSnapshot::Change { id, .. } => out.push(id.clone()),
            RefSnapshot::Head(Some(id)) => out.push(id.clone()),
            RefSnapshot::Workspace { value: Some(m), .. } => out.push(m.change_id.clone()),
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Decide whether `caller` is allowed to see this op un-redacted.
///
/// Conservative rule: visible iff *every* change the op references is
/// visible to the caller. If any referenced change is hidden — or has
/// been deleted (NotFound) — we redact the whole op rather than risk
/// leaking through partial disclosure (the op's `before`/`after` carry
/// full Change records, snapshot hashes, descriptions).
fn is_op_visible(state: &AppState, op: &Op, caller: &PrincipalId) -> ApiResult<bool> {
    for id in referenced_change_ids(op) {
        match state.repo.get_change(&id) {
            Ok(c) => {
                if !can_see(&c.visibility, &c.author, Some(caller)) {
                    return Ok(false);
                }
            }
            // Change was deleted (e.g. an undo of ChangeNew). We can't
            // re-evaluate its visibility, so play it safe and redact.
            Err(tig_store::Error::NotFound(_)) => return Ok(false),
            Err(e) => return Err(ApiError::from(e)),
        }
    }
    Ok(true)
}

/// The redacted form an op takes on the wire when the caller isn't
/// allowed to see what it did. Preserves the op's id and timestamp —
/// callers can see "an op happened at time T" — but blanks the actor,
/// kind, and one_line summary so neither the author nor the action
/// leaks.
fn redacted_op_view(op: &Op) -> OpView {
    OpView {
        id: op.id.0,
        ts_ns: op.ts_ns,
        actor: "<redacted>".to_string(),
        kind: "Redacted".to_string(),
        one_line: "<redacted>".to_string(),
    }
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
    Json(HealthView {
        ok: true,
        version: DAEMON_VERSION.to_string(),
    })
}

// --- changes -------------------------------------------------------------

pub async fn list_changes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<ChangeView>>> {
    use tig_store::RefStore;
    let caller = caller_from(&state, &headers)?;
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
    let caller = caller_from(&state, &headers)?;
    let change = load_visible_change(&state, &id, &caller)?;
    Ok(Json(ChangeView::from_core(&change)))
}

pub async fn create_change(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateChangeReq>,
) -> ApiResult<(StatusCode, Json<ChangeView>)> {
    let _lock = state.repo.lock_for_write()?;
    let caller = caller_from(&state, &headers)?;

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
        state.repo.put(&snap.encode().map_err(ApiError::from)?)?
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
    let caller = caller_from(&state, &headers)?;
    let change = load_visible_change(&state, &id, &caller)?;
    let snap = Snapshot::decode(&state.repo.get(&change.current)?).map_err(ApiError::from)?;
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
    let caller = caller_from(&state, &headers)?;
    let change = load_visible_change(&state, &id, &caller)?;
    let snap = Snapshot::decode(&state.repo.get(&change.current)?).map_err(ApiError::from)?;

    let parts = path_parts(&path)?;
    let entry = lookup_entry(&state.repo, &snap.tree, &parts).map_err(ApiError::from)?;

    match entry.kind {
        EntryKind::File => {
            let bytes = read_blob_at_path(&state.repo, snap.tree, &path)?;
            Ok((
                StatusCode::OK,
                [
                    (axum::http::header::CONTENT_TYPE, "application/octet-stream"),
                    (
                        axum::http::header::ETAG,
                        &format!("\"{}\"", entry.target.to_hex()),
                    ),
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
            let sealed = Sealed::decode(&state.repo.get(&entry.target)?).map_err(ApiError::from)?;
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
    let _lock = state.repo.lock_for_write()?;
    let id = parse_change_id(&id)?;
    let caller = caller_from(&state, &headers)?;
    let change = load_mutable_change(&state, &id, &caller)?;
    let snap = Snapshot::decode(&state.repo.get(&change.current)?).map_err(ApiError::from)?;

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
    let _lock = state.repo.lock_for_write()?;
    let id = parse_change_id(&id)?;
    let caller = caller_from(&state, &headers)?;
    let change = load_mutable_change(&state, &id, &caller)?;
    let snap = Snapshot::decode(&state.repo.get(&change.current)?).map_err(ApiError::from)?;

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
    let _lock = state.repo.lock_for_write()?;
    let id = parse_change_id(&id)?;
    let caller = caller_from(&state, &headers)?;
    let change = load_mutable_change(&state, &id, &caller)?;
    let snap = Snapshot::decode(&state.repo.get(&change.current)?).map_err(ApiError::from)?;

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
        SnapOutcome::Snapped {
            snapshot, change, ..
        } => {
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
    let _lock = state.repo.lock_for_write()?;
    let id = parse_change_id(&id)?;
    let caller = caller_from(&state, &headers)?;
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

// --- diff ----------------------------------------------------------------

/// `GET /v1/changes/{id}/diff?from=<hash>&to=<hash>&no_hunks=<bool>&paths=...`
///
/// Defaults: `to` = change.current; `from` = the parent of the `to`
/// snapshot (empty tree if `to` has no parents). Visibility-gated:
/// callers must be able to see the change. The `from` and `to`
/// snapshots additionally must be reachable from at least one visible
/// change — same gate as the raw snapshot fetch.
pub async fn diff_change(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<DiffQuery>,
    headers: HeaderMap,
) -> ApiResult<Json<DiffView>> {
    let id = parse_change_id(&id)?;
    let caller = caller_from(&state, &headers)?;
    let change = load_visible_change(&state, &id, &caller)?;

    // Resolve `to`: arg or change.current.
    let to_snap_hash = match &q.to {
        Some(s) => parse_hash(s)?,
        None => change.current,
    };
    let to_snap = Snapshot::decode(&state.repo.get(&to_snap_hash)?).map_err(ApiError::from)?;

    // Resolve `from`: arg → parent of `to` → empty tree.
    let from_tree = match &q.from {
        Some(s) => {
            let h = parse_hash(s)?;
            let snap = Snapshot::decode(&state.repo.get(&h)?).map_err(ApiError::from)?;
            snap.tree
        }
        None => match to_snap.parents.first() {
            Some(parent_hash) => {
                let parent =
                    Snapshot::decode(&state.repo.get(parent_hash)?).map_err(ApiError::from)?;
                parent.tree
            }
            None => state
                .repo
                .put(&Tree::new().encode().map_err(ApiError::from)?)?,
        },
    };

    // Reachability: both endpoints must be reachable from a visible
    // change. If a caller could diff any tree by hash, draft contents
    // would leak through this endpoint.
    let visible = visible_snapshot_set(&state, &caller)?;
    let to_reachable = visible.contains(&to_snap_hash);
    // The `from` arg is a snapshot if provided, but we resolved it to
    // a tree hash. Re-check the original snapshot if it was supplied.
    let from_snap_visible = match &q.from {
        Some(s) => {
            let h = parse_hash(s)?;
            visible.contains(&h)
        }
        None => true, // implicit parent of a visible `to` is fine
    };
    if !to_reachable || !from_snap_visible {
        return Err(ApiError::NotFound(format!("change {}", id.0)));
    }

    let opts = DiffOptions {
        no_hunks: q.no_hunks,
        paths: q.paths.clone(),
        context_lines: 3,
    };
    let diffs = diff_trees(&state.repo, &from_tree, &to_snap.tree, &opts)?;

    let view = DiffView {
        from: from_tree.to_hex(),
        to: to_snap.tree.to_hex(),
        files: diffs.iter().map(file_diff_view).collect(),
    };
    Ok(Json(view))
}

fn file_diff_view(d: &FileDiff) -> FileDiffView {
    let (kind_name, type_changed_from, type_changed_to) = match &d.kind {
        FsChangeKind::Added => ("Added".to_string(), String::new(), String::new()),
        FsChangeKind::Removed => ("Removed".to_string(), String::new(), String::new()),
        FsChangeKind::Modified => ("Modified".to_string(), String::new(), String::new()),
        FsChangeKind::TypeChanged { from, to } => (
            "TypeChanged".to_string(),
            format!("{from:?}"),
            format!("{to:?}"),
        ),
    };
    FileDiffView {
        path: d.path.clone(),
        kind: kind_name,
        type_changed_from,
        type_changed_to,
        entry_kind: format!("{:?}", d.entry_kind),
        from_target: d.from_target.map(|h| h.to_hex()),
        to_target: d.to_target.map(|h| h.to_hex()),
        binary: d.binary,
        hunks: d
            .hunks
            .as_ref()
            .map(|hs| hs.iter().map(hunk_view).collect()),
    }
}

fn hunk_view(h: &Hunk) -> HunkView {
    HunkView {
        from_start: h.from_start,
        from_len: h.from_len,
        to_start: h.to_start,
        to_len: h.to_len,
        lines: h
            .lines
            .iter()
            .map(|l| match l {
                HunkLine::Context(s) => HunkLineView::Context(s.clone()),
                HunkLine::Add(s) => HunkLineView::Add(s.clone()),
                HunkLine::Remove(s) => HunkLineView::Remove(s.clone()),
            })
            .collect(),
    }
}

// --- blame ---------------------------------------------------------------

/// `GET /v1/changes/{id}/blame/{*path}?snap=<hash>`
///
/// Per-line authorship attribution. The change must be visible to
/// the caller. The optional `snap` query parameter pins the
/// attribution to a specific snapshot — that snap must also be
/// reachable from a visible change (same reachability gate the
/// raw-snapshot endpoint applies).
pub async fn blame_path(
    State(state): State<Arc<AppState>>,
    Path((id, path)): Path<(String, String)>,
    Query(q): Query<BlameQuery>,
    headers: HeaderMap,
) -> ApiResult<Json<BlameView>> {
    let id = parse_change_id(&id)?;
    let caller = caller_from(&state, &headers)?;
    let change = load_visible_change(&state, &id, &caller)?;

    let at_hash = match &q.snap {
        Some(s) => parse_hash(s)?,
        None => change.current,
    };
    // Reachability gate: if the caller supplied a snap that isn't
    // reachable from any change they can see, refuse. Without this,
    // a leaked snap hash could be used to blame across visibility
    // boundaries.
    let visible = visible_snapshot_set(&state, &caller)?;
    if !visible.contains(&at_hash) {
        return Err(ApiError::NotFound(format!(
            "snapshot {} not visible",
            &at_hash.to_hex()[..12]
        )));
    }

    let lines = blame_at(&state.repo, &path, &at_hash)?;
    Ok(Json(BlameView {
        path,
        at: at_hash.to_hex(),
        lines: lines.iter().map(blame_line_view).collect(),
    }))
}

fn blame_line_view(b: &BlameLine) -> BlameLineView {
    BlameLineView {
        line: b.line.clone(),
        snap: b.snap.to_hex(),
        author: b.author.0.clone(),
        timestamp_ns: b.timestamp_ns,
        message: b.message.clone(),
    }
}

// --- snapshots -----------------------------------------------------------

pub async fn get_snapshot(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<SnapshotView>> {
    let h = parse_hash(&hash)?;
    let caller = caller_from(&state, &headers)?;

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
    headers: HeaderMap,
) -> ApiResult<Json<Vec<OpView>>> {
    let caller = caller_from(&state, &headers)?;
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
    // Per-op visibility filtering: an op is shown un-redacted only if
    // the caller is allowed to see every change it references. Anything
    // else collapses to a `Redacted` stub that preserves only the op's
    // id and timestamp (callers still know *that* an op happened).
    let mut out = Vec::with_capacity(ops.len());
    for op in &ops {
        if is_op_visible(&state, op, &caller)? {
            out.push(OpView::from_core(op));
        } else {
            out.push(redacted_op_view(op));
        }
    }
    Ok(Json(out))
}

pub async fn undo(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UndoReq>,
) -> ApiResult<Json<UndoResp>> {
    let _lock = state.repo.lock_for_write()?;
    let actor = req.author.map(PrincipalId).unwrap_or_else(default_actor);
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

// --- gc ------------------------------------------------------------------

/// `POST /v1/gc` — sweep the object store.
///
/// Requires the caller to be *authenticated* via Authorization
/// (Bearer). The trust-by-name `X-Tig-Principal` header is rejected
/// here even though other endpoints accept it: GC is a destructive,
/// IO-heavy operation, and we'd rather force operators to issue a
/// signed token than let any unauth'd local caller spin the disk.
///
/// Takes the repo write lock so concurrent writers serialize behind
/// us. The oplog lock is acquired too because we read the log to
/// build the root set.
pub async fn gc(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<GcReq>>,
) -> ApiResult<Json<GcView>> {
    // Require a real signed token; reject the trust-by-name fallback.
    if headers.get(AUTH_HEADER).is_none() {
        return Err(ApiError::Unauthorized(
            "POST /v1/gc requires a signed Bearer token; trust-by-name is not accepted here".into(),
        ));
    }
    let _caller = caller_from(&state, &headers)?;

    let req = body.map(|Json(r)| r).unwrap_or_default();
    let opts = GcOptions {
        dry_run: req.dry_run,
        include_oplog_snapshots: !req.ignore_oplog,
    };

    let _lock = state.repo.lock_for_write()?;
    let log = state.log.lock().await;
    let summary = collect_garbage(&state.repo, &log, &opts)
        .map_err(|e| ApiError::Internal(format!("gc: {e}")))?;

    Ok(Json(GcView {
        roots: summary.roots,
        kept: summary.kept,
        removed: summary.removed,
        bytes_freed: summary.bytes_freed,
        dry_run: summary.dry_run,
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
