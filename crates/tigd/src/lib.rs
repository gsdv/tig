//! The tigd HTTP API.
//!
//! One repo per daemon, fixed at startup. The server holds an open
//! `Repository` and a single-writer `OpLog` behind a `Mutex` so writes
//! serialize cleanly. Reads also take the lock — fine for milestone
//! since every request touches the oplog or the small refs files; the
//! per-request work is microseconds.
//!
//! Surface (versioned at `/v1/`):
//!
//! ```text
//! GET    /v1/health
//! GET    /v1/changes                            list
//! POST   /v1/changes                            create
//! GET    /v1/changes/{id}                       fetch
//! GET    /v1/changes/{id}/tree                  list root tree
//! GET    /v1/changes/{id}/tree/{*path}          read bytes / sub-listing
//! PATCH  /v1/changes/{id}/tree/{*path}          write blob bytes
//! DELETE /v1/changes/{id}/tree/{*path}          remove entry
//! POST   /v1/changes/{id}/snap                  build a snapshot
//! GET    /v1/snapshots/{hash}                   fetch a snapshot object
//! GET    /v1/oplog                              list ops, newest last
//! POST   /v1/oplog/undo                         rewind one op
//! ```
//!
//! The body of `GET /tree/{*path}` is the raw blob if path is a file, or
//! a JSON `TreeView` if path is a directory. The body of `PATCH
//! /tree/{*path}` is the raw bytes to write — no JSON envelope.

pub mod error;
pub mod handlers;
pub mod state;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::{delete, get, patch, post};
use axum::Router;

pub use error::ApiError;
pub use state::AppState;

pub struct ServerConfig {
    pub repo_root: PathBuf,
    pub bind: SocketAddr,
}

/// Construct the axum app. Exposed for in-process integration testing.
pub fn build_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/health", get(handlers::health))
        .route(
            "/v1/changes",
            get(handlers::list_changes).post(handlers::create_change),
        )
        .route("/v1/changes/{id}", get(handlers::get_change))
        .route("/v1/changes/{id}/tree", get(handlers::get_tree_root))
        .route(
            "/v1/changes/{id}/tree/{*path}",
            get(handlers::get_tree_path)
                .patch(handlers::patch_tree_path)
                .delete(handlers::delete_tree_path),
        )
        .route("/v1/changes/{id}/snap", post(handlers::snap_change))
        .route(
            "/v1/changes/{id}/transition",
            post(handlers::transition_change),
        )
        .route("/v1/snapshots/{hash}", get(handlers::get_snapshot))
        .route("/v1/oplog", get(handlers::list_oplog))
        .route("/v1/oplog/undo", post(handlers::undo))
        .with_state(state)
}

pub async fn serve(cfg: ServerConfig) -> anyhow::Result<()> {
    let state = Arc::new(AppState::open(cfg.repo_root.clone())?);
    let app = build_app(state);
    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    tracing::info!("tigd listening on http://{}", cfg.bind);
    tracing::info!("serving repo at {}", cfg.repo_root.display());
    axum::serve(listener, app).await?;
    Ok(())
}

// satisfy `delete` import lint
#[allow(unused_imports)]
use delete as _delete;
#[allow(unused_imports)]
use patch as _patch;
