//! HTTP error envelope.
//!
//! Every endpoint returns `Result<T, ApiError>`. `ApiError` lossily maps
//! the various tig + IO errors to a status code + a structured JSON
//! envelope: `{ "code": "...", "message": "..." }`. The mapping is
//! intentionally narrow — anything we can't classify becomes 500
//! "internal" so the client never sees a leaked stack trace.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use thiserror::Error;
use tig_protocol::ErrorResp;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Conflict(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl ApiError {
    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            ApiError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            ApiError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        let body = ErrorResp {
            code: code.to_string(),
            message: self.to_string(),
        };
        (status, Json(body)).into_response()
    }
}

impl From<tig_store::Error> for ApiError {
    fn from(e: tig_store::Error) -> Self {
        match e {
            tig_store::Error::NotFound(s) => ApiError::NotFound(s),
            tig_store::Error::AlreadyExists(s) => ApiError::Conflict(s),
            tig_store::Error::Core(c) => ApiError::BadRequest(c.to_string()),
            tig_store::Error::Json(j) => ApiError::Internal(j.to_string()),
            tig_store::Error::Io(io) => ApiError::Internal(io.to_string()),
            tig_store::Error::Corrupt(s) => ApiError::Internal(format!("corrupt: {s}")),
        }
    }
}

impl From<tig_fs::Error> for ApiError {
    fn from(e: tig_fs::Error) -> Self {
        match e {
            tig_fs::Error::Core(c) => ApiError::BadRequest(c.to_string()),
            tig_fs::Error::Store(s) => ApiError::from(s),
            tig_fs::Error::Io(io) => ApiError::Internal(io.to_string()),
            tig_fs::Error::Walk(w) => ApiError::Internal(w.to_string()),
            tig_fs::Error::Notify(n) => ApiError::Internal(n.to_string()),
            tig_fs::Error::UnsupportedFileKind { path, kind } => {
                ApiError::BadRequest(format!("unsupported file kind {kind} at {path}"))
            }
            tig_fs::Error::EscapesWorkdir(s) => ApiError::BadRequest(s),
        }
    }
}

impl From<tig_core::Error> for ApiError {
    fn from(e: tig_core::Error) -> Self {
        ApiError::BadRequest(e.to_string())
    }
}

pub type ApiResult<T> = std::result::Result<T, ApiError>;
