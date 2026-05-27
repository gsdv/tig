use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("already exists: {0}")]
    AlreadyExists(String),

    #[error("core: {0}")]
    Core(#[from] tig_core::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("corrupt object: {0}")]
    Corrupt(String),
}
