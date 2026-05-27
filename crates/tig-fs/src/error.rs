use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("walk: {0}")]
    Walk(#[from] walkdir::Error),

    #[error("core: {0}")]
    Core(#[from] tig_core::Error),

    #[error("store: {0}")]
    Store(#[from] tig_store::Error),

    #[error("unsupported file kind at {path}: {kind}")]
    UnsupportedFileKind { path: String, kind: String },

    #[error("path is not in workdir: {0}")]
    EscapesWorkdir(String),

    #[error("notify: {0}")]
    Notify(#[from] notify::Error),
}
