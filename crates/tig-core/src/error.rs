use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("encode: {0}")]
    Encode(String),

    #[error("decode: {0}")]
    Decode(String),

    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("invalid hex: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("invalid object kind tag: {0}")]
    InvalidKind(u8),

    #[error("invalid path component: {0:?}")]
    InvalidPathComponent(String),
}
