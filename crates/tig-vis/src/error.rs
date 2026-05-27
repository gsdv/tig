use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("core: {0}")]
    Core(#[from] tig_core::Error),

    #[error("identity not found: {0}")]
    IdentityNotFound(String),
    #[error("identity already exists: {0}")]
    IdentityAlreadyExists(String),
    #[error("identity {0} has no secret key — cannot decrypt or sign as them")]
    SecretMissing(String),

    #[error("not a recipient of this sealed value")]
    NotARecipient,
    #[error(
        "sealed payload integrity check failed (wrong key, wrong path, or tampered ciphertext)"
    )]
    AuthFailure,
    #[error("unsupported sealing algorithm")]
    UnsupportedAlgo,
    #[error("malformed sealed object: {0}")]
    MalformedSealed(String),
}
