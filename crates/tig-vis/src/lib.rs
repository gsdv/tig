//! Visibility, identity, and sealed (encrypted) values.
//!
//! Three layers:
//!
//!   - [`keys`] — typed wrappers around X25519 keypairs and a helper to
//!     generate fresh ones with the OS RNG.
//!   - [`principal`] — `Principal` records (name + pubkey + maybe local
//!     secret), plus an on-disk store under `<repo>/vis/keys/`.
//!   - [`seal`] — the [`seal`](seal::seal) and [`unseal`](seal::unseal)
//!     functions. Implementation is the architecture's exact §2.6 shape:
//!     X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305 with multi-recipient
//!     wrap entries and AAD path binding.
//!
//! The daemon never holds a principal's secret; sealing and unsealing
//! happen client-side. The daemon just stores and serves the `Sealed`
//! object alongside ordinary blobs and trees.

pub mod error;
pub mod keys;
pub mod principal;
pub mod seal;

pub use error::Error;
pub use keys::{PublicKey, SecretKey, KeyPair};
pub use principal::{Principal, PrincipalKind, PrincipalStore};
pub use seal::{seal, unseal};

pub type Result<T> = std::result::Result<T, Error>;
