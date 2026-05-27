//! Principal records and on-disk storage.
//!
//! Layout: `<repo>/vis/keys/<name>.json`. Each file holds:
//!
//! ```text
//! { "id": "alice",
//!   "kind": "User",
//!   "pubkey": "ab12…",
//!   "secret": "9f3c…"     (optional — present only on machines
//!                          where this identity can decrypt/sign) }
//! ```
//!
//! The presence of `secret` is what makes an identity *local*. A
//! repo can hold pubkeys for any number of remote principals (for
//! sealing-to); secrets exist only where the user actually owns that
//! identity.
//!
//! This file format is deliberately tiny and hand-editable so it can
//! be migrated, version-controlled (carefully — without secrets!), or
//! shared via other channels.

use crate::{Error, KeyPair, PublicKey, Result, SecretKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const KEYS_DIR: &str = "vis/keys";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrincipalKind {
    User,
    Agent,
    Bot,
    System,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
    pub kind: PrincipalKind,
    pub pubkey: PublicKey,
    /// Hex-encoded X25519 secret. Optional — absent for remote
    /// principals you only know the pubkey for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_hex: Option<String>,
}

impl Principal {
    pub fn new_local(id: impl Into<String>, kind: PrincipalKind, kp: KeyPair) -> Self {
        let pubkey = kp.public.clone();
        let secret_hex = Some(kp.secret.to_hex());
        Self { id: id.into(), kind, pubkey, secret_hex }
    }

    pub fn new_remote(id: impl Into<String>, kind: PrincipalKind, pubkey: PublicKey) -> Self {
        Self { id: id.into(), kind, pubkey, secret_hex: None }
    }

    pub fn has_secret(&self) -> bool {
        self.secret_hex.is_some()
    }

    pub fn secret(&self) -> Result<SecretKey> {
        let s = self
            .secret_hex
            .as_deref()
            .ok_or_else(|| Error::SecretMissing(self.id.clone()))?;
        SecretKey::from_hex(s)
    }
}

/// CRUD over `<repo>/vis/keys/`.
pub struct PrincipalStore {
    root: PathBuf,
}

impl PrincipalStore {
    pub fn open(repo_root: &Path) -> Result<Self> {
        let root = repo_root.join(KEYS_DIR);
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path_for(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.json"))
    }

    pub fn put(&self, principal: &Principal) -> Result<()> {
        validate_id(&principal.id)?;
        let path = self.path_for(&principal.id);
        let bytes = serde_json::to_vec_pretty(principal)?;
        atomic_write(&path, &bytes)
    }

    pub fn put_new(&self, principal: &Principal) -> Result<()> {
        let path = self.path_for(&principal.id);
        if path.exists() {
            return Err(Error::IdentityAlreadyExists(principal.id.clone()));
        }
        self.put(principal)
    }

    pub fn get(&self, id: &str) -> Result<Principal> {
        let path = self.path_for(id);
        let bytes = fs::read(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::IdentityNotFound(id.to_string()),
            _ => Error::Io(e),
        })?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn list(&self) -> Result<Vec<Principal>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if !s.ends_with(".json") || s.starts_with('.') {
                continue;
            }
            let p: Principal = serde_json::from_slice(&fs::read(entry.path())?)?;
            out.push(p);
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        let path = self.path_for(id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::IdentityNotFound(id.to_string()))
            }
            Err(e) => Err(Error::Io(e)),
        }
    }
}

fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.contains('/')
        || id.contains('\\')
        || id.contains('\0')
        || id == "."
        || id == ".."
    {
        return Err(Error::Crypto(format!("invalid principal id: {id:?}")));
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().expect("principal path has a parent");
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".tmp-{}",
        path.file_name().unwrap().to_string_lossy()
    ));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn local_principal_can_recover_secret() {
        let kp = KeyPair::generate();
        let pub_hex = kp.public.to_hex();
        let p = Principal::new_local("alice", PrincipalKind::User, kp);
        assert!(p.has_secret());
        let sk = p.secret().unwrap();
        assert_eq!(sk.public().to_hex(), pub_hex);
    }

    #[test]
    fn remote_principal_cannot_recover_secret() {
        let kp = KeyPair::generate();
        let p = Principal::new_remote("alice", PrincipalKind::User, kp.public);
        assert!(!p.has_secret());
        match p.secret() {
            Err(Error::SecretMissing(_)) => {}
            other => panic!("expected SecretMissing, got {other:?}"),
        }
    }

    #[test]
    fn store_roundtrips_a_principal() {
        let dir = tempdir().unwrap();
        let store = PrincipalStore::open(dir.path()).unwrap();
        let kp = KeyPair::generate();
        let p = Principal::new_local("alice", PrincipalKind::User, kp);
        store.put_new(&p).unwrap();
        let back = store.get("alice").unwrap();
        assert_eq!(back.id, "alice");
        assert_eq!(back.pubkey, p.pubkey);
        assert!(back.has_secret());
    }

    #[test]
    fn put_new_rejects_duplicates() {
        let dir = tempdir().unwrap();
        let store = PrincipalStore::open(dir.path()).unwrap();
        let kp = KeyPair::generate();
        store
            .put_new(&Principal::new_local("alice", PrincipalKind::User, kp))
            .unwrap();
        let kp2 = KeyPair::generate();
        match store.put_new(&Principal::new_local("alice", PrincipalKind::User, kp2)) {
            Err(Error::IdentityAlreadyExists(_)) => {}
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
    }

    #[test]
    fn list_sorts_by_id() {
        let dir = tempdir().unwrap();
        let store = PrincipalStore::open(dir.path()).unwrap();
        for name in ["zara", "alice", "marvin"] {
            store
                .put_new(&Principal::new_local(name, PrincipalKind::User, KeyPair::generate()))
                .unwrap();
        }
        let ids: Vec<String> = store.list().unwrap().into_iter().map(|p| p.id).collect();
        assert_eq!(ids, vec!["alice", "marvin", "zara"]);
    }

    #[test]
    fn invalid_ids_are_rejected() {
        let dir = tempdir().unwrap();
        let store = PrincipalStore::open(dir.path()).unwrap();
        for bad in ["", ".", "..", "a/b", "x\\y", "a\0b"] {
            let kp = KeyPair::generate();
            let p = Principal {
                id: bad.into(),
                kind: PrincipalKind::User,
                pubkey: kp.public,
                secret_hex: Some(kp.secret.to_hex()),
            };
            assert!(store.put(&p).is_err(), "should reject id: {bad:?}");
        }
    }
}
