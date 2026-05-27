//! Content-addressed object storage.
//!
//! On disk: `objects/<2 hex>/<62 hex>`. File contents are framed as:
//!   `[kind: u8][canonical-cbor payload bytes]`
//! so a reader can recover the `RawObject` without out-of-band context.
//!
//! Writes are atomic (tempfile + rename). If two writers race on the same
//! hash, both succeed because writing identical content twice is a no-op
//! at the directory level — we use `rename(2)`, which is atomic on the
//! same filesystem.

use crate::{Error, Result};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tig_core::{Hash, ObjectKind, RawObject};

/// Abstract object store. Lets the daemon and tests share clients.
pub trait ObjectStore {
    fn put(&self, obj: &RawObject) -> Result<Hash>;
    fn get(&self, hash: &Hash) -> Result<RawObject>;
    fn has(&self, hash: &Hash) -> Result<bool>;
}

/// Object store backed by a filesystem directory.
pub struct FsObjectStore {
    root: PathBuf,
}

impl FsObjectStore {
    /// Open (creating if needed) the object store rooted at `root`.
    /// `root` should be `.tig/store/objects/`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path_for(&self, hash: &Hash) -> PathBuf {
        let mut p = self.root.clone();
        p.push(hash.fanout());
        p.push(hash.rest());
        p
    }

    fn frame(obj: &RawObject) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + obj.bytes.len());
        out.push(obj.kind as u8);
        out.extend_from_slice(&obj.bytes);
        out
    }

    fn unframe(bytes: Vec<u8>) -> Result<RawObject> {
        let mut iter = bytes.into_iter();
        let tag = iter
            .next()
            .ok_or_else(|| Error::Corrupt("object file is empty".into()))?;
        let kind = ObjectKind::from_tag(tag).map_err(Error::Core)?;
        Ok(RawObject {
            kind,
            bytes: iter.collect(),
        })
    }
}

impl FsObjectStore {
    /// Resolve a hex prefix to a full `Hash`. Requires a prefix of at
    /// least 4 hex chars (else the search is too wide to be useful).
    /// Returns `Err(NotFound)` if no object matches, `Err(Conflict)` if
    /// the prefix is ambiguous (mentioning a couple of matches in the
    /// error so the user can disambiguate).
    pub fn resolve_prefix(&self, prefix: &str) -> Result<tig_core::Hash> {
        if prefix.len() < 4 {
            return Err(Error::Corrupt(format!(
                "hash prefix must be at least 4 hex chars, got {:?}",
                prefix
            )));
        }
        let prefix = prefix.to_lowercase();
        if !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Corrupt(format!(
                "hash prefix has non-hex characters: {prefix:?}"
            )));
        }

        // Fast path: full 64-char hash. No walk needed.
        if prefix.len() == 64 {
            let h = tig_core::Hash::from_hex(&prefix).map_err(Error::Core)?;
            if self.path_for(&h).exists() {
                return Ok(h);
            } else {
                return Err(Error::NotFound(prefix));
            }
        }

        let fanout = &prefix[..2];
        let rest_prefix = &prefix[2..];
        let dir = self.root.join(fanout);
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::NotFound(prefix));
            }
            Err(e) => return Err(Error::Io(e)),
        };

        let mut matches: Vec<String> = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            if name.starts_with(rest_prefix) {
                matches.push(format!("{fanout}{name}"));
                if matches.len() > 4 {
                    break;
                }
            }
        }

        match matches.len() {
            0 => Err(Error::NotFound(prefix)),
            1 => tig_core::Hash::from_hex(&matches[0]).map_err(Error::Core),
            _ => {
                let preview: Vec<&str> = matches.iter().map(|s| &s[..16]).collect();
                Err(Error::Corrupt(format!(
                    "ambiguous prefix {prefix:?}; matches: {}…",
                    preview.join(", ")
                )))
            }
        }
    }
}

impl FsObjectStore {
    /// The root directory holding all `<fanout>/<rest>` shards. Exposed
    /// for the GC, which has to walk the entire store.
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    /// Yield every `(hash, size_on_disk)` pair currently stored. The GC
    /// uses this to sweep — we'd rather iterate once than call `fs::stat`
    /// twice per file. The order is unspecified.
    ///
    /// Skips tempfiles (`.tmp-*`) and dotfiles so a writer racing with
    /// the iterator doesn't surface half-written objects.
    pub fn iter_all<F: FnMut(Hash, u64) -> Result<()>>(&self, mut f: F) -> Result<()> {
        let entries = match fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(Error::Io(e)),
        };
        for shard in entries {
            let shard = shard?;
            let shard_name = shard.file_name().to_string_lossy().into_owned();
            if shard_name.starts_with('.') || shard_name.len() != 2 {
                continue;
            }
            for file in fs::read_dir(shard.path())? {
                let file = file?;
                let name = file.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') || name.len() != 62 {
                    continue;
                }
                let hex = format!("{shard_name}{name}");
                let hash = match Hash::from_hex(&hex) {
                    Ok(h) => h,
                    // A stray non-hash file in the store is suspicious
                    // but shouldn't crash the sweep — skip it.
                    Err(_) => continue,
                };
                let size = file.metadata()?.len();
                f(hash, size)?;
            }
        }
        Ok(())
    }

    /// Best-effort delete by hash. Used by the GC sweep — never call
    /// this from regular code paths; objects are content-addressed and
    /// should be considered immutable once written.
    pub fn remove(&self, hash: &Hash) -> Result<()> {
        let path = self.path_for(hash);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io(e)),
        }
    }
}

impl ObjectStore for FsObjectStore {
    fn put(&self, obj: &RawObject) -> Result<Hash> {
        let hash = obj.hash();
        let final_path = self.path_for(&hash);

        if final_path.exists() {
            // Content-addressed: identical hash ⇒ identical content. Skip.
            return Ok(hash);
        }

        let dir = final_path.parent().expect("hash path has a parent");
        fs::create_dir_all(dir)?;

        // Write to a sibling tempfile, then rename — atomic on same FS.
        let tmp = dir.join(format!(".tmp-{}", hash.rest()));
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&Self::frame(obj))?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &final_path)?;
        Ok(hash)
    }

    fn get(&self, hash: &Hash) -> Result<RawObject> {
        let path = self.path_for(hash);
        let bytes = fs::read(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::NotFound(hash.to_hex()),
            _ => Error::Io(e),
        })?;
        let raw = Self::unframe(bytes)?;
        raw.verify(hash).map_err(Error::Core)?;
        Ok(raw)
    }

    fn has(&self, hash: &Hash) -> Result<bool> {
        Ok(self.path_for(hash).exists())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tig_core::{Blob, Encodable, EntryKind, FileMode, Tree, TreeEntry};

    fn store() -> (tempfile::TempDir, FsObjectStore) {
        let dir = tempdir().unwrap();
        let store = FsObjectStore::open(dir.path().join("objects")).unwrap();
        (dir, store)
    }

    #[test]
    fn put_then_get_blob() {
        let (_dir, s) = store();
        let blob = Blob::new(b"hello".to_vec());
        let raw = blob.encode().unwrap();
        let h = s.put(&raw).unwrap();

        assert!(s.has(&h).unwrap());
        let back = s.get(&h).unwrap();
        let blob_back = Blob::decode(&back).unwrap();
        assert_eq!(blob, blob_back);
    }

    #[test]
    fn put_is_idempotent() {
        let (_dir, s) = store();
        let blob = Blob::new(b"x".to_vec());
        let raw = blob.encode().unwrap();
        let h1 = s.put(&raw).unwrap();
        let h2 = s.put(&raw).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn get_unknown_is_not_found() {
        let (_dir, s) = store();
        let fake = Hash::compute(ObjectKind::Blob, b"never written");
        let err = s.get(&fake).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn tree_roundtrips_through_store() {
        let (_dir, s) = store();
        let blob = Blob::new(b"contents".to_vec());
        let raw_blob = blob.encode().unwrap();
        let bh = s.put(&raw_blob).unwrap();

        let t = Tree::from_entries([TreeEntry {
            name: "file.txt".into(),
            kind: EntryKind::File,
            target: bh,
            mode: FileMode::REGULAR,
            vis: None,
        }])
        .unwrap();
        let raw_t = t.encode().unwrap();
        let th = s.put(&raw_t).unwrap();

        let back = Tree::decode(&s.get(&th).unwrap()).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn prefix_resolve_finds_unique_match() {
        let (_d, s) = store();
        let blob = Blob::new(b"hello".to_vec());
        let raw = blob.encode().unwrap();
        let h = s.put(&raw).unwrap();
        let full = h.to_hex();
        let resolved = s.resolve_prefix(&full[..12]).unwrap();
        assert_eq!(resolved, h);
    }

    #[test]
    fn prefix_resolve_rejects_too_short() {
        let (_d, s) = store();
        let err = s.resolve_prefix("ab").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("at least 4 hex"), "got: {msg}");
    }

    #[test]
    fn prefix_resolve_returns_not_found_for_unknown() {
        let (_d, s) = store();
        let err = s.resolve_prefix("deadbeef00").unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn prefix_resolve_full_hash_works() {
        let (_d, s) = store();
        let h = s.put(&Blob::new(b"x".to_vec()).encode().unwrap()).unwrap();
        let back = s.resolve_prefix(&h.to_hex()).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn prefix_resolve_rejects_non_hex() {
        let (_d, s) = store();
        let err = s.resolve_prefix("zzzz").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("non-hex"), "got: {msg}");
    }

    #[test]
    fn corruption_is_detected() {
        let (dir, s) = store();
        let blob = Blob::new(b"hello".to_vec());
        let raw = blob.encode().unwrap();
        let h = s.put(&raw).unwrap();

        // tamper with the on-disk bytes
        let mut p = dir.path().join("objects");
        p.push(h.fanout());
        p.push(h.rest());
        let mut bytes = fs::read(&p).unwrap();
        *bytes.last_mut().unwrap() ^= 0xff;
        fs::write(&p, bytes).unwrap();

        let err = s.get(&h).unwrap_err();
        assert!(matches!(
            err,
            Error::Core(tig_core::Error::HashMismatch { .. })
        ));
    }
}
