//! Wire protocol — the request/response DTOs that flow between any
//! tig client (CLI, daemon, WASM SDK) and `tigd`.
//!
//! Three guiding rules:
//!
//!   1. **Hashes are hex strings on the wire.** Easy to log, easy to
//!      curl, easy to round-trip through JSON. Server converts to
//!      `tig_core::Hash` at the boundary.
//!
//!   2. **DTOs are owned by this crate, not by `tig-core`.** The core
//!      object model can evolve its binary encoding; the wire shape is
//!      versioned independently.
//!
//!   3. **Conversion is explicit.** `ChangeView::from(&Change)` and
//!      friends — no `impl Serialize for Change` magic, because the
//!      core encoding (canonical CBOR for hashing) is *not* the wire
//!      format.

use serde::{Deserialize, Serialize};
use tig_core::{
    Change, ChangeState, EntryKind, FileMode, RecipientWrap, SealAlgo, Sealed, Snapshot, Tree,
    TreeEntry,
};
use tig_store::{Op, OpKind};

/// Health check response body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthView {
    pub ok: bool,
    pub version: String,
}

// --- changes -------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangeView {
    pub id: String,
    pub bookmark: Option<String>,
    pub description: String,
    pub state: String,
    /// Hex hash of the snapshot this change currently points at.
    pub current: String,
    /// Hex hashes of every snapshot this change has ever pointed at.
    pub history: Vec<String>,
    pub author: String,
    pub visibility: String,
}

impl ChangeView {
    pub fn from_core(c: &Change) -> Self {
        Self {
            id: c.id.0.clone(),
            bookmark: c.bookmark.clone(),
            description: c.description.clone(),
            state: format!("{:?}", c.state),
            current: c.current.to_hex(),
            history: c.history.iter().map(|h| h.to_hex()).collect(),
            author: c.author.0.clone(),
            visibility: c.visibility.name().to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CreateChangeReq {
    pub description: String,
    /// Optional: branch from this existing change's current snapshot.
    /// If omitted, the new change starts from the empty tree.
    #[serde(default)]
    pub from_change: Option<String>,
    /// Optional initial visibility ("public" | "private"). Default: public.
    #[serde(default)]
    pub visibility: Option<String>,
    /// Optional initial state ("working" | "draft" | etc.). Default: working.
    #[serde(default)]
    pub state: Option<String>,
}

/// Body for `POST /v1/changes/{id}/transition` — flip state and/or visibility.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct TransitionReq {
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub visibility: Option<String>,
}

// --- snapshots -----------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotView {
    pub hash: String,
    pub parents: Vec<String>,
    pub tree: String,
    pub author: String,
    pub timestamp_ns: u64,
    pub message: Option<String>,
}

impl SnapshotView {
    pub fn from_core(hash: tig_core::Hash, s: &Snapshot) -> Self {
        Self {
            hash: hash.to_hex(),
            parents: s.parents.iter().map(|h| h.to_hex()).collect(),
            tree: s.tree.to_hex(),
            author: s.author.to_string(),
            timestamp_ns: s.timestamp_ns,
            message: s.message.clone(),
        }
    }
}

// --- trees & entries -----------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeView {
    pub hash: Option<String>,
    pub entries: Vec<TreeEntryView>,
}

impl TreeView {
    pub fn from_core(hash: Option<tig_core::Hash>, t: &Tree) -> Self {
        Self {
            hash: hash.map(|h| h.to_hex()),
            entries: t.entries.iter().map(TreeEntryView::from_core).collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeEntryView {
    pub name: String,
    pub kind: String,
    pub target: String,
    pub mode: u32,
    pub vis: Option<String>,
}

impl TreeEntryView {
    pub fn from_core(e: &TreeEntry) -> Self {
        Self {
            name: e.name.clone(),
            kind: format!("{:?}", e.kind),
            target: e.target.to_hex(),
            mode: e.mode.0,
            vis: e.vis.as_ref().map(|v| v.0.clone()),
        }
    }
}

// --- snap & undo ---------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SnapReq {
    pub message: Option<String>,
    pub author: Option<String>,
    pub force: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapResp {
    pub outcome: String, // "snapped" | "unchanged"
    pub change: ChangeView,
    pub snapshot: Option<SnapshotView>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct UndoReq {
    pub author: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UndoResp {
    pub undone_op_id: Option<u64>,
    pub undone_kind: Option<String>,
    pub recorded_op_id: Option<u64>,
    pub message: String,
}

// --- op log --------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpView {
    pub id: u64,
    pub ts_ns: u64,
    pub actor: String,
    pub kind: String,
    pub one_line: String,
}

impl OpView {
    pub fn from_core(op: &Op) -> Self {
        Self {
            id: op.id.0,
            ts_ns: op.ts_ns,
            actor: op.actor.to_string(),
            kind: kind_discriminator(&op.kind).to_string(),
            one_line: op.kind.one_line(),
        }
    }
}

fn kind_discriminator(k: &OpKind) -> &'static str {
    match k {
        OpKind::Snap { .. } => "Snap",
        OpKind::ChangeNew { .. } => "ChangeNew",
        OpKind::WtMake { .. } => "WtMake",
        OpKind::WtDrop { .. } => "WtDrop",
        OpKind::ChangeTransition { .. } => "ChangeTransition",
        OpKind::Undo { .. } => "Undo",
    }
}

// --- file modes (hint for clients) ---------------------------------------

pub const MODE_REGULAR: u32 = FileMode::REGULAR.0;
pub const MODE_EXEC: u32 = FileMode::EXEC.0;
pub const MODE_SYMLINK: u32 = FileMode::SYMLINK.0;
pub const MODE_DIR: u32 = FileMode::DIR.0;

// --- sealed values (wire shape) -----------------------------------------

/// Hex-encoded `Sealed` for JSON transport. The core CBOR encoding uses
/// `serde_bytes`, which would expand into arrays of u8 in JSON — ugly
/// and large. Hex strings stay readable and compact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedView {
    pub algo: u8,
    pub ephemeral_pk: String,
    pub recipients: Vec<RecipientView>,
    pub ciphertext: String,
    pub nonce: String,
    pub aad: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecipientView {
    pub recipient_pk: String,
    pub wrapped_key: String,
    pub wrap_nonce: String,
}

impl SealedView {
    pub fn from_core(s: &Sealed) -> Self {
        Self {
            algo: s.algo as u8,
            ephemeral_pk: hex::encode(&s.ephemeral_pk),
            recipients: s.recipients.iter().map(RecipientView::from_core).collect(),
            ciphertext: hex::encode(&s.ciphertext),
            nonce: hex::encode(&s.nonce),
            aad: hex::encode(&s.aad),
        }
    }

    pub fn into_core(self) -> Result<Sealed, String> {
        if self.algo != 1 {
            return Err(format!("unknown seal algo {}", self.algo));
        }
        let recipients: Result<Vec<RecipientWrap>, String> = self
            .recipients
            .into_iter()
            .map(RecipientView::into_core)
            .collect();
        Ok(Sealed {
            algo: SealAlgo::X25519XChaCha20Poly1305,
            ephemeral_pk: hex::decode(self.ephemeral_pk).map_err(|e| e.to_string())?,
            recipients: recipients?,
            ciphertext: hex::decode(self.ciphertext).map_err(|e| e.to_string())?,
            nonce: hex::decode(self.nonce).map_err(|e| e.to_string())?,
            aad: hex::decode(self.aad).map_err(|e| e.to_string())?,
        })
    }
}

impl RecipientView {
    pub fn from_core(r: &RecipientWrap) -> Self {
        Self {
            recipient_pk: hex::encode(&r.recipient_pk),
            wrapped_key: hex::encode(&r.wrapped_key),
            wrap_nonce: hex::encode(&r.wrap_nonce),
        }
    }

    pub fn into_core(self) -> Result<RecipientWrap, String> {
        Ok(RecipientWrap {
            recipient_pk: hex::decode(self.recipient_pk).map_err(|e| e.to_string())?,
            wrapped_key: hex::decode(self.wrapped_key).map_err(|e| e.to_string())?,
            wrap_nonce: hex::decode(self.wrap_nonce).map_err(|e| e.to_string())?,
        })
    }
}

// --- diff (wire shape) ---------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiffView {
    pub from: String, // hex tree hash
    pub to: String,   // hex tree hash
    pub files: Vec<FileDiffView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileDiffView {
    pub path: String,
    pub kind: String, // "Added" | "Removed" | "Modified" | "TypeChanged"
    /// For `TypeChanged`, the previous entry kind. Empty otherwise.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub type_changed_from: String,
    /// For `TypeChanged`, the new entry kind. Empty otherwise.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub type_changed_to: String,
    pub entry_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_target: Option<String>,
    pub binary: bool,
    /// Omitted for trees, symlinks, sealed entries, and binaries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunks: Option<Vec<HunkView>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HunkView {
    pub from_start: usize,
    pub from_len: usize,
    pub to_start: usize,
    pub to_len: usize,
    pub lines: Vec<HunkLineView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "tag", content = "text")]
pub enum HunkLineView {
    Context(String),
    Add(String),
    Remove(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DiffQuery {
    /// Hex hash of the "from" snapshot. If omitted, the daemon uses the
    /// change's current snapshot's parent. If the current snapshot has
    /// no parent, the diff is against the empty tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Hex hash of the "to" snapshot. If omitted, the daemon uses the
    /// change's current snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// If true, omit unified-diff hunks (file list only).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_hunks: bool,
    /// Path-prefix filters; empty = no filter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
}

// --- blame (wire shape) --------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlameView {
    pub path: String,
    /// Hex hash of the snapshot the blame was computed against.
    pub at: String,
    pub lines: Vec<BlameLineView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlameLineView {
    /// Line content, no trailing newline.
    pub line: String,
    /// Hex hash of the snap that last introduced/modified this line.
    pub snap: String,
    pub author: String,
    pub timestamp_ns: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct BlameQuery {
    /// Hex hash of the snapshot to blame against. Defaults to the
    /// change's current snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snap: Option<String>,
}

// --- error envelope ------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorResp {
    pub code: String,
    pub message: String,
}

// Make the core ChangeState convertible to a stable wire string.
pub fn change_state_name(s: ChangeState) -> &'static str {
    match s {
        ChangeState::Working => "Working",
        ChangeState::Draft => "Draft",
        ChangeState::Review => "Review",
        ChangeState::Landed => "Landed",
        ChangeState::Abandoned => "Abandoned",
    }
}

pub fn entry_kind_name(k: EntryKind) -> &'static str {
    match k {
        EntryKind::File => "File",
        EntryKind::Tree => "Tree",
        EntryKind::Symlink => "Symlink",
        EntryKind::Sealed => "Sealed",
        EntryKind::Conflict => "Conflict",
        EntryKind::Submodule => "Submodule",
    }
}

// Make `RefSnapshot` JSON-friendly for the op-log endpoint. The default
// serde encoding works fine; we expose a re-export so callers don't have
// to depend on tig-store directly.
pub use tig_store::RefSnapshot as WireRefSnapshot;

#[cfg(test)]
mod tests {
    use super::*;
    use tig_core::{Change, ChangeId, ObjectKind, PrincipalId};

    #[test]
    fn change_view_roundtrip_through_json() {
        let mut change = Change::new(
            "test",
            PrincipalId::local("t"),
            tig_core::Hash::compute(ObjectKind::Snapshot, b"x"),
        );
        change.bookmark = Some("main".into());

        let view = ChangeView::from_core(&change);
        let json = serde_json::to_string(&view).unwrap();
        let back: ChangeView = serde_json::from_str(&json).unwrap();
        assert_eq!(view.id, back.id);
        assert_eq!(view.bookmark, back.bookmark);
        assert_eq!(view.history, back.history);
    }

    #[test]
    fn snapshot_view_includes_hash_explicitly() {
        let h = tig_core::Hash::compute(ObjectKind::Snapshot, b"v");
        let snap = Snapshot {
            parents: vec![],
            tree: tig_core::Hash::compute(ObjectKind::Tree, b"t"),
            author: PrincipalId::local("t"),
            timestamp_ns: 0,
            message: Some("hi".into()),
            op_id: None,
        };
        let view = SnapshotView::from_core(h, &snap);
        assert_eq!(view.hash, h.to_hex());
        assert_eq!(view.message.as_deref(), Some("hi"));
    }

    #[test]
    fn create_change_request_roundtrips() {
        let req = CreateChangeReq {
            description: "fix bug".into(),
            from_change: Some(ChangeId::new().0),
            visibility: Some("private".into()),
            state: Some("draft".into()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: CreateChangeReq = serde_json::from_str(&json).unwrap();
        assert_eq!(req.description, back.description);
        assert_eq!(req.from_change, back.from_change);
    }
}
