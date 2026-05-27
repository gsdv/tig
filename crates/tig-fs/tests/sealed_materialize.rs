//! End-to-end test: real `tig_vis::seal`, real `unseal`, and verify
//! that the materializer wires the AAD through correctly.
//!
//! The unit tests inside `materialize.rs` use stub `Sealed` objects
//! and a stub unsealer closure — they prove the engine's plumbing but
//! they don't catch an AAD-convention mismatch between `tig seal` and
//! the render path. This test does.

use std::fs;
use std::sync::{Arc, Mutex};

use tempfile::tempdir;
use tig_core::{Encodable, EntryKind, FileMode, PrincipalId, Snapshot, Tree, TreeEntry};
use tig_fs::{materialize_change_into, MaterializeOptions, MaterializeOutcome, OnUnsealable};
use tig_store::Repository;
use tig_vis::{seal, unseal, KeyPair};

#[test]
fn real_seal_then_real_unseal_through_render_round_trips() {
    let dir = tempdir().unwrap();
    let repo = Repository::init(dir.path()).unwrap();

    // Alice owns the only recipient key.
    let alice = KeyPair::generate();
    let plaintext = b"DATABASE_URL=postgres://prod/x".to_vec();
    // `tig seal <path>` uses the path bytes as AAD. Mirror that
    // convention. The materializer must pass the same bytes to the
    // unsealer for decryption to succeed.
    let path = "config/prod.env";
    let sealed_obj = seal(
        &plaintext,
        std::slice::from_ref(&alice.public),
        path.as_bytes(),
    )
    .unwrap();
    let sealed_h = repo.put(&sealed_obj.encode().unwrap()).unwrap();

    // Build the surrounding tree: config/ → prod.env (Sealed).
    let subtree = Tree::from_entries([TreeEntry {
        name: "prod.env".into(),
        kind: EntryKind::Sealed,
        target: sealed_h,
        mode: FileMode::REGULAR,
        vis: None,
    }])
    .unwrap();
    let subtree_h = repo.put(&subtree.encode().unwrap()).unwrap();
    let root = Tree::from_entries([TreeEntry {
        name: "config".into(),
        kind: EntryKind::Tree,
        target: subtree_h,
        mode: FileMode::DIR,
        vis: None,
    }])
    .unwrap();
    let root_h = repo.put(&root.encode().unwrap()).unwrap();
    let snap = Snapshot {
        parents: vec![],
        tree: root_h,
        author: PrincipalId::local("alice"),
        timestamp_ns: 0,
        message: None,
        op_id: None,
    };
    let snap_h = repo.put(&snap.encode().unwrap()).unwrap();

    // Build alice's unsealer — wraps the real `tig_vis::unseal`. The
    // arc is just here so the secret can outlive the closure
    // ergonomically in this test.
    let secret = Arc::new(alice.secret);
    let secret_for_closure = Arc::clone(&secret);
    let unsealer =
        move |s: &tig_core::Sealed, aad: &[u8]| -> std::result::Result<Vec<u8>, String> {
            unseal(s, &secret_for_closure, aad).map_err(|e| e.to_string())
        };
    let opts = MaterializeOptions {
        unsealer: Some(&unsealer),
        on_unsealable: OnUnsealable::Error,
    };

    let target = dir.path().join("rendered");
    let outcome = materialize_change_into(&repo, &snap_h, &target, &opts).unwrap();
    match outcome {
        MaterializeOutcome::Rendered {
            sealed_unsealed,
            sealed_skipped,
            ..
        } => {
            assert_eq!(sealed_unsealed, 1);
            assert_eq!(sealed_skipped, 0);
        }
        other => panic!("expected Rendered, got {other:?}"),
    }

    let on_disk = fs::read(target.join("config/prod.env")).unwrap();
    assert_eq!(
        on_disk, plaintext,
        "AAD wiring must match `tig seal`'s convention"
    );
}

#[test]
fn non_recipient_identity_cannot_decrypt() {
    // Alice seals, bob tries to materialize → unsealer fails (not a
    // recipient), and the Error policy aborts the whole render.
    let dir = tempdir().unwrap();
    let repo = Repository::init(dir.path()).unwrap();

    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let sealed_obj = seal(
        b"alice-only",
        std::slice::from_ref(&alice.public),
        b"secret",
    )
    .unwrap();
    let sealed_h = repo.put(&sealed_obj.encode().unwrap()).unwrap();
    let tree = Tree::from_entries([TreeEntry {
        name: "secret".into(),
        kind: EntryKind::Sealed,
        target: sealed_h,
        mode: FileMode::REGULAR,
        vis: None,
    }])
    .unwrap();
    let tree_h = repo.put(&tree.encode().unwrap()).unwrap();
    let snap = Snapshot {
        parents: vec![],
        tree: tree_h,
        author: PrincipalId::local("alice"),
        timestamp_ns: 0,
        message: None,
        op_id: None,
    };
    let snap_h = repo.put(&snap.encode().unwrap()).unwrap();

    // Track that bob's unsealer was actually called (so we know the
    // failure came from real crypto, not a wiring bug).
    let calls = Arc::new(Mutex::new(0_usize));
    let calls_for_closure = Arc::clone(&calls);
    let bob_secret = Arc::new(bob.secret);
    let bob_secret_for_closure = Arc::clone(&bob_secret);
    let unsealer =
        move |s: &tig_core::Sealed, aad: &[u8]| -> std::result::Result<Vec<u8>, String> {
            *calls_for_closure.lock().unwrap() += 1;
            unseal(s, &bob_secret_for_closure, aad).map_err(|e| e.to_string())
        };
    let opts = MaterializeOptions {
        unsealer: Some(&unsealer),
        on_unsealable: OnUnsealable::Error,
    };
    let target = dir.path().join("rendered");
    let err = materialize_change_into(&repo, &snap_h, &target, &opts).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("decrypt failed"), "got: {msg}");
    assert_eq!(*calls.lock().unwrap(), 1, "unsealer was invoked");
}
