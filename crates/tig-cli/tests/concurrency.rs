//! Cross-process concurrency test for the per-repo write lock.
//!
//! Spawns N `tig snap -m "..."` children against the same repo and
//! waits for them to complete. With the lock in place, the resulting
//! op log should contain exactly N ops, each with a unique
//! monotonically-increasing id and no torn records. Without locking,
//! racing `OpLog::open` reads + appends would routinely produce
//! duplicate ids or truncated records.
//!
//! This is the production-readiness test from the candid review.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::thread;

fn tig_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tig"))
}

/// Run `tig` from `cwd` with the given args, asserting success.
fn run_tig(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
    let out = Command::new(tig_binary())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn tig");
    if !out.status.success() {
        panic!(
            "`tig {}` failed: stdout={:?} stderr={:?}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out
}

#[test]
fn concurrent_snaps_serialize_with_unique_op_ids() {
    let dir = tempfile::tempdir().unwrap();
    let workdir = dir.path().to_path_buf();

    // 1. Initialize a repo.
    run_tig(&workdir, &["init"]);

    // 2. Seed an initial snap so the racing children advance an
    //    existing change rather than each trying to bootstrap one.
    fs::write(workdir.join("seed.txt"), b"seed\n").unwrap();
    run_tig(&workdir, &["snap", "-m", "seed"]);

    // 3. Fire N parallel `tig snap -m "child <i>"` children. Each
    //    writes a unique file first so each snap has something to
    //    capture (and to avoid the "nothing to snap" early-return).
    const N: usize = 20;
    let (tx, rx) = mpsc::channel();
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let workdir = workdir.clone();
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            let path = workdir.join(format!("file_{i:02}.txt"));
            fs::write(&path, format!("contents {i}").as_bytes()).unwrap();
            let out = Command::new(tig_binary())
                .args(["snap", "-m"])
                .arg(format!("child {i:02}"))
                .current_dir(&workdir)
                .output()
                .expect("spawn tig");
            tx.send((i, out.status.success(), out.stdout, out.stderr))
                .unwrap();
        }));
    }
    drop(tx);
    for h in handles {
        h.join().unwrap();
    }

    // Confirm every child succeeded.
    let mut results: Vec<_> = rx.into_iter().collect();
    results.sort_by_key(|(i, ..)| *i);
    for (i, ok, stdout, stderr) in &results {
        assert!(
            ok,
            "child {i} failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(stdout),
            String::from_utf8_lossy(stderr)
        );
    }

    // 4. Read the op log directly and verify invariants.
    let oplog_path = workdir.join(".tig/oplog/000000.log");
    let bytes = fs::read(&oplog_path).expect("oplog file");
    let ops = decode_oplog(&bytes);

    // 1 seed snap + N child snaps = N + 1 total.
    assert_eq!(
        ops.len(),
        N + 1,
        "expected {} ops (1 seed + {} children), got {}",
        N + 1,
        N,
        ops.len()
    );

    // Op ids should be 0..N (no gaps, no duplicates).
    let mut ids: Vec<u64> = ops.iter().map(|o| o.id).collect();
    ids.sort();
    let expected: Vec<u64> = (0..(N as u64 + 1)).collect();
    assert_eq!(
        ids,
        expected,
        "op ids should be a strict 0..{} sequence",
        N + 1
    );

    // 5. The repo's HEAD should point at a valid change with all N+1
    //    snapshots in its history. Drive `tig log` to verify it
    //    parses cleanly — that's the indirect "no torn refs" check.
    let out = run_tig(&workdir, &["log", "--all"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let snap_count = stdout.matches("  ").filter(|_| true).count();
    let _ = snap_count;
    // Direct: parse change.history via JSON.
    let mut change_id = None;
    let changes_dir = workdir.join(".tig/refs/changes");
    for entry in fs::read_dir(&changes_dir).unwrap() {
        let entry = entry.unwrap();
        let s = entry.file_name().to_string_lossy().into_owned();
        if !s.starts_with('.') {
            change_id = Some(s);
            break;
        }
    }
    let change_path = changes_dir.join(change_id.expect("a change record"));
    let change_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&change_path).unwrap()).unwrap();
    let history_len = change_json["history"].as_array().unwrap().len();
    assert_eq!(
        history_len,
        N + 1,
        "change history should contain the seed + all N child snaps"
    );
}

#[derive(Debug)]
struct ParsedOp {
    id: u64,
}

/// Decode just enough of the op log to extract each record's id.
/// Format: framed records of `[u32 BE length][CBOR Op]`. We pull the
/// `id` field out via ciborium without depending on the engine's
/// internal `Op` struct.
fn decode_oplog(bytes: &[u8]) -> Vec<ParsedOp> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        assert!(
            bytes.len() - pos >= 4,
            "truncated record at byte {pos} (oplog is corrupt — torn write?)"
        );
        let len = u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
            as usize;
        pos += 4;
        assert!(
            bytes.len() - pos >= len,
            "record at {pos} claims {len} bytes but only {} remain — torn write?",
            bytes.len() - pos
        );
        let record = &bytes[pos..pos + len];
        pos += len;

        // Decode as a serde_json::Value-like generic shape. ciborium
        // can deserialize CBOR into serde_json::Value via the
        // serde-compatible path.
        let value: ciborium::Value = ciborium::de::from_reader(record)
            .expect("CBOR record decodes — torn write would fail here");
        // The Op struct has `id: OpId(u64)` which CBOR-encodes as a
        // single-element array or tuple under serde — actually
        // `OpId(u64)` is a tuple struct, encoded as just `u64`.
        // So we look for an integer field named "id".
        let id =
            extract_op_id(&value).expect("op record should have an `id` field decodable as u64");
        out.push(ParsedOp { id });
    }
    out
}

/// Find the `id` field in a CBOR-decoded Op record and pull out the
/// u64. Robust against the various ways `OpId(u64)` might serialize.
fn extract_op_id(value: &ciborium::Value) -> Option<u64> {
    if let ciborium::Value::Map(entries) = value {
        for (k, v) in entries {
            if let ciborium::Value::Text(name) = k {
                if name == "id" {
                    return as_u64(v);
                }
            }
        }
    }
    None
}

fn as_u64(v: &ciborium::Value) -> Option<u64> {
    match v {
        ciborium::Value::Integer(i) => {
            let i128: i128 = (*i).into();
            u64::try_from(i128).ok()
        }
        // OpId(u64) might serialize as Array([u64]) depending on serde
        // settings; handle both.
        ciborium::Value::Array(a) if a.len() == 1 => as_u64(&a[0]),
        _ => None,
    }
}
