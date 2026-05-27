# tig

[![CI](https://github.com/gsdv/tig/actions/workflows/ci.yml/badge.svg)](https://github.com/gsdv/tig/actions/workflows/ci.yml)

An alternative to git, built for agents. Hosted, with appropriate irony,
on GitHub.

## What it is

A from-scratch source-control system written over a single session in
Rust. The design responds to four specific complaints from
[@theo](https://x.com/theo) about git:

1. "Open source" shouldn't mean 100% public 100% of the time.
2. Commits are a bad primitive; branches are worse. Snapshots, not
   commits, are the truth.
3. Worktrees are an abomination. Filesystem-native CoW exists.
4. Source control shouldn't require a "real OS" + filesystem. Agents
   in sandboxes need an API.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

## What's in here

Seven crates, roughly 11k lines of Rust, 144 unit + integration tests:

| crate | what it does |
|---|---|
| `tig-core` | object model (Blob/Tree/Snapshot/Change/Sealed), BLAKE3 hashing with kind-prefixed collision resistance, visibility labels |
| `tig-store` | content-addressed object store, refs, oplog, workspace manifests, principal-key registry root |
| `tig-fs` | working-copy scan, fsevents-driven auto-snap, APFS clonefile workspaces, materialize/restore, tree-edit primitives |
| `tig-vis` | X25519 + XChaCha20-Poly1305 multi-recipient sealing for the "encrypted .env" use case |
| `tig-protocol` | wire DTOs shared between `tig` and `tigd` |
| `tigd` | axum HTTP daemon, OS-optional source control over JSON |
| `tig-cli` | the `tig` binary |

## End-to-end demos verified

Reproducible from the working directory — each was run during
development:

- **Snapshot-first model**: edit a file, `tig snap`, no `add`/`commit`
  ceremony. Auto-snaps on save via fsevents (`tig watch`).
- **APFS clonefile workspaces**: a 100 MB workdir cloned to a second
  workspace added **8 KB** of disk usage on APFS vs. **102 MB** for the
  `cp -r` baseline. Wall-clock about the same.
- **Op log + undo**: every state change recorded, skip-pairing undo
  walks past prior undos to reach the next "real" op.
- **Daemon, no working copy**: an agent over `curl` creates a change,
  PATCHes files, snaps, fetches the snapshot — never materializing
  anything to disk outside `.tig/store/objects/`.
- **Sealed values**: alice seals a `.env` for alice+bob using X25519 +
  XChaCha20-Poly1305 with per-recipient AAD binding. Both decrypt; carol
  is rejected with `NotARecipient`. The daemon ships ciphertext only.
- **Draft hiding**: alice's `tig draft` is invisible to bob — 404 on
  fetch, 404 on the snapshot hash (reachability gate). Publishing
  flips visibility; bob still can't mutate (409 — visibility ≠ ownership).
- **Restore**: `tig restore <prefix>` rewinds the working directory to
  any prior snapshot, refuses dirty workdirs without `--force`, refuses
  trees with sealed entries cleanly.

## Try it

```bash
cargo build --release
./target/release/tig init
echo "hello" > notes.md
./target/release/tig snap -m "first"
./target/release/tig log
```

`tigd` runs on `127.0.0.1:7400` by default:

```bash
./target/release/tigd /path/to/repo --bind 127.0.0.1:7400
curl http://127.0.0.1:7400/v1/changes
```

## Is this production-ready?

**No.** It is a prototype that proves the architecture compiles and
behaves. Notable gaps before anyone should trust it with code they care
about:

- No multi-process locking. Two `tig snap` invocations on the same repo
  can race and corrupt refs.
- No signing of objects. `X-Tig-Principal: alice` is trust-by-name.
- CBOR encoding is not canonical — content hashes are only stable
  *within this codebase*.
- No GC. The object store grows forever.
- `fs::remove_dir_all` mid-restore is not atomic; power loss can leave
  a half-restored workdir.
- O(N) oplog scan on every open; O(N changes) for snapshot reachability.
- Only validated on macOS / APFS. The Linux + Windows code paths
  compile but haven't been exercised.
- No diff, blame, grep, push, pull, or hooks.
- The daemon serializes all writes through a single Mutex.

See the full critique by asking a copy of the assistant that built it
"is this project ready for production use?" — the answer is candid.

## Provenance

Built end-to-end in a single Claude Code session, milestone by milestone:

1. Scaffolding + object model + first snap
2. fsevents auto-snap watcher
3. APFS clonefile workspaces
4. Op log + `tig undo`
5. `tigd` HTTP API
6. Sealed values
7. Draft-hiding + per-change visibility
8. `tig restore`

Each milestone shipped with an end-to-end demo against a real
filesystem and a real `curl` against a running daemon. The full
architecture document was written *first* and the code converged on it.

## License

Apache-2.0 OR MIT, dual-licensed at the user's choice. Same as most of
the Rust ecosystem.
