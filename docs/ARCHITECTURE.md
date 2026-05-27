# tig — architecture

> An alternative source control system designed for an era where most code
> is authored, reviewed, and operated on by AI agents.
>
> Inspired by Theo Browne's manifesto: git is barely good; we've been taken for
> fools; our agents deserve better.

This document is the foundation. Code that disagrees with this document is
wrong; this document being wrong is also possible — fix it here first, then
the code.

---

## 0. The thesis

git's data model was designed for distributed humans emailing patches in 2005.
It survived because nothing better shipped — not because it's right. Four
specific cracks have widened to chasms:

1. **All-or-nothing visibility.** "Public repo" means every byte, every
   in-flight branch, every CVE-fixing commit is world-readable the moment it
   touches `origin`. Every team reinvents `.env`, git-crypt, draft PRs, and
   private forks badly.
2. **Commits as the editing unit.** Humans are forced to context-switch
   between "writing code" and "narrating history." Agents inherit this
   ceremony and waste turns on `git add`, `git commit -m "wip"`, `git reset
   --soft HEAD~`.
3. **Worktrees as a bolt-on.** Same branch in two checkouts is forbidden.
   Storage is duplicated. Sync to `main` is manual. Modern filesystems offer
   block-level copy-on-write for free; git doesn't know.
4. **OS / filesystem dependence.** To run `git status` you need a real kernel,
   a real working tree, a real shell. An agent running in a 50MB lambda or a
   browser tab can't.

tig is the response.

---

## 1. Principles

These bind every design choice downstream.

**P1. Snapshots are the truth, commits are a presentation.**
Every operation produces an immutable snapshot. Users never "forget to
commit." `commit` as a verb does not exist.

**P2. Visibility is a first-class field, not a deployment story.**
Every object — blob, tree, snapshot, change — carries a visibility label.
The server enforces it on every fetch. There is no "make the repo public"
button; visibility is per-path, per-snapshot, per-principal.

**P3. The working copy is one of many projections.**
The repo's source of truth is the object store. Working copies are
filesystem materializations, cheap to create (block-clone), cheap to
discard. You can have zero working copies and still do useful work over the
API.

**P4. The API is the interface; the CLI is a client.**
Everything `tig` can do is also a `tigd` HTTP/2 call. WASM build of the
core lets a browser or sandboxed agent skip the daemon entirely.

**P5. Agents are first-class principals.**
Identities are typed (`user`, `agent`, `bot`, `system`). Every snapshot is
signed by its principal. "Show me what claude-3 changed last Tuesday" is a
single query.

**P6. Conflicts are data, not text markup.**
A conflict is a structured object. The CLI renders it as `<<<<<<<` for
humans; the API returns JSON for agents. Resolutions are records, not
file edits-that-happen-to-remove-markers.

**P7. The op log is the undo button.**
Every state-changing operation appends to a per-repo append-only oplog.
`tig undo` is `oplog.last().revert()`. This includes "I rebased and lost
work" — the previous snapshot is still in the store, the oplog has the
pointer.

---

## 2. Object model

Seven primitive object kinds. All are content-addressed by **BLAKE3-256**
(faster than SHA-256, tree-friendly, no length-extension foot-guns).

### 2.1 `Blob`
Opaque bytes. The unit of file content.

```rust
struct Blob { bytes: Vec<u8> }  // hash = BLAKE3(canonical_encoding(self))
```

### 2.2 `Tree`
A directory snapshot. Entries are sorted lexicographically by name for a
canonical encoding; encoding is length-prefixed CBOR (`tig-net::canonical`)
so hashes are stable across implementations.

```rust
struct Tree { entries: Vec<TreeEntry> }
struct TreeEntry {
    name: String,             // a single path component, no '/'
    kind: EntryKind,          // File | Tree | Symlink | Sealed | Conflict | Submodule
    target: Hash,             // hash of the referenced object
    mode: FileMode,           // unix-ish bits (preserved on round-trip)
    vis: Option<VisTag>,      // None = inherit from parent
}
```

`Sealed` and `Conflict` as first-class entry kinds is load-bearing — see §4
and §6.

### 2.3 `Snapshot`
The immutable point. Replaces git's `commit`.

```rust
struct Snapshot {
    parents: Vec<Hash>,       // 0 for root, ≥2 for merges
    tree: Hash,               // root tree
    author: PrincipalId,      // signed below
    timestamp: u64,           // unix nanos
    message: Option<String>,  // optional — auto-snaps are unmessaged
    op_id: Option<OpId>,      // the op that produced this snapshot
    vis: VisPolicy,           // who may read this snapshot
    sig: Signature,           // Ed25519 over canonical_encoding(snapshot-sans-sig)
}
```

Snapshots are **dense** — there is one per save event, not one per "commit
ceremony." A typical day produces hundreds. The DAG-walking UX (`tig log`)
filters by default to "snapshots that named a change" (i.e. user-meaningful
points).

### 2.4 `Change`
A *mutable* label pointing at a snapshot. Replaces git's `branch` and `HEAD`.
Inspired directly by jj's change-id concept.

```rust
struct Change {
    id: ChangeId,             // stable ULID, never mutates
    current: Hash,            // current Snapshot
    bookmark: Option<String>, // human name, optional — "main", "fix-foo"
    description: String,      // editable; not part of any snapshot hash
    visibility: VisLabel,     // public | org | team:X | private
    state: ChangeState,       // Working | Draft | Review | Landed | Abandoned
    history: Vec<Hash>,       // snapshots that have ever been .current
}
```

Key invariants:
- A `Change` is not content-addressed — it is a row in `refs/changes/`.
- `current` advances on every snapshot of the working copy.
- `history` lets `tig undo` rewind without losing data.
- Multiple workspaces can point at the same `Change`; the last writer wins,
  but conflicts surface immediately because both observed the same `current`.

### 2.5 `Op`
A line in the operation log. Append-only, per-repo.

```rust
struct Op {
    id: OpId,                 // monotonic
    ts: u64,
    actor: PrincipalId,
    kind: OpKind,             // Snap | NewChange | Land | Rebase | Seal | ...
    before: Vec<RefSnapshot>, // refs touched, before
    after: Vec<RefSnapshot>,  // refs touched, after
}
```

`tig undo` = "compute the diff between `before` and `after`, apply
inverse, append a compensating op."

### 2.6 `Sealed`
Encrypted-at-rest content with an explicit recipient set. Replaces `.env`.

```rust
struct Sealed {
    algo: SealAlgo,           // X25519 + ChaCha20-Poly1305 (default)
    recipients: Vec<RecipientKey>,
    ciphertext: Vec<u8>,
    nonce: [u8; 24],
    aad: Vec<u8>,             // includes the path → key is bound to location
}
```

A `Sealed` lives in the tree like a regular file (`TreeEntry::kind =
Sealed`). Reading it requires the principal's key. The hash is over the
ciphertext, so the object store doesn't need to decrypt to dedupe.

### 2.7 `Conflict`
A node in the tree that wasn't resolved by automatic merge.

```rust
struct Conflict {
    base: Option<Hash>,       // blob/tree at the merge base
    sides: Vec<ConflictSide>, // one per merge parent
    hints: Vec<ResolutionHint>, // semantic suggestions
}
struct ConflictSide { snapshot: Hash, value: Hash }
```

The CLI renders text-file conflicts as `<<<<<<<` markers (with the source
snapshot id, not just `HEAD`/`branch`). The API returns the struct. Either
form can resolve — the resolution is just `PATCH /tree/{path}` with the
chosen content.

---

## 3. Storage layout

A tig repo lives in `.tig/`. The directory is portable, but the canonical
form is a remote `tigd` instance — local `.tig/` is functionally a cache +
working set.

```
.tig/
  config.toml               # repo config, remotes, principal identity
  keys/                     # device keypair, signed by user/agent root
  store/
    objects/
      ab/                   # first 2 hex of BLAKE3
        cdef0123…           # remaining 62 hex; file contains canonical encoding
    pack/                   # repacked older objects (zstd-framed)
  refs/
    changes/<change-id>     # JSON, mutable; the Change record
    bookmarks/<name>        # text file, one line: change-id
    remotes/<remote>/…
  oplog/
    000000.log              # framed append-only; rotates at 64MiB
    index.lmdb              # opid → offset lookup
  workspaces/
    <ws-id>/
      manifest.toml         # which change(s) this WS materializes
      view.toml             # vis filter applied at materialization
      .marker               # APFS clonefile lineage marker
  vis/
    policy.toml             # default visibility, principal map
    keys/                   # recipient pubkeys for sealing
```

`store/objects/` is the only file-format-stable thing; everything else can
be rebuilt from the object store + oplog.

---

## 4. Visibility model (Theo §1)

The single biggest departure from git.

### 4.1 Labels

A `VisLabel` is one of:

- `public` — anyone with the repo URL
- `org:<org-id>` — members of an org
- `team:<team-id>` — members of a team
- `principal:<id>` — exactly one identity
- `sealed` — encrypted; only key-holders can read

Labels compose via a `VisPolicy` (a sorted set; "anyone in *any* listed
group" wins). A snapshot's effective visibility is the intersection of its
own `vis` and each tree entry's `vis` along the path.

### 4.2 Enforcement

Visibility is enforced by `tigd` at fetch time, not by client convention:

- `GET /repos/{r}/snapshots/{h}` returns 404 if the principal can't read it.
- A `Tree` returned to a non-privileged principal has `Sealed`-but-not-mine
  entries elided; their hashes are replaced with opaque "redacted" markers
  so the tree's hash *for that principal* still validates.
- The op log is filtered the same way: ops referencing redacted refs appear
  as `{kind: Redacted}` stubs.

This means "make subfolder X private inside an open-source repo" is:
```
tig share src/internal/ --vis=team:core
```
…and that's it. The public clone sees `src/internal/` as a `Redacted` tree.

### 4.3 In-flight PRs

A `Change` with `state: Draft` and `visibility: private` is invisible to
everyone but its author until they `tig publish`. The snapshots underneath
exist but are unfetchable. This is how you "hide in-flight PRs."

### 4.4 Embargoed security fixes

A snapshot can be authored, signed, and ready to deploy, but not yet
fetchable by the public. The author lands it with `--embargo=2026-07-01`;
`tigd` refuses to serve it to the public label until the embargo lifts. At
lift time, the snapshot becomes visible *atomically* — there's no race
where the tracker shows the fix before the binary ships.

### 4.5 Sealed values (replaces .env)

```
tig seal config/prod.env --recipients=team:ops -- \
    DATABASE_URL=postgres://… STRIPE_KEY=sk_live_…
```

writes a `Sealed` entry at `config/prod.env`. To a CI runner with the right
key it materializes as a real `.env`; to anyone else it's opaque
ciphertext. There is no separate "secrets product."

---

## 5. Snapshots over commits (Theo §2)

### 5.1 The save model

The working copy is watched (fsevents / inotify / ReadDirectoryChangesW).
On every meaningful pause (default 750ms debounced, configurable, or
synchronously before any `tig` command), the watcher:

1. Walks the working tree, hashing changed paths.
2. Builds a candidate `Tree` (reusing unchanged subtrees by hash).
3. If the new root tree differs from the current `Change`'s snapshot,
   constructs a `Snapshot { parents: [previous], tree, author, op_id }`.
4. Updates `Change::current` and `Change::history`.
5. Appends an `Op { kind: Snap }`.

Snapshots are cheap. A repo with 100k auto-snapshots is fine; the object
store is content-addressed, so unchanged trees and blobs cost zero bytes.

### 5.2 No staging area

`git add` does not exist. There is no "index." If you don't want a file
included, mark it ignored or unbind it from the change:

```
tig hold path/to/scratch.txt       # exclude from snapshots until released
tig release path/to/scratch.txt
```

### 5.3 The log presentation

By default `tig log` shows only **anchored snapshots** — ones with a
message, or a state transition (`Draft → Review`, `Review → Landed`), or
that were explicitly named (`tig anchor "fix the thing"`). Raw auto-snaps
are reachable with `tig log --all` or `tig op log`.

### 5.4 History rewriting is editing the present

There's no `rebase -i`. To "squash" you create a new Change whose parent is
the merge base and whose tree is the final tree. The old snapshots remain
in the store, reachable from the oplog for the GC interval (default 30
days). This is jj's "rewrite is just snapshot" insight, applied uniformly.

---

## 6. Workspaces & CoW (Theo §3)

### 6.1 The primitive

A **workspace** is a materialization of a Change into a real directory,
backed by filesystem block-cloning. Workspaces are ephemeral; the source of
truth is always the Change.

```
tig wt make feature-x --change=foo
# creates ./worktrees/feature-x/ with APFS clonefile of the parent change
```

### 6.2 Implementation per filesystem

| OS / FS         | Mechanism                                | Granularity |
| --------------- | ---------------------------------------- | ----------- |
| macOS APFS      | `clonefile(2)` per file                  | per-file    |
| Linux btrfs/xfs | `FICLONE` ioctl per file; `reflink` dir  | per-file    |
| Linux ext4      | hardlinks + break-on-write via watcher   | per-file*   |
| Windows ReFS    | `DUPLICATE_EXTENTS_TO_FILE`              | per-extent  |
| Windows NTFS    | hardlinks; CoW emulated via watcher      | per-file*   |
| anywhere        | fall back to `copy_file_range` + cache   | per-file    |

The `tig-fs` crate has one trait, `CloneEngine`, with a default
implementation per platform. `*` cases break-on-write by intercepting via
the watcher and copying-then-modifying.

### 6.3 Same change in two places

A `Change` can have N workspaces. They're independent CoW projections; if
both write, both produce candidate snapshots, and the second to finalize
sees a conflict (resolved with the §6 conflict model, not a wedge).

### 6.4 Auto-sync to bookmarks

```
tig wt make feature-x --change=foo --track=main:auto
```

If `main` advances while `feature-x` is checked out, the workspace
auto-rebases the change atop new `main` in the background. Because rebase
is "produce a new snapshot whose tree is `merge(old_tree, new_main_tree)`",
there's no working-copy stall — the new snapshot is computed against
hashes, then the working tree is updated only if there are no local edits.
If there are, the user is notified and resolves via §6.

### 6.5 Deletion is safe

`tig wt drop feature-x` removes the workspace directory. The Change is
untouched. There's no equivalent of `git worktree remove --force` data loss
because the working copy is never authoritative.

---

## 7. API-first; OS-optional (Theo §4)

### 7.1 `tigd` HTTP/2 surface

```
POST   /v1/repos
GET    /v1/repos/{repo}/changes                  list visible changes
POST   /v1/repos/{repo}/changes                  create change
GET    /v1/repos/{repo}/changes/{cid}            change record
PATCH  /v1/repos/{repo}/changes/{cid}/tree/{p}   write blob at path
GET    /v1/repos/{repo}/changes/{cid}/tree/{p}   read blob at path
DELETE /v1/repos/{repo}/changes/{cid}/tree/{p}
POST   /v1/repos/{repo}/changes/{cid}/anchor     promote auto-snap → named
POST   /v1/repos/{repo}/changes/{cid}/publish    Draft → Review
POST   /v1/repos/{repo}/changes/{cid}/land
POST   /v1/repos/{repo}/workspaces               create CoW materialization
DELETE /v1/repos/{repo}/workspaces/{wid}
GET    /v1/repos/{repo}/snapshots/{hash}         raw object (vis-checked)
POST   /v1/repos/{repo}/oplog/undo
GET    /v1/repos/{repo}/oplog?from=…             stream oplog
WS     /v1/repos/{repo}/watch                    live updates
```

Request bodies are JSON for ergonomics; bulk object fetch uses framed
length-prefixed BLAKE3-tagged binary.

### 7.2 No-filesystem mode

The same crate (`tig-core` + `tig-store-mem` + `tig-net`) compiles to
WASM with `wasm32-wasip2`. The whole "do source control" loop is:

```js
const tig = await Tig.connect("https://tigd.example.com/v1/repos/myrepo");
await tig.change("fix-thing").patch("src/foo.rs", newContents);
await tig.change("fix-thing").anchor("fix off-by-one");
await tig.change("fix-thing").publish();
```

No shell. No filesystem. An agent in a 50MB ephemeral container does
source control via HTTP.

### 7.3 Structured patches

A `PATCH /tree/{p}` accepts either:
- raw bytes (`Content-Type: application/octet-stream`), or
- a structured op (`Content-Type: application/vnd.tig.patch+json`):

```json
{ "op": "json-merge", "patch": {"version": "1.2.0"} }
{ "op": "line-edit", "diff": "@@ -3,2 +3,3 @@\n …" }
{ "op": "replace-region", "anchor": "fn foo", "with": "…" }
```

The server applies semantically. Two structured patches that touch
disjoint regions of the same file *don't conflict*. This is the agent
deserves better point made concrete.

---

## 8. Identity, signing, audit

Every snapshot is signed by its `author` (Ed25519). Principals are typed:

```toml
[principal.alice]
kind = "user"
pubkey = "ed25519:…"

[principal.claude-code]
kind = "agent"
pubkey = "ed25519:…"
parent = "alice"             # this agent acts on alice's behalf
```

`tig blame --by-kind=agent path/file.rs` lists every line last touched by
an agent. `tig audit --principal=claude-code --since=2026-05-01` lists
every snapshot the agent authored.

---

## 9. Networking & sync

Sync is **view-aware**: the client says "I am principal P; give me the
state of bookmark `main` and any of my Drafts." The server walks the DAG,
applies visibility filtering, and streams only the objects P doesn't have
and is allowed to see.

Wire protocol is HTTP/2 + a streaming framed format for object payloads.
Resumable on a per-object basis (object boundaries are natural chunk
boundaries; BLAKE3 verifies each).

No `git fetch --all` equivalent. There is no "all"; there is only "what I
can see."

---

## 10. Crate layout

```
tig/
  Cargo.toml                           workspace
  crates/
    tig-core/                          object model, hashing, canonical enc
    tig-store/                         on-disk object store
    tig-store-mem/                     in-memory store (tests, WASM)
    tig-fs/                            workspaces, CoW, watcher
    tig-vis/                           visibility, sealing, principals
    tig-protocol/                      shared wire types (serde + schemars)
    tig-net/                           HTTP client/server primitives
    tig-cli/                           the `tig` binary
    tigd/                              the `tigd` daemon binary
    tig-wasm/                          WASM bindings
  docs/
    ARCHITECTURE.md                    ← this file
```

Each crate has a clear seam. `tig-core` has zero I/O. `tig-store` depends
only on `tig-core` + `std::fs`. The CLI depends on everything; the daemon
depends on everything-except-fs (it can run with `tig-store-mem` for tests).

---

## 11. What ships in milestone 0

This is what gets built in the first sprint, so the project is real and
demonstrable rather than aspirational:

- [x] Repo scaffold + this doc.
- [ ] `tig-core`: Blob/Tree/Snapshot/Change with canonical CBOR enc + BLAKE3.
- [ ] `tig-store`: on-disk content store under `.tig/store/objects/`.
- [ ] `tig-fs::scan`: walk a directory, produce a candidate Tree.
- [ ] `tig-cli`:
  - `tig init` — create `.tig/`
  - `tig snap [-m msg]` — synchronous snapshot of CWD
  - `tig log` — show change history
  - `tig cat-object <hash>` — debug: print any object
  - `tig change new <desc>` — create a Change
- [ ] End-to-end smoke test: init → edit → snap → snap → log shows two
      snapshots → cat-object recovers the blob.

Subsequent milestones, in rough dependency order:
1. Op log + `tig undo`.
2. fs watcher → auto-snap.
3. Workspaces + APFS clonefile.
4. Visibility labels + sealing.
5. `tigd` + remote sync.
6. Conflict objects + structured patches.
7. WASM build.
8. Agent identities + audit.

---

## 12. What this is not

- Not a git-compatible rewrite. We import via `git fast-export`; we don't
  pretend to be `git`.
- Not a SaaS. `tigd` is the daemon you self-host; a hosted offering can
  exist later. Local-first works fully without a server.
- Not a replacement for code review tooling — but a Change with `state:
  Review` is the unit a review tool would attach to, and reviews are
  another kind of `Op` in the log.
