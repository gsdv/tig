//! The `tig` CLI binary.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use tig_core::{
    Blob, Change, ChangeState, Encodable, ObjectKind, PrincipalId, Snapshot, Tree, VisLabel,
};
use tig_fs::{
    blame_at, detect_clone_engine, diff_trees, grep_tree, lookup_entry, materialize_change_into,
    materialize_from_workspace, restore_tree_into, snap_change_directly, snap_now, watch_and_snap,
    write_sealed_at_path, BlameLine, ChangeKind as FsChangeKind, DiffOptions, FileDiff,
    GrepOptions, HunkLine, MaterializeOptions, MaterializeOutcome, OnUnsealable, RestoreOptions,
    SnapOptions, SnapOutcome, WatchEvent, WatchOptions,
};
use tig_store::{
    collect_garbage, undo_once, workspace_ref_snapshot, write_marker, GcOptions, OpInProgress,
    OpKind, OpLog, RefSnapshot, RefStore, Repository, Workspace, WorkspaceId, WorkspaceKind,
    WorkspaceManifest, WorkspaceMarker, WorkspaceStore, DEFAULT_WORKTREE_DIR,
};
use tig_vis::{
    seal as do_seal, sign_token, unseal as do_unseal, Claims, KeyPair, Principal, PrincipalKind,
    PrincipalStore, SignKeyPair,
};

#[derive(Parser)]
#[command(
    name = "tig",
    version,
    about = "An alternative to git, built for agents"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a fresh tig repo in the current directory.
    Init,

    /// Take a snapshot of the working directory.
    Snap {
        #[arg(short, long)]
        message: Option<String>,
    },

    /// Auto-snap on every save. Press ctrl-c to stop.
    Watch {
        #[arg(long, default_value_t = 750)]
        debounce_ms: u64,
    },

    /// Show the history of the current Change.
    Log {
        #[arg(long)]
        all: bool,
        /// Show each snapshot's diff against its parent (unified format).
        /// Equivalent of `git log -p`.
        #[arg(short = 'p', long = "patch")]
        patch: bool,
    },

    /// Show what HEAD points at.
    Status,

    /// Work with Changes.
    #[command(subcommand)]
    Change(ChangeCmd),

    /// Work with workspaces (worktrees).
    #[command(subcommand, alias = "worktree")]
    Wt(WtCmd),

    /// Rewind the most recent operation that hasn't been undone yet.
    Undo,

    /// Inspect the operation log.
    #[command(subcommand)]
    Op(OpCmd),

    /// Manage identities (X25519 keypairs for sealing).
    #[command(subcommand)]
    Identity(IdentityCmd),

    /// Encrypt a value for one or more recipients and write it at PATH.
    Seal {
        /// Tree path inside the current change. Also used as AAD —
        /// moving the sealed entry to another path breaks decryption.
        path: String,
        /// Comma-separated recipient names (must exist in the principal store).
        #[arg(long, value_delimiter = ',', required = true)]
        recipients: Vec<String>,
        /// Read the plaintext from this file. If omitted, read stdin.
        #[arg(long)]
        from_file: Option<PathBuf>,
        /// Inline plaintext. Mutually exclusive with --from-file.
        #[arg(long, conflicts_with = "from_file")]
        data: Option<String>,
    },

    /// Decrypt a sealed entry as the identity given by --as (or $TIG_AS).
    Reveal {
        path: String,
        /// Identity to decrypt as. Falls back to $TIG_AS.
        #[arg(long, value_name = "NAME")]
        r#as: Option<String>,
    },

    /// Create a new change in Draft + Private state — invisible to
    /// anyone but you until you `tig change publish` it. The "hidden
    /// in-flight PR" from Theo's §1.
    Draft { description: String },

    /// Show changes in unified-diff format. Defaults follow git's
    /// conventions — the workdir is the implicit "to" side.
    ///
    /// RANGE forms:
    ///   tig diff                 (current snap → workdir)
    ///   tig diff <prefix>        (<prefix> snap → workdir)
    ///   tig diff <from>..<to>    (snap-to-snap, no workdir involved)
    Diff {
        #[arg(value_name = "RANGE")]
        range: Option<String>,
        /// Skip hunks; print file list only.
        #[arg(long)]
        no_hunks: bool,
        /// Path-prefix filter, comma-separated. Empty = no filter.
        #[arg(long, value_delimiter = ',')]
        path: Vec<String>,
    },

    /// Bring the working directory's contents back into alignment with
    /// a chosen snapshot. The current change advances with a new
    /// snapshot whose tree matches the restored state.
    ///
    /// SNAP_PREFIX is any unambiguous hex prefix (≥ 4 chars) of a
    /// snapshot hash. Look up candidates with `tig log --all` or
    /// `tig op log`.
    Restore {
        snap_prefix: String,
        /// Discard uncommitted changes in the workdir. Required when
        /// the workdir doesn't match the current snapshot's tree.
        #[arg(long)]
        force: bool,
        /// Identity to decrypt sealed entries with. Falls back to
        /// `$TIG_AS`. Without it, a target tree containing any sealed
        /// entries is refused.
        #[arg(long, value_name = "NAME")]
        r#as: Option<String>,
    },

    /// Mint a signed bearer token for the daemon. Print the token
    /// string to stdout; pass it to the daemon as
    /// `Authorization: Bearer <token>`.
    AuthToken {
        /// Identity to mint for. Must have an Ed25519 signing
        /// secret in the local principal store. Falls back to
        /// $TIG_AS.
        #[arg(long, value_name = "NAME")]
        r#as: Option<String>,
        /// Token lifetime in seconds. Default 1 hour.
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
    },

    /// Per-line authorship attribution. Walks back through the
    /// snapshot history and assigns each line to the snap that last
    /// introduced or modified it.
    Blame {
        path: String,
        /// Snap prefix to blame against. Defaults to the current snap.
        #[arg(value_name = "SNAP")]
        snap: Option<String>,
    },

    /// Pattern search across the files of a snapshot's tree. Output
    /// is `path:line_number:line`, one match per line. Skips binary
    /// files, sealed entries, and the conflict/submodule kinds.
    ///
    /// Defaults to literal substring matching. Pass `-E` / `--regex`
    /// for a Rust-`regex` expression.
    Grep {
        /// The pattern to search for.
        pattern: String,
        /// Snap prefix to search at. Defaults to the workspace's
        /// current snap.
        #[arg(long, value_name = "SNAP")]
        snap: Option<String>,
        /// Treat the pattern as a regex.
        #[arg(short = 'E', long)]
        regex: bool,
        /// Case-insensitive match.
        #[arg(short = 'i', long = "ignore-case")]
        ignore_case: bool,
        /// Path-prefix filter. Repeatable.
        #[arg(long = "path", value_name = "PREFIX")]
        path: Vec<String>,
        /// Cap matches per file.
        #[arg(long, value_name = "N")]
        max_per_file: Option<usize>,
        /// Cap total matches.
        #[arg(long, value_name = "N")]
        max_total: Option<usize>,
    },

    /// Print any object by its hash. Useful for debugging.
    CatObject { hash: String },

    /// Collect garbage in the object store. Removes objects unreachable
    /// from any current change *or* from any operation still in the
    /// op-log (so `tig undo` of a `ChangeNew` is not silently
    /// destructive).
    Gc {
        /// Print what would be removed, but don't actually delete.
        #[arg(long)]
        dry_run: bool,
        /// **Dangerous.** Skip oplog-captured snapshots when marking.
        /// A subsequent `tig undo` of a `ChangeNew` op will silently
        /// fail to restore the change's contents. Only useful if you
        /// know the oplog is already truncated past your last
        /// `ChangeNew` and you want to free a chunk of disk.
        #[arg(long)]
        ignore_oplog: bool,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Generate a fresh X25519 keypair and register it locally.
    New { name: String },
    /// List every principal known to this repo.
    List,
    /// Show one principal (pubkey + whether the local secret is present).
    Show { name: String },
}

#[derive(Subcommand)]
enum OpCmd {
    /// Show every operation recorded against this repo, newest first.
    Log {
        #[arg(long, default_value_t = 30)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum ChangeCmd {
    /// Create a new change at the current snapshot. Defaults to
    /// Working/Public — see `tig draft` for the hidden-in-flight variant.
    New { description: String },
    /// List every change in the repo (no visibility filtering — this is
    /// the local CLI; the daemon is where filtering happens).
    List,
    /// Flip a change's state. Defaults to the current workspace's change.
    SetState {
        #[arg(long, value_parser = ["working", "draft", "review", "landed", "abandoned"])]
        state: String,
        #[arg(long)]
        id: Option<String>,
    },
    /// Flip a change's visibility ("public" or "private").
    SetVisibility {
        #[arg(long, value_parser = ["public", "private"])]
        vis: String,
        #[arg(long)]
        id: Option<String>,
    },
    /// Convenience: flip state to `Working` and visibility to `Public`.
    /// The common "I'm done hiding this; let other people see it" move.
    Publish {
        #[arg(long)]
        id: Option<String>,
    },
}

#[derive(Subcommand)]
enum WtCmd {
    /// Materialize a new workspace from the current change.
    Make {
        /// Human-readable name for the new workspace.
        name: String,
        /// Where to put it. Default: `<current-workdir>/.tig-worktrees/<name>`.
        #[arg(long)]
        at: Option<PathBuf>,
        /// Identity to decrypt sealed entries with. Falls back to
        /// `$TIG_AS`. When set, the donor-clone fast path is skipped
        /// so that sealed entries are always decrypted from the
        /// canonical objects rather than copied from whatever a donor
        /// happens to hold on disk.
        #[arg(long, value_name = "NAME")]
        r#as: Option<String>,
    },
    /// List every workspace known to this repo.
    List,
    /// Remove a secondary workspace.
    Drop {
        name: String,
        /// Keep the workspace's files on disk; just deregister it.
        #[arg(long)]
        keep_files: bool,
    },
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("tig: error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Init => cmd_init(),
        Cmd::Snap { message } => cmd_snap(message),
        Cmd::Watch { debounce_ms } => cmd_watch(debounce_ms),
        Cmd::Log { all, patch } => cmd_log(all, patch),
        Cmd::Status => cmd_status(),
        Cmd::Change(ChangeCmd::New { description }) => cmd_change_new(&description),
        Cmd::Change(ChangeCmd::List) => cmd_change_list(),
        Cmd::Change(ChangeCmd::SetState { state, id }) => {
            cmd_change_transition(id.as_deref(), Some(&state), None)
        }
        Cmd::Change(ChangeCmd::SetVisibility { vis, id }) => {
            cmd_change_transition(id.as_deref(), None, Some(&vis))
        }
        Cmd::Change(ChangeCmd::Publish { id }) => {
            cmd_change_transition(id.as_deref(), Some("working"), Some("public"))
        }
        Cmd::Draft { description } => cmd_draft(&description),
        Cmd::Diff {
            range,
            no_hunks,
            path,
        } => cmd_diff(range.as_deref(), no_hunks, &path),
        Cmd::Restore {
            snap_prefix,
            force,
            r#as,
        } => cmd_restore(&snap_prefix, force, r#as.as_deref()),
        Cmd::Blame { path, snap } => cmd_blame(&path, snap.as_deref()),
        Cmd::Grep {
            pattern,
            snap,
            regex,
            ignore_case,
            path,
            max_per_file,
            max_total,
        } => cmd_grep(
            &pattern,
            snap.as_deref(),
            regex,
            ignore_case,
            &path,
            max_per_file,
            max_total,
        ),
        Cmd::AuthToken { r#as, ttl } => cmd_auth_token(r#as.as_deref(), ttl),
        Cmd::Wt(WtCmd::Make { name, at, r#as }) => {
            cmd_wt_make(&name, at.as_deref(), r#as.as_deref())
        }
        Cmd::Wt(WtCmd::List) => cmd_wt_list(),
        Cmd::Wt(WtCmd::Drop { name, keep_files }) => cmd_wt_drop(&name, keep_files),
        Cmd::Undo => cmd_undo(),
        Cmd::Op(OpCmd::Log { limit }) => cmd_op_log(limit),
        Cmd::Identity(IdentityCmd::New { name }) => cmd_identity_new(&name),
        Cmd::Identity(IdentityCmd::List) => cmd_identity_list(),
        Cmd::Identity(IdentityCmd::Show { name }) => cmd_identity_show(&name),
        Cmd::Seal {
            path,
            recipients,
            from_file,
            data,
        } => cmd_seal(&path, &recipients, from_file.as_deref(), data.as_deref()),
        Cmd::Reveal { path, r#as } => cmd_reveal(&path, r#as.as_deref()),
        Cmd::CatObject { hash } => cmd_cat_object(&hash),
        Cmd::Gc {
            dry_run,
            ignore_oplog,
        } => cmd_gc(dry_run, ignore_oplog),
    }
}

fn cmd_gc(dry_run: bool, ignore_oplog: bool) -> Result<()> {
    let ws = discover_workspace()?;
    let _lock = ws.repo.lock_for_write()?;
    let log = OpLog::open(ws.repo.root())?;
    let opts = GcOptions {
        dry_run,
        include_oplog_snapshots: !ignore_oplog,
    };
    let summary = collect_garbage(&ws.repo, &log, &opts)?;
    if summary.dry_run {
        println!(
            "dry-run: would remove {} object(s), {} kept, {} bytes freed",
            summary.removed, summary.kept, summary.bytes_freed,
        );
    } else {
        println!(
            "removed {} object(s), {} kept, {} bytes freed",
            summary.removed, summary.kept, summary.bytes_freed,
        );
    }
    if ignore_oplog && summary.removed > 0 {
        eprintln!(
            "  warning: --ignore-oplog was set; future `tig undo` of a ChangeNew may be incomplete",
        );
    }
    Ok(())
}

fn cwd() -> Result<PathBuf> {
    std::env::current_dir().context("getting current directory")
}

fn discover_workspace() -> Result<Workspace> {
    Ok(Workspace::discover(cwd()?)?)
}

fn principal() -> PrincipalId {
    let name = std::env::var("USER").unwrap_or_else(|_| "anonymous".into());
    PrincipalId::local(&name)
}

fn snap_options(message: Option<String>) -> SnapOptions {
    SnapOptions {
        author: principal(),
        message,
        ..Default::default()
    }
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Look up the named identity (or `$TIG_AS`) in the principal store
/// and return its X25519 secret. Returns `Ok(None)` if neither was
/// supplied. Errors if the name was given but missing/keyless.
fn resolve_unseal_identity(
    repo: &Repository,
    as_name: Option<&str>,
) -> Result<Option<tig_vis::SecretKey>> {
    let name = match as_name
        .map(String::from)
        .or_else(|| std::env::var("TIG_AS").ok())
    {
        Some(n) => n,
        None => return Ok(None),
    };
    let store = PrincipalStore::open(repo.root())?;
    let identity = store.get(&name)?;
    let secret = identity
        .secret()
        .with_context(|| format!("identity {name:?} has no local sealing secret"))?;
    Ok(Some(secret))
}

// --- commands -------------------------------------------------------------

fn cmd_init() -> Result<()> {
    let repo = Repository::init(cwd()?)?;
    println!(
        "Initialized empty tig repository in {}",
        repo.root().display()
    );
    Ok(())
}

fn cmd_snap(message: Option<String>) -> Result<()> {
    let mut ws = discover_workspace()?;
    let _lock = ws.repo.lock_for_write()?;
    let mut log = OpLog::open(ws.repo.root())?;
    let outcome = snap_now(&mut ws, &mut log, &snap_options(message))?;
    print_snap_outcome(&ws, &outcome, /* verbose */ true);
    Ok(())
}

fn cmd_watch(debounce_ms: u64) -> Result<()> {
    let mut ws = discover_workspace()?;
    let mut log = OpLog::open(ws.repo.root())?;
    let stop = Arc::new(AtomicBool::new(false));

    let stop_for_handler = stop.clone();
    ctrlc::set_handler(move || stop_for_handler.store(true, Ordering::SeqCst))
        .context("installing ctrl-c handler")?;

    let watch_opts = WatchOptions {
        debounce: Duration::from_millis(debounce_ms),
        stop,
        ..Default::default()
    };
    let snap_opts = snap_options(None);

    let label = ws.id_for_display();
    watch_and_snap(
        &mut ws,
        &mut log,
        &watch_opts,
        &snap_opts,
        |event| match event {
            WatchEvent::Started { workdir } => {
                println!(
                    "watching {} [{label}] (debounce {}ms) — ctrl-c to stop",
                    workdir.display(),
                    debounce_ms
                );
            }
            WatchEvent::Snap(outcome) => print_outcome_one_liner(&outcome),
            WatchEvent::Idle => {}
            WatchEvent::Error(e) => eprintln!("  ! {e}"),
            WatchEvent::Stopped => println!("stopped."),
        },
    )?;
    Ok(())
}

fn print_outcome_one_liner(outcome: &SnapOutcome) {
    if let SnapOutcome::Snapped { snapshot, .. } = outcome {
        println!("  snap {}  (auto)", &snapshot.to_hex()[..12]);
    }
}

fn print_snap_outcome(ws: &Workspace, outcome: &SnapOutcome, verbose: bool) {
    match outcome {
        SnapOutcome::Snapped {
            snapshot, change, ..
        } => {
            let snap = Snapshot::decode(&ws.repo.get(snapshot).expect("just wrote it"))
                .expect("just encoded it");
            let label = snap.message.as_deref().unwrap_or("(auto)");
            println!("  snap {}  {label}", &snapshot.to_hex()[..12]);
            if verbose {
                println!("    on change {} ({})", change.id, change.description);
                println!("    in workspace {}", ws.id_for_display());
            }
        }
        SnapOutcome::Unchanged { change } => {
            if verbose {
                println!(
                    "nothing to snap: working copy matches {}",
                    &change.current.to_hex()[..12]
                );
            }
        }
    }
}

fn cmd_log(all: bool, patch: bool) -> Result<()> {
    let ws = discover_workspace()?;
    let head = ws
        .current_change_id()?
        .ok_or_else(|| anyhow!("no current change — repo is empty (try `tig snap`)"))?;
    let change = ws.repo.get_change(&head)?;

    println!("change {}", change.id);
    println!("    {}", change.description);
    println!(
        "    {:?}, {} snapshot(s), in workspace {}",
        change.state,
        change.history.len(),
        ws.id_for_display()
    );
    println!();

    let diff_opts = DiffOptions {
        no_hunks: false,
        paths: Vec::new(),
        context_lines: 3,
    };

    for h in change.history.iter().rev() {
        let snap = Snapshot::decode(&ws.repo.get(h)?)?;
        if !all && snap.message.is_none() {
            continue;
        }
        let short = &h.to_hex()[..12];
        let label = snap.message.as_deref().unwrap_or("(auto)");
        let ts = format_ts(snap.timestamp_ns);
        println!("  {short}  {ts}  {}  — {label}", snap.author);

        if patch {
            // Compute diff against this snap's parent. Root snaps diff
            // against the empty tree.
            let parent_tree = match snap.parents.first() {
                Some(p) => Snapshot::decode(&ws.repo.get(p)?)?.tree,
                None => ws.repo.put(&Tree::new().encode()?)?,
            };
            let diffs = diff_trees(&ws.repo, &parent_tree, &snap.tree, &diff_opts)?;
            // Indent each diff line under the log entry so it's visually
            // attached to the snap above it.
            for fd in &diffs {
                print_file_diff_indented(fd, "    ");
            }
            if !diffs.is_empty() {
                println!();
            }
        }
    }
    Ok(())
}

/// Same as `print_file_diff` but prefixes every output line with
/// `prefix`. Used by `log -p` so the inline diffs visually nest under
/// each snap entry.
fn print_file_diff_indented(fd: &FileDiff, prefix: &str) {
    use std::fmt::Write as _;
    // Render to a string and emit each line with the prefix. This
    // avoids forking the format-emitting code.
    let mut buf = String::new();
    let _ = writeln!(&mut buf, "diff --tig a/{0} b/{0}", fd.path);
    match &fd.kind {
        FsChangeKind::TypeChanged { from, to } => {
            let _ = writeln!(&mut buf, "type changed: {from:?} -> {to:?}");
            print_indented(&buf, prefix);
            return;
        }
        FsChangeKind::Added => {
            let _ = writeln!(&mut buf, "new {} mode", entry_kind_label(fd.entry_kind));
        }
        FsChangeKind::Removed => {
            let _ = writeln!(&mut buf, "removed {}", entry_kind_label(fd.entry_kind));
        }
        FsChangeKind::Modified => {}
    }
    if fd.entry_kind != tig_core::EntryKind::File {
        print_indented(&buf, prefix);
        return;
    }
    if fd.binary {
        let _ = writeln!(&mut buf, "Binary files a/{0} and b/{0} differ", fd.path);
        print_indented(&buf, prefix);
        return;
    }
    let (left, right) = match fd.kind {
        FsChangeKind::Added => ("/dev/null".to_string(), format!("b/{}", fd.path)),
        FsChangeKind::Removed => (format!("a/{}", fd.path), "/dev/null".to_string()),
        _ => (format!("a/{}", fd.path), format!("b/{}", fd.path)),
    };
    let _ = writeln!(&mut buf, "--- {left}");
    let _ = writeln!(&mut buf, "+++ {right}");
    if let Some(hunks) = &fd.hunks {
        for h in hunks {
            let from_r = if h.from_len == 1 {
                format!("{}", h.from_start)
            } else {
                format!("{},{}", h.from_start, h.from_len)
            };
            let to_r = if h.to_len == 1 {
                format!("{}", h.to_start)
            } else {
                format!("{},{}", h.to_start, h.to_len)
            };
            let _ = writeln!(&mut buf, "@@ -{from_r} +{to_r} @@");
            for line in &h.lines {
                match line {
                    HunkLine::Context(s) => {
                        let _ = writeln!(&mut buf, " {s}");
                    }
                    HunkLine::Add(s) => {
                        let _ = writeln!(&mut buf, "+{s}");
                    }
                    HunkLine::Remove(s) => {
                        let _ = writeln!(&mut buf, "-{s}");
                    }
                }
            }
        }
    }
    print_indented(&buf, prefix);
}

fn print_indented(buf: &str, prefix: &str) {
    for line in buf.lines() {
        println!("{prefix}{line}");
    }
}

fn cmd_status() -> Result<()> {
    let ws = discover_workspace()?;
    println!("workspace:   {}", ws.id_for_display());
    println!("workdir:     {}", ws.workdir().display());
    println!("repo:        {}", ws.repo.root().display());
    match ws.current_change_id()? {
        None => println!("change:      <none — try `tig snap`>"),
        Some(id) => {
            let c = ws.repo.get_change(&id)?;
            println!("change:      {}", c.id);
            println!("  description: {}", c.description);
            println!("  author:      {}", c.author);
            println!("  state:       {:?}", c.state);
            println!("  visibility:  {}", c.visibility.name());
            println!("  current:     {}", c.current);
            println!("  snapshots:   {}", c.history.len());
        }
    }
    Ok(())
}

fn cmd_change_new(description: &str) -> Result<()> {
    let mut ws = discover_workspace()?;
    let _lock = ws.repo.lock_for_write()?;
    let mut log = OpLog::open(ws.repo.root())?;

    let current = match ws.current_change_id()? {
        Some(id) => ws.repo.get_change(&id)?.current,
        None => {
            let tree_h = ws.repo.put(&Tree::new().encode()?)?;
            let snap = Snapshot {
                parents: vec![],
                tree: tree_h,
                author: principal(),
                timestamp_ns: Snapshot::current_timestamp_ns(),
                message: Some("(empty)".into()),
                op_id: None,
            };
            ws.repo.put(&snap.encode()?)?
        }
    };
    let change = Change::new(description, principal(), current);

    let workspace_ref_before = workspace_ref_snapshot(&ws)?;
    let change_ref_before = RefSnapshot::Change {
        id: change.id.clone(),
        value: None,
    };

    ws.repo.put_change(&change)?;
    ws.set_current_change_id(&change.id)?;

    let workspace_ref_after = workspace_ref_snapshot(&ws)?;
    let change_ref_after = RefSnapshot::Change {
        id: change.id.clone(),
        value: Some(change.clone()),
    };

    log.append(OpInProgress {
        actor: principal(),
        kind: OpKind::ChangeNew {
            change_id: change.id.clone(),
            description: description.to_string(),
        },
        before: vec![workspace_ref_before, change_ref_before],
        after: vec![workspace_ref_after, change_ref_after],
    })?;

    println!("created change {}", change.id);
    println!("    {description}");
    Ok(())
}

fn cmd_change_list() -> Result<()> {
    let ws = discover_workspace()?;
    let current = ws.current_change_id()?;
    let mut any = false;
    for id in ws.repo.refs().list_changes()? {
        let c = ws.repo.get_change(&id)?;
        let marker = if current.as_ref() == Some(&c.id) {
            "*"
        } else {
            " "
        };
        println!(
            "{marker} {}  {:?}/{:<7}  by {:<14} — {}",
            c.id,
            c.state,
            c.visibility.name(),
            c.author.to_string(),
            c.description
        );
        any = true;
    }
    if !any {
        println!("no changes yet");
    }
    Ok(())
}

// --- workspace commands --------------------------------------------------

fn cmd_wt_make(name: &str, at: Option<&Path>, as_name: Option<&str>) -> Result<()> {
    if !is_valid_workspace_name(name) {
        return Err(anyhow!(
            "invalid workspace name: {name:?} (no '/', '..', or empty)"
        ));
    }

    let source = discover_workspace()?;
    let _lock = source.repo.lock_for_write()?;
    let source_change = source
        .current_change_id()?
        .ok_or_else(|| anyhow!("nothing checked out here yet — try `tig snap` first"))?;

    // Destination path.
    let dest = match at {
        Some(p) => p.to_path_buf(),
        None => source.workdir().join(DEFAULT_WORKTREE_DIR).join(name),
    };
    if dest.exists() {
        return Err(anyhow!("destination already exists: {}", dest.display()));
    }

    // Resolve the optional `--as` identity into an X25519 secret. We
    // build the closure here so it borrows the secret for the
    // duration of materialize.
    let identity_secret = resolve_unseal_identity(&source.repo, as_name)?;
    let unsealer_closure = identity_secret.as_ref().map(|secret| {
        move |sealed: &tig_core::Sealed, aad: &[u8]| -> std::result::Result<Vec<u8>, String> {
            do_unseal(sealed, secret, aad).map_err(|e| e.to_string())
        }
    });

    // With `--as`, force the render path so sealed entries get
    // decrypted from the canonical objects. Without `--as`, prefer
    // the donor-clone fast path when available.
    let donor = if unsealer_closure.is_some() {
        None
    } else {
        pick_donor(&source, &source_change)?
    };

    // Make parent directories so `dest` itself can be created by the
    // materializer.
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let outcome = match &donor {
        Some(donor_path) => {
            let engine = detect_clone_engine();
            let label = engine.name();
            let outcome = materialize_from_workspace(donor_path, &dest, engine.as_ref())?;
            println!("  cloned from {} via {label}", donor_path.display());
            outcome
        }
        None => {
            let change = source.repo.get_change(&source_change)?;
            let opts = MaterializeOptions {
                unsealer: unsealer_closure
                    .as_ref()
                    .map(|c| c as &tig_fs::UnsealFn<'_>),
                on_unsealable: OnUnsealable::Error,
            };
            let outcome = materialize_change_into(&source.repo, &change.current, &dest, &opts)?;
            if unsealer_closure.is_some() {
                println!(
                    "  rendered from objects, decrypting sealed entries as {}",
                    as_name
                        .map(String::from)
                        .or_else(|| std::env::var("TIG_AS").ok())
                        .unwrap_or_else(|| "?".into())
                );
            } else {
                println!("  rendered from objects (no donor workspace available)");
            }
            outcome
        }
    };

    // Register the new workspace.
    let manifest = WorkspaceManifest {
        id: WorkspaceId::new(),
        name: name.to_string(),
        location: dest.canonicalize().unwrap_or(dest.clone()),
        change_id: source_change.clone(),
        created_ns: now_ns(),
    };
    let store = WorkspaceStore::open(source.repo.root())?;
    store.put(&manifest)?;
    write_marker(
        &manifest.location,
        &WorkspaceMarker {
            repo: source.repo.root().to_path_buf(),
            workspace_id: manifest.id.clone(),
        },
    )?;

    let mut log = OpLog::open(source.repo.root())?;
    log.append(OpInProgress {
        actor: principal(),
        kind: OpKind::WtMake {
            workspace_id: manifest.id.clone(),
            name: manifest.name.clone(),
        },
        before: vec![RefSnapshot::Workspace {
            id: manifest.id.clone(),
            value: None,
        }],
        after: vec![RefSnapshot::Workspace {
            id: manifest.id.clone(),
            value: Some(manifest.clone()),
        }],
    })?;

    match outcome {
        MaterializeOutcome::Cloned { engine, .. } => {
            println!(
                "  workspace {} ({}) ready at {} [engine: {engine}]",
                manifest.name,
                manifest.id,
                manifest.location.display()
            );
        }
        MaterializeOutcome::Rendered {
            files,
            bytes,
            sealed_unsealed,
            ..
        } => {
            println!(
                "  workspace {} ({}) ready at {} [{} files, {} bytes]",
                manifest.name,
                manifest.id,
                manifest.location.display(),
                files,
                bytes
            );
            if sealed_unsealed > 0 {
                eprintln!(
                    "  note: {sealed_unsealed} sealed entr{} decrypted to plaintext on disk. \
                     Re-seal before snap with `tig seal <path> --recipients ...` \
                     or the next snap will store them as regular blobs.",
                    if sealed_unsealed == 1 { "y" } else { "ies" }
                );
            }
        }
    }
    Ok(())
}

fn cmd_wt_list() -> Result<()> {
    let ws = discover_workspace()?;
    let store = WorkspaceStore::open(ws.repo.root())?;
    let manifests = store.list()?;

    // Main workspace first.
    let head = ws.repo.head()?;
    let head_label = head
        .as_ref()
        .map(|c| c.to_string())
        .unwrap_or("<none>".into());
    println!(
        "* (main)  {}  → change {}",
        ws.repo.workdir().display(),
        head_label
    );

    let current_id = ws.workspace_id().cloned();
    for m in manifests {
        let marker = if current_id.as_ref() == Some(&m.id) {
            "*"
        } else {
            " "
        };
        println!(
            "{marker} {}    {}  → change {}",
            m.name,
            m.location.display(),
            m.change_id
        );
    }
    Ok(())
}

fn cmd_wt_drop(name: &str, keep_files: bool) -> Result<()> {
    let ws = discover_workspace()?;
    let _lock = ws.repo.lock_for_write()?;
    let store = WorkspaceStore::open(ws.repo.root())?;
    let target = store
        .find_by_name(name)?
        .ok_or_else(|| anyhow!("no workspace named {name:?}"))?;

    if ws.workspace_id() == Some(&target.id) {
        return Err(anyhow!(
            "refusing to drop the workspace you're currently in"
        ));
    }

    if !keep_files && target.location.exists() {
        std::fs::remove_dir_all(&target.location)
            .with_context(|| format!("removing {}", target.location.display()))?;
    }
    let target_snapshot = target.clone();
    store.delete(&target.id)?;

    let mut log = OpLog::open(ws.repo.root())?;
    log.append(OpInProgress {
        actor: principal(),
        kind: OpKind::WtDrop {
            workspace_id: target_snapshot.id.clone(),
            name: target_snapshot.name.clone(),
        },
        before: vec![RefSnapshot::Workspace {
            id: target_snapshot.id.clone(),
            value: Some(target_snapshot.clone()),
        }],
        after: vec![RefSnapshot::Workspace {
            id: target_snapshot.id.clone(),
            value: None,
        }],
    })?;

    println!(
        "dropped workspace {} ({})",
        target_snapshot.name, target_snapshot.id
    );
    if keep_files {
        println!("  files left at {}", target_snapshot.location.display());
    }
    Ok(())
}

fn is_valid_workspace_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && !name.contains('\0') && name != "." && name != ".."
}

fn pick_donor(source: &Workspace, target_change: &tig_core::ChangeId) -> Result<Option<PathBuf>> {
    // 1. The current workspace itself if its change matches.
    if source.current_change_id()?.as_ref() == Some(target_change) {
        return Ok(Some(source.workdir().to_path_buf()));
    }
    // 2. Any registered secondary workspace whose change matches.
    let store = WorkspaceStore::open(source.repo.root())?;
    for m in store.list()? {
        if &m.change_id == target_change && m.location.exists() {
            return Ok(Some(m.location));
        }
    }
    // 3. If the target_change matches the main workspace's HEAD, use the
    //    main workdir.
    if matches!(source.kind, WorkspaceKind::Secondary(_)) {
        if let Some(head) = source.repo.head()? {
            if &head == target_change {
                return Ok(Some(source.repo.workdir().to_path_buf()));
            }
        }
    }
    Ok(None)
}

// --- op log + undo -------------------------------------------------------

fn cmd_undo() -> Result<()> {
    let ws = discover_workspace()?;
    let _lock = ws.repo.lock_for_write()?;
    let mut log = OpLog::open(ws.repo.root())?;
    let actor = principal();
    match undo_once(&ws.repo, &mut log, &actor)? {
        Some(out) => {
            println!("undid op#{}", out.undone.id.0);
            println!("  was: {}", out.undone.kind.one_line());
            println!("  recorded as op#{}", out.recorded.id.0);
            note_files_after_wt_drop_undo(&out);
        }
        None => println!("nothing to undo"),
    }
    Ok(())
}

/// `tig wt drop` removes a workspace's files by default. Undoing it
/// restores the manifest pointing back at that (now-missing) path. Tell
/// the user so they don't think the rest of undo silently corrupted.
fn note_files_after_wt_drop_undo(outcome: &tig_store::UndoOutcome) {
    if let OpKind::WtDrop { name, .. } = &outcome.undone.kind {
        if let Some(RefSnapshot::Workspace { value: Some(m), .. }) = outcome.undone.before.first() {
            if !m.location.exists() {
                println!(
                    "  note: manifest for {name} restored, but its directory at {} no longer exists.",
                    m.location.display()
                );
                println!(
                    "        re-materialize with `tig wt make {name} --at {}` if you need it.",
                    m.location.display()
                );
            }
        }
    }
}

fn cmd_op_log(limit: usize) -> Result<()> {
    let ws = discover_workspace()?;
    let log = OpLog::open(ws.repo.root())?;
    let ops = log.list()?;
    if ops.is_empty() {
        println!("no operations recorded");
        return Ok(());
    }
    let total = ops.len();
    for op in ops.iter().rev().take(limit) {
        println!(
            "op#{:<4} {}  {:<20}  {}",
            op.id.0,
            format_ts(op.ts_ns),
            op.actor.to_string(),
            op.kind.one_line()
        );
    }
    if total > limit {
        println!("... ({} earlier ops not shown)", total - limit);
    }
    Ok(())
}

// --- draft + transition --------------------------------------------------

fn parse_state_str(s: &str) -> Result<ChangeState> {
    match s.to_lowercase().as_str() {
        "working" => Ok(ChangeState::Working),
        "draft" => Ok(ChangeState::Draft),
        "review" => Ok(ChangeState::Review),
        "landed" => Ok(ChangeState::Landed),
        "abandoned" => Ok(ChangeState::Abandoned),
        other => Err(anyhow!("unknown state {other:?}")),
    }
}

fn parse_vis_str(s: &str) -> Result<VisLabel> {
    match s {
        "public" => Ok(VisLabel::Public),
        "private" => Ok(VisLabel::Private),
        other => Err(anyhow!("unknown visibility {other:?}")),
    }
}

fn cmd_draft(description: &str) -> Result<()> {
    let mut ws = discover_workspace()?;
    let _lock = ws.repo.lock_for_write()?;
    let mut log = OpLog::open(ws.repo.root())?;

    // Bootstrap an empty snapshot if there's no current change yet —
    // same trick `tig change new` uses.
    let current = match ws.current_change_id()? {
        Some(id) => ws.repo.get_change(&id)?.current,
        None => {
            let tree_h = ws.repo.put(&Tree::new().encode()?)?;
            let snap = Snapshot {
                parents: vec![],
                tree: tree_h,
                author: principal(),
                timestamp_ns: Snapshot::current_timestamp_ns(),
                message: Some("(empty)".into()),
                op_id: None,
            };
            ws.repo.put(&snap.encode()?)?
        }
    };
    let change = Change::new_private_draft(description, principal(), current);

    let workspace_ref_before = workspace_ref_snapshot(&ws)?;
    ws.repo.put_change(&change)?;
    ws.set_current_change_id(&change.id)?;
    let workspace_ref_after = workspace_ref_snapshot(&ws)?;

    log.append(OpInProgress {
        actor: principal(),
        kind: OpKind::ChangeNew {
            change_id: change.id.clone(),
            description: description.to_string(),
        },
        before: vec![
            workspace_ref_before,
            RefSnapshot::Change {
                id: change.id.clone(),
                value: None,
            },
        ],
        after: vec![
            workspace_ref_after,
            RefSnapshot::Change {
                id: change.id.clone(),
                value: Some(change.clone()),
            },
        ],
    })?;

    println!("created Draft+Private change {}", change.id);
    println!("    {description}");
    println!(
        "    visible only to {} until `tig change publish`",
        change.author
    );
    Ok(())
}

fn cmd_change_transition(
    id_opt: Option<&str>,
    state_str: Option<&str>,
    vis_str: Option<&str>,
) -> Result<()> {
    let ws = discover_workspace()?;
    let _lock = ws.repo.lock_for_write()?;
    let id = match id_opt {
        Some(s) => tig_core::ChangeId(s.to_string()),
        None => ws
            .current_change_id()?
            .ok_or_else(|| anyhow!("no current change and no --id given"))?,
    };
    let mut change = ws.repo.get_change(&id)?;
    let before = change.clone();

    if let Some(s) = state_str {
        change.state = parse_state_str(s)?;
    }
    if let Some(v) = vis_str {
        change.visibility = parse_vis_str(v)?;
    }
    ws.repo.put_change(&change)?;

    let mut log = OpLog::open(ws.repo.root())?;
    log.append(OpInProgress {
        actor: principal(),
        kind: OpKind::ChangeTransition {
            change_id: change.id.clone(),
            from_state: before.state,
            to_state: change.state,
            from_vis: before.visibility.clone(),
            to_vis: change.visibility.clone(),
        },
        before: vec![RefSnapshot::Change {
            id: change.id.clone(),
            value: Some(before.clone()),
        }],
        after: vec![RefSnapshot::Change {
            id: change.id.clone(),
            value: Some(change.clone()),
        }],
    })?;

    println!(
        "transitioned {}: {:?}/{} → {:?}/{}",
        change.id,
        before.state,
        before.visibility.name(),
        change.state,
        change.visibility.name()
    );
    Ok(())
}

// --- diff ----------------------------------------------------------------

/// Resolve diff endpoints into `(from_tree, to_tree, from_label, to_label)`
/// following git's conventions:
///
///   None             → from = current snap's tree,    to = scanned workdir
///   Some("abc")      → from = abc snap's tree,        to = scanned workdir
///   Some("a..b")     → from = a snap's tree,          to = b snap's tree
///
/// In the first two forms the workdir is the implicit "to" — that
/// answers "what would my next snap capture?", which is the most common
/// question after editing files. To compare two stored snapshots use
/// the explicit `a..b` form.
fn resolve_diff_endpoints(
    ws: &Workspace,
    range: Option<&str>,
) -> Result<(tig_core::Hash, tig_core::Hash, String, String)> {
    match range {
        // Explicit range: never involves the workdir.
        Some(r) if r.contains("..") => {
            let (l, r2) = r.split_once("..").unwrap();
            if l.is_empty() || r2.is_empty() {
                return Err(anyhow!(
                    "range {:?} needs prefixes on both sides of `..`",
                    r
                ));
            }
            let from_h = ws.repo.resolve_hash_prefix(l)?;
            let to_h = ws.repo.resolve_hash_prefix(r2)?;
            let from_snap = Snapshot::decode(&ws.repo.get(&from_h)?)?;
            let to_snap = Snapshot::decode(&ws.repo.get(&to_h)?)?;
            Ok((
                from_snap.tree,
                to_snap.tree,
                format!("snap {}", &from_h.to_hex()[..12]),
                format!("snap {}", &to_h.to_hex()[..12]),
            ))
        }
        // Single prefix: workdir is the "to" side.
        Some(r) => {
            let from_h = ws.repo.resolve_hash_prefix(r)?;
            let from_snap = Snapshot::decode(&ws.repo.get(&from_h)?)?;
            let to_tree = scan_workdir(ws)?;
            Ok((
                from_snap.tree,
                to_tree,
                format!("snap {}", &from_h.to_hex()[..12]),
                "workdir".to_string(),
            ))
        }
        // No args: current snap → workdir. The "what would my next snap
        // capture?" question.
        None => {
            let id = ws
                .current_change_id()?
                .ok_or_else(|| anyhow!("no current change to diff"))?;
            let current = ws.repo.get_change(&id)?.current;
            let current_snap = Snapshot::decode(&ws.repo.get(&current)?)?;
            let to_tree = scan_workdir(ws)?;
            Ok((
                current_snap.tree,
                to_tree,
                format!("snap {}", &current.to_hex()[..12]),
                "workdir".to_string(),
            ))
        }
    }
}

/// Walk the workspace's working directory, write blobs+trees into the
/// object store, return the root tree hash. The same operation `tig
/// snap` does pre-snapshot.
///
/// Side effect: blobs and trees end up in the object store. That's
/// fine — content addressing means later snaps dedupe to them.
fn scan_workdir(ws: &Workspace) -> Result<tig_core::Hash> {
    Ok(tig_fs::scan(
        ws.workdir(),
        ws.repo.objects(),
        &tig_fs::ScanOptions::default(),
    )?)
}

fn cmd_diff(range: Option<&str>, no_hunks: bool, paths: &[String]) -> Result<()> {
    let ws = discover_workspace()?;
    let (from_tree, to_tree, from_label, to_label) = resolve_diff_endpoints(&ws, range)?;

    let opts = DiffOptions {
        no_hunks,
        paths: paths.to_vec(),
        context_lines: 3,
    };
    let diffs = diff_trees(&ws.repo, &from_tree, &to_tree, &opts)?;

    if diffs.is_empty() {
        println!("(no differences: {from_label} == {to_label})");
        return Ok(());
    }

    // Header: tell the user what's being compared. Useful especially
    // when the to-side is the workdir (which can change second to
    // second).
    println!("# diff {from_label} -> {to_label}");
    for fd in &diffs {
        print_file_diff(fd);
    }
    Ok(())
}

fn print_file_diff(fd: &FileDiff) {
    println!("diff --tig a/{0} b/{0}", fd.path);
    match &fd.kind {
        FsChangeKind::TypeChanged { from, to } => {
            println!("type changed: {from:?} -> {to:?}");
            return;
        }
        FsChangeKind::Added => println!("new {} mode", entry_kind_label(fd.entry_kind)),
        FsChangeKind::Removed => println!("removed {}", entry_kind_label(fd.entry_kind)),
        FsChangeKind::Modified => {}
    }

    // For non-File kinds, we don't emit hunks (no text to render).
    if fd.entry_kind != tig_core::EntryKind::File {
        let from = fd
            .from_target
            .map(|h| h.to_hex()[..12].to_string())
            .unwrap_or_default();
        let to = fd
            .to_target
            .map(|h| h.to_hex()[..12].to_string())
            .unwrap_or_default();
        if !from.is_empty() && !to.is_empty() {
            println!("  {from} -> {to}");
        }
        return;
    }

    if fd.binary {
        println!("Binary files a/{0} and b/{0} differ", fd.path);
        return;
    }

    let (left_path, right_path) = match fd.kind {
        FsChangeKind::Added => ("/dev/null".to_string(), format!("b/{}", fd.path)),
        FsChangeKind::Removed => (format!("a/{}", fd.path), "/dev/null".to_string()),
        _ => (format!("a/{}", fd.path), format!("b/{}", fd.path)),
    };
    println!("--- {left_path}");
    println!("+++ {right_path}");

    if let Some(hunks) = &fd.hunks {
        for h in hunks {
            // git's convention: omit ",N" when N is 1.
            let from_range = if h.from_len == 1 {
                format!("{}", h.from_start)
            } else {
                format!("{},{}", h.from_start, h.from_len)
            };
            let to_range = if h.to_len == 1 {
                format!("{}", h.to_start)
            } else {
                format!("{},{}", h.to_start, h.to_len)
            };
            println!("@@ -{from_range} +{to_range} @@");
            for line in &h.lines {
                match line {
                    HunkLine::Context(s) => println!(" {s}"),
                    HunkLine::Add(s) => println!("+{s}"),
                    HunkLine::Remove(s) => println!("-{s}"),
                }
            }
        }
    }
}

fn entry_kind_label(k: tig_core::EntryKind) -> &'static str {
    match k {
        tig_core::EntryKind::File => "file",
        tig_core::EntryKind::Tree => "directory",
        tig_core::EntryKind::Symlink => "symlink",
        tig_core::EntryKind::Sealed => "sealed entry",
        tig_core::EntryKind::Conflict => "conflict marker",
        tig_core::EntryKind::Submodule => "submodule",
    }
}

// --- auth-token ----------------------------------------------------------

fn cmd_auth_token(as_name: Option<&str>, ttl: u64) -> Result<()> {
    let ws = discover_workspace()?;
    let store = PrincipalStore::open(ws.repo.root())?;

    let name = as_name
        .map(String::from)
        .or_else(|| std::env::var("TIG_AS").ok())
        .ok_or_else(|| anyhow!("--as <name> required (or set TIG_AS)"))?;
    let identity = store.get(&name)?;
    let secret = identity
        .sign_secret()
        .map_err(|e| anyhow!("identity {name:?} has no signing secret: {e}"))?;

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_add(ttl);
    let claims = Claims {
        sub: name.clone(),
        exp,
    };
    let token = sign_token(&claims, &secret)?;
    println!("{token}");
    eprintln!("  (sub: {name}, expires in {ttl}s)");
    Ok(())
}

// --- blame ---------------------------------------------------------------

fn cmd_blame(path: &str, snap_arg: Option<&str>) -> Result<()> {
    let ws = discover_workspace()?;

    // Resolve target snap: arg or current.
    let target = match snap_arg {
        Some(p) => ws.repo.resolve_hash_prefix(p)?,
        None => {
            let id = ws
                .current_change_id()?
                .ok_or_else(|| anyhow!("no current change to blame against"))?;
            ws.repo.get_change(&id)?.current
        }
    };

    // Validate it's a Snapshot kind.
    let raw = ws.repo.get(&target)?;
    if raw.kind != ObjectKind::Snapshot {
        return Err(anyhow!(
            "{} is a {}, not a snapshot",
            &target.to_hex()[..12],
            raw.kind.name()
        ));
    }

    let lines = blame_at(&ws.repo, path, &target)?;
    if lines.is_empty() {
        println!("(empty file)");
        return Ok(());
    }

    // Build a width for line-number alignment.
    let n_width = lines.len().to_string().len();
    // Find the longest author for column alignment.
    let author_width = lines
        .iter()
        .map(|l| l.author.0.len())
        .max()
        .unwrap_or(0)
        .min(20); // cap to keep output readable

    for (i, line) in lines.iter().enumerate() {
        print_blame_line(line, i + 1, n_width, author_width);
    }
    Ok(())
}

fn print_blame_line(b: &BlameLine, line_no: usize, n_width: usize, author_width: usize) {
    let short = &b.snap.to_hex()[..12];
    let author_disp: String = if b.author.0.len() <= author_width {
        format!("{:<width$}", b.author.0, width = author_width)
    } else {
        format!("{}…", &b.author.0[..author_width.saturating_sub(1)])
    };
    let ts = b.timestamp_ns / 1_000_000_000;
    println!(
        "{short} ({author_disp} {ts:>10}) {line_no:>width$}  {content}",
        width = n_width,
        content = b.line,
    );
}

// --- grep ---------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn cmd_grep(
    pattern: &str,
    snap_arg: Option<&str>,
    regex: bool,
    ignore_case: bool,
    paths: &[String],
    max_per_file: Option<usize>,
    max_total: Option<usize>,
) -> Result<()> {
    let ws = discover_workspace()?;

    // Resolve target snap: arg or current.
    let target = match snap_arg {
        Some(p) => ws.repo.resolve_hash_prefix(p)?,
        None => {
            let id = ws
                .current_change_id()?
                .ok_or_else(|| anyhow!("no current change to grep against"))?;
            ws.repo.get_change(&id)?.current
        }
    };

    let raw = ws.repo.get(&target)?;
    if raw.kind != ObjectKind::Snapshot {
        return Err(anyhow!(
            "{} is a {}, not a snapshot",
            &target.to_hex()[..12],
            raw.kind.name()
        ));
    }
    let snap = Snapshot::decode(&raw)?;

    let opts = GrepOptions {
        regex,
        ignore_case,
        paths: paths.to_vec(),
        max_matches_per_file: max_per_file,
        max_total_matches: max_total,
    };
    let hits = grep_tree(&ws.repo, &snap.tree, pattern, &opts)?;
    if hits.is_empty() {
        // Exit code 1 for "no matches", matching grep's convention.
        // Don't print anything — that's also what grep does.
        std::process::exit(1);
    }
    for m in &hits {
        println!("{}:{}:{}", m.path, m.line_number, m.line);
    }
    Ok(())
}

// --- restore -------------------------------------------------------------

fn cmd_restore(snap_prefix: &str, force: bool, as_name: Option<&str>) -> Result<()> {
    let mut ws = discover_workspace()?;
    let _lock = ws.repo.lock_for_write()?;
    let mut log = OpLog::open(ws.repo.root())?;

    // 1. Resolve the prefix to a full hash.
    let target_hash = ws
        .repo
        .resolve_hash_prefix(snap_prefix)
        .with_context(|| format!("resolving snapshot prefix {snap_prefix:?}"))?;
    let raw = ws.repo.get(&target_hash)?;
    if raw.kind != ObjectKind::Snapshot {
        return Err(anyhow!(
            "object {} is a {}, not a snapshot",
            &target_hash.to_hex()[..12],
            raw.kind.name()
        ));
    }
    // The kind check above is the cheapest validation; decoding gives
    // us the tree hash for the snap message below.
    let target_snap = Snapshot::decode(&raw)?;

    // 2. Find the change's current snapshot (for the dirty check).
    let current_change_id = ws
        .current_change_id()?
        .ok_or_else(|| anyhow!("no current change; nothing to restore into"))?;
    let current_change = ws.repo.get_change(&current_change_id)?;

    // 3. Render. The engine refuses on dirty workdir unless force is
    //    on, and refuses on sealed entries when no --as identity was
    //    supplied (else they get decrypted in place).
    let identity_secret = resolve_unseal_identity(&ws.repo, as_name)?;
    let unsealer_closure = identity_secret.as_ref().map(|secret| {
        move |sealed: &tig_core::Sealed, aad: &[u8]| -> std::result::Result<Vec<u8>, String> {
            do_unseal(sealed, secret, aad).map_err(|e| e.to_string())
        }
    });

    let workdir = ws.workdir().to_path_buf();
    let outcome = restore_tree_into(
        &ws.repo,
        &target_hash,
        &workdir,
        &current_change.current,
        &RestoreOptions {
            force,
            materialize: MaterializeOptions {
                unsealer: unsealer_closure
                    .as_ref()
                    .map(|c| c as &tig_fs::UnsealFn<'_>),
                on_unsealable: OnUnsealable::Error,
            },
        },
    )?;
    if outcome.render.sealed_unsealed > 0 {
        eprintln!(
            "  note: {} sealed entr{} decrypted to plaintext on disk. \
             Re-seal before snap with `tig seal <path> --recipients ...` \
             or the next snap will store them as regular blobs.",
            outcome.render.sealed_unsealed,
            if outcome.render.sealed_unsealed == 1 {
                "y"
            } else {
                "ies"
            },
        );
    }

    println!(
        "  restored {} files ({} bytes), removed {} top-level entries",
        outcome.render.files, outcome.render.bytes, outcome.top_level_removed
    );

    // 4. Snap the restored state so the change advances and the op
    //    log captures what we did. We force the snap so the message
    //    sticks even if the new tree happens to be byte-equal to the
    //    current snap (rare but possible with content-addressed dedup).
    let snap_outcome = snap_now(
        &mut ws,
        &mut log,
        &SnapOptions {
            author: principal(),
            message: Some(format!("restore {}", &target_hash.to_hex()[..12])),
            force: true,
            ..Default::default()
        },
    )?;
    match snap_outcome {
        SnapOutcome::Snapped {
            snapshot, change, ..
        } => {
            println!(
                "  snap {}  restore {}",
                &snapshot.to_hex()[..12],
                &target_hash.to_hex()[..12],
            );
            println!(
                "    change {} now at {}",
                change.id,
                &change.current.to_hex()[..12]
            );
        }
        SnapOutcome::Unchanged { .. } => {
            // Shouldn't happen given force: true, but be defensive.
            println!("  (no change recorded — workdir already matched current snapshot)");
        }
    }
    let _ = target_snap; // tree hash already captured in outcome.tree
    Ok(())
}

// --- identity + sealed values --------------------------------------------

fn cmd_identity_new(name: &str) -> Result<()> {
    let ws = discover_workspace()?;
    let store = PrincipalStore::open(ws.repo.root())?;
    // Generate both keypairs: X25519 (for sealing) and Ed25519 (for
    // signing bearer tokens). Stored together in the principal record.
    let seal_kp = KeyPair::generate();
    let sign_kp = SignKeyPair::generate();
    let seal_pub_hex = seal_kp.public.to_hex();
    let sign_pub_hex = sign_kp.public.to_hex();
    let p = Principal::new_local_full(name, PrincipalKind::User, seal_kp, sign_kp);
    store.put_new(&p)?;
    println!("created identity {name}");
    println!("  seal pubkey: {seal_pub_hex}");
    println!("  sign pubkey: {sign_pub_hex}");
    println!(
        "  secrets stored at {}/vis/keys/{name}.json",
        ws.repo.root().display()
    );
    println!("  (secrets never leave this machine; mint tokens with `tig auth-token`.)");
    Ok(())
}

fn cmd_identity_list() -> Result<()> {
    let ws = discover_workspace()?;
    let store = PrincipalStore::open(ws.repo.root())?;
    let mut any = false;
    for p in store.list()? {
        let secret_marker = if p.has_secret() {
            "[local]"
        } else {
            "[remote]"
        };
        println!(
            "{:<12} {:<10} {} {secret_marker}",
            p.id,
            format!("{:?}", p.kind),
            &p.pubkey.to_hex()[..16]
        );
        any = true;
    }
    if !any {
        println!("no identities yet; create one with `tig identity new <name>`");
    }
    Ok(())
}

fn cmd_identity_show(name: &str) -> Result<()> {
    let ws = discover_workspace()?;
    let store = PrincipalStore::open(ws.repo.root())?;
    let p = store.get(name)?;
    println!("id:     {}", p.id);
    println!("kind:   {:?}", p.kind);
    println!("pubkey: {}", p.pubkey.to_hex());
    println!(
        "secret: {}",
        if p.has_secret() {
            "<local>"
        } else {
            "<remote — pubkey only>"
        }
    );
    Ok(())
}

fn cmd_seal(
    path: &str,
    recipient_names: &[String],
    from_file: Option<&Path>,
    inline_data: Option<&str>,
) -> Result<()> {
    let mut ws = discover_workspace()?;
    let _lock = ws.repo.lock_for_write()?;
    let store = PrincipalStore::open(ws.repo.root())?;

    // Resolve recipients.
    let mut recipients = Vec::with_capacity(recipient_names.len());
    for name in recipient_names {
        let p = store
            .get(name)
            .with_context(|| format!("looking up recipient {name:?}"))?;
        recipients.push(p.pubkey);
    }

    // Read plaintext.
    let plaintext: Vec<u8> = match (from_file, inline_data) {
        (Some(p), _) => std::fs::read(p).with_context(|| format!("reading {}", p.display()))?,
        (None, Some(d)) => d.as_bytes().to_vec(),
        (None, None) => {
            use std::io::Read;
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("reading plaintext from stdin")?;
            buf
        }
    };

    // Encrypt.
    let sealed = do_seal(&plaintext, &recipients, path.as_bytes())?;

    // Look up current change + tree.
    let current_change_id = ws
        .current_change_id()?
        .ok_or_else(|| anyhow!("no current change — run `tig snap` first"))?;
    let change = ws.repo.get_change(&current_change_id)?;
    let snap = Snapshot::decode(&ws.repo.get(&change.current)?)?;

    // Edit the tree, then snap directly (no workdir scan — there's no
    // sealed file *on disk*; the sealed bytes only exist in the store).
    let new_tree = write_sealed_at_path(&ws.repo, snap.tree, path, sealed)?;
    let mut log = OpLog::open(ws.repo.root())?;
    let outcome = snap_change_directly(
        &ws.repo,
        &mut log,
        &current_change_id,
        new_tree,
        &SnapOptions {
            author: principal(),
            message: Some(format!("seal {path}")),
            ..Default::default()
        },
    )?;

    let _ = &mut ws; // silence "mut not needed" if we don't end up advancing
    match outcome {
        SnapOutcome::Snapped { snapshot, .. } => {
            println!(
                "sealed {path} for {} recipient(s); snap {}",
                recipient_names.len(),
                &snapshot.to_hex()[..12]
            );
        }
        SnapOutcome::Unchanged { .. } => {
            println!("sealed {path} (no tree change — bytes match existing entry)");
        }
    }
    Ok(())
}

fn cmd_reveal(path: &str, as_name: Option<&str>) -> Result<()> {
    let ws = discover_workspace()?;
    let store = PrincipalStore::open(ws.repo.root())?;

    let name = as_name
        .map(String::from)
        .or_else(|| std::env::var("TIG_AS").ok())
        .ok_or_else(|| anyhow!("--as <name> required (or set TIG_AS)"))?;
    let identity = store.get(&name)?;
    let secret = identity.secret()?;

    // Walk the tree to find the sealed entry.
    let current_change_id = ws
        .current_change_id()?
        .ok_or_else(|| anyhow!("no current change"))?;
    let change = ws.repo.get_change(&current_change_id)?;
    let snap = Snapshot::decode(&ws.repo.get(&change.current)?)?;

    let parts: Vec<String> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    if parts.is_empty() {
        return Err(anyhow!("empty path"));
    }
    let entry = lookup_entry(&ws.repo, &snap.tree, &parts)?;
    if entry.kind != tig_core::EntryKind::Sealed {
        return Err(anyhow!(
            "path {path} is a {:?}, not a sealed entry",
            entry.kind
        ));
    }
    let sealed = tig_core::Sealed::decode(&ws.repo.get(&entry.target)?)?;

    let plaintext = do_unseal(&sealed, &secret, path.as_bytes())?;
    use std::io::Write;
    std::io::stdout().write_all(&plaintext)?;
    Ok(())
}

// --- cat-object ----------------------------------------------------------

fn cmd_cat_object(hash_str: &str) -> Result<()> {
    let ws = discover_workspace()?;
    let hash = tig_core::Hash::from_hex(hash_str)?;
    let raw = ws.repo.get(&hash)?;
    println!("kind: {}", raw.kind.name());
    println!("size: {} bytes (payload, excl. kind tag)", raw.bytes.len());
    println!("hash: {hash}");
    println!();
    match raw.kind {
        ObjectKind::Blob => {
            let b = Blob::decode(&raw)?;
            match std::str::from_utf8(&b.bytes) {
                Ok(s) => println!("{s}"),
                Err(_) => println!("(binary, {} bytes)", b.bytes.len()),
            }
        }
        ObjectKind::Tree => {
            let t = Tree::decode(&raw)?;
            for e in &t.entries {
                println!("  {:?} {:>6o}  {}  {}", e.kind, e.mode.0, e.target, e.name);
            }
        }
        ObjectKind::Snapshot => {
            let s = Snapshot::decode(&raw)?;
            println!("tree:    {}", s.tree);
            for p in &s.parents {
                println!("parent:  {p}");
            }
            println!("author:  {}", s.author);
            println!("time:    {}", format_ts(s.timestamp_ns));
            if let Some(m) = &s.message {
                println!("message: {m}");
            }
        }
        ObjectKind::Sealed | ObjectKind::Conflict => {
            println!("(viewer for {} not yet implemented)", raw.kind.name());
        }
    }
    Ok(())
}

fn format_ts(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let micros = (ns % 1_000_000_000) / 1_000;
    format!("@{secs}.{micros:06}")
}
