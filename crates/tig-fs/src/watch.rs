//! Auto-snap on file-system change.
//!
//! `watch_and_snap` runs a loop:
//!   1. Subscribe to debounced fsevents/inotify/ReadDirectoryChangesW
//!      notifications under the working directory (via `notify` +
//!      `notify-debouncer-full`).
//!   2. When a batch arrives, ignore anything inside `.tig/` (so our own
//!      object-store writes don't ping us back into a snap loop).
//!   3. If anything outside `.tig/` was touched, call `snap_now`.
//!   4. Emit a `WatchEvent` on each batch — `Snap`, `Idle`, `Error`,
//!      `Stopped` — so callers (CLI, daemon, tests) can react.
//!
//! The function is single-threaded from the caller's point of view: it
//! blocks until `WatchOptions::stop` is set, then returns. Tests flip the
//! flag directly; the CLI installs a ctrl-c handler.
//!
//! Theo's manifesto, §2: "Snapshots are taken when you run any command at
//! all." This is the broader read: snapshots are taken when *anything
//! changes*, with no command at all. The user just edits code.

use crate::{snap_now, Error, Result, SnapOptions, SnapOutcome};
use notify::{EventKind, RecursiveMode};
use notify_debouncer_full::new_debouncer;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use tig_store::{OpLog, Workspace};

#[derive(Clone, Debug)]
pub struct WatchOptions {
    /// How long to wait for events to settle before snapping. Default
    /// 750ms — short enough to feel live, long enough to coalesce a save
    /// that hits multiple temp-files (e.g. editors using atomic renames).
    pub debounce: Duration,

    /// Set this to `true` from another thread (or via a ctrl-c handler)
    /// to stop the watcher. The loop notices within `poll_interval`.
    pub stop: Arc<AtomicBool>,

    /// How often the loop wakes to check the stop flag. Default 250ms.
    /// Independent of `debounce` — this only affects shutdown latency.
    pub poll_interval: Duration,
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self {
            debounce: Duration::from_millis(750),
            stop: Arc::new(AtomicBool::new(false)),
            poll_interval: Duration::from_millis(250),
        }
    }
}

// The `Snap` variant carries a `SnapOutcome` which is much larger than
// the other variants. Boxing would technically slim the enum but the
// type is public API and the events are emitted at human-event rate
// (debounced fs notifications), so it's not perf-critical.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum WatchEvent {
    /// Emitted once at the start, after the watcher is set up.
    Started { workdir: PathBuf },
    /// A debounced event batch caused a snapshot — possibly `Unchanged`
    /// if the tree happens to round-trip to the same hash (e.g. a save-
    /// no-change in the editor).
    Snap(SnapOutcome),
    /// A batch arrived but every path was inside `.tig/`. Most often our
    /// own object-store writes. The caller usually just ignores this.
    Idle,
    /// The notify layer reported a problem. We keep watching.
    Error(String),
    /// The loop has exited cleanly (`stop` flipped or sender hung up).
    Stopped,
}

/// Watch the workspace's working directory and snap on every external
/// change. Blocks until `opts.stop` is set or the underlying watcher
/// fails terminally.
///
/// Filters out events that only touch the repo's `.tig/` directory (the
/// snap routine writes there itself; we must not chase our own tail).
pub fn watch_and_snap(
    workspace: &mut Workspace,
    log: &mut OpLog,
    opts: &WatchOptions,
    snap_opts: &SnapOptions,
    mut on_event: impl FnMut(WatchEvent),
) -> Result<()> {
    let workdir = workspace.workdir().to_path_buf();
    let tig_dir = workspace.repo.root().to_path_buf();

    let (tx, rx) = mpsc::channel();
    let mut debouncer = new_debouncer(opts.debounce, None, tx).map_err(Error::Notify)?;
    debouncer
        .watch(&workdir, RecursiveMode::Recursive)
        .map_err(Error::Notify)?;

    on_event(WatchEvent::Started {
        workdir: workdir.clone(),
    });

    loop {
        if opts.stop.load(Ordering::SeqCst) {
            break;
        }

        match rx.recv_timeout(opts.poll_interval) {
            Ok(Ok(events)) => {
                let touches_workdir = events
                    .iter()
                    .any(|de| de.event.paths.iter().any(|p| !p.starts_with(&tig_dir)));
                let kinds_meaningful = events.iter().any(|de| {
                    matches!(
                        de.event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    )
                });
                if !(touches_workdir && kinds_meaningful) {
                    on_event(WatchEvent::Idle);
                    continue;
                }
                // Take the per-repo write lock for the duration of
                // each snap — not the whole watch session — so other
                // tig processes can still mutate between events.
                let snap_result = match workspace.repo.lock_for_write() {
                    Ok(_lock) => snap_now(workspace, log, snap_opts),
                    Err(e) => Err(crate::Error::Store(e)),
                };
                match snap_result {
                    Ok(out) => on_event(WatchEvent::Snap(out)),
                    Err(e) => on_event(WatchEvent::Error(e.to_string())),
                }
            }
            Ok(Err(errors)) => {
                for e in errors {
                    on_event(WatchEvent::Error(e.to_string()));
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // Stop explicitly so we don't pay the Drop blocking penalty during
    // a hot shutdown. `stop` consumes self.
    debouncer.stop();
    on_event(WatchEvent::Stopped);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Instant;
    use tempfile::tempdir;
    use tig_core::PrincipalId;
    use tig_store::Repository;

    /// Helper: run the watcher in a thread, collect events into a Mutex.
    fn spawn_watcher(
        repo_dir: PathBuf,
        opts: WatchOptions,
    ) -> (
        thread::JoinHandle<()>,
        Arc<Mutex<Vec<WatchEvent>>>,
        Arc<AtomicBool>,
    ) {
        let events = Arc::new(Mutex::new(Vec::<WatchEvent>::new()));
        let stop = opts.stop.clone();

        let events_clone = events.clone();
        let handle = thread::spawn(move || {
            let repo = Repository::open(&repo_dir).unwrap();
            let mut log = OpLog::open(repo.root()).unwrap();
            let mut ws = Workspace::main_for(repo);
            let snap_opts = SnapOptions {
                author: PrincipalId::local("watcher-test"),
                ..Default::default()
            };
            let _ = watch_and_snap(&mut ws, &mut log, &opts, &snap_opts, |ev| {
                events_clone.lock().unwrap().push(ev);
            });
        });

        (handle, events, stop)
    }

    fn wait_for<F: Fn() -> bool>(deadline: Duration, condition: F) -> bool {
        let start = Instant::now();
        while start.elapsed() < deadline {
            if condition() {
                return true;
            }
            thread::sleep(Duration::from_millis(25));
        }
        false
    }

    #[test]
    fn watcher_snaps_on_external_write() {
        let dir = tempdir().unwrap();
        Repository::init(dir.path()).unwrap();

        let opts = WatchOptions {
            debounce: Duration::from_millis(150),
            stop: Arc::new(AtomicBool::new(false)),
            poll_interval: Duration::from_millis(50),
        };
        let (handle, events, stop) = spawn_watcher(dir.path().to_path_buf(), opts);

        // Wait for the watcher to set up before we touch the filesystem;
        // otherwise the write can race the subscription.
        assert!(
            wait_for(Duration::from_secs(2), || {
                events
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|e| matches!(e, WatchEvent::Started { .. }))
            }),
            "watcher never started"
        );

        // Touch a file in the working directory.
        fs::write(dir.path().join("hello.txt"), b"watched").unwrap();

        // Wait for a Snap event.
        assert!(
            wait_for(Duration::from_secs(5), || {
                events
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|e| matches!(e, WatchEvent::Snap(SnapOutcome::Snapped { .. })))
            }),
            "watcher never snapped; events: {:?}",
            events.lock().unwrap()
        );

        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        // Final state: HEAD points at a Change with at least one snapshot.
        let repo = Repository::open(dir.path()).unwrap();
        let head = repo.head().unwrap().expect("HEAD should be set");
        let change = repo.get_change(&head).unwrap();
        assert!(!change.history.is_empty());
    }

    #[test]
    fn writes_inside_tig_directory_do_not_cause_loop() {
        // Sanity: our own snap writes (which land in .tig/) should be
        // filtered out. If they weren't, a single user edit would
        // trigger an unbounded cascade of snaps.

        let dir = tempdir().unwrap();
        Repository::init(dir.path()).unwrap();

        let opts = WatchOptions {
            debounce: Duration::from_millis(100),
            stop: Arc::new(AtomicBool::new(false)),
            poll_interval: Duration::from_millis(50),
        };
        let (handle, events, stop) = spawn_watcher(dir.path().to_path_buf(), opts);

        assert!(wait_for(Duration::from_secs(2), || {
            events
                .lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, WatchEvent::Started { .. }))
        }));

        // One edit, then sit and watch for a while.
        fs::write(dir.path().join("a.txt"), b"once").unwrap();
        thread::sleep(Duration::from_millis(1200));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        let snaps: Vec<_> = events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, WatchEvent::Snap(SnapOutcome::Snapped { .. })))
            .cloned()
            .collect();

        // A single edit should produce at most a small bounded number of
        // snaps. (Sometimes the OS coalesces; sometimes it doesn't. We
        // assert ≤ 3 as a sanity guard against runaway loops.)
        assert!(
            snaps.len() <= 3,
            "single edit caused {} snaps — looks like a self-trigger loop",
            snaps.len()
        );
        assert!(
            !snaps.is_empty(),
            "edit should have caused at least one snap"
        );
    }
}
