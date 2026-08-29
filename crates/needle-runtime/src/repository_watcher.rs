use crate::RuntimeStore;
use crate::repository_observer::{
    RepositoryReconciliation, RepositoryReconciliationError,
    git_repository_observer_definition_digest, reconcile_git_repository,
};
use crate::snapshot::{SnapshotError, discover_git_repository_root};
use needle_core::{CanonicalHasher, Digest};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use thiserror::Error;

pub const REPOSITORY_WATCHER_REVISION: u16 = 1;
pub const REPOSITORY_WATCHER_DEBOUNCE: Duration = Duration::from_millis(100);
pub const REPOSITORY_WATCHER_RECONCILIATION_INTERVAL: Duration = Duration::from_secs(60);
const REPOSITORY_WATCHER_QUEUE_CAPACITY: usize = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryWatcherHealth {
    pub successful_reconciliations: u64,
    pub failed_reconciliations: u64,
    pub backend_errors: u64,
    pub coalesced_signals: u64,
    pub uncertain: bool,
}

/// Cloneable, read-only view of watcher health for resident-runtime status
/// surfaces. Owning this handle does not keep the watcher worker alive.
#[derive(Clone, Debug)]
pub struct RepositoryWatcherHealthHandle {
    state: Arc<RepositoryWatcherState>,
}

impl RepositoryWatcherHealthHandle {
    pub fn health(&self) -> RepositoryWatcherHealth {
        self.state.health()
    }
}

#[derive(Debug, Error)]
pub enum RepositoryWatcherError {
    #[error("repository discovery failed: {0}")]
    Snapshot(#[from] SnapshotError),
    #[error("filesystem watcher setup failed: {0}")]
    Watcher(String),
    #[error("initial repository reconciliation failed: {0}")]
    InitialReconciliation(#[source] RepositoryReconciliationError),
    #[error("repository watcher worker could not start: {0}")]
    WorkerStart(#[source] std::io::Error),
    #[error("repository watcher worker panicked")]
    WorkerPanicked,
}

#[derive(Debug)]
struct RepositoryWatcherState {
    stop: AtomicBool,
    reconciliation_failed: AtomicBool,
    backend_error_epoch: AtomicU64,
    reconciled_backend_error_epoch: AtomicU64,
    successful_reconciliations: AtomicU64,
    failed_reconciliations: AtomicU64,
    backend_errors: AtomicU64,
    coalesced_signals: AtomicU64,
}

impl RepositoryWatcherState {
    fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
            reconciliation_failed: AtomicBool::new(true),
            backend_error_epoch: AtomicU64::new(0),
            reconciled_backend_error_epoch: AtomicU64::new(0),
            successful_reconciliations: AtomicU64::new(0),
            failed_reconciliations: AtomicU64::new(0),
            backend_errors: AtomicU64::new(0),
            coalesced_signals: AtomicU64::new(0),
        }
    }

    fn record_success(&self, observed_backend_error_epoch: u64) {
        self.successful_reconciliations.fetch_add(1, Ordering::Relaxed);
        self.reconciled_backend_error_epoch.store(observed_backend_error_epoch, Ordering::Release);
        self.reconciliation_failed.store(false, Ordering::Release);
    }

    fn record_failure(&self) {
        self.failed_reconciliations.fetch_add(1, Ordering::Relaxed);
        self.reconciliation_failed.store(true, Ordering::Release);
    }

    fn health(&self) -> RepositoryWatcherHealth {
        RepositoryWatcherHealth {
            successful_reconciliations: self.successful_reconciliations.load(Ordering::Relaxed),
            failed_reconciliations: self.failed_reconciliations.load(Ordering::Relaxed),
            backend_errors: self.backend_errors.load(Ordering::Relaxed),
            coalesced_signals: self.coalesced_signals.load(Ordering::Relaxed),
            uncertain: self.reconciliation_failed.load(Ordering::Acquire)
                || self.backend_error_epoch.load(Ordering::Acquire)
                    != self.reconciled_backend_error_epoch.load(Ordering::Acquire),
        }
    }
}

#[derive(Clone, Debug)]
struct RepositoryWatchSignal {
    sender: SyncSender<()>,
    state: Arc<RepositoryWatcherState>,
}

impl RepositoryWatchSignal {
    fn notify(&self, backend_error: bool) {
        if backend_error {
            self.state.backend_errors.fetch_add(1, Ordering::Relaxed);
            self.state.backend_error_epoch.fetch_add(1, Ordering::AcqRel);
        }
        match self.sender.try_send(()) {
            Ok(()) | Err(TrySendError::Disconnected(())) => {}
            Err(TrySendError::Full(())) => {
                self.state.coalesced_signals.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn wake_for_shutdown(&self) {
        let _ = self.sender.try_send(());
    }
}

#[derive(Clone, Copy, Debug)]
struct RepositoryWatcherPolicy {
    debounce: Duration,
    reconciliation_interval: Duration,
}

impl Default for RepositoryWatcherPolicy {
    fn default() -> Self {
        Self {
            debounce: REPOSITORY_WATCHER_DEBOUNCE,
            reconciliation_interval: REPOSITORY_WATCHER_RECONCILIATION_INTERVAL,
        }
    }
}

pub struct RepositoryWatcher {
    repository_root: PathBuf,
    initial_reconciliation: RepositoryReconciliation,
    watcher: Option<RecommendedWatcher>,
    worker: Option<JoinHandle<()>>,
    signal: RepositoryWatchSignal,
    state: Arc<RepositoryWatcherState>,
}

impl fmt::Debug for RepositoryWatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryWatcher")
            .field("repository_root", &self.repository_root)
            .field("initial_reconciliation", &self.initial_reconciliation)
            .field("health", &self.health())
            .finish_non_exhaustive()
    }
}

impl RepositoryWatcher {
    pub fn start(
        store: RuntimeStore,
        root: impl AsRef<Path>,
    ) -> Result<Self, RepositoryWatcherError> {
        Self::start_with_policy(store, root.as_ref(), RepositoryWatcherPolicy::default())
    }

    fn start_with_policy(
        store: RuntimeStore,
        root: &Path,
        policy: RepositoryWatcherPolicy,
    ) -> Result<Self, RepositoryWatcherError> {
        let repository_root = discover_git_repository_root(root)?;
        let state = Arc::new(RepositoryWatcherState::new());
        let (sender, receiver) = sync_channel(REPOSITORY_WATCHER_QUEUE_CAPACITY);
        let signal = RepositoryWatchSignal { sender, state: Arc::clone(&state) };
        let callback_signal = signal.clone();
        let mut watcher =
            notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
                callback_signal.notify(result.is_err())
            })
            .map_err(|error| RepositoryWatcherError::Watcher(error.to_string()))?;
        watcher
            .watch(&repository_root, RecursiveMode::Recursive)
            .map_err(|error| RepositoryWatcherError::Watcher(error.to_string()))?;

        let initial_error_epoch = state.backend_error_epoch.load(Ordering::Acquire);
        let initial_reconciliation = reconcile_git_repository(&store, &repository_root)
            .map_err(RepositoryWatcherError::InitialReconciliation)?;
        state.record_success(initial_error_epoch);

        let worker_root = repository_root.clone();
        let worker_state = Arc::clone(&state);
        let worker = thread::Builder::new()
            .name("needle-repository-watcher".to_owned())
            .spawn(move || watch_loop(store, worker_root, receiver, worker_state, policy))
            .map_err(RepositoryWatcherError::WorkerStart)?;

        Ok(Self {
            repository_root,
            initial_reconciliation,
            watcher: Some(watcher),
            worker: Some(worker),
            signal,
            state,
        })
    }

    pub fn repository_root(&self) -> &Path {
        &self.repository_root
    }

    pub fn initial_reconciliation(&self) -> &RepositoryReconciliation {
        &self.initial_reconciliation
    }

    pub fn health(&self) -> RepositoryWatcherHealth {
        self.state.health()
    }

    pub fn health_handle(&self) -> RepositoryWatcherHealthHandle {
        RepositoryWatcherHealthHandle { state: Arc::clone(&self.state) }
    }

    pub fn shutdown(mut self) -> Result<(), RepositoryWatcherError> {
        self.stop_worker()
    }

    fn stop_worker(&mut self) -> Result<(), RepositoryWatcherError> {
        self.state.stop.store(true, Ordering::Release);
        self.signal.wake_for_shutdown();
        self.watcher.take();
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| RepositoryWatcherError::WorkerPanicked)?;
        }
        Ok(())
    }
}

impl Drop for RepositoryWatcher {
    fn drop(&mut self) {
        let _ = self.stop_worker();
    }
}

pub fn repository_watcher_definition_digest() -> Digest {
    let mut hasher = CanonicalHasher::new(b"repository-watcher-definition-v1");
    hasher.field_u16(REPOSITORY_WATCHER_REVISION);
    hasher.field_digest(git_repository_observer_definition_digest());
    hasher.field_str("notify-8.2.0-recommended-recursive");
    hasher.field_u8(REPOSITORY_WATCHER_QUEUE_CAPACITY.try_into().unwrap_or(u8::MAX));
    hasher.field_bytes(
        &u64::try_from(REPOSITORY_WATCHER_DEBOUNCE.as_millis()).unwrap_or(u64::MAX).to_le_bytes(),
    );
    hasher.field_bytes(&REPOSITORY_WATCHER_RECONCILIATION_INTERVAL.as_secs().to_le_bytes());
    hasher.finish()
}

fn watch_loop(
    store: RuntimeStore,
    repository_root: PathBuf,
    receiver: Receiver<()>,
    state: Arc<RepositoryWatcherState>,
    policy: RepositoryWatcherPolicy,
) {
    let mut last_reconciliation = Instant::now();
    loop {
        if state.stop.load(Ordering::Acquire) {
            return;
        }
        let timeout = policy.reconciliation_interval.saturating_sub(last_reconciliation.elapsed());
        let signaled = match receiver.recv_timeout(timeout) {
            Ok(()) => true,
            Err(RecvTimeoutError::Timeout) => false,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        if state.stop.load(Ordering::Acquire) {
            return;
        }
        if signaled {
            thread::sleep(policy.debounce);
            while receiver.try_recv().is_ok() {}
        }
        if state.stop.load(Ordering::Acquire) {
            return;
        }

        let observed_error_epoch = state.backend_error_epoch.load(Ordering::Acquire);
        match reconcile_git_repository(&store, &repository_root) {
            Ok(_) => state.record_success(observed_error_epoch),
            Err(_) => state.record_failure(),
        }
        last_reconciliation = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use needle_core::{DependencyLocator, RepositoryGeneration};
    use std::fs;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture() -> (PathBuf, PathBuf, RuntimeStore) {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let root = std::env::temp_dir()
            .join(format!("needle-repository-watcher-{}-{suffix}", std::process::id()));
        let repository = root.join("repository");
        fs::create_dir_all(repository.join("src")).unwrap();
        fs::write(repository.join("src/lib.rs"), b"pub fn answer() -> u32 { 42 }\n").unwrap();
        for arguments in [
            &["init", "--quiet"][..],
            &["config", "user.email", "needle@example.invalid"],
            &["config", "user.name", "Needle Test"],
            &["add", "src/lib.rs"],
            &["commit", "--quiet", "-m", "fixture"],
        ] {
            let output =
                Command::new("git").arg("-C").arg(&repository).args(arguments).output().unwrap();
            assert!(
                output.status.success(),
                "git failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let store = RuntimeStore::new(root.join("data/needle.sqlite3"));
        store.initialize().unwrap();
        (root, repository, store)
    }

    fn wait_for_generation(
        store: &RuntimeStore,
        initial: &RepositoryGeneration,
        minimum: u64,
    ) -> RepositoryGeneration {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let current = store
                .current_repository_generation(
                    initial.repository_lineage,
                    initial.repository_context,
                )
                .unwrap()
                .unwrap();
            if current.generation >= minimum {
                return current;
            }
            assert!(Instant::now() < deadline, "repository generation did not advance");
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn watcher_reconciles_changes_and_shuts_down_cleanly() {
        let (root, repository, store) = fixture();
        let watcher = RepositoryWatcher::start_with_policy(
            store.clone(),
            &repository,
            RepositoryWatcherPolicy {
                debounce: Duration::from_millis(10),
                reconciliation_interval: Duration::from_secs(10),
            },
        )
        .unwrap();
        let initial = watcher.initial_reconciliation().generation.clone();
        assert_eq!(initial.generation, 0);
        assert_eq!(watcher.repository_root(), fs::canonicalize(&repository).unwrap());

        fs::write(repository.join("src/lib.rs"), b"pub fn answer() -> u32 { 43 }\n").unwrap();
        let current = wait_for_generation(&store, &initial, 1);
        let delta = store
            .repository_state_delta(
                initial.repository_lineage,
                initial.repository_context,
                current.generation,
            )
            .unwrap()
            .unwrap();
        assert!(delta.complete);
        assert!(
            delta
                .changed_locators
                .contains(&DependencyLocator::repository_path("src/lib.rs").unwrap())
        );
        assert!(watcher.health().successful_reconciliations >= 2);
        watcher.shutdown().unwrap();
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn periodic_reconciliation_recovers_without_an_event_signal() {
        let (root, repository, store) = fixture();
        let initial = reconcile_git_repository(&store, &repository).unwrap().generation;
        let state = Arc::new(RepositoryWatcherState::new());
        state.record_success(0);
        let (sender, receiver) = sync_channel(REPOSITORY_WATCHER_QUEUE_CAPACITY);
        let worker_state = Arc::clone(&state);
        let worker_store = store.clone();
        let worker_root = fs::canonicalize(&repository).unwrap();
        let worker = thread::spawn(move || {
            watch_loop(
                worker_store,
                worker_root,
                receiver,
                worker_state,
                RepositoryWatcherPolicy {
                    debounce: Duration::from_millis(1),
                    reconciliation_interval: Duration::from_millis(50),
                },
            );
        });

        fs::write(repository.join("src/lib.rs"), b"pub fn answer() -> u32 { 44 }\n").unwrap();
        let current = wait_for_generation(&store, &initial, 1);
        assert_eq!(current.generation, 1);
        state.stop.store(true, Ordering::Release);
        let _ = sender.try_send(());
        worker.join().unwrap();
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn signal_queue_is_bounded_and_backend_errors_fail_closed() {
        let state = Arc::new(RepositoryWatcherState::new());
        let (sender, receiver) = sync_channel(REPOSITORY_WATCHER_QUEUE_CAPACITY);
        let signal = RepositoryWatchSignal { sender, state: Arc::clone(&state) };

        signal.notify(true);
        for _ in 0..32 {
            signal.notify(false);
        }
        assert!(state.health().uncertain);
        assert_eq!(state.health().backend_errors, 1);
        assert_eq!(state.health().coalesced_signals, 32);
        assert_eq!(receiver.try_recv(), Ok(()));
        assert!(receiver.try_recv().is_err());

        let epoch = state.backend_error_epoch.load(Ordering::Acquire);
        state.record_success(epoch);
        assert!(!state.health().uncertain);

        let stale_epoch = state.backend_error_epoch.load(Ordering::Acquire);
        signal.notify(true);
        state.record_success(stale_epoch);
        assert!(state.health().uncertain);
        let current_epoch = state.backend_error_epoch.load(Ordering::Acquire);
        state.record_success(current_epoch);
        assert!(!state.health().uncertain);
    }

    #[test]
    fn watcher_definition_is_stable_and_binds_the_observer() {
        assert_eq!(repository_watcher_definition_digest(), repository_watcher_definition_digest());
        assert_ne!(
            repository_watcher_definition_digest(),
            git_repository_observer_definition_digest()
        );
    }
}
