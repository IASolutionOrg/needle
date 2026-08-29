use needle_runtime::{
    ActionSafetyMetrics, RepositoryWatcher, RepositoryWatcherHealth, RepositoryWatcherHealthHandle,
    RuntimeStore,
};
use serde::Serialize;
use std::path::Path;

const RUNTIME_HEALTH_SCHEMA: &str = "needle.runtime-health/2";
const REPOSITORY_WATCHER_HEALTH_SCHEMA: &str = "needle.repository-watcher-health/1";
const ACTION_SAFETY_HEALTH_SCHEMA: &str = "needle.action-safety-health/1";

pub(super) struct ResidentRepositoryWatcher {
    _watcher: Option<RepositoryWatcher>,
    health: RepositoryRuntimeHealth,
}

impl ResidentRepositoryWatcher {
    pub(super) fn start(store: RuntimeStore, repository_root: &Path) -> Self {
        match RepositoryWatcher::start(store, repository_root) {
            Ok(watcher) => {
                let health = RepositoryRuntimeHealth::Running(watcher.health_handle());
                Self { _watcher: Some(watcher), health }
            }
            Err(_) => Self { _watcher: None, health: RepositoryRuntimeHealth::Unavailable },
        }
    }

    pub(super) fn health(&self) -> RepositoryRuntimeHealth {
        self.health.clone()
    }
}

#[derive(Clone, Debug)]
pub(super) enum RepositoryRuntimeHealth {
    Running(RepositoryWatcherHealthHandle),
    Unavailable,
}

impl RepositoryRuntimeHealth {
    #[cfg(test)]
    pub(super) fn unavailable() -> Self {
        Self::Unavailable
    }

    #[cfg(test)]
    pub(super) fn response(&self) -> RuntimeHealthResponse {
        self.response_with_action_safety(Some(ActionSafetyMetrics::default()))
    }

    pub(super) fn response_with_action_safety(
        &self,
        metrics: Option<ActionSafetyMetrics>,
    ) -> RuntimeHealthResponse {
        let repository_watcher = match self {
            Self::Running(handle) => RepositoryWatcherHealthResponse::running(handle.health()),
            Self::Unavailable => RepositoryWatcherHealthResponse::unavailable(),
        };
        let action_safety = ActionSafetyHealthResponse::new(metrics);
        RuntimeHealthResponse {
            schema: RUNTIME_HEALTH_SCHEMA,
            status: if repository_watcher.status == RepositoryWatcherStatus::Healthy
                && action_safety.status == ActionSafetyStatus::Healthy
            {
                RuntimeStatus::Ok
            } else {
                RuntimeStatus::Degraded
            },
            repository_watcher,
            action_safety,
        }
    }

    pub(super) fn uncertain(&self) -> bool {
        match self {
            Self::Running(handle) => handle.health().uncertain,
            Self::Unavailable => true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeStatus {
    Ok,
    Degraded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RepositoryWatcherStatus {
    Healthy,
    Uncertain,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ActionSafetyStatus {
    Healthy,
    Violations,
    Unavailable,
}

#[derive(Debug, Serialize)]
pub(super) struct RuntimeHealthResponse {
    schema: &'static str,
    status: RuntimeStatus,
    repository_watcher: RepositoryWatcherHealthResponse,
    action_safety: ActionSafetyHealthResponse,
}

#[derive(Debug, Serialize)]
struct ActionSafetyHealthResponse {
    schema: &'static str,
    status: ActionSafetyStatus,
    metrics: Option<ActionSafetyMetrics>,
}

impl ActionSafetyHealthResponse {
    fn new(metrics: Option<ActionSafetyMetrics>) -> Self {
        let status = match metrics {
            Some(metrics) if metrics.is_clean() => ActionSafetyStatus::Healthy,
            Some(_) => ActionSafetyStatus::Violations,
            None => ActionSafetyStatus::Unavailable,
        };
        Self { schema: ACTION_SAFETY_HEALTH_SCHEMA, status, metrics }
    }
}

#[derive(Debug, Serialize)]
struct RepositoryWatcherHealthResponse {
    schema: &'static str,
    status: RepositoryWatcherStatus,
    successful_reconciliations: u64,
    failed_reconciliations: u64,
    backend_errors: u64,
    coalesced_signals: u64,
}

impl RepositoryWatcherHealthResponse {
    fn running(health: RepositoryWatcherHealth) -> Self {
        Self {
            schema: REPOSITORY_WATCHER_HEALTH_SCHEMA,
            status: if health.uncertain {
                RepositoryWatcherStatus::Uncertain
            } else {
                RepositoryWatcherStatus::Healthy
            },
            successful_reconciliations: health.successful_reconciliations,
            failed_reconciliations: health.failed_reconciliations,
            backend_errors: health.backend_errors,
            coalesced_signals: health.coalesced_signals,
        }
    }

    fn unavailable() -> Self {
        Self {
            schema: REPOSITORY_WATCHER_HEALTH_SCHEMA,
            status: RepositoryWatcherStatus::Unavailable,
            successful_reconciliations: 0,
            failed_reconciliations: 0,
            backend_errors: 0,
            coalesced_signals: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_root(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        std::env::temp_dir()
            .join(format!("needle-runtime-health-{name}-{}-{nonce}", std::process::id()))
    }

    fn git_repository(root: &Path) {
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), b"pub fn answer() -> u32 { 42 }\n").unwrap();
        for arguments in [
            &["init", "--quiet"][..],
            &["config", "user.email", "needle@example.invalid"],
            &["config", "user.name", "Needle Test"],
            &["add", "src/lib.rs"],
            &["commit", "--quiet", "-m", "fixture"],
        ] {
            assert!(
                Command::new("git").args(arguments).current_dir(root).status().unwrap().success()
            );
        }
    }

    #[test]
    fn resident_owner_reports_the_initial_reconciliation() {
        let root = temporary_root("running");
        let repository = root.join("repository");
        git_repository(&repository);
        let store = RuntimeStore::new(root.join("needle.sqlite3"));
        store.initialize().unwrap();

        let owner = ResidentRepositoryWatcher::start(store, &repository);
        let response = serde_json::to_value(owner.health().response()).unwrap();
        assert_eq!(response["status"], "ok");
        assert_eq!(response["repository_watcher"]["status"], "healthy");
        assert_eq!(response["repository_watcher"]["successful_reconciliations"], 1);
        assert_eq!(response["action_safety"]["status"], "healthy");
        assert_eq!(response["action_safety"]["metrics"]["stale_artifact_served"], 0);

        drop(owner);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unavailable_watcher_degrades_health_without_failing_startup() {
        let root = temporary_root("unavailable");
        let repository = root.join("repository");
        fs::create_dir_all(&repository).unwrap();
        let store = RuntimeStore::new(root.join("needle.sqlite3"));
        store.initialize().unwrap();

        let owner = ResidentRepositoryWatcher::start(store, &repository);
        let response = serde_json::to_value(owner.health().response()).unwrap();
        assert_eq!(response["status"], "degraded");
        assert_eq!(response["repository_watcher"]["status"], "unavailable");

        drop(owner);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn uncertain_watcher_degrades_runtime_health() {
        let response = RepositoryWatcherHealthResponse::running(RepositoryWatcherHealth {
            successful_reconciliations: 2,
            failed_reconciliations: 1,
            backend_errors: 1,
            coalesced_signals: 3,
            uncertain: true,
        });
        assert_eq!(response.status, RepositoryWatcherStatus::Uncertain);
    }
}
