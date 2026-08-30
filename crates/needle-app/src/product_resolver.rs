use crate::runtime_instance;
use needle_core::{
    AgentHost, RoleProfileProvenance, WorkerConfig, WorkerFailure, WorkerOutcome, WorkerRequest,
};
use needle_platform_antigravity::{AntigravityWorker, inspect_installation};
use needle_platform_codex::CodexWorker;
use needle_runtime::{ResolveOutcome, ResolveRequest, RuntimeEngine, RuntimeStore, WorkerExecutor};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerPolicy {
    Allow,
    CacheOnly,
}

pub(crate) struct ProductResolver {
    data_directory: PathBuf,
    store: RuntimeStore,
    engine: RuntimeEngine<HostWorker>,
    worker_policy: WorkerPolicy,
}

#[derive(Clone, Debug)]
struct HostWorker {
    store: RuntimeStore,
    codex: CodexWorker,
    antigravity: AntigravityWorker,
    antigravity_executable: Option<PathBuf>,
}

impl HostWorker {
    fn selected_host(&self, config: &WorkerConfig) -> Result<AgentHost, String> {
        let Some(provenance) = config.role_profile_provenance.as_ref() else {
            return Ok(AgentHost::Codex);
        };
        provenance.validate().map_err(|error| error.to_string())?;
        let revision = self
            .store
            .read_role_profile_revision(&provenance.profile_id, provenance.revision)
            .map_err(|error| error.to_string())?;
        let actual =
            RoleProfileProvenance::from_revision(&revision).map_err(|error| error.to_string())?;
        if &actual != provenance {
            return Err(
                "worker role-profile provenance does not match its immutable revision".to_owned()
            );
        }
        Ok(revision.definition.host)
    }
}

impl WorkerExecutor for HostWorker {
    fn execute(
        &self,
        config: &WorkerConfig,
        request: &WorkerRequest,
    ) -> Result<WorkerOutcome, Box<WorkerFailure>> {
        match self.selected_host(config) {
            Ok(AgentHost::Codex) => self.codex.execute(config, request),
            Ok(AgentHost::Antigravity) => {
                let Some(executable) = &self.antigravity_executable else {
                    return Err(dispatch_failure(
                        config,
                        "host_unavailable",
                        "the selected Antigravity role has no installed agy CLI",
                    ));
                };
                let mut host_config = config.clone();
                host_config.executable = executable.display().to_string();
                self.antigravity.execute(&host_config, request)
            }
            Err(error) => Err(dispatch_failure(config, "host_selection_invalid", &error)),
        }
    }
}

fn dispatch_failure(config: &WorkerConfig, code: &str, diagnostic: &str) -> Box<WorkerFailure> {
    Box::new(WorkerFailure {
        code: code.to_owned(),
        diagnostic: diagnostic.to_owned(),
        input_tokens: None,
        cached_input_tokens: None,
        output_tokens: None,
        duration_ms: 0,
        logical_worker_spawns: 0,
        worker_turns: 0,
        repair_performed: false,
        discarded_facts: 0,
        worker_session_id: None,
        session_cleanup_success: Some(true),
        role_profile_provenance: config.role_profile_provenance.clone(),
    })
}

impl ProductResolver {
    pub(crate) fn new(
        data_directory: impl Into<PathBuf>,
        worker_policy: WorkerPolicy,
    ) -> Result<Self, String> {
        Self::new_with_cancellation(data_directory, worker_policy, None)
    }

    pub(crate) fn new_cancellable(
        data_directory: impl Into<PathBuf>,
        worker_policy: WorkerPolicy,
        cancellation: Arc<AtomicBool>,
    ) -> Result<Self, String> {
        Self::new_with_cancellation(data_directory, worker_policy, Some(cancellation))
    }

    fn new_with_cancellation(
        data_directory: impl Into<PathBuf>,
        worker_policy: WorkerPolicy,
        cancellation: Option<Arc<AtomicBool>>,
    ) -> Result<Self, String> {
        let data_directory = data_directory.into();
        let store = RuntimeStore::new(data_directory.join("needle.sqlite3"));
        store.initialize().map_err(|error| error.to_string())?;
        // A migrated database without product settings is not runnable. Fail at
        // startup instead of returning a misleading tool-level cache miss.
        store.settings().map_err(|error| error.to_string())?;
        let antigravity_executable = inspect_installation().cli_executable;
        let codex = CodexWorker::new(data_directory.clone());
        let antigravity = AntigravityWorker::new(data_directory.clone());
        let (codex, antigravity) = if let Some(cancellation) = cancellation {
            (
                codex.with_cancellation(Arc::clone(&cancellation)),
                antigravity.with_cancellation(cancellation),
            )
        } else {
            (codex, antigravity)
        };
        let worker =
            HostWorker { store: store.clone(), codex, antigravity, antigravity_executable };
        let engine = RuntimeEngine::new(store.clone(), worker);
        Ok(Self { data_directory, store, engine, worker_policy })
    }

    pub(crate) fn store(&self) -> &RuntimeStore {
        &self.store
    }

    pub(crate) fn resolve(&self, request: &ResolveRequest) -> Result<ResolveOutcome, String> {
        if self.worker_policy == WorkerPolicy::CacheOnly {
            return self.engine.resolve_cache_only(request).map_err(|error| error.to_string());
        }
        if !runtime_instance::is_published(&self.data_directory) {
            return self.engine.resolve(request).map_err(|error| error.to_string());
        }
        match runtime_instance::resolve_resident(&self.data_directory, request) {
            Ok(outcome) => Ok(outcome),
            Err(runtime_instance::ResidentResolveError::Unavailable(error)) => {
                eprintln!("needle: resident runtime unavailable ({error}); using local resolver");
                self.engine.resolve(request).map_err(|error| error.to_string())
            }
            Err(runtime_instance::ResidentResolveError::Remote(error)) => Err(error),
        }
    }

    pub(crate) fn resolve_direct_explore(
        &self,
        request: &ResolveRequest,
    ) -> Result<ResolveOutcome, String> {
        if self.worker_policy == WorkerPolicy::CacheOnly {
            return self
                .engine
                .resolve_direct_explore_cache_only(request)
                .map_err(|error| error.to_string());
        }
        self.engine.resolve_direct_explore(request).map_err(|error| error.to_string())
    }

    pub(crate) fn resolve_semantic_required(
        &self,
        request: &ResolveRequest,
    ) -> Result<ResolveOutcome, String> {
        if self.worker_policy == WorkerPolicy::CacheOnly {
            return self
                .engine
                .resolve_semantic_required_cache_only(request)
                .map_err(|error| error.to_string());
        }
        self.engine.resolve_semantic_required(request).map_err(|error| error.to_string())
    }

    pub(crate) fn resolve_semantic_required_calibration(
        &self,
        request: &ResolveRequest,
    ) -> Result<ResolveOutcome, String> {
        if self.worker_policy == WorkerPolicy::CacheOnly {
            return self
                .engine
                .resolve_semantic_required_cache_only(request)
                .map_err(|error| error.to_string());
        }
        self.engine
            .resolve_semantic_required_calibration(request)
            .map_err(|error| error.to_string())
    }

    pub(crate) fn resolve_semantic_required_cache_only(
        &self,
        request: &ResolveRequest,
    ) -> Result<ResolveOutcome, String> {
        self.engine.resolve_semantic_required_cache_only(request).map_err(|error| error.to_string())
    }

    pub(crate) fn data_directory(&self) -> &Path {
        &self.data_directory
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use needle_core::{
        CodexRole, CommandPolicy, Digest, FallbackPolicy, FilesystemPolicy, NetworkPolicy,
        ReasoningLevel, RepairPolicy, RoleProfileBudget, RoleProfileDefinition,
        RoleProfileDefinitionInput, RoleProfileId, ServiceTier, TestPolicy, ToolPolicy,
    };
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn immutable_profile_provenance_selects_antigravity_without_model_inference() {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("needle-host-dispatch-{suffix}"));
        fs::create_dir_all(&root).unwrap();
        let store = RuntimeStore::new(root.join("needle.sqlite3"));
        store.initialize().unwrap();
        let revision = store
            .create_role_profile(
                RoleProfileDefinition::new(RoleProfileDefinitionInput {
                    profile_id: RoleProfileId::new("explorer.antigravity").unwrap(),
                    role: CodexRole::Explorer,
                    host: AgentHost::Antigravity,
                    model: "gemini-3.7-flash-medium".to_owned(),
                    reasoning: ReasoningLevel::Medium,
                    service_tier: ServiceTier::Default,
                    timeout_seconds: 120,
                    budget: RoleProfileBudget {
                        max_turns: 1,
                        max_output_tokens: 1_200,
                        max_cost_microusd: 1_000,
                    },
                    prompt_profile_digest: Digest::blake3(b"prompt"),
                    output_contract_digest: Digest::blake3(b"output"),
                    tool_policy: ToolPolicy::ReadOnly,
                    command_policy: CommandPolicy::ReadOnly,
                    filesystem_policy: FilesystemPolicy::ReadOnlyCheckout,
                    network_policy: NetworkPolicy::Denied,
                    test_policy: TestPolicy::Disabled,
                    repair_policy: RepairPolicy::None,
                    fallback_policy: FallbackPolicy::Disabled,
                    concurrency: 1,
                    route_assignments: Vec::new(),
                })
                .unwrap(),
            )
            .unwrap();
        let config = revision.to_worker_config("codex").unwrap();
        let worker = HostWorker {
            store: store.clone(),
            codex: CodexWorker::new(&root),
            antigravity: AntigravityWorker::new(&root),
            antigravity_executable: None,
        };

        assert_eq!(worker.selected_host(&config).unwrap(), AgentHost::Antigravity);

        drop(worker);
        drop(store);
        let _ = fs::remove_dir_all(root);
    }
}
