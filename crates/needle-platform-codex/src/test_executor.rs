use crate::app_server::{AppServerSession, AppServerTurn};
use crate::{CodexWorker, codex_change_action_provider_definition};
use needle_core::{
    ArtifactId, ArtifactRequestId, CanonicalHasher, ChangeId, Digest, PatchId,
    TestExecutionEvidence, TestExecutionStatus, TestPlan, WorkerConfig,
};
use needle_runtime::{
    IsolatedCheckout, RuntimeStore, capture_git_snapshot, materialize_patch_artifact,
};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TEST_EXECUTOR_POLICY_VERSION: &[u8] = b"needle-codex-test-executor-policy-v2";

#[derive(Clone, Debug)]
pub(crate) struct CodexTestExecutor {
    data_directory: PathBuf,
    codex_home: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub(crate) struct TestExecutionBinding {
    pub action_request: ArtifactRequestId,
    pub change_id: ChangeId,
    pub requirements_digest: Digest,
    pub patch_id: PatchId,
    pub test_plan_artifact: ArtifactId,
    pub source_snapshot: Digest,
}

impl CodexTestExecutor {
    pub(crate) fn new(data_directory: impl Into<PathBuf>) -> Self {
        Self { data_directory: data_directory.into(), codex_home: None }
    }

    pub(crate) fn with_codex_home(mut self, codex_home: impl Into<PathBuf>) -> Self {
        self.codex_home = Some(codex_home.into());
        self
    }

    pub(crate) fn execute(
        &self,
        config: &WorkerConfig,
        repository_root: &Path,
        binding: TestExecutionBinding,
    ) -> Result<TestExecutionEvidence, String> {
        let store = RuntimeStore::new(self.data_directory.join("needle.sqlite3"));
        let prepared = store
            .prepared_change(&binding.change_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("change `{}` is not prepared", binding.change_id))?;
        if prepared.patch.id != binding.patch_id
            || prepared.source_snapshot != binding.source_snapshot
            || prepared.request_digest != binding.requirements_digest
            || prepared.request_digest != prepared.request.digest(binding.source_snapshot)
        {
            return Err("test execution patch binding is stale or inconsistent".to_owned());
        }
        let candidate = store
            .lifecycle_start_test_plan_candidates(binding.source_snapshot)
            .map_err(|error| error.to_string())?
            .into_iter()
            .find(|candidate| candidate.artifact_id == binding.test_plan_artifact)
            .ok_or_else(|| {
                "test execution requires a certified TestPlan for the exact source".to_owned()
            })?;
        let plan_digest = candidate.binding.plan_digest();
        let plan = candidate.binding.plan;
        plan.test_command()
            .map_err(|violations| format!("TestPlan is not canonical: {violations:?}"))?;

        let command_digest = plan.identity_digest();
        let environment_digest = environment_definition_digest();
        let policy_digest = execution_policy_digest(config);
        let settings = store.settings().map_err(|error| error.to_string())?;
        if !settings.trusted_test_execution {
            return TestExecutionEvidence::new(
                binding.action_request,
                binding.change_id,
                binding.patch_id,
                binding.test_plan_artifact,
                plan_digest,
                None,
                binding.source_snapshot,
                None,
                command_digest,
                unresolved_toolchain_digest(&plan),
                environment_digest,
                policy_digest,
                TestExecutionStatus::Unavailable,
                None,
                Digest::blake3(b"trusted_test_execution_disabled"),
                0,
                now_ms(),
            )
            .map_err(|error| error.to_string());
        }

        let isolation = CodexWorker::verify_isolation(&config.executable)?;
        if !isolation.verified() {
            return Err(format!(
                "test executor isolation is not verified for Codex {}",
                isolation.codex_version
            ));
        }
        let repository_root = fs::canonicalize(repository_root)
            .map_err(|error| format!("cannot resolve test repository: {error}"))?;
        let sandbox = IsolatedCheckout::materialize(
            &repository_root,
            &self.data_directory.join("test-execution-runs"),
        )
        .map_err(|error| error.to_string())?;
        if sandbox.snapshot().source_digest != binding.source_snapshot {
            return cleanup_after_error(
                sandbox,
                "active source snapshot changed before test execution".to_owned(),
            );
        }
        let blobs = match store.patch_file_blobs(prepared.patch.id) {
            Ok(blobs) => blobs,
            Err(error) => return cleanup_after_error(sandbox, error.to_string()),
        };
        if let Err(error) =
            materialize_patch_artifact(sandbox.checkout_root(), &prepared.patch, &blobs)
        {
            return cleanup_after_error(sandbox, error.to_string());
        }
        let (_, patched_snapshot) = match capture_git_snapshot(sandbox.checkout_root()) {
            Ok(snapshot) => snapshot,
            Err(error) => return cleanup_after_error(sandbox, error.to_string()),
        };
        let cwd = match safe_test_cwd(sandbox.checkout_root(), &plan.cwd_relative) {
            Ok(cwd) => cwd,
            Err(error) => return cleanup_after_error(sandbox, error),
        };
        let toolchain_digest = toolchain_definition_digest(&plan, &cwd);
        let instructions = test_executor_instructions(&plan);
        let mut session = match AppServerSession::start_test_executor(
            config,
            self.codex_home.as_deref(),
            &instructions,
            sandbox.checkout_root(),
            sandbox.target_root(),
            sandbox.temp_root(),
            patched_snapshot.source_digest,
            patched_snapshot.repository_id,
            plan.clone(),
            store,
        ) {
            Ok(session) => session,
            Err(error) => return cleanup_after_error(sandbox, error),
        };
        session.fail_fast_on_pending_approvals();
        let turn = session.run_turn_cancellable(
            &test_executor_prompt(&plan),
            &test_executor_output_schema(),
            Duration::from_secs(config.timeout_seconds),
            None,
        );
        let result = evidence_from_turn(
            turn,
            &plan,
            binding,
            plan_digest,
            patched_snapshot.source_digest,
            command_digest,
            toolchain_digest,
            environment_digest,
            policy_digest,
        );
        let session_error = session.cleanup().err();
        let after =
            capture_git_snapshot(sandbox.checkout_root()).map_err(|error| error.to_string());
        let sandbox_error = sandbox.cleanup().err();
        if let Some(error) = session_error {
            return Err(format!("test executor App Server cleanup failed: {error}"));
        }
        let (_, after) = after?;
        if after.source_digest != patched_snapshot.source_digest {
            return Err("certified test command modified the patched source checkout".to_owned());
        }
        if let Some(error) = sandbox_error {
            return Err(format!("test executor checkout cleanup failed: {error}"));
        }
        result
    }
}

#[allow(clippy::too_many_arguments)]
fn evidence_from_turn(
    turn: Result<AppServerTurn, crate::app_server::AppServerTurnFailure>,
    plan: &TestPlan,
    binding: TestExecutionBinding,
    plan_digest: Digest,
    execution_snapshot: Digest,
    command_digest: Digest,
    toolchain_digest: Digest,
    environment_digest: Digest,
    policy_digest: Digest,
) -> Result<TestExecutionEvidence, String> {
    let (status, exit_status, command_evidence_id, output_digest, duration_ms) = match turn {
        Ok(turn) => {
            let mut captured = turn
                .test_evidence
                .into_iter()
                .filter(|item| item.plan_digest == plan.identity_digest())
                .collect::<Vec<_>>();
            if captured.len() != 1 {
                (
                    TestExecutionStatus::Inconclusive,
                    None,
                    None,
                    Digest::blake3(b"expected exactly one certified command execution"),
                    0,
                )
            } else {
                let evidence = captured.pop().expect("length checked").evidence;
                let evidence_id = Some(evidence.id.clone());
                if evidence.argv != plan.argv || evidence.infrastructure_failure.is_some() {
                    (
                        TestExecutionStatus::Inconclusive,
                        None,
                        evidence_id,
                        evidence.output_digest,
                        evidence.duration_ms,
                    )
                } else {
                    let exit = evidence.exit_status;
                    (
                        if exit == Some(0) {
                            TestExecutionStatus::Passed
                        } else {
                            TestExecutionStatus::Failed
                        },
                        exit,
                        evidence_id,
                        evidence.output_digest,
                        evidence.duration_ms,
                    )
                }
            }
        }
        Err(error) => (
            TestExecutionStatus::Inconclusive,
            None,
            None,
            Digest::blake3(error.diagnostic.as_bytes()),
            0,
        ),
    };
    TestExecutionEvidence::new(
        binding.action_request,
        binding.change_id,
        binding.patch_id,
        binding.test_plan_artifact,
        plan_digest,
        command_evidence_id,
        binding.source_snapshot,
        Some(execution_snapshot),
        command_digest,
        toolchain_digest,
        environment_digest,
        policy_digest,
        status,
        exit_status,
        output_digest,
        duration_ms,
        now_ms(),
    )
    .map_err(|error| error.to_string())
}

fn safe_test_cwd(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let path = Path::new(relative);
    if relative.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(component, Component::ParentDir | Component::RootDir | Component::Prefix(_))
        })
    {
        return Err("TestPlan cwd is not a safe repository-relative path".to_owned());
    }
    let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    let cwd = fs::canonicalize(root.join(path)).map_err(|error| error.to_string())?;
    if cwd != root && !cwd.starts_with(&root) {
        return Err("TestPlan cwd escapes the isolated checkout".to_owned());
    }
    Ok(cwd)
}

fn test_executor_instructions(plan: &TestPlan) -> String {
    format!(
        "You are Needle's dedicated test executor. Execute exactly one parent-certified direct command in the disposable checkout and do nothing else. Do not inspect files, discover commands, modify source, use the network, hooks, plugins, MCP, project instructions, memory, or other agents. Request exactly the argv and cwd supplied by the parent, wait for completion, then return the closed JSON result. Certified TestPlan digest: {}.",
        plan.identity_digest()
    )
}

fn test_executor_prompt(plan: &TestPlan) -> String {
    serde_json::to_string(&json!({
        "operation": "execute_certified_test_plan",
        "argv": plan.argv,
        "cwd_relative": plan.cwd_relative,
        "test_identifier": plan.test_identifier,
        "maximum_executions": 1
    }))
    .expect("bounded TestPlan serializes")
}

fn test_executor_output_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["completed"],
        "properties": {"completed": {"type": "boolean"}}
    })
}

fn environment_definition_digest() -> Digest {
    const KEYS: &[&str] = &["PATH", "Path", "PATHEXT", "SYSTEMROOT", "WINDIR"];
    let mut values = KEYS
        .iter()
        .filter_map(|key| env::var(key).ok().map(|value| ((*key).to_ascii_uppercase(), value)))
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    let mut hasher = CanonicalHasher::new(b"needle-test-environment-v1");
    hasher.field_str(env::consts::OS);
    hasher.field_str(env::consts::ARCH);
    hasher.field_u16(values.len().try_into().unwrap_or(u16::MAX));
    for (key, value) in values {
        hasher.field_str(&key);
        hasher.field_str(&value);
    }
    hasher.finish()
}

fn execution_policy_digest(config: &WorkerConfig) -> Digest {
    let mut hasher = CanonicalHasher::new(TEST_EXECUTOR_POLICY_VERSION);
    hasher.field_digest(codex_change_action_provider_definition());
    hasher.field_digest(config.digest());
    hasher.finish()
}

fn toolchain_definition_digest(plan: &TestPlan, cwd: &Path) -> Digest {
    let candidate = resolve_runner(&plan.runner, cwd);
    let mut hasher = CanonicalHasher::new(b"needle-test-toolchain-binding-v1");
    hasher.field_str(&plan.runner);
    if let Some(path) = candidate {
        hasher.field_str(&path.to_string_lossy());
        if let Ok(metadata) = fs::metadata(&path) {
            hasher.field_bytes(&metadata.len().to_le_bytes());
            if let Ok(modified) = metadata.modified()
                && let Ok(duration) = modified.duration_since(UNIX_EPOCH)
            {
                hasher.field_bytes(&duration.as_nanos().to_le_bytes());
            }
        }
    }
    hasher.finish()
}

fn unresolved_toolchain_digest(plan: &TestPlan) -> Digest {
    let mut hasher = CanonicalHasher::new(b"needle-test-toolchain-unavailable-v1");
    hasher.field_str(&plan.runner);
    hasher.finish()
}

fn resolve_runner(runner: &str, cwd: &Path) -> Option<PathBuf> {
    let path = Path::new(runner);
    if path.components().count() > 1 || path.is_absolute() {
        return fs::canonicalize(if path.is_absolute() {
            path.to_path_buf()
        } else {
            cwd.join(path)
        })
        .ok();
    }
    let path_value = env::var_os("PATH").or_else(|| env::var_os("Path"))?;
    let extensions = env::var_os("PATHEXT")
        .map(|value| {
            value
                .to_string_lossy()
                .split(';')
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![String::new()]);
    for directory in env::split_paths(&path_value) {
        for extension in &extensions {
            let candidate = directory.join(format!("{runner}{extension}"));
            if candidate.is_file()
                && let Ok(canonical) = fs::canonicalize(candidate)
            {
                return Some(canonical);
            }
        }
    }
    None
}

fn cleanup_after_error<T>(sandbox: IsolatedCheckout, error: String) -> Result<T, String> {
    match sandbox.cleanup() {
        Ok(()) => Err(error),
        Err(cleanup) => Err(format!("{error}; test checkout cleanup failed: {cleanup}")),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toolchain_binding_is_ecosystem_agnostic() {
        let python = TestPlan {
            runner: "python".to_owned(),
            argv: vec![
                "python".to_owned(),
                "-m".to_owned(),
                "pytest".to_owned(),
                "tests/test_api.py::test_ok".to_owned(),
            ],
            cwd_relative: ".".to_owned(),
            test_identifier: "tests/test_api.py::test_ok".to_owned(),
            requires_approval: true,
            execution_evidence_id: None,
        };
        let node = TestPlan {
            runner: "npm".to_owned(),
            argv: vec![
                "npm".to_owned(),
                "test".to_owned(),
                "--".to_owned(),
                "api.test.ts".to_owned(),
            ],
            cwd_relative: ".".to_owned(),
            test_identifier: "api.test.ts".to_owned(),
            requires_approval: true,
            execution_evidence_id: None,
        };
        assert!(python.test_command().is_ok());
        assert!(node.test_command().is_ok());
        assert_ne!(python.identity_digest(), node.identity_digest());
    }
}
