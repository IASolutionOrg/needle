use super::{
    AppError, absolute_run_path, ensure_codex_authenticated, option_value, required_value,
    resolve_codex,
};
use needle_core::{
    AllowedPath, AllowedPathScope, ChangeRequest, CodexHost, CodexRole, CommandPolicy, Digest,
    EvidenceFailurePolicy, Facet, FallbackPolicy, FilesystemPolicy, LifecycleExecutionRequest,
    MultiNeedPolicy, NeedExecution, NeedExecutionEnvelopeV1, NeedIr, NeedKey, NetworkPolicy,
    ObligationExpression, ReasoningLevel, RepairPolicy, RoleProfileBudget, RoleProfileDefinition,
    RoleProfileDefinitionInput, RoleProfileId, ServiceTier, SubjectExpression, SubjectKind,
    TestPolicy, ToolPolicy,
};
use needle_platform_codex::CodexWorker;
use needle_runtime::{RuntimeSettings, RuntimeStore, capture_git_snapshot};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MANIFEST_SCHEMA: &str = "needle.lifecycle-gate-a7-manifest/1";
const PREFLIGHT_SCHEMA: &str = "needle.lifecycle-gate-a7-preflight/1";
const RUN_SCHEMA: &str = "needle.lifecycle-gate-a7-run/1";
const EXECUTION_CONFIRMATION: &str = "I_ACCEPT_6_LUNA_PROVIDER_SESSIONS";
const MAX_PROVIDER_SESSIONS: u8 = 6;
const MAX_CHILD_STDOUT_BYTES: usize = 1024 * 1024;
const MAX_CHILD_STDERR_BYTES: usize = 64 * 1024;
const MAX_EXECUTION_SECONDS: u64 = 30 * 60;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GateA7Manifest {
    schema: String,
    repository: PathBuf,
    data_directory: PathBuf,
    codex_executable: PathBuf,
    auth_source_codex_home: PathBuf,
    codex_version: String,
    repository_id: Digest,
    source_snapshot: Digest,
    request_digest: Digest,
    operation_id: Digest,
    maximum_provider_sessions: u8,
    model: String,
    reasoning: String,
    service_tier: String,
}

pub(super) fn run(arguments: &[String]) -> Result<(), AppError> {
    let preflight = arguments.iter().any(|argument| argument == "--preflight-only");
    let execute = arguments.iter().any(|argument| argument == "--execute-to-approval");
    if u8::from(preflight) + u8::from(execute) != 1 {
        return Err(AppError::Usage(
            "lifecycle-gate-a7 requires exactly one of --preflight-only or --execute-to-approval"
                .to_owned(),
        ));
    }
    let artifact_root =
        absolute_run_path(Path::new(&required_value(arguments, "--artifact-root")?))?;
    if preflight {
        prepare(arguments, &artifact_root)
    } else {
        execute_to_approval(arguments, &artifact_root)
    }
}

fn prepare(arguments: &[String], artifact_root: &Path) -> Result<(), AppError> {
    if artifact_root.exists() {
        return Err(AppError::Experiment(format!(
            "Gate A7 artifact root already exists: {}",
            artifact_root.display()
        )));
    }
    let codex = resolve_codex(option_value(arguments, "--codex"))?;
    let codex_home = PathBuf::from(required_value(arguments, "--codex-home")?);
    let codex_home = fs::canonicalize(codex_home)?;
    verify_auth_source(&codex, &codex_home)?;
    let isolation =
        CodexWorker::verify_isolation(&codex.display().to_string()).map_err(AppError::Runtime)?;
    if !isolation.verified() {
        return Err(AppError::Experiment(format!(
            "Gate A7 worker isolation is not verified for Codex {}",
            isolation.codex_version
        )));
    }

    fs::create_dir_all(artifact_root)?;
    let repository = artifact_root.join("repository");
    let data_directory = artifact_root.join("data");
    create_fixture(&repository)?;
    fs::create_dir_all(&data_directory)?;
    let (_, snapshot) = capture_git_snapshot(&repository)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let envelope = fixture_envelope(snapshot.source_digest);
    envelope.validate().map_err(|error| AppError::Experiment(error.to_string()))?;
    let request_bytes = serde_json::to_vec_pretty(&envelope)?;
    let request_digest = Digest::blake3(&request_bytes);
    fs::write(artifact_root.join("request.json"), &request_bytes)?;

    initialize_store(&data_directory, &codex)?;
    let manifest = GateA7Manifest {
        schema: MANIFEST_SCHEMA.to_owned(),
        repository: fs::canonicalize(&repository)?,
        data_directory: fs::canonicalize(&data_directory)?,
        codex_executable: codex,
        auth_source_codex_home: codex_home,
        codex_version: isolation.codex_version,
        repository_id: snapshot.repository_id,
        source_snapshot: snapshot.source_digest,
        request_digest,
        operation_id: envelope.operation_id,
        maximum_provider_sessions: MAX_PROVIDER_SESSIONS,
        model: "gpt-5.6-luna".to_owned(),
        reasoning: "medium".to_owned(),
        service_tier: "priority".to_owned(),
    };
    write_create_new(&artifact_root.join("manifest.json"), &manifest)?;
    let report = json!({
        "schema": PREFLIGHT_SCHEMA,
        "passed": true,
        "live_provider_sessions_started": 0,
        "repository": manifest.repository,
        "repository_id": manifest.repository_id,
        "source_snapshot": manifest.source_snapshot,
        "operation_id": manifest.operation_id,
        "request_digest": manifest.request_digest,
        "model": manifest.model,
        "reasoning": manifest.reasoning,
        "service_tier": manifest.service_tier,
        "maximum_provider_sessions": MAX_PROVIDER_SESSIONS,
        "planned_sessions": [
            "explore",
            "implement",
            "test_plan_discovery",
            "certified_test_execution",
            "review",
            "verify"
        ],
        "active_worktree_mutation_before_apply": false,
        "apply_included": false,
        "automatic_retries": 0,
        "execution_confirmation": EXECUTION_CONFIRMATION,
    });
    write_create_new(&artifact_root.join("preflight.json"), &report)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn execute_to_approval(arguments: &[String], artifact_root: &Path) -> Result<(), AppError> {
    if required_value(arguments, "--confirmation")? != EXECUTION_CONFIRMATION {
        return Err(AppError::Usage(format!(
            "--execute-to-approval requires --confirmation {EXECUTION_CONFIRMATION}"
        )));
    }
    let manifest: GateA7Manifest = read_json(&artifact_root.join("manifest.json"))?;
    if manifest.schema != MANIFEST_SCHEMA
        || manifest.maximum_provider_sessions != MAX_PROVIDER_SESSIONS
        || manifest.model != "gpt-5.6-luna"
        || manifest.reasoning != "medium"
        || manifest.service_tier != "priority"
    {
        return Err(AppError::Experiment("Gate A7 manifest is incompatible".to_owned()));
    }
    let request_path = artifact_root.join("request.json");
    let request_bytes =
        read_bounded_file(&request_path, needle_core::MAX_NEED_EXECUTION_WIRE_BYTES)?;
    if Digest::blake3(&request_bytes) != manifest.request_digest {
        return Err(AppError::Experiment("Gate A7 request digest changed".to_owned()));
    }
    let envelope = NeedExecutionEnvelopeV1::decode_json(&request_bytes)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    if envelope.operation_id != manifest.operation_id {
        return Err(AppError::Experiment("Gate A7 operation id changed".to_owned()));
    }
    let (_, before) = capture_git_snapshot(&manifest.repository)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    if before.repository_id != manifest.repository_id
        || before.source_digest != manifest.source_snapshot
    {
        return Err(AppError::Experiment(
            "Gate A7 fixture source changed after preflight".to_owned(),
        ));
    }
    let dedicated_codex_home = artifact_root.join("live-codex-home");
    if dedicated_codex_home.exists() {
        return Err(AppError::Experiment("Gate A7 dedicated Codex home already exists".to_owned()));
    }
    fs::create_dir(&dedicated_codex_home)?;
    fs::copy(
        manifest.auth_source_codex_home.join("auth.json"),
        dedicated_codex_home.join("auth.json"),
    )?;
    let auth_check = ensure_codex_authenticated(
        &manifest.codex_executable,
        &dedicated_codex_home,
        "lifecycle-gate-a7",
    );
    if let Err(error) = auth_check {
        let _ = fs::remove_dir_all(&dedicated_codex_home);
        return Err(error);
    }
    let child = run_needle_child(&manifest, &dedicated_codex_home, &request_bytes);
    let cleanup = fs::remove_dir_all(&dedicated_codex_home);
    let output = child?;
    cleanup?;
    let outcome: Value = serde_json::from_slice(&output)?;
    let (_, after) = capture_git_snapshot(&manifest.repository)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let active_worktree_unchanged = after.source_digest == manifest.source_snapshot;
    let reached_apply_boundary = lifecycle_reached_apply_boundary(&outcome);
    let lifecycle_status =
        outcome.pointer("/result/lifecycle/status").and_then(Value::as_str).unwrap_or("missing");
    let lifecycle_phase =
        outcome.pointer("/result/lifecycle/phase").and_then(Value::as_str).unwrap_or("missing");
    write_create_new(&artifact_root.join("lifecycle-outcome.json"), &outcome)?;
    let safety = RuntimeStore::new(manifest.data_directory.join("needle.sqlite3"))
        .action_safety_metrics()
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let report = json!({
        "schema": RUN_SCHEMA,
        "passed": reached_apply_boundary && active_worktree_unchanged && safety.is_clean(),
        "provider_session_ceiling": MAX_PROVIDER_SESSIONS,
        "lifecycle_status": lifecycle_status,
        "lifecycle_phase": lifecycle_phase,
        "terminal_reason": outcome.pointer("/result/lifecycle/terminal_reason"),
        "reached_apply_approval_boundary": reached_apply_boundary,
        "active_worktree_unchanged": active_worktree_unchanged,
        "apply_executed": false,
        "safety_metrics": safety,
        "outcome_digest": Digest::blake3(&output),
    });
    write_create_new(&artifact_root.join("run-report.json"), &report)?;
    if !active_worktree_unchanged {
        return Err(AppError::Experiment(
            "Gate A7 mutated the active worktree before Apply".to_owned(),
        ));
    }
    if !reached_apply_boundary {
        return Err(AppError::Experiment(format!(
            "Gate A7 lifecycle did not stop at an Apply approval boundary (status={lifecycle_status}, phase={lifecycle_phase})"
        )));
    }
    if !safety.is_clean() {
        return Err(AppError::Experiment("Gate A7 action safety metrics are not clean".to_owned()));
    }
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn lifecycle_reached_apply_boundary(outcome: &Value) -> bool {
    outcome.pointer("/execution").and_then(Value::as_str) == Some("lifecycle")
        && outcome.pointer("/result/lifecycle/status").and_then(Value::as_str)
            == Some("awaiting_approval")
        && outcome.pointer("/result/lifecycle/phase").and_then(Value::as_str) == Some("apply")
        && outcome.pointer("/result/awaiting_apply").is_some_and(|value| !value.is_null())
}

fn initialize_store(data_directory: &Path, codex: &Path) -> Result<(), AppError> {
    let store = RuntimeStore::new(data_directory.join("needle.sqlite3"));
    store
        .initialize_defaults(&RuntimeSettings {
            codex_executable: codex.display().to_string(),
            worker_model: "gpt-5.6-luna".to_owned(),
            worker_reasoning: "medium".to_owned(),
            worker_timeout_seconds: 180,
            evidence_failure_policy: EvidenceFailurePolicy::DiscardInvalidFact,
            trusted_test_execution: true,
            multi_need_policy: MultiNeedPolicy::default(),
        })
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    for (role, id) in [
        (CodexRole::Explorer, "gate-a7.explore"),
        (CodexRole::Implementer, "gate-a7.implement"),
        (CodexRole::TestRunner, "gate-a7.test"),
        (CodexRole::Reviewer, "gate-a7.review"),
        (CodexRole::Verifier, "gate-a7.verify"),
    ] {
        let writes = role == CodexRole::Implementer;
        let tests = matches!(role, CodexRole::TestRunner | CodexRole::Verifier);
        let definition = RoleProfileDefinition::new(RoleProfileDefinitionInput {
            profile_id: RoleProfileId::new(id)
                .map_err(|error| AppError::Experiment(error.to_string()))?,
            role,
            host: CodexHost::Codex,
            model: "gpt-5.6-luna".to_owned(),
            reasoning: ReasoningLevel::Medium,
            service_tier: ServiceTier::Priority,
            timeout_seconds: 180,
            budget: RoleProfileBudget {
                max_turns: if role == CodexRole::TestRunner { 2 } else { 1 },
                max_output_tokens: 1_200,
                max_cost_microusd: if role == CodexRole::TestRunner { 200_000 } else { 100_000 },
            },
            prompt_profile_digest: Digest::blake3(format!("{id}:prompt")),
            output_contract_digest: Digest::blake3(format!("{id}:output")),
            tool_policy: if writes { ToolPolicy::IsolatedWrite } else { ToolPolicy::ReadOnly },
            command_policy: if tests {
                CommandPolicy::CertifiedTests
            } else {
                CommandPolicy::Denied
            },
            filesystem_policy: if writes {
                FilesystemPolicy::DisposableCheckout
            } else {
                FilesystemPolicy::ReadOnlyCheckout
            },
            network_policy: NetworkPolicy::Denied,
            test_policy: if tests { TestPolicy::Certified } else { TestPolicy::Disabled },
            repair_policy: RepairPolicy::None,
            fallback_policy: FallbackPolicy::Disabled,
            concurrency: 1,
            route_assignments: if role == CodexRole::Explorer {
                vec![
                    NeedKey::new("locate.implementation")
                        .map_err(|error| AppError::Experiment(error.to_string()))?,
                ]
            } else {
                Vec::new()
            },
        })
        .map_err(|error| AppError::Experiment(error.to_string()))?;
        let revision = store
            .create_role_profile(definition)
            .map_err(|error| AppError::Experiment(error.to_string()))?;
        let state = store
            .role_profile_state(&revision.profile_id)
            .map_err(|error| AppError::Experiment(error.to_string()))?;
        store
            .activate_role_profile(&revision.profile_id, revision.revision, state.state_digest)
            .map_err(|error| AppError::Experiment(error.to_string()))?;
    }
    Ok(())
}

fn fixture_envelope(source_snapshot: Digest) -> NeedExecutionEnvelopeV1 {
    let change = ChangeRequest {
        task: "Make increment reject non-number values with TypeError while preserving numeric increments."
            .to_owned(),
        acceptance_criteria: vec![
            "increment(1) returns 2.".to_owned(),
            "increment('1') throws TypeError.".to_owned(),
        ],
        allowed_paths: vec![AllowedPath {
            path: "src/counter.js".to_owned(),
            scope: AllowedPathScope::Exact,
        }],
        artifact_ids: Vec::new(),
        claim_ids: Vec::new(),
        constraints: vec![
            "Do not modify tests or package metadata.".to_owned(),
            "Keep the active worktree unchanged until Apply approval.".to_owned(),
        ],
    };
    let need = NeedIr {
        route_hint: Some(NeedKey::new("locate.implementation").expect("static route")),
        subjects: vec![SubjectExpression {
            kind: SubjectKind::Symbol,
            canonical_name: "increment".to_owned(),
        }],
        required: vec![ObligationExpression {
            predicate: needle_core::PredicateKind::ImplementationLocation,
            facets: vec![
                Facet { key: "granularity".to_owned(), value: "exact-location".to_owned() },
                Facet { key: "selection".to_owned(), value: "primary".to_owned() },
            ],
        }],
        preferred: Vec::new(),
        semantic_constraints: Vec::new(),
        world: vec![
            Facet { key: "features".to_owned(), value: "default".to_owned() },
            Facet { key: "source".to_owned(), value: "current".to_owned() },
        ],
        input_artifacts: Vec::new(),
        projection: Vec::new(),
        body: "Locate increment and the focused tests that specify its behavior.".to_owned(),
        format_revision: needle_core::NEED_IR_FORMAT_REVISION,
    };
    NeedExecutionEnvelopeV1::new(
        Digest::blake3(format!("gate-a7:{source_snapshot}")),
        need,
        NeedExecution::Lifecycle {
            lifecycle: LifecycleExecutionRequest { change, budget_override: None },
        },
    )
}

fn create_fixture(repository: &Path) -> Result<(), AppError> {
    fs::create_dir_all(repository.join("src"))?;
    fs::create_dir_all(repository.join("test"))?;
    fs::write(
        repository.join("package.json"),
        "{\"name\":\"needle-gate-a7-fixture\",\"private\":true,\"type\":\"module\",\"scripts\":{\"test\":\"node --test test/counter.test.js\"}}\n",
    )?;
    fs::write(
        repository.join("src/counter.js"),
        "export function increment(value) {\n  return value + 1;\n}\n",
    )?;
    fs::write(
        repository.join("test/counter.test.js"),
        "import test from 'node:test';\nimport assert from 'node:assert/strict';\nimport { increment } from '../src/counter.js';\n\ntest('increment preserves numeric behavior', () => assert.equal(increment(1), 2));\ntest('increment rejects non-number values', () => assert.throws(() => increment('1'), TypeError));\n",
    )?;
    git(repository, &["init", "--quiet"])?;
    git(repository, &["config", "user.email", "needle@example.invalid"])?;
    git(repository, &["config", "user.name", "Needle Gate A7"])?;
    git(repository, &["add", "."])?;
    git(repository, &["commit", "--quiet", "-m", "gate-a7 fixture"])?;
    Ok(())
}

fn git(repository: &Path, arguments: &[&str]) -> Result<(), AppError> {
    let status = Command::new("git")
        .args(arguments)
        .current_dir(repository)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()?;
    if !status.success() {
        return Err(AppError::Experiment(format!("git {arguments:?} failed with {status}")));
    }
    Ok(())
}

fn verify_auth_source(codex: &Path, source: &Path) -> Result<(), AppError> {
    let auth = source.join("auth.json");
    if !auth.is_file() {
        return Err(AppError::Experiment(format!(
            "Gate A7 authentication source has no auth.json: {}",
            source.display()
        )));
    }
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let isolated =
        std::env::temp_dir().join(format!("needle-gate-a7-auth-{}-{nonce}", std::process::id()));
    fs::create_dir(&isolated)?;
    fs::copy(&auth, isolated.join("auth.json"))?;
    let verification = ensure_codex_authenticated(codex, &isolated, "lifecycle-gate-a7");
    let cleanup = fs::remove_dir_all(&isolated);
    verification?;
    cleanup?;
    Ok(())
}

fn run_needle_child(
    manifest: &GateA7Manifest,
    codex_home: &Path,
    request: &[u8],
) -> Result<Vec<u8>, AppError> {
    let executable = std::env::current_exe()?;
    let mut child = Command::new(executable)
        .args(["run", "--request-stdin", "--repository"])
        .arg(&manifest.repository)
        .arg("--data-dir")
        .arg(&manifest.data_directory)
        .env("CODEX_HOME", codex_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| AppError::Experiment("Needle stdin unavailable".to_owned()))?
        .write_all(request)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::Experiment("Needle stdout unavailable".to_owned()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| AppError::Experiment("Needle stderr unavailable".to_owned()))?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, MAX_CHILD_STDOUT_BYTES));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, MAX_CHILD_STDERR_BYTES));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= Duration::from_secs(MAX_EXECUTION_SECONDS) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(AppError::Experiment("Gate A7 lifecycle timed out".to_owned()));
        }
        thread::sleep(Duration::from_millis(20));
    };
    let stdout = join_reader(stdout_reader, "stdout")?;
    let stderr = join_reader(stderr_reader, "stderr")?;
    if stdout.overflow || stderr.overflow {
        return Err(AppError::Experiment("Gate A7 child output exceeded its bound".to_owned()));
    }
    if !status.success() {
        return Err(AppError::Experiment(format!(
            "Gate A7 lifecycle child failed with {status}: {}",
            String::from_utf8_lossy(&stderr.bytes).trim()
        )));
    }
    Ok(stdout.bytes)
}

struct BoundedRead {
    bytes: Vec<u8>,
    overflow: bool,
}

fn read_bounded(mut reader: impl Read, maximum: usize) -> std::io::Result<BoundedRead> {
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    reader.by_ref().take((maximum as u64).saturating_add(1)).read_to_end(&mut bytes)?;
    let overflow = bytes.len() > maximum;
    if overflow {
        bytes.truncate(maximum);
    }
    Ok(BoundedRead { bytes, overflow })
}

fn join_reader(
    handle: thread::JoinHandle<std::io::Result<BoundedRead>>,
    stream: &str,
) -> Result<BoundedRead, AppError> {
    handle
        .join()
        .map_err(|_| AppError::Experiment(format!("Gate A7 {stream} reader panicked")))?
        .map_err(AppError::Io)
}

fn read_bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, AppError> {
    let file = fs::File::open(path)?;
    let result = read_bounded(file, maximum)?;
    if result.overflow {
        return Err(AppError::Experiment(format!(
            "Gate A7 file exceeds its bound: {}",
            path.display()
        )));
    }
    Ok(result.bytes)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, AppError> {
    serde_json::from_slice(&read_bounded_file(path, 128 * 1024)?).map_err(AppError::Json)
}

fn write_create_new(path: &Path, value: &impl Serialize) -> Result<(), AppError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_envelope_is_closed_bounded_and_does_not_encode_execution_in_need_identity() {
        let source = Digest::blake3(b"source");
        let lifecycle = fixture_envelope(source);
        lifecycle.validate().unwrap();
        let resolve = NeedExecutionEnvelopeV1::new(
            Digest::blake3(b"resolve-operation"),
            lifecycle.need.clone(),
            NeedExecution::Resolve,
        );
        assert_eq!(lifecycle.semantic_need_digest(), resolve.semantic_need_digest());
        assert!(
            serde_json::to_vec(&lifecycle).unwrap().len()
                <= needle_core::MAX_NEED_EXECUTION_WIRE_BYTES
        );
        assert_eq!(MAX_PROVIDER_SESSIONS, 6);
    }

    #[test]
    fn offline_fixture_and_profiles_prepare_without_a_provider_session() {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("needle-gate-a7-preflight-{nonce}"));
        let repository = root.join("repository");
        let data = root.join("data");
        create_fixture(&repository).unwrap();
        fs::create_dir_all(&data).unwrap();
        initialize_store(&data, Path::new("codex")).unwrap();
        let (_, snapshot) = capture_git_snapshot(&repository).unwrap();
        fixture_envelope(snapshot.source_digest).validate().unwrap();
        let store = RuntimeStore::new(data.join("needle.sqlite3"));
        let profiles = store.active_lifecycle_role_profiles().unwrap();
        assert_eq!(profiles.len(), 5);
        assert_eq!(
            profiles
                .iter()
                .map(|profile| u32::from(profile.definition.budget.max_turns))
                .sum::<u32>(),
            6
        );
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn apply_boundary_detection_rejects_terminal_failure_and_requires_apply_binding() {
        let failed = json!({
            "execution": "lifecycle",
            "result": {
                "lifecycle": {"status": "failed", "phase": "test"},
                "awaiting_apply": null
            }
        });
        assert!(!lifecycle_reached_apply_boundary(&failed));

        let awaiting = json!({
            "execution": "lifecycle",
            "result": {
                "lifecycle": {"status": "awaiting_approval", "phase": "apply"},
                "awaiting_apply": {"patch_id": "b3:fixture"}
            }
        });
        assert!(lifecycle_reached_apply_boundary(&awaiting));
    }
}
