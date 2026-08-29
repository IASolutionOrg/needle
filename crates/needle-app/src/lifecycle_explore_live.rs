use super::{
    AppError, absolute_run_path, canonical_child_path, ensure_codex_authenticated,
    ensure_dedicated_codex_home, ensure_product_pilot_hook_isolation, option_value,
    repository_status_clean, required_value, resolve_codex, validate_model_value,
    validate_reasoning, validate_service_tier,
};
use needle_bench::read_bounded_file;
use needle_core::{
    ARTIFACT_RESULT_SCHEMA_ID, ActionRequest, ArtifactRequest, CanonicalHasher, ChangeId,
    ChangeRequest, CodexHost, CodexRole, CommandPolicy, Digest, EvidenceFailurePolicy,
    FallbackPolicy, FilesystemPolicy, LifecycleArtifactKind, LifecycleBudget, LifecyclePhase,
    LifecycleSpec, LifecycleStatus, LifecycleWorkerProfiles, NeedIr, NeedKey, NeedRequest,
    NetworkPolicy, PredicateKind, ReasoningLevel, RepairPolicy, RoleProfileBudget,
    RoleProfileDefinition, RoleProfileDefinitionInput, RoleProfileId, RoleProfileProvenance,
    RoleProfileRevision, SemanticWorkerArtifact, ServiceTier, TestPlan, TestPolicy, ToolPolicy,
    built_in_route_contracts, compile_need, need_fragment,
};
use needle_platform_codex::{CodexWorker, HookConfig, TransportPreflightReport};
use needle_runtime::{
    FreshLifecycleExploreAdapter, LifecycleAdapterInvocationState, LifecycleExecutionDisposition,
    LifecycleExecutionKernel, LifecycleExecutionOutcome,
    LifecycleExploreShadowObservationPersistence, LifecycleExploreShadowResolutionKind,
    LifecyclePhaseAdapters, NeedShadowWrite, NeverCancel, RuntimeSettings, RuntimeStore,
    SemanticLifecycleExploreActionResolver, ShadowActionResolutionAuthority,
    built_in_action_for_predicate, capture_git_snapshot, compile_lifecycle_explore_action_plan,
    validate_semantic_test_plan,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const FIXTURE_SCHEMA: &str = "needle.lifecycle-explore-live-fixture/1";
const PREFLIGHT_SCHEMA: &str = "needle.lifecycle-explore-live-preflight/1";
const REPORT_SCHEMA: &str = "needle.lifecycle-explore-live-report/1";
const MAX_FIXTURE_BYTES: usize = 32 * 1024;
pub(super) const MAX_LIFECYCLE_EXPLORE_LIVE_REPORT_BYTES: usize = 64 * 1024;
const MAX_WORKER_TURNS: u32 = 1;
const MAX_OUTPUT_TOKENS: u64 = 1_200;
const MAX_COST_MICROUSD: u64 = 1_000_000;
const MAX_TEST_EVIDENCE_PATHS: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleExploreLiveFixture {
    schema: String,
    repository_sha: String,
    need_ir: String,
    change: ChangeRequest,
    test_plan: TestPlan,
    test_evidence_paths: Vec<String>,
}

impl LifecycleExploreLiveFixture {
    fn decode(path: &Path) -> Result<Self, AppError> {
        let bytes = read_bounded_file(path, MAX_FIXTURE_BYTES)
            .map_err(|error| AppError::Experiment(error.to_string()))?;
        let fixture: Self = serde_json::from_slice(&bytes)?;
        fixture.validate()?;
        Ok(fixture)
    }

    fn validate(&self) -> Result<(), AppError> {
        if self.schema != FIXTURE_SCHEMA {
            return Err(AppError::Experiment("lifecycle Explore fixture schema is invalid".into()));
        }
        if self.repository_sha.len() != 40
            || !self
                .repository_sha
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AppError::Experiment(
                "lifecycle Explore fixture repository SHA must be lowercase hexadecimal".into(),
            ));
        }
        if self.change.task.trim().is_empty()
            || self.change.task.len() > needle_core::MAX_CHANGE_TASK_BYTES
            || self.change.acceptance_criteria.is_empty()
            || self.change.acceptance_criteria.len() > needle_core::MAX_ACCEPTANCE_CRITERIA
            || self.change.allowed_paths.is_empty()
            || self.change.allowed_paths.len() > needle_core::MAX_ALLOWED_PATHS
        {
            return Err(AppError::Experiment(
                "lifecycle Explore fixture change request is incomplete or out of bounds".into(),
            ));
        }
        if !self.test_plan.requires_approval
            || self.test_plan.execution_evidence_id.is_some()
            || self.test_plan.test_command().is_err()
        {
            return Err(AppError::Experiment(
                "lifecycle Explore fixture TestPlan must be canonical, approval-bound, and unexecuted"
                    .into(),
            ));
        }
        if self.test_evidence_paths.is_empty()
            || self.test_evidence_paths.len() > MAX_TEST_EVIDENCE_PATHS
            || self.test_evidence_paths.iter().any(|path| !safe_relative_path(path))
        {
            return Err(AppError::Experiment(
                "lifecycle Explore fixture test evidence paths are invalid or out of bounds".into(),
            ));
        }
        let need_ir = NeedIr::parse(&self.need_ir)
            .map_err(|error| AppError::Experiment(format!("fixture NeedIR is invalid: {error}")))?
            .ok_or_else(|| AppError::Experiment("fixture contains no NeedIR marker".into()))?;
        if need_ir.route_hint.as_ref().map(NeedKey::as_str) != Some("locate.implementation") {
            return Err(AppError::Experiment(
                "lifecycle Explore fixture must use locate.implementation".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct LifecycleExploreLivePreflight {
    schema: &'static str,
    passed: bool,
    provider_turns_started: u32,
    repository_sha: String,
    repository_id: Digest,
    source_snapshot: Digest,
    codex_version: String,
    worker_model: String,
    worker_reasoning: String,
    service_tier: String,
    lifecycle_id: needle_core::LifecycleId,
    change_id: ChangeId,
    need_id: needle_core::NeedId,
    action_plan_definition_digest: Digest,
    test_plan_certificate_digest: Digest,
    maximum_logical_workers: u32,
    maximum_worker_turns: u32,
    maximum_output_tokens: u64,
    approved_budget_microusd: u64,
    budget_is_hard_provider_ceiling: bool,
    repair_enabled: bool,
    native_fallback: bool,
    transport: TransportPreflightReport,
    execute_flag_required: &'static str,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderAttemptSummary {
    input_tokens: Option<u64>,
    cached_input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    logical_worker_spawns: u32,
    worker_turns: u32,
    repair_performed: bool,
    session_cleanup_success: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleExploreLiveReport {
    schema: String,
    mode: String,
    repository_sha: String,
    repository_id: Digest,
    source_snapshot: Digest,
    codex_version: String,
    worker_model: String,
    worker_reasoning: String,
    service_tier: String,
    lifecycle_id: needle_core::LifecycleId,
    change_id: ChangeId,
    action_plan_definition_digest: Digest,
    test_plan_certificate_digest: Digest,
    approved_budget_microusd: u64,
    budget_is_hard_provider_ceiling: bool,
    outcome: LifecycleExecutionOutcome,
    provider_attempt: Option<ProviderAttemptSummary>,
    invocation_completed: bool,
    source_unchanged: bool,
    checkout_clean: bool,
    passed: bool,
    failures: Vec<String>,
    wall_time_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LifecycleExploreAuthoritySource {
    pub repository: Digest,
    pub source_snapshot: Digest,
    pub change: ChangeId,
    pub lifecycle: needle_core::LifecycleId,
    pub adapter_invocation: Digest,
    pub artifact: needle_core::ArtifactId,
}

pub(super) fn decode_authority_source(
    bytes: &[u8],
) -> Result<LifecycleExploreAuthoritySource, AppError> {
    if bytes.len() > MAX_LIFECYCLE_EXPLORE_LIVE_REPORT_BYTES {
        return Err(AppError::Experiment(format!(
            "lifecycle Explore report has {} bytes; maximum is {}",
            bytes.len(),
            MAX_LIFECYCLE_EXPLORE_LIVE_REPORT_BYTES
        )));
    }
    let report: LifecycleExploreLiveReport = serde_json::from_slice(bytes)?;
    if report.schema != REPORT_SCHEMA
        || report.mode != "provider-live-phase7-fresh-shadow"
        || !report.passed
        || !report.failures.is_empty()
        || !report.invocation_completed
        || !report.source_unchanged
        || !report.checkout_clean
        || report.outcome.disposition != LifecycleExecutionDisposition::Advanced
        || report.outcome.projection.lifecycle.id != report.lifecycle_id
        || report.outcome.projection.lifecycle.change_id != report.change_id
        || report.outcome.projection.lifecycle.source_snapshot != report.source_snapshot
        || report.outcome.projection.lifecycle.phase != LifecyclePhase::Implement
        || report.outcome.projection.lifecycle.status != LifecycleStatus::Active
        || report.outcome.projection.lifecycle.exploration_artifacts.len() != 1
        || report.outcome.explore_action_observation_persistence
            != Some(LifecycleExploreShadowObservationPersistence::Stored)
        || !report.outcome.cleanup.as_ref().is_some_and(|cleanup| cleanup.succeeded)
    {
        return Err(AppError::Experiment(
            "lifecycle Explore report is not a successful retained Fresh/Shadow observation".into(),
        ));
    }
    let provider_attempt = report.provider_attempt.as_ref().ok_or_else(|| {
        AppError::Experiment("lifecycle Explore report has no provider attempt".into())
    })?;
    if provider_attempt.logical_worker_spawns != 1
        || provider_attempt.worker_turns != 1
        || provider_attempt.repair_performed
        || provider_attempt.session_cleanup_success != Some(true)
    {
        return Err(AppError::Experiment(
            "lifecycle Explore report is not the bounded one-turn provider observation".into(),
        ));
    }
    let observation = report.outcome.explore_action_observation.as_ref().ok_or_else(|| {
        AppError::Experiment("lifecycle Explore report has no Shadow action observation".into())
    })?;
    if observation.lifecycle != report.lifecycle_id
        || observation.plan_definition_digest != report.action_plan_definition_digest
        || observation.planned_action_count != 1
        || observation.resolution != LifecycleExploreShadowResolutionKind::Miss
        || observation.authority != ShadowActionResolutionAuthority::Shadow
        || !observation.adapter_invocation_required
        || !observation.actions.is_empty()
    {
        return Err(AppError::Experiment(
            "lifecycle Explore report does not bind the exact Fresh/Shadow action plan".into(),
        ));
    }
    let artifact = &report.outcome.projection.lifecycle.exploration_artifacts[0];
    if artifact.kind != LifecycleArtifactKind::Exploration
        || artifact.source_snapshot != report.source_snapshot
    {
        return Err(AppError::Experiment(
            "lifecycle Explore report artifact does not bind the retained source".into(),
        ));
    }
    let adapter_invocation = report.outcome.invocation_id.ok_or_else(|| {
        AppError::Experiment("lifecycle Explore report has no adapter invocation id".into())
    })?;
    Ok(LifecycleExploreAuthoritySource {
        repository: report.repository_id,
        source_snapshot: report.source_snapshot,
        change: report.change_id,
        lifecycle: report.lifecycle_id,
        adapter_invocation,
        artifact: needle_core::ArtifactId::new(artifact.id),
    })
}

struct CommonInput {
    codex: PathBuf,
    codex_home: PathBuf,
    source_repository: PathBuf,
    artifact_root: PathBuf,
    fixture: LifecycleExploreLiveFixture,
    model: String,
    reasoning: String,
    service_tier: String,
    timeout_seconds: u64,
    codex_version: String,
}

struct PreparedRun {
    store: RuntimeStore,
    change_id: ChangeId,
    lifecycle_id: needle_core::LifecycleId,
    need_id: needle_core::NeedId,
    repository_id: Digest,
    source_snapshot: Digest,
    action_plan_definition_digest: Digest,
    test_plan_certificate_digest: Digest,
    explorer_revision: RoleProfileRevision,
}

pub(super) fn run(arguments: &[String]) -> Result<(), AppError> {
    validate_arguments(arguments)?;
    let preflight_only = arguments.iter().any(|argument| argument == "--preflight-only");
    let execute_paid = arguments.iter().any(|argument| argument == "--execute-paid");
    if preflight_only == execute_paid {
        return Err(AppError::Usage(
            "lifecycle-explore-live requires exactly one of --preflight-only or --execute-paid"
                .into(),
        ));
    }
    let input = common_input(arguments)?;
    if input.artifact_root.exists() {
        return Err(AppError::Experiment(format!(
            "lifecycle Explore artifact root already exists: {}",
            input.artifact_root.display()
        )));
    }
    if preflight_only {
        return preflight(arguments, &input);
    }
    let approved_budget =
        required_value(arguments, "--approved-budget-microusd")?
            .parse::<u64>()
            .map_err(|error| AppError::Usage(format!("invalid approved budget: {error}")))?;
    if approved_budget != MAX_COST_MICROUSD {
        return Err(AppError::Experiment(format!(
            "approved budget must equal the frozen lifecycle bound {MAX_COST_MICROUSD} microusd"
        )));
    }
    execute(input, approved_budget)
}

fn common_input(arguments: &[String]) -> Result<CommonInput, AppError> {
    let codex = resolve_codex(option_value(arguments, "--codex"))?;
    let codex_home = PathBuf::from(required_value(arguments, "--codex-home")?);
    ensure_dedicated_codex_home(&codex_home)?;
    let codex_home = canonical_child_path(&codex_home)?;
    ensure_product_pilot_hook_isolation(&codex_home)?;
    ensure_codex_authenticated(&codex, &codex_home, "lifecycle-explore-live")?;
    let isolation =
        CodexWorker::verify_isolation(&codex.display().to_string()).map_err(AppError::Runtime)?;
    if !isolation.verified() {
        return Err(AppError::Experiment(format!(
            "lifecycle Explore isolation is not verified for Codex {}",
            isolation.codex_version
        )));
    }
    let source_repository =
        canonical_child_path(Path::new(&required_value(arguments, "--source-repository")?))?;
    let artifact_root =
        absolute_run_path(Path::new(&required_value(arguments, "--artifact-root")?))?;
    let fixture =
        LifecycleExploreLiveFixture::decode(Path::new(&required_value(arguments, "--fixture")?))?;
    let (_, snapshot) = capture_git_snapshot(&source_repository)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    if snapshot.head_sha != fixture.repository_sha || !repository_status_clean(&source_repository)?
    {
        return Err(AppError::Experiment(format!(
            "source repository must be clean at {}",
            fixture.repository_sha
        )));
    }
    for path in &fixture.test_evidence_paths {
        if !source_repository.join(path).is_file() {
            return Err(AppError::Experiment(format!(
                "fixture test evidence path is unavailable: {path}"
            )));
        }
    }
    let model = required_value(arguments, "--worker-model")?;
    let reasoning = required_value(arguments, "--worker-reasoning")?;
    let service_tier = required_value(arguments, "--service-tier")?;
    validate_model_value(&model, "worker model")?;
    validate_reasoning(&reasoning)?;
    validate_service_tier(&service_tier)?;
    let timeout_seconds = option_value(arguments, "--timeout-seconds")
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|error| AppError::Usage(format!("invalid --timeout-seconds: {error}")))?
        .unwrap_or(180);
    if !(60..=180).contains(&timeout_seconds) {
        return Err(AppError::Usage("--timeout-seconds must be between 60 and 180".into()));
    }
    Ok(CommonInput {
        codex,
        codex_home,
        source_repository,
        artifact_root,
        fixture,
        model,
        reasoning,
        service_tier,
        timeout_seconds,
        codex_version: isolation.codex_version,
    })
}

fn preflight(arguments: &[String], input: &CommonInput) -> Result<(), AppError> {
    let temporary = TemporaryRunRoot::create(&input.artifact_root)?;
    let prepared = prepare_run(input, temporary.path())?;
    let config = prepared
        .explorer_revision
        .to_worker_config(input.codex.display().to_string())
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let transport =
        CodexWorker::with_codex_home(temporary.path().join("transport"), &input.codex_home)
            .preflight_transport(&config, &input.source_repository)
            .map_err(AppError::Runtime)?;
    let passed = transport.provider_turns_started == 0
        && transport.ephemeral_thread_cleanup_completed
        && transport.sandbox_cleaned
        && transport.source_head_sha == input.fixture.repository_sha
        && transport.source_snapshot_digest == prepared.source_snapshot.to_string();
    let report = LifecycleExploreLivePreflight {
        schema: PREFLIGHT_SCHEMA,
        passed,
        provider_turns_started: transport.provider_turns_started,
        repository_sha: input.fixture.repository_sha.clone(),
        repository_id: prepared.repository_id,
        source_snapshot: prepared.source_snapshot,
        codex_version: input.codex_version.clone(),
        worker_model: input.model.clone(),
        worker_reasoning: input.reasoning.clone(),
        service_tier: input.service_tier.clone(),
        lifecycle_id: prepared.lifecycle_id,
        change_id: prepared.change_id,
        need_id: prepared.need_id,
        action_plan_definition_digest: prepared.action_plan_definition_digest,
        test_plan_certificate_digest: prepared.test_plan_certificate_digest,
        maximum_logical_workers: 1,
        maximum_worker_turns: MAX_WORKER_TURNS,
        maximum_output_tokens: MAX_OUTPUT_TOKENS,
        approved_budget_microusd: MAX_COST_MICROUSD,
        budget_is_hard_provider_ceiling: false,
        repair_enabled: false,
        native_fallback: false,
        transport,
        execute_flag_required: "--execute-paid",
    };
    let rendered = serde_json::to_vec_pretty(&report)?;
    if let Some(path) = option_value(arguments, "--output") {
        let output = absolute_run_path(Path::new(&path))?;
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&output, rendered)?;
        println!("lifecycle Explore live preflight written to {}", output.display());
    } else {
        println!("{}", String::from_utf8_lossy(&rendered));
    }
    if passed {
        Ok(())
    } else {
        Err(AppError::Experiment("lifecycle Explore live preflight failed".into()))
    }
}

fn execute(input: CommonInput, approved_budget: u64) -> Result<(), AppError> {
    fs::create_dir_all(&input.artifact_root)?;
    let artifact_root = canonical_child_path(&input.artifact_root)?;
    fs::write(artifact_root.join("fixture.json"), serde_json::to_vec_pretty(&input.fixture)?)?;
    let data_directory = artifact_root.join("data");
    fs::create_dir(&data_directory)?;
    let prepared = prepare_run(&input, &data_directory)?;
    let (_, initial_snapshot) = capture_git_snapshot(&input.source_repository)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let adapter = FreshLifecycleExploreAdapter::new(
        prepared.store.clone(),
        CodexWorker::with_codex_home(&data_directory, &input.codex_home),
        &input.source_repository,
    )
    .map_err(AppError::Runtime)?;
    let resolver = SemanticLifecycleExploreActionResolver::new(prepared.store.clone());
    let adapters = LifecyclePhaseAdapters {
        explore: &adapter,
        implement: &adapter,
        test: &adapter,
        review: &adapter,
        verify: &adapter,
    };
    let started = Instant::now();
    let outcome = LifecycleExecutionKernel::new_with_explore_resolver(
        &prepared.store,
        adapters,
        &NeverCancel,
        &resolver,
    )
    .step(&prepared.change_id)
    .map_err(|error| AppError::Experiment(error.to_string()))?;
    let wall_time_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    let invocation_completed = outcome.invocation_id.is_some_and(|invocation_id| {
        prepared.store.lifecycle_adapter_invocation_state(invocation_id).is_ok_and(|state| {
            matches!(state, Some(LifecycleAdapterInvocationState::Completed { .. }))
        })
    });
    let provider_attempt = prepared
        .store
        .latest_worker_run()
        .map_err(|error| AppError::Experiment(error.to_string()))?
        .map(|run| ProviderAttemptSummary {
            input_tokens: run.input_tokens,
            cached_input_tokens: run.cached_input_tokens,
            output_tokens: run.output_tokens,
            logical_worker_spawns: run.logical_worker_spawns,
            worker_turns: run.worker_turns,
            repair_performed: run.repair_performed,
            session_cleanup_success: run.session_cleanup_success,
        });
    let (_, final_snapshot) = capture_git_snapshot(&input.source_repository)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let source_unchanged = final_snapshot.source_digest == initial_snapshot.source_digest;
    let checkout_clean = repository_status_clean(&input.source_repository)?;
    let observation_valid =
        outcome.explore_action_observation.as_ref().is_some_and(|observation| {
            observation.authority == ShadowActionResolutionAuthority::Shadow
                && observation.adapter_invocation_required
                && observation.planned_action_count == 1
        });
    let exactly_one_turn = provider_attempt.as_ref().is_some_and(|attempt| {
        attempt.logical_worker_spawns == 1
            && attempt.worker_turns == 1
            && !attempt.repair_performed
            && attempt.session_cleanup_success == Some(true)
    });
    let mut failures = Vec::new();
    for (passed, code) in [
        (outcome.disposition == LifecycleExecutionDisposition::Advanced, "lifecycle_advance"),
        (invocation_completed, "invocation_completion"),
        (observation_valid, "shadow_observation"),
        (exactly_one_turn, "provider_turn_count"),
        (source_unchanged, "source_integrity"),
        (checkout_clean, "checkout_cleanliness"),
    ] {
        if !passed {
            failures.push(code.to_owned());
        }
    }
    let report = LifecycleExploreLiveReport {
        schema: REPORT_SCHEMA.to_owned(),
        mode: "provider-live-phase7-fresh-shadow".to_owned(),
        repository_sha: input.fixture.repository_sha,
        repository_id: prepared.repository_id,
        source_snapshot: prepared.source_snapshot,
        codex_version: input.codex_version,
        worker_model: input.model,
        worker_reasoning: input.reasoning,
        service_tier: input.service_tier,
        lifecycle_id: prepared.lifecycle_id,
        change_id: prepared.change_id,
        action_plan_definition_digest: prepared.action_plan_definition_digest,
        test_plan_certificate_digest: prepared.test_plan_certificate_digest,
        approved_budget_microusd: approved_budget,
        budget_is_hard_provider_ceiling: false,
        outcome,
        provider_attempt,
        invocation_completed,
        source_unchanged,
        checkout_clean,
        passed: failures.is_empty(),
        failures,
        wall_time_ms,
    };
    let report_path = artifact_root.join("lifecycle-explore-live-report.json");
    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("lifecycle Explore live report written to {}", report_path.display());
    if report.passed {
        Ok(())
    } else {
        Err(AppError::Experiment(format!(
            "lifecycle Explore live gate failed: {}",
            report.failures.join(", ")
        )))
    }
}

fn prepare_run(input: &CommonInput, data_directory: &Path) -> Result<PreparedRun, AppError> {
    let store = RuntimeStore::new(data_directory.join("needle.sqlite3"));
    store
        .initialize_defaults(&RuntimeSettings {
            codex_executable: input.codex.display().to_string(),
            worker_model: input.model.clone(),
            worker_reasoning: input.reasoning.clone(),
            worker_timeout_seconds: input.timeout_seconds,
            evidence_failure_policy: EvidenceFailurePolicy::DiscardInvalidFact,
            trusted_test_execution: false,
            multi_need_policy: needle_core::MultiNeedPolicy::default(),
        })
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let prompt_profile_digest = HookConfig::default()
        .profile()
        .map_err(|error| AppError::Experiment(error.to_string()))?
        .definition_digest;
    let need_ir = NeedIr::parse(&input.fixture.need_ir)
        .map_err(|error| AppError::Experiment(error.to_string()))?
        .ok_or_else(|| AppError::Experiment("fixture NeedIR is unavailable".into()))?;
    let route = need_ir
        .route_hint
        .clone()
        .ok_or_else(|| AppError::Experiment("fixture NeedIR route is unavailable".into()))?;
    let profiles = provision_profiles(
        &store,
        prompt_profile_digest,
        &input.model,
        &input.reasoning,
        &input.service_tier,
        input.timeout_seconds,
        &route,
    )?;
    let explorer_revision = store
        .read_role_profile_revision(&profiles.explore.profile_id, profiles.explore.revision)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let (_, snapshot) = capture_git_snapshot(&input.source_repository)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let route_contract = built_in_route_contracts()
        .into_iter()
        .find(|contract| contract.route == route)
        .ok_or_else(|| AppError::Experiment("fixture route has no built-in contract".into()))?;
    let need = compile_need(&need_ir, snapshot.repository_id, &route_contract)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    if need.required.len() != 1
        || need.required[0].predicate != PredicateKind::ImplementationLocation
    {
        return Err(AppError::Experiment(
            "live lifecycle fixture must compile to exactly one ImplementationLocation action"
                .into(),
        ));
    }
    let fragment = need_fragment(&need, need.required.clone(), Vec::new());
    let session_id = "lifecycle-explore-live";
    let turn_id = "prepare";
    let cwd = input.source_repository.to_string_lossy();
    store
        .record_session_start_profiled(
            session_id,
            prompt_profile_digest,
            Some("lifecycle-live-main"),
            Some(&cwd),
            &profiles.explore.profile_id,
        )
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    store
        .record_user_prompt(session_id, Some(turn_id), &input.fixture.change.task, Some(&cwd))
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    store
        .record_need_shadow(NeedShadowWrite {
            session_id,
            turn_id,
            transport_digest: need_ir.transport_digest(),
            parser_definition_digest: needle_core::need_grammar_definition_digest(),
            prompt_profile_digest,
            need_ir: &need_ir,
            need: &need,
            fragments: std::slice::from_ref(&fragment),
        })
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let test_plan_certificate_digest = seed_test_plan(
        &store,
        &input.source_repository,
        snapshot.repository_id,
        snapshot.source_digest,
        &input.fixture.test_plan,
        &input.fixture.test_evidence_paths,
    )?;
    let test_plan_binding = store
        .lifecycle_start_test_plan_candidates(snapshot.source_digest)
        .map_err(|error| AppError::Experiment(error.to_string()))?
        .into_iter()
        .find(|candidate| candidate.binding.certificate_digest == test_plan_certificate_digest)
        .map(|candidate| candidate.binding)
        .ok_or_else(|| {
            AppError::Experiment("seeded lifecycle TestPlan certificate is unavailable".into())
        })?;
    let need_request = NeedRequest { key: route, body: need_ir.body.clone() };
    let action_plan = compile_lifecycle_explore_action_plan(
        &need_request,
        &need,
        &fragment,
        snapshot.repository_id,
        snapshot.source_digest,
    )
    .map_err(|error| AppError::Experiment(error.to_string()))?;
    let spec = LifecycleSpec {
        worker_depth_limit: 1,
        profiles,
        budget: LifecycleBudget {
            max_worker_turns: MAX_WORKER_TURNS,
            max_output_tokens: MAX_OUTPUT_TOKENS,
            max_cost_microusd: MAX_COST_MICROUSD,
            max_concurrent_workers: 1,
        },
        explore_action_plan: Some(action_plan.clone()),
        action_phase_plans: None,
        test_plans: vec![test_plan_binding],
    };
    let mut change_hasher = CanonicalHasher::new(b"needle-lifecycle-explore-live-dogfood-v1");
    change_hasher.field_digest(snapshot.repository_id);
    change_hasher.field_digest(snapshot.source_digest);
    change_hasher.field_digest(action_plan.definition_digest);
    change_hasher.field_str(&input.model);
    let change_id = ChangeId::from_digest(change_hasher.finish());
    let creation = store
        .create_lifecycle_with_request(
            &change_id,
            snapshot.repository_id,
            snapshot.source_digest,
            &input.fixture.change,
            spec,
        )
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    Ok(PreparedRun {
        store,
        change_id,
        lifecycle_id: creation.projection.lifecycle.id,
        need_id: need.id,
        repository_id: snapshot.repository_id,
        source_snapshot: snapshot.source_digest,
        action_plan_definition_digest: action_plan.definition_digest,
        test_plan_certificate_digest,
        explorer_revision,
    })
}

fn provision_profiles(
    store: &RuntimeStore,
    prompt_profile_digest: Digest,
    model: &str,
    reasoning: &str,
    service_tier: &str,
    timeout_seconds: u64,
    explore_route: &NeedKey,
) -> Result<LifecycleWorkerProfiles, AppError> {
    let reasoning = parse_reasoning(reasoning)?;
    let service_tier = parse_service_tier(service_tier)?;
    let create = |role: CodexRole, suffix: &str| -> Result<RoleProfileProvenance, AppError> {
        let profile_id = RoleProfileId::new(format!("lifecycle-live.{suffix}"))
            .map_err(|error| AppError::Experiment(error.to_string()))?;
        let definition = RoleProfileDefinition::new(RoleProfileDefinitionInput {
            profile_id: profile_id.clone(),
            role,
            host: CodexHost::Codex,
            model: model.to_owned(),
            reasoning,
            service_tier,
            timeout_seconds,
            budget: RoleProfileBudget {
                max_turns: MAX_WORKER_TURNS as u8,
                max_output_tokens: MAX_OUTPUT_TOKENS as u32,
                max_cost_microusd: MAX_COST_MICROUSD,
            },
            prompt_profile_digest,
            output_contract_digest: Digest::blake3(ARTIFACT_RESULT_SCHEMA_ID),
            tool_policy: ToolPolicy::ReadOnly,
            command_policy: CommandPolicy::ReadOnly,
            filesystem_policy: FilesystemPolicy::ReadOnlyCheckout,
            network_policy: NetworkPolicy::Denied,
            test_policy: TestPolicy::Disabled,
            repair_policy: RepairPolicy::None,
            fallback_policy: FallbackPolicy::Disabled,
            concurrency: 1,
            route_assignments: if role == CodexRole::Explorer {
                vec![explore_route.clone()]
            } else {
                Vec::new()
            },
        })
        .map_err(|error| AppError::Experiment(error.to_string()))?;
        let revision = store
            .create_role_profile(definition)
            .map_err(|error| AppError::Experiment(error.to_string()))?;
        let state = store
            .role_profile_state(&profile_id)
            .map_err(|error| AppError::Experiment(error.to_string()))?;
        store
            .activate_role_profile(&profile_id, revision.revision, state.state_digest)
            .map_err(|error| AppError::Experiment(error.to_string()))?;
        let active = store
            .read_role_profile_revision(&profile_id, revision.revision)
            .map_err(|error| AppError::Experiment(error.to_string()))?;
        RoleProfileProvenance::from_revision(&active)
            .map_err(|error| AppError::Experiment(error.to_string()))
    };
    Ok(LifecycleWorkerProfiles {
        explore: create(CodexRole::Explorer, "explorer")?,
        implement: create(CodexRole::Implementer, "implementer")?,
        test: create(CodexRole::TestRunner, "test-runner")?,
        review: create(CodexRole::Reviewer, "reviewer")?,
        verify: create(CodexRole::Verifier, "verifier")?,
    })
}

fn seed_test_plan(
    store: &RuntimeStore,
    repository_root: &Path,
    repository_id: Digest,
    source_snapshot: Digest,
    plan: &TestPlan,
    evidence_paths: &[String],
) -> Result<Digest, AppError> {
    let marker = format!(
        "@@need\n@route tests.relevant\n@subject test:{}\n@require focused-tests selection=representative\n@world source=current features=default\n\nLocate the parent-declared focused test.\n@@end",
        serde_json::to_string(&plan.test_identifier)?
    );
    let need_ir = NeedIr::parse(&marker)
        .map_err(|error| AppError::Experiment(error.to_string()))?
        .ok_or_else(|| AppError::Experiment("test-plan NeedIR is unavailable".into()))?;
    let route = built_in_route_contracts()
        .into_iter()
        .find(|contract| contract.route.as_str() == "tests.relevant")
        .ok_or_else(|| AppError::Experiment("tests.relevant contract is unavailable".into()))?;
    let need = compile_need(&need_ir, repository_id, &route)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let fragment = need_fragment(&need, need.required.clone(), Vec::new());
    let need_request = NeedRequest { key: route.route, body: need_ir.body };
    let definition = built_in_action_for_predicate(PredicateKind::FocusedTests);
    let request = ActionRequest::new(
        &definition.contract,
        ArtifactRequest {
            contract_id: definition.output_contract_id.to_owned(),
            contract_revision: definition.output_contract_revision,
            repository_id,
            source_snapshot_digest: source_snapshot,
            route_key: need_request.key.clone(),
            normalized_request: need_request.body,
            semantic_fragment_id: Some(fragment.id),
            input_artifact_ids: Vec::new(),
        },
        definition.contract.default_dispatch_policy,
        need_request.key,
        fragment.root_need,
    )
    .map_err(|error| AppError::Experiment(error.to_string()))?;
    let worker_artifact = SemanticWorkerArtifact::TestPlan {
        runner: plan.runner.clone(),
        argv: plan.argv.clone(),
        cwd_relative: plan.cwd_relative.clone(),
        identifiers: vec![plan.test_identifier.clone()],
        selection: "representative".into(),
        evidence_paths: evidence_paths.to_vec(),
    };
    let validated = validate_semantic_test_plan(
        &fragment,
        &worker_artifact,
        repository_root,
        request.semantic_id().digest(),
        None,
        plan,
    )
    .map_err(|error| AppError::Experiment(error.to_string()))?;
    let certificate_digest = validated.certificate.id.digest();
    store
        .publish_action_artifact(&request, &validated.artifact, &validated.certificate)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    Ok(certificate_digest)
}

fn parse_reasoning(value: &str) -> Result<ReasoningLevel, AppError> {
    match value {
        "low" => Ok(ReasoningLevel::Low),
        "medium" => Ok(ReasoningLevel::Medium),
        "high" => Ok(ReasoningLevel::High),
        "xhigh" => Ok(ReasoningLevel::Xhigh),
        _ => Err(AppError::Usage(
            "lifecycle-explore-live reasoning must be low|medium|high|xhigh".into(),
        )),
    }
}

fn parse_service_tier(value: &str) -> Result<ServiceTier, AppError> {
    match value {
        "default" => Ok(ServiceTier::Default),
        "priority" => Ok(ServiceTier::Priority),
        _ => Err(AppError::Usage(
            "lifecycle-explore-live service tier must be default|priority".into(),
        )),
    }
}

fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !value.contains('\\')
        && !path.is_absolute()
        && path.components().all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn validate_arguments(arguments: &[String]) -> Result<(), AppError> {
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--preflight-only" | "--execute-paid" => index += 1,
            "--codex"
            | "--codex-home"
            | "--source-repository"
            | "--artifact-root"
            | "--fixture"
            | "--worker-model"
            | "--worker-reasoning"
            | "--service-tier"
            | "--timeout-seconds"
            | "--approved-budget-microusd"
            | "--output" => {
                if arguments.get(index + 1).is_none() {
                    return Err(AppError::Usage(format!("{} requires a value", arguments[index])));
                }
                index += 2;
            }
            argument => {
                return Err(AppError::Usage(format!(
                    "unknown lifecycle-explore-live argument `{argument}`"
                )));
            }
        }
    }
    Ok(())
}

struct TemporaryRunRoot {
    path: PathBuf,
}

impl TemporaryRunRoot {
    fn create(artifact_root: &Path) -> Result<Self, AppError> {
        let parent = artifact_root.parent().ok_or_else(|| {
            AppError::Experiment("lifecycle Explore artifact root has no parent".into())
        })?;
        let parent = canonical_child_path(parent)?;
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let path = parent.join(format!(".nle-{}-{suffix:x}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(Self { path: canonical_child_path(&path)? })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryRunRoot {
    fn drop(&mut self) {
        if self
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.starts_with(".nle-"))
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str =
        include_str!("../../../benchmarks/corpus/lifecycle-explore/thiserror/fixture.json");

    #[test]
    fn checked_in_fixture_is_bounded_and_canonical() {
        assert!(FIXTURE.len() <= MAX_FIXTURE_BYTES);
        let fixture: LifecycleExploreLiveFixture = serde_json::from_str(FIXTURE).unwrap();
        fixture.validate().unwrap();
        assert_eq!(fixture.repository_sha, "485c2b7eed2702c4a109be3cf42bb4be27fe16bd");
        assert_eq!(fixture.test_plan.test_identifier, "test_unused_qualifications");
    }

    #[test]
    fn argument_surface_requires_an_explicit_mode() {
        assert!(validate_arguments(&["--network".into()]).is_err());
        assert!(run(&[]).is_err());
    }

    #[test]
    fn provider_bounds_are_single_turn_and_not_misrepresented_as_hard_ceiling() {
        assert_eq!(MAX_WORKER_TURNS, 1);
        assert_eq!(MAX_OUTPUT_TOKENS, 1_200);
        assert_eq!(MAX_COST_MICROUSD, 1_000_000);
    }
}
