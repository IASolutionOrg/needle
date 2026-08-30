use super::{AppError, option_value, product_data_directory};
use crate::product_resolver::{ProductResolver, WorkerPolicy};
use needle_core::{
    AgentHost, ChangeActionInput, ChangeId, CodexRole, Digest, LifecycleBudget, LifecyclePhase,
    LifecycleSpec, LifecycleStatus, LifecycleWorkerProfiles, NeedExecution,
    NeedExecutionEnvelopeV1, NeedRequest, RoleProfileProvenance, RoleProfileRevision,
    built_in_route_contracts, compile_need, need_fragment, need_grammar_definition_digest,
};
use needle_platform_antigravity::{AntigravityChangeActionProvider, inspect_installation};
use needle_platform_codex::{
    CodexChangeActionProvider, CodexLifecycleActionAdapter, CodexWorker, HookConfig,
};
use needle_runtime::{
    ActionExecutionService, FreshLifecycleExploreAdapter, LifecycleAdapterInvocationState,
    LifecycleExecutionDisposition, LifecycleExecutionKernel, LifecyclePhaseAdapters,
    LifecycleProjection, NeedShadowWrite, NeverCancel, ResolveRequest, RuntimeStore,
    SemanticLifecycleExploreActionResolver, capture_git_snapshot,
    compile_lifecycle_explore_action_plan, lifecycle_adapter_invocation_id,
};
use serde_json::{Value, json};
use std::env;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const RUN_TRANSPORT_DEFINITION: &[u8] = b"needle.run.request-stdin/1";
const MAX_LIFECYCLE_STEPS_PER_INVOCATION: usize = 32;

pub(crate) fn run(arguments: Vec<String>) -> Result<(), AppError> {
    if matches!(arguments.as_slice(), [argument] if argument == "--help" || argument == "-h") {
        println!("Usage: needle run --request-stdin [--repository <path>] [--data-dir <path>]");
        return Ok(());
    }
    validate_arguments(&arguments)?;
    if !arguments.iter().any(|argument| argument == "--request-stdin") {
        return Err(AppError::Usage("run requires --request-stdin".to_owned()));
    }
    let envelope = read_envelope()?;
    let candidate =
        option_value(&arguments, "--repository").map(PathBuf::from).unwrap_or(env::current_dir()?);
    let (repository_root, snapshot) = capture_git_snapshot(&candidate).map_err(|error| {
        AppError::Runtime(format!(
            "cannot resolve a trusted Git repository from {}: {error}",
            candidate.display()
        ))
    })?;
    let data_directory = product_data_directory(&arguments)?;
    let store = RuntimeStore::new(data_directory.join("needle.sqlite3"));
    if !store.path().is_file() {
        return Err(AppError::Runtime(
            "Needle is not initialized; run `needle enable` in this repository first".to_owned(),
        ));
    }
    store.initialize().map_err(|error| AppError::Runtime(error.to_string()))?;

    let result = match &envelope.execution {
        NeedExecution::Resolve => run_resolve(&envelope, &store, &data_directory, repository_root)?,
        NeedExecution::Action { action } => run_action(
            &envelope,
            action.input.clone(),
            &store,
            &data_directory,
            &repository_root,
            snapshot.repository_id,
            snapshot.source_digest,
        )?,
        NeedExecution::Lifecycle { lifecycle } => run_lifecycle(
            &envelope,
            lifecycle,
            &store,
            &data_directory,
            &repository_root,
            snapshot.repository_id,
            snapshot.source_digest,
        )?,
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn run_resolve(
    envelope: &NeedExecutionEnvelopeV1,
    store: &RuntimeStore,
    data_directory: &Path,
    repository_root: PathBuf,
) -> Result<Value, AppError> {
    let profile = unique_active_profile(store, CodexRole::Explorer)?;
    let provenance = RoleProfileProvenance::from_revision(&profile)
        .map_err(|error| AppError::Runtime(error.to_string()))?;
    let prompt_profile_digest = HookConfig::default().profile()?.definition_digest;
    let session_id = format!("needle-run-{}", envelope.operation_id.to_hex());
    let turn_id = "turn-1";
    let cwd = repository_root.to_string_lossy();
    store
        .record_session_start_for_transport_profiled(
            &session_id,
            prompt_profile_digest,
            Some("codex"),
            Some(&cwd),
            "run",
            Digest::blake3(RUN_TRANSPORT_DEFINITION),
            None,
            &provenance.profile_id,
        )
        .map_err(|error| AppError::Runtime(error.to_string()))?;
    store
        .record_user_prompt(&session_id, Some(turn_id), &envelope.need.body, Some(&cwd))
        .map_err(|error| AppError::Runtime(error.to_string()))?;
    let route = envelope
        .need
        .route_hint
        .clone()
        .ok_or_else(|| AppError::Runtime("execution Need has no route".to_owned()))?;
    let request = ResolveRequest {
        session_id: session_id.clone(),
        turn_id: turn_id.to_owned(),
        platform: "codex".to_owned(),
        main_model: "codex".to_owned(),
        cwd: repository_root,
        need: NeedRequest { key: route, body: envelope.need.body.clone() },
        need_ir: Some(envelope.need.clone()),
        declared_test_plan: None,
    };
    let resolver =
        ProductResolver::new(data_directory, WorkerPolicy::Allow).map_err(AppError::Runtime)?;
    let outcome = resolver.resolve_direct_explore(&request).map_err(AppError::Runtime);
    let cleanup =
        store.end_session(&session_id).map_err(|error| AppError::Runtime(error.to_string()));
    let outcome = outcome?;
    cleanup?;
    Ok(json!({
        "schema": needle_core::NEED_EXECUTION_OUTCOME_SCHEMA_V1,
        "operation_id": envelope.operation_id,
        "execution": "resolve",
        "result": outcome,
    }))
}

#[allow(clippy::too_many_arguments)]
fn run_action(
    envelope: &NeedExecutionEnvelopeV1,
    input: ChangeActionInput,
    store: &RuntimeStore,
    data_directory: &Path,
    repository_root: &Path,
    repository_id: Digest,
    source_snapshot: Digest,
) -> Result<Value, AppError> {
    let role = action_role(&input);
    let profile = unique_active_profile(store, role)?;
    validate_action_host_contract(profile.definition.host, &input)?;
    let provenance = RoleProfileProvenance::from_revision(&profile)
        .map_err(|error| AppError::Runtime(error.to_string()))?;
    let result = match profile.definition.host {
        AgentHost::Codex => {
            let settings =
                store.settings().map_err(|error| AppError::Runtime(error.to_string()))?;
            let config = store
                .worker_config_for_provenance(&provenance, settings.codex_executable)
                .map_err(|error| AppError::Runtime(error.to_string()))?;
            let provider = CodexChangeActionProvider::new(data_directory, repository_root, config);
            ActionExecutionService::new(store.clone(), provider)
                .execute_action(envelope, repository_id, source_snapshot)
                .map_err(|error| AppError::Runtime(error.to_string()))?
        }
        AgentHost::Antigravity => {
            let installation = inspect_installation();
            let executable = installation.cli_executable.ok_or_else(|| {
                AppError::Runtime("Antigravity CLI `agy` was not discovered".to_owned())
            })?;
            let preflight = installation.cli_preflight.ok_or_else(|| {
                AppError::Runtime(installation.cli_error.unwrap_or_else(|| {
                    "Antigravity CLI preflight did not produce a compatibility report".to_owned()
                }))
            })?;
            if !preflight.verified() {
                return Err(AppError::Runtime(preflight.incompatibility_reason.unwrap_or_else(
                    || "Antigravity CLI does not satisfy the required host contract".to_owned(),
                )));
            }
            let config = store
                .worker_config_for_provenance(
                    &provenance,
                    executable.to_string_lossy().into_owned(),
                )
                .map_err(|error| AppError::Runtime(error.to_string()))?;
            let provider =
                AntigravityChangeActionProvider::new(data_directory, repository_root, config);
            ActionExecutionService::new(store.clone(), provider)
                .execute_action(envelope, repository_id, source_snapshot)
                .map_err(|error| AppError::Runtime(error.to_string()))?
        }
    };
    Ok(json!({
        "schema": needle_core::NEED_EXECUTION_OUTCOME_SCHEMA_V1,
        "operation_id": result.operation_id,
        "execution": "action",
        "result": {
            "action_request_id": result.request.semantic_id(),
            "artifact_id": result.artifact.id,
            "validation_certificate_id": result.validation_certificate,
            "partition_manifest_id": result.partition_manifest,
            "usage": result.usage,
            "host_usage": result.host_usage,
            "authority": result.authority,
            "completion_reused": result.completion_reused,
            "idempotent_replay": result.idempotent_replay,
            "output": result.output.to_value()?,
        }
    }))
}

fn validate_action_host_contract(
    host: AgentHost,
    input: &ChangeActionInput,
) -> Result<(), AppError> {
    if host == AgentHost::Antigravity && !matches!(input, ChangeActionInput::ReviewDiff { .. }) {
        return Err(AppError::Runtime(format!(
            "Antigravity action `{}` is unavailable before Gate A8; only `needle.review.diff` is implemented",
            input.contract_id()
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_lifecycle(
    envelope: &NeedExecutionEnvelopeV1,
    lifecycle_request: &needle_core::LifecycleExecutionRequest,
    store: &RuntimeStore,
    data_directory: &Path,
    repository_root: &Path,
    repository_id: Digest,
    source_snapshot: Digest,
) -> Result<Value, AppError> {
    let active = store
        .active_lifecycle_role_profiles()
        .map_err(|error| AppError::Runtime(error.to_string()))?;
    let profiles = LifecycleWorkerProfiles {
        explore: provenance_for_role(&active, CodexRole::Explorer)?,
        implement: provenance_for_role(&active, CodexRole::Implementer)?,
        test: provenance_for_role(&active, CodexRole::TestRunner)?,
        review: provenance_for_role(&active, CodexRole::Reviewer)?,
        verify: provenance_for_role(&active, CodexRole::Verifier)?,
    };
    let configured_budget = aggregate_budget(&active)?;
    let budget = lifecycle_request.budget_override.clone().unwrap_or(configured_budget.clone());
    if !budget_restricts(&budget, &configured_budget) {
        return Err(AppError::Runtime(
            "lifecycle budget override may only restrict active profile budgets".to_owned(),
        ));
    }
    let route_key = envelope
        .need
        .route_hint
        .as_ref()
        .ok_or_else(|| AppError::Runtime("execution Need has no route".to_owned()))?;
    let route = built_in_route_contracts()
        .into_iter()
        .find(|candidate| &candidate.route == route_key)
        .ok_or_else(|| AppError::Runtime("execution Need route is not registered".to_owned()))?;
    let need = compile_need(&envelope.need, repository_id, &route)
        .map_err(|error| AppError::Runtime(error.to_string()))?;
    let fragment = need_fragment(&need, need.required.clone(), need.input_artifacts.clone());
    let request = NeedRequest { key: route_key.clone(), body: envelope.need.body.clone() };
    let action_plan = compile_lifecycle_explore_action_plan(
        &request,
        &need,
        &fragment,
        repository_id,
        source_snapshot,
    )
    .map_err(|error| AppError::Runtime(error.to_string()))?;

    persist_lifecycle_need(store, envelope, repository_root, &profiles.explore, &need, &fragment)?;
    let spec = LifecycleSpec {
        worker_depth_limit: 1,
        profiles,
        budget,
        explore_action_plan: Some(action_plan),
        action_phase_plans: Some(
            CodexLifecycleActionAdapter::phase_plans().map_err(AppError::Runtime)?,
        ),
        test_plans: Vec::new(),
    };
    let change_id = ChangeId::from_digest(lifecycle_request.change.digest(source_snapshot));
    let operational_request_digest =
        envelope.operational_request_digest(repository_id, source_snapshot);
    store
        .create_lifecycle_for_operation(
            envelope.operation_id,
            operational_request_digest,
            &change_id,
            repository_id,
            source_snapshot,
            &lifecycle_request.change,
            spec,
        )
        .map_err(|error| AppError::Runtime(error.to_string()))?;

    let explore = FreshLifecycleExploreAdapter::new(
        store.clone(),
        CodexWorker::new(data_directory),
        repository_root,
    )
    .map_err(AppError::Runtime)?;
    let implement = CodexLifecycleActionAdapter::new(
        store.clone(),
        data_directory,
        repository_root,
        LifecyclePhase::Implement,
    )
    .map_err(AppError::Runtime)?;
    let test = CodexLifecycleActionAdapter::new(
        store.clone(),
        data_directory,
        repository_root,
        LifecyclePhase::Test,
    )
    .map_err(AppError::Runtime)?;
    let review = CodexLifecycleActionAdapter::new(
        store.clone(),
        data_directory,
        repository_root,
        LifecyclePhase::Review,
    )
    .map_err(AppError::Runtime)?;
    let verify = CodexLifecycleActionAdapter::new(
        store.clone(),
        data_directory,
        repository_root,
        LifecyclePhase::Verify,
    )
    .map_err(AppError::Runtime)?;
    let resolver = SemanticLifecycleExploreActionResolver::new(store.clone());
    let adapters = LifecyclePhaseAdapters {
        explore: &explore,
        implement: &implement,
        test: &test,
        review: &review,
        verify: &verify,
    };
    let kernel = LifecycleExecutionKernel::new_with_explore_resolver(
        store,
        adapters,
        &NeverCancel,
        &resolver,
    );
    let mut last_disposition = LifecycleExecutionDisposition::Advanced;
    let mut recovery_required = None;
    for _ in 0..MAX_LIFECYCLE_STEPS_PER_INVOCATION {
        let projection = store
            .replay_lifecycle(&change_id)
            .map_err(|error| AppError::Runtime(error.to_string()))?;
        if projection.lifecycle.status.terminal()
            || projection.lifecycle.status == LifecycleStatus::AwaitingApproval
        {
            break;
        }
        let invocation_id = lifecycle_adapter_invocation_id(&projection);
        match store
            .lifecycle_adapter_invocation_state(invocation_id)
            .map_err(|error| AppError::Runtime(error.to_string()))?
        {
            Some(LifecycleAdapterInvocationState::InProgress { .. }) => {
                recovery_required = Some(json!({
                    "invocation_id": invocation_id,
                    "expected_state_digest": projection.state_digest,
                    "provider_stop_confirmation_required": true,
                }));
                break;
            }
            Some(LifecycleAdapterInvocationState::Aborted { .. }) => {
                return Err(AppError::Runtime(
                    "lifecycle adapter invocation was explicitly aborted".to_owned(),
                ));
            }
            Some(LifecycleAdapterInvocationState::Completed { .. }) | None => {}
        }
        let outcome =
            kernel.step(&change_id).map_err(|error| AppError::Runtime(error.to_string()))?;
        last_disposition = outcome.disposition;
        if matches!(
            last_disposition,
            LifecycleExecutionDisposition::Terminal
                | LifecycleExecutionDisposition::AdapterFailed
                | LifecycleExecutionDisposition::CleanupFailed
                | LifecycleExecutionDisposition::Cancelled
                | LifecycleExecutionDisposition::BudgetExhausted
                | LifecycleExecutionDisposition::AwaitingApproval
        ) {
            break;
        }
    }
    let projection =
        store.replay_lifecycle(&change_id).map_err(|error| AppError::Runtime(error.to_string()))?;
    let awaiting_apply = awaiting_apply_binding(store, &projection, lifecycle_request)?;
    Ok(json!({
        "schema": needle_core::NEED_EXECUTION_OUTCOME_SCHEMA_V1,
        "operation_id": envelope.operation_id,
        "execution": "lifecycle",
        "result": {
            "change_id": change_id,
            "disposition": last_disposition,
            "state_digest": projection.state_digest,
            "lifecycle": projection.lifecycle,
            "recovery_required": recovery_required,
            "awaiting_apply": awaiting_apply,
        }
    }))
}

fn awaiting_apply_binding(
    store: &RuntimeStore,
    projection: &LifecycleProjection,
    request: &needle_core::LifecycleExecutionRequest,
) -> Result<Option<Value>, AppError> {
    if projection.lifecycle.status != LifecycleStatus::AwaitingApproval {
        return Ok(None);
    }
    let patch = projection
        .lifecycle
        .patch
        .as_ref()
        .ok_or_else(|| AppError::Runtime("awaiting Apply lifecycle has no patch".to_owned()))?;
    let verification = projection.lifecycle.verification.as_ref().ok_or_else(|| {
        AppError::Runtime("awaiting Apply lifecycle has no verification".to_owned())
    })?;
    let patch_contract =
        needle_core::ActionContractId::new(needle_core::PATCH_PROPOSE_ACTION_CONTRACT)
            .map_err(|error| AppError::Runtime(error.to_string()))?;
    let patch_artifact = store
        .opaque_action_artifact_by_payload(&patch_contract, patch.patch_id.0)
        .map_err(|error| AppError::Runtime(error.to_string()))?
        .ok_or_else(|| AppError::Runtime("awaiting Apply patch artifact is missing".to_owned()))?;
    let verification_contract =
        needle_core::ActionContractId::new(needle_core::PATCH_VERIFY_ACTION_CONTRACT)
            .map_err(|error| AppError::Runtime(error.to_string()))?;
    let verification_artifact = store
        .opaque_action_artifact_by_payload(&verification_contract, verification.verification_id.0)
        .map_err(|error| AppError::Runtime(error.to_string()))?
        .ok_or_else(|| {
            AppError::Runtime("awaiting Apply verification artifact is missing".to_owned())
        })?;
    Ok(Some(json!({
        "contract": needle_core::PATCH_APPLY_ACTION_CONTRACT,
        "change_id": projection.lifecycle.change_id,
        "requirements_digest": request.change.digest(projection.lifecycle.source_snapshot),
        "patch": {
            "artifact": needle_core::ArtifactId::new(patch_artifact.id),
            "patch": patch.patch_id,
        },
        "verification": {
            "artifact": needle_core::ArtifactId::new(verification_artifact.id),
            "verification": verification.verification_id,
        },
        "expected_state_digest": projection.state_digest,
        "confirm_required": true,
    })))
}

fn persist_lifecycle_need(
    store: &RuntimeStore,
    envelope: &NeedExecutionEnvelopeV1,
    repository_root: &Path,
    explorer: &RoleProfileProvenance,
    need: &needle_core::Need,
    fragment: &needle_core::NeedFragment,
) -> Result<(), AppError> {
    let session_id = format!("needle-lifecycle-{}", envelope.operation_id.to_hex());
    let turn_id = "turn-1";
    let prompt_profile_digest = HookConfig::default().profile()?.definition_digest;
    let cwd = repository_root.to_string_lossy();
    store
        .record_session_start_profiled(
            &session_id,
            prompt_profile_digest,
            Some("codex"),
            Some(&cwd),
            &explorer.profile_id,
        )
        .map_err(|error| AppError::Runtime(error.to_string()))?;
    store
        .record_user_prompt(&session_id, Some(turn_id), &envelope.need.body, Some(&cwd))
        .map_err(|error| AppError::Runtime(error.to_string()))?;
    store
        .record_need_shadow(NeedShadowWrite {
            session_id: &session_id,
            turn_id,
            transport_digest: envelope.need.transport_digest(),
            parser_definition_digest: need_grammar_definition_digest(),
            prompt_profile_digest,
            need_ir: &envelope.need,
            need,
            fragments: std::slice::from_ref(fragment),
        })
        .map_err(|error| AppError::Runtime(error.to_string()))?;
    store.end_session(&session_id).map_err(|error| AppError::Runtime(error.to_string()))
}

fn unique_active_profile(
    store: &RuntimeStore,
    role: CodexRole,
) -> Result<RoleProfileRevision, AppError> {
    let active = store
        .active_lifecycle_role_profiles()
        .map_err(|error| AppError::Runtime(error.to_string()))?;
    let mut matches = active.into_iter().filter(|profile| profile.definition.role == role);
    let profile = matches
        .next()
        .ok_or_else(|| AppError::Runtime(format!("no active {role:?} profile is configured")))?;
    if matches.next().is_some() {
        return Err(AppError::Runtime(format!(
            "multiple active {role:?} profiles are ambiguous for structured execution"
        )));
    }
    Ok(profile)
}

fn provenance_for_role(
    active: &[RoleProfileRevision],
    role: CodexRole,
) -> Result<RoleProfileProvenance, AppError> {
    let mut matches = active.iter().filter(|profile| profile.definition.role == role);
    let profile = matches
        .next()
        .ok_or_else(|| AppError::Runtime(format!("no active {role:?} profile is configured")))?;
    if matches.next().is_some() {
        return Err(AppError::Runtime(format!(
            "multiple active {role:?} profiles are ambiguous for structured execution"
        )));
    }
    RoleProfileProvenance::from_revision(profile)
        .map_err(|error| AppError::Runtime(error.to_string()))
}

fn aggregate_budget(active: &[RoleProfileRevision]) -> Result<LifecycleBudget, AppError> {
    let mut max_worker_turns = 0u32;
    let mut max_output_tokens = 0u64;
    let mut max_cost_microusd = 0u64;
    for role in [
        CodexRole::Explorer,
        CodexRole::Implementer,
        CodexRole::TestRunner,
        CodexRole::Reviewer,
        CodexRole::Verifier,
    ] {
        let mut matches = active.iter().filter(|profile| profile.definition.role == role);
        let profile = matches.next().ok_or_else(|| {
            AppError::Runtime(format!("no active {role:?} profile is configured"))
        })?;
        if matches.next().is_some() {
            return Err(AppError::Runtime(format!(
                "multiple active {role:?} profiles are ambiguous for structured execution"
            )));
        }
        max_worker_turns = max_worker_turns
            .checked_add(u32::from(profile.definition.budget.max_turns))
            .ok_or_else(|| AppError::Runtime("active worker-turn budgets overflow".to_owned()))?;
        max_output_tokens = max_output_tokens
            .checked_add(u64::from(profile.definition.budget.max_output_tokens))
            .ok_or_else(|| AppError::Runtime("active output-token budgets overflow".to_owned()))?;
        max_cost_microusd = max_cost_microusd
            .checked_add(profile.definition.budget.max_cost_microusd)
            .ok_or_else(|| AppError::Runtime("active cost budgets overflow".to_owned()))?;
    }
    Ok(LifecycleBudget {
        max_worker_turns,
        max_output_tokens,
        max_cost_microusd,
        max_concurrent_workers: 1,
    })
}

fn budget_restricts(candidate: &LifecycleBudget, configured: &LifecycleBudget) -> bool {
    candidate.max_worker_turns <= configured.max_worker_turns
        && candidate.max_output_tokens <= configured.max_output_tokens
        && candidate.max_cost_microusd <= configured.max_cost_microusd
        && candidate.max_concurrent_workers == 1
}

fn action_role(input: &ChangeActionInput) -> CodexRole {
    match input {
        ChangeActionInput::PatchPropose { .. } | ChangeActionInput::PatchApply { .. } => {
            CodexRole::Implementer
        }
        ChangeActionInput::TestsExecute { .. } => CodexRole::TestRunner,
        ChangeActionInput::ReviewDiff { .. } => CodexRole::Reviewer,
        ChangeActionInput::PatchVerify { .. } => CodexRole::Verifier,
    }
}

fn read_envelope() -> Result<NeedExecutionEnvelopeV1, AppError> {
    let mut bytes = Vec::new();
    io::stdin()
        .take((needle_core::MAX_NEED_EXECUTION_WIRE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    NeedExecutionEnvelopeV1::decode_json(&bytes)
        .map_err(|error| AppError::Runtime(error.to_string()))
}

fn validate_arguments(arguments: &[String]) -> Result<(), AppError> {
    let mut index = 0;
    let mut request_stdin = false;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--request-stdin" if !request_stdin => {
                request_stdin = true;
                index += 1;
            }
            "--repository" | "--data-dir" => {
                if arguments.get(index + 1).is_none() {
                    return Err(AppError::Usage(format!("{} requires a value", arguments[index])));
                }
                index += 2;
            }
            argument => {
                return Err(AppError::Usage(format!("unknown run argument `{argument}`")));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_argument_surface_is_closed() {
        assert!(validate_arguments(&["--request-stdin".to_owned()]).is_ok());
        assert!(validate_arguments(&["--request-stdin".to_owned(), "--json".to_owned()]).is_err());
        assert!(
            validate_arguments(&["--request-stdin".to_owned(), "--request-stdin".to_owned()])
                .is_err()
        );
    }

    #[test]
    fn budget_override_can_only_restrict() {
        let configured = LifecycleBudget {
            max_worker_turns: 10,
            max_output_tokens: 1_000,
            max_cost_microusd: 100,
            max_concurrent_workers: 1,
        };
        assert!(budget_restricts(
            &LifecycleBudget {
                max_worker_turns: 5,
                max_output_tokens: 500,
                max_cost_microusd: 50,
                max_concurrent_workers: 1,
            },
            &configured,
        ));
        assert!(!budget_restricts(
            &LifecycleBudget { max_worker_turns: 11, ..configured.clone() },
            &configured,
        ));
    }

    #[test]
    fn antigravity_action_surface_is_review_only_before_gate_a8() {
        let change = needle_core::ChangeRequest {
            task: "Update the fixture.".to_owned(),
            acceptance_criteria: vec!["The fixture changes.".to_owned()],
            allowed_paths: vec![needle_core::AllowedPath {
                path: "fixture.txt".to_owned(),
                scope: needle_core::AllowedPathScope::Exact,
            }],
            artifact_ids: Vec::new(),
            claim_ids: Vec::new(),
            constraints: Vec::new(),
        };
        let patch = ChangeActionInput::PatchPropose {
            change,
            prior_patch: None,
            repair_verification: None,
        };
        assert!(validate_action_host_contract(AgentHost::Codex, &patch).is_ok());
        assert!(validate_action_host_contract(AgentHost::Antigravity, &patch).is_err());

        let review = ChangeActionInput::ReviewDiff {
            change_id: ChangeId::from_digest(Digest::blake3(b"change")),
            requirements_digest: Digest::blake3(b"requirements"),
            patch: needle_core::PatchActionInputRef {
                artifact: needle_core::ArtifactId::new(Digest::blake3(b"patch-artifact")),
                patch: needle_core::PatchId(Digest::blake3(b"patch")),
            },
            prior_review_artifacts: Vec::new(),
        };
        assert!(validate_action_host_contract(AgentHost::Antigravity, &review).is_ok());
    }
}
