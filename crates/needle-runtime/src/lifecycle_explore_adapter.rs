use crate::lifecycle_action_plan::validate_lifecycle_explore_action_plan_need;
use crate::{
    LifecycleAdapterCleanup, LifecycleAdapterFailure, LifecycleAdapterInvocationClaim,
    LifecycleAdapterInvocationState, LifecycleAdapterResult, LifecyclePhaseAdapter,
    LifecyclePhaseAdapterOutcome, LifecyclePhaseAdapterRequest, RuntimeStore, WorkerExecutor,
    bind_evidence_digests, built_in_action_contracts, capture_git_snapshot, select_route,
    validate_need_result, validate_semantic_artifact_with_trace,
};
use needle_core::{
    ActionRequest, ArtifactKind, CanonicalHasher, CodexRole, Digest, LifecycleArtifactKind,
    LifecycleArtifactRef, LifecyclePhase, LifecycleTransition, LifecycleUsage, NeedCacheEntry,
    NeedCacheIdentity, RoleProfileRevision, SEMANTIC_ARTIFACT_RESULT_SCHEMA_ID,
    SemanticArtifactResult, WorkerFailure, WorkerOutcome, WorkerRequest,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub const FRESH_LIFECYCLE_EXPLORE_ADAPTER_REVISION: u16 = 1;

pub fn fresh_lifecycle_explore_adapter_definition_digest() -> Digest {
    let mut hasher = CanonicalHasher::new(b"needle-fresh-lifecycle-explore-adapter");
    hasher.field_u16(FRESH_LIFECYCLE_EXPLORE_ADAPTER_REVISION);
    hasher.field_str(crate::LIFECYCLE_ADAPTER_REQUEST_SCHEMA);
    hasher.field_str(crate::LIFECYCLE_ADAPTER_OUTCOME_SCHEMA);
    hasher.field_u16(built_in_action_contracts().len() as u16);
    for definition in built_in_action_contracts() {
        hasher.field_digest(definition.contract.definition_digest);
        hasher.field_digest(definition.output_contract_definition_digest);
        hasher.field_digest(definition.validator_definition_digest);
    }
    hasher.finish()
}

/// A fresh-only Explore adapter for the parent-owned lifecycle kernel.
///
/// This adapter deliberately performs no cache lookup. Shadow action
/// resolution happens before it is invoked, but cannot suppress or reduce this
/// worker execution. The worker transport is generic; the application selects
/// the concrete host implementation.
pub struct FreshLifecycleExploreAdapter<W> {
    store: RuntimeStore,
    worker: W,
    repository_root: PathBuf,
    definition_digest: Digest,
}

impl<W> FreshLifecycleExploreAdapter<W> {
    pub fn new(
        store: RuntimeStore,
        worker: W,
        repository_root: impl AsRef<Path>,
    ) -> Result<Self, String> {
        let repository_root = fs::canonicalize(repository_root.as_ref()).map_err(|error| {
            format!(
                "cannot resolve lifecycle adapter repository {}: {error}",
                repository_root.as_ref().display()
            )
        })?;
        Ok(Self {
            store,
            worker,
            repository_root,
            definition_digest: fresh_lifecycle_explore_adapter_definition_digest(),
        })
    }

    pub fn definition_digest(&self) -> Digest {
        self.definition_digest
    }
}

impl<W: WorkerExecutor> LifecyclePhaseAdapter for FreshLifecycleExploreAdapter<W> {
    fn invoke(&self, request: &LifecyclePhaseAdapterRequest) -> LifecyclePhaseAdapterOutcome {
        if request.phase != LifecyclePhase::Explore {
            return failure_outcome(
                request,
                "unsupported_phase",
                "the fresh lifecycle adapter supports Explore only",
                LifecycleUsage::default(),
                LifecycleAdapterCleanup::succeeded(),
            );
        }
        match self.store.claim_lifecycle_adapter_invocation(request, self.definition_digest) {
            Ok(LifecycleAdapterInvocationClaim::Existing(
                LifecycleAdapterInvocationState::Completed { outcome, .. },
            )) => return *outcome,
            Ok(LifecycleAdapterInvocationClaim::Existing(
                LifecycleAdapterInvocationState::InProgress { .. },
            )) => {
                return failure_outcome(
                    request,
                    "adapter_in_progress",
                    "the durable adapter invocation is already in progress",
                    LifecycleUsage::default(),
                    LifecycleAdapterCleanup::succeeded(),
                );
            }
            Ok(LifecycleAdapterInvocationClaim::Existing(
                LifecycleAdapterInvocationState::Aborted { .. },
            )) => {
                return failure_outcome(
                    request,
                    "adapter_invocation_aborted",
                    "the durable adapter invocation was explicitly aborted",
                    LifecycleUsage::default(),
                    LifecycleAdapterCleanup::succeeded(),
                );
            }
            Ok(LifecycleAdapterInvocationClaim::Claimed) => {}
            Err(error) => {
                return failure_outcome(
                    request,
                    "adapter_claim_failed",
                    &error.to_string(),
                    LifecycleUsage::default(),
                    LifecycleAdapterCleanup::succeeded(),
                );
            }
        }

        let outcome = match self.execute_fresh(request) {
            Ok(outcome) => outcome,
            Err(failure) => failure.outcome(request),
        };
        if let Err(error) = self.store.complete_lifecycle_adapter_invocation(
            request,
            self.definition_digest,
            &outcome,
        ) {
            return failure_outcome(
                request,
                "adapter_outcome_persistence_failed",
                &error.to_string(),
                outcome.usage,
                outcome.cleanup,
            );
        }
        outcome
    }
}

impl<W: WorkerExecutor> FreshLifecycleExploreAdapter<W> {
    fn execute_fresh(
        &self,
        request: &LifecyclePhaseAdapterRequest,
    ) -> Result<LifecyclePhaseAdapterOutcome, AdapterExecutionFailure> {
        let plan = request.lifecycle.spec.explore_action_plan.as_ref().ok_or_else(|| {
            AdapterExecutionFailure::before_worker(
                "explore_plan_unavailable",
                "the lifecycle has no frozen Explore action plan",
            )
        })?;
        let need = self
            .store
            .need(&plan.fragment.root_need.to_string())
            .map_err(AdapterExecutionFailure::store)?
            .ok_or_else(|| {
                AdapterExecutionFailure::before_worker(
                    "explore_need_unavailable",
                    "the frozen Explore Need is unavailable",
                )
            })?;
        let need_request =
            validate_lifecycle_explore_action_plan_need(plan, &need).map_err(|error| {
                AdapterExecutionFailure::before_worker("explore_plan_invalid", &error.to_string())
            })?;
        let stored_repository_root = self
            .store
            .repository_root_for_need(&need.id.to_string())
            .map_err(AdapterExecutionFailure::store)?
            .ok_or_else(|| {
                AdapterExecutionFailure::before_worker(
                    "repository_unavailable",
                    "the frozen Need has no repository root",
                )
            })?;
        let stored_repository_root =
            fs::canonicalize(&stored_repository_root).map_err(|error| {
                AdapterExecutionFailure::before_worker("repository_unavailable", &error.to_string())
            })?;
        if stored_repository_root != self.repository_root {
            return Err(AdapterExecutionFailure::before_worker(
                "repository_mismatch",
                "the frozen Need belongs to a different repository root",
            ));
        }
        let (repository_root, snapshot) =
            capture_git_snapshot(&self.repository_root).map_err(|error| {
                AdapterExecutionFailure::before_worker("snapshot_failed", &error.to_string())
            })?;
        if snapshot.repository_id != request.change.repository_id
            || snapshot.source_digest != request.change.source_snapshot
        {
            return Err(AdapterExecutionFailure::before_worker(
                "source_changed",
                "the repository source changed before fresh Explore execution",
            ));
        }

        let settings = self.store.settings().map_err(AdapterExecutionFailure::store)?;
        let revision = self
            .store
            .read_role_profile_revision(&request.profile.profile_id, request.profile.revision)
            .map_err(AdapterExecutionFailure::store)?;
        validate_explore_profile(&revision, request, &need_request.key)?;
        let config = self
            .store
            .worker_config_for_provenance(&request.profile, settings.codex_executable)
            .map_err(AdapterExecutionFailure::store)?;
        let routes = self.store.routes().map_err(AdapterExecutionFailure::store)?;
        let route = select_route(
            &routes,
            "codex",
            &config.model,
            &snapshot.repository_id.to_string(),
            need_request.key.as_str(),
        )
        .map_err(|error| {
            AdapterExecutionFailure::before_worker("route_selection_failed", &error.to_string())
        })?
        .ok_or_else(|| {
            AdapterExecutionFailure::before_worker(
                "route_unavailable",
                "no route matches the frozen Explore request",
            )
        })?;
        let preset = self
            .store
            .preset(&route.preset_id)
            .map_err(AdapterExecutionFailure::store)?
            .ok_or_else(|| {
            AdapterExecutionFailure::before_worker(
                "preset_unavailable",
                "the selected route preset is unavailable",
            )
        })?;
        let requested_artifact_kinds = requested_artifact_kinds(plan)?;
        let worker_request = WorkerRequest {
            root_task: request.change.request.task.clone(),
            need_key: need_request.key.clone(),
            need_body: need_request.body.clone(),
            preset: preset.clone(),
            repository_root: repository_root.to_string_lossy().into_owned(),
            repository_snapshot: snapshot.clone(),
            declared_test_plan: None,
            trusted_test_execution: false,
            requested_artifact_kinds,
            preferred_artifact_kinds: Vec::new(),
            semantic_fragment: Some(plan.fragment.clone()),
        };
        let identity = NeedCacheIdentity {
            repository_id: snapshot.repository_id,
            source_snapshot_digest: snapshot.source_digest,
            prompt_profile_digest: revision.definition.prompt_profile_digest,
            route_definition_digest: route.definition_digest,
            preset_definition_digest: preset.definition_digest,
            need_key: need_request.key.clone(),
            normalized_request_digest: need_request.digest(),
            worker_configuration_digest: config.digest(),
            output_schema_digest: Digest::blake3(SEMANTIC_ARTIFACT_RESULT_SCHEMA_ID),
            role_profile_provenance: Some(request.profile.clone()),
        };
        let identity_digest = identity.digest();
        let mut worker_outcome = match self.worker.execute(&config, &worker_request) {
            Ok(outcome) => outcome,
            Err(failure) => {
                let _ = self.store.record_worker_failure(identity_digest, &config, &failure);
                return Err(AdapterExecutionFailure::from_worker_failure(*failure, &revision));
            }
        };
        let usage = lifecycle_usage(&worker_outcome, &revision, request)?;
        let cleanup = worker_cleanup(worker_outcome.session_cleanup_success);
        if !cleanup.succeeded {
            return Err(AdapterExecutionFailure {
                code: "worker_cleanup_failed",
                detail: "the Codex worker did not confirm session cleanup".to_owned(),
                usage,
                cleanup,
            });
        }
        if worker_outcome.role_profile_provenance.as_ref() != Some(&request.profile)
            || worker_outcome.logical_worker_spawns != 1
            || worker_outcome.worker_turns == 0
        {
            return Err(AdapterExecutionFailure::after_worker(
                "worker_provenance_invalid",
                "worker provenance or single-worker accounting is invalid",
                usage,
                cleanup,
            ));
        }
        bind_evidence_digests(&repository_root, &mut worker_outcome.result).map_err(|error| {
            AdapterExecutionFailure::after_worker(
                "evidence_binding_failed",
                &error.to_string(),
                usage.clone(),
                cleanup.clone(),
            )
        })?;
        validate_need_result(&repository_root, &worker_outcome.result).map_err(|error| {
            AdapterExecutionFailure::after_worker(
                "evidence_validation_failed",
                &error.to_string(),
                usage.clone(),
                cleanup.clone(),
            )
        })?;
        if !worker_outcome.result.complete {
            return Err(AdapterExecutionFailure::after_worker(
                "explore_incomplete",
                "the fresh Explore worker reported an incomplete result",
                usage,
                cleanup,
            ));
        }
        let (_, current_snapshot) = capture_git_snapshot(&repository_root).map_err(|error| {
            AdapterExecutionFailure::after_worker(
                "snapshot_failed",
                &error.to_string(),
                usage.clone(),
                cleanup.clone(),
            )
        })?;
        if current_snapshot.source_digest != snapshot.source_digest {
            return Err(AdapterExecutionFailure::after_worker(
                "source_changed",
                "the repository source changed during fresh Explore execution",
                usage,
                cleanup,
            ));
        }

        let validated_artifacts = validate_worker_artifacts(
            plan,
            &repository_root,
            worker_outcome.semantic_artifact_result.as_ref(),
        )
        .map_err(|error| {
            AdapterExecutionFailure::after_worker(
                "artifact_validation_failed",
                &error,
                usage.clone(),
                cleanup.clone(),
            )
        })?;
        let entry = NeedCacheEntry {
            identity,
            result: worker_outcome.result.clone(),
            worker_outcome,
            created_unix_ms: crate::store::now_ms(),
            hit_count: 0,
        };
        self.store.record_worker_run(&entry).map_err(|error| {
            AdapterExecutionFailure::after_worker(
                "worker_record_failed",
                &error.to_string(),
                usage.clone(),
                cleanup.clone(),
            )
        })?;
        let artifact_refs =
            publish_worker_artifacts(&self.store, &validated_artifacts).map_err(|error| {
                AdapterExecutionFailure::after_worker(
                    "artifact_publication_failed",
                    &error,
                    usage.clone(),
                    cleanup.clone(),
                )
            })?;
        Ok(LifecyclePhaseAdapterOutcome {
            schema: crate::LIFECYCLE_ADAPTER_OUTCOME_SCHEMA.to_owned(),
            invocation_id: request.invocation_id,
            expected_state_digest: request.expected_state_digest,
            phase: request.phase,
            usage: usage.clone(),
            result: LifecycleAdapterResult::Completed {
                transition: Box::new(LifecycleTransition::CompleteExplore {
                    worker: needle_core::LifecycleWorkerCompletion {
                        profile: request.profile.clone(),
                        worker_depth: 1,
                        logical_worker_spawns: 1,
                        usage,
                    },
                    artifacts: artifact_refs,
                }),
            },
            cleanup,
        })
    }
}

fn validate_explore_profile(
    revision: &RoleProfileRevision,
    request: &LifecyclePhaseAdapterRequest,
    route: &needle_core::NeedKey,
) -> Result<(), AdapterExecutionFailure> {
    revision.validate().map_err(|error| {
        AdapterExecutionFailure::before_worker("profile_invalid", &error.to_string())
    })?;
    if revision.definition.role != CodexRole::Explorer
        || !revision.definition.route_assignments.contains(route)
        || revision.definition.budget.max_turns as u32 > request.remaining_budget.worker_turns
        || u64::from(revision.definition.budget.max_output_tokens)
            > request.remaining_budget.output_tokens
        || revision.definition.budget.max_cost_microusd > request.remaining_budget.cost_microusd
    {
        return Err(AdapterExecutionFailure::before_worker(
            "profile_incompatible",
            "the frozen Explorer profile or its reserved budget is incompatible with this phase",
        ));
    }
    Ok(())
}

fn requested_artifact_kinds(
    plan: &needle_core::LifecycleExploreActionPlan,
) -> Result<Vec<ArtifactKind>, AdapterExecutionFailure> {
    let mut kinds = Vec::with_capacity(plan.actions.len());
    for action in &plan.actions {
        let definition = built_in_action_contracts()
            .iter()
            .find(|definition| definition.contract.id == action.contract)
            .filter(|definition| {
                definition.output_contract_id == action.artifact_request.contract_id
                    && definition.output_contract_revision
                        == action.artifact_request.contract_revision
            })
            .ok_or_else(|| {
                AdapterExecutionFailure::before_worker(
                    "action_contract_unavailable",
                    "the frozen Explore action is not a current built-in contract",
                )
            })?;
        kinds.push(definition.artifact_kind.clone());
    }
    kinds.sort();
    kinds.dedup();
    if kinds.len() != plan.actions.len() {
        return Err(AdapterExecutionFailure::before_worker(
            "action_contract_ambiguous",
            "the frozen Explore actions do not map one-to-one to artifact kinds",
        ));
    }
    Ok(kinds)
}

struct ValidatedExploreArtifact<'a> {
    action: &'a ActionRequest,
    artifact: crate::ValidatedSemanticArtifact,
    lifecycle_ref: LifecycleArtifactRef,
}

fn validate_worker_artifacts<'a>(
    plan: &'a needle_core::LifecycleExploreActionPlan,
    repository_root: &Path,
    result: Option<&SemanticArtifactResult>,
) -> Result<Vec<ValidatedExploreArtifact<'a>>, String> {
    let result = result.ok_or_else(|| "worker returned no semantic artifact result".to_owned())?;
    if result.schema_id != SEMANTIC_ARTIFACT_RESULT_SCHEMA_ID
        || result.artifacts.len() != plan.actions.len()
    {
        return Err("worker semantic artifact result does not match the frozen plan".to_owned());
    }
    let mut expected = BTreeMap::new();
    for action in &plan.actions {
        let definition = built_in_action_contracts()
            .iter()
            .find(|definition| definition.contract.id == action.contract)
            .ok_or_else(|| "frozen action contract is unavailable".to_owned())?;
        expected.insert(definition.artifact_kind.clone(), action);
    }
    let mut validated = Vec::with_capacity(result.artifacts.len());
    let mut observed = BTreeSet::new();
    for worker_artifact in &result.artifacts {
        let kind = worker_artifact.kind();
        if !observed.insert(kind.clone()) {
            return Err("worker returned a duplicate semantic artifact kind".to_owned());
        }
        let action = expected
            .get(&kind)
            .ok_or_else(|| "worker returned an artifact outside the frozen plan".to_owned())?;
        let trace = result.artifact_traces.get(&kind).unwrap_or(&result.observation_trace);
        let artifact = validate_semantic_artifact_with_trace(
            &plan.fragment,
            worker_artifact,
            repository_root,
            action.semantic_id().digest(),
            Some(trace),
        )
        .map_err(|error| error.to_string())?;
        validated.push(ValidatedExploreArtifact {
            action,
            lifecycle_ref: LifecycleArtifactRef {
                kind: LifecycleArtifactKind::Exploration,
                id: artifact.artifact.id,
                source_snapshot: action.artifact_request.source_snapshot_digest,
            },
            artifact,
        });
    }
    if observed.len() != expected.len() {
        return Err("worker omitted a frozen Explore artifact kind".to_owned());
    }
    validated.sort_by_key(|artifact| artifact.lifecycle_ref.id);
    if validated.is_empty()
        || validated.windows(2).any(|pair| pair[0].lifecycle_ref.id >= pair[1].lifecycle_ref.id)
    {
        return Err("validated Explore artifact identities are not canonical".to_owned());
    }
    Ok(validated)
}

fn publish_worker_artifacts(
    store: &RuntimeStore,
    artifacts: &[ValidatedExploreArtifact<'_>],
) -> Result<Vec<LifecycleArtifactRef>, String> {
    let mut refs = Vec::with_capacity(artifacts.len());
    for validated in artifacts {
        store
            .publish_action_artifact(
                validated.action,
                &validated.artifact.artifact,
                &validated.artifact.certificate,
            )
            .map_err(|error| error.to_string())?;
        refs.push(validated.lifecycle_ref.clone());
    }
    Ok(refs)
}

fn lifecycle_usage(
    outcome: &WorkerOutcome,
    revision: &RoleProfileRevision,
    request: &LifecyclePhaseAdapterRequest,
) -> Result<LifecycleUsage, AdapterExecutionFailure> {
    let worker_turns = outcome.worker_turns;
    let output_tokens =
        outcome.output_tokens.unwrap_or(u64::from(revision.definition.budget.max_output_tokens));
    let cost_microusd =
        if worker_turns == 0 { 0 } else { revision.definition.budget.max_cost_microusd };
    let usage = LifecycleUsage { worker_turns, output_tokens, cost_microusd };
    if usage.worker_turns > request.remaining_budget.worker_turns
        || usage.output_tokens > request.remaining_budget.output_tokens
        || usage.cost_microusd > request.remaining_budget.cost_microusd
    {
        return Err(AdapterExecutionFailure::after_worker(
            "worker_budget_exceeded",
            "fresh Explore worker usage exceeded the frozen lifecycle budget",
            usage,
            worker_cleanup(outcome.session_cleanup_success),
        ));
    }
    Ok(usage)
}

fn worker_cleanup(succeeded: Option<bool>) -> LifecycleAdapterCleanup {
    if succeeded == Some(true) {
        LifecycleAdapterCleanup::succeeded()
    } else {
        LifecycleAdapterCleanup {
            succeeded: false,
            failure: Some(LifecycleAdapterFailure {
                code: "worker_cleanup_unconfirmed".to_owned(),
                detail: "Codex worker session cleanup was not confirmed".to_owned(),
            }),
        }
    }
}

struct AdapterExecutionFailure {
    code: &'static str,
    detail: String,
    usage: LifecycleUsage,
    cleanup: LifecycleAdapterCleanup,
}

impl AdapterExecutionFailure {
    fn before_worker(code: &'static str, detail: &str) -> Self {
        Self {
            code,
            detail: bound_detail(detail),
            usage: LifecycleUsage::default(),
            cleanup: LifecycleAdapterCleanup::succeeded(),
        }
    }

    fn after_worker(
        code: &'static str,
        detail: &str,
        usage: LifecycleUsage,
        cleanup: LifecycleAdapterCleanup,
    ) -> Self {
        Self { code, detail: bound_detail(detail), usage, cleanup }
    }

    fn store(error: crate::StoreError) -> Self {
        Self::before_worker("adapter_storage_failed", &error.to_string())
    }

    fn from_worker_failure(failure: WorkerFailure, revision: &RoleProfileRevision) -> Self {
        let worker_turns = failure.worker_turns;
        let output_tokens = failure
            .output_tokens
            .unwrap_or_else(|| u64::from(revision.definition.budget.max_output_tokens));
        let usage = LifecycleUsage {
            worker_turns,
            output_tokens,
            cost_microusd: if worker_turns == 0 {
                0
            } else {
                revision.definition.budget.max_cost_microusd
            },
        };
        Self {
            code: "codex_worker_failed",
            detail: bound_detail(&format!("{}: {}", failure.code, failure.diagnostic)),
            usage,
            cleanup: worker_cleanup(failure.session_cleanup_success),
        }
    }

    fn outcome(self, request: &LifecyclePhaseAdapterRequest) -> LifecyclePhaseAdapterOutcome {
        failure_outcome(request, self.code, &self.detail, self.usage, self.cleanup)
    }
}

fn failure_outcome(
    request: &LifecyclePhaseAdapterRequest,
    code: &str,
    detail: &str,
    usage: LifecycleUsage,
    cleanup: LifecycleAdapterCleanup,
) -> LifecyclePhaseAdapterOutcome {
    LifecyclePhaseAdapterOutcome {
        schema: crate::LIFECYCLE_ADAPTER_OUTCOME_SCHEMA.to_owned(),
        invocation_id: request.invocation_id,
        expected_state_digest: request.expected_state_digest,
        phase: request.phase,
        usage,
        result: LifecycleAdapterResult::Failed {
            failure: LifecycleAdapterFailure {
                code: code.to_owned(),
                detail: bound_detail(detail),
            },
        },
        cleanup,
    }
}

fn bound_detail(value: &str) -> String {
    let mut end = value.len().min(crate::MAX_LIFECYCLE_ADAPTER_DETAIL_BYTES);
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value[..end].to_owned()
}
