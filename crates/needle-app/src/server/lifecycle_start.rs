use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use needle_core::{
    CanonicalHasher, ChangeId, CodexRole, Digest, LifecycleBudget, LifecyclePhase, LifecycleSpec,
    LifecycleStatus, LifecycleTestPlanBinding, LifecycleWorkerProfiles, NeedId, NeedRequest,
    PredicateKind, RoleProfileId, RoleProfileProvenance, RoleProfileRevision, RoleProfileState,
    need_fragment,
};
use needle_runtime::{
    LifecycleProjection, RuntimeStore, StoreError, capture_git_snapshot,
    compile_lifecycle_explore_action_plan,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::mcp::change_schema::McpPrepareChangeRequest;

use super::AppState;

pub(super) const MAX_CREATE_BODY_BYTES: usize = 32 * 1024;
const PREFLIGHT_SCHEMA: &str = "needle.lifecycle-start-preflight/1";
const CREATE_SCHEMA: &str = "needle.lifecycle-create/1";
const ERROR_SCHEMA: &str = "needle.lifecycle-error/1";
const MAX_PREFLIGHT_NEEDS: u32 = 100;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LifecycleCreateBody {
    operation_id: String,
    expected_source_snapshot: Digest,
    need_id: NeedId,
    change: McpPrepareChangeRequest,
    profiles: LifecycleCreateProfiles,
    budget: LifecycleCreateBudget,
    #[serde(default)]
    test_plan_certificates: Vec<Digest>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleCreateProfileRef {
    profile_id: RoleProfileId,
    definition_digest: Digest,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleCreateProfiles {
    explore: LifecycleCreateProfileRef,
    implement: LifecycleCreateProfileRef,
    test: LifecycleCreateProfileRef,
    review: LifecycleCreateProfileRef,
    verify: LifecycleCreateProfileRef,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleCreateBudget {
    max_worker_turns: u32,
    max_output_tokens: u64,
    max_cost_microusd: u64,
}

#[derive(Debug, Serialize)]
struct LifecycleStartProfileDto {
    profile_id: RoleProfileId,
    role: CodexRole,
    revision: u64,
    definition_digest: Digest,
}

#[derive(Debug, Serialize)]
struct LifecycleStartNeedDto {
    need_id: NeedId,
    route: String,
    required_predicates: Vec<PredicateKind>,
    need_definition_digest: Digest,
    action_plan_definition_digest: Digest,
}

#[derive(Debug, Serialize)]
struct LifecycleStartTestPlanDto {
    artifact_id: needle_core::ArtifactId,
    plan_digest: Digest,
    certificate_digest: Digest,
    issued_unix_ms: u64,
}

#[derive(Debug, Serialize)]
struct LifecycleStartPreflightDto {
    schema: &'static str,
    repository_id: Digest,
    source_snapshot: Digest,
    watcher_uncertain: bool,
    eligible: bool,
    blockers: Vec<&'static str>,
    profiles: Vec<LifecycleStartProfileDto>,
    needs: Vec<LifecycleStartNeedDto>,
    test_plans: Vec<LifecycleStartTestPlanDto>,
    max_selected_test_plans: usize,
    default_budget: LifecycleCreateBudgetDto,
}

#[derive(Debug, Serialize)]
struct LifecycleCreateBudgetDto {
    max_worker_turns: u32,
    max_output_tokens: u64,
    max_cost_microusd: u64,
    max_concurrent_workers: u8,
}

#[derive(Debug, Serialize)]
struct LifecycleCreateDto {
    schema: &'static str,
    created: bool,
    change_id: ChangeId,
    lifecycle_id: needle_core::LifecycleId,
    phase: LifecyclePhase,
    status: LifecycleStatus,
    generation: u64,
    state_digest: Digest,
    source_snapshot: Digest,
    action_plan_definition_digest: Digest,
}

#[derive(Debug, Serialize)]
struct LifecycleStartErrorDto {
    schema: &'static str,
    code: &'static str,
    message: &'static str,
}

#[derive(Debug)]
enum LifecycleStartError {
    Invalid(&'static str),
    StaleSource,
    Missing(&'static str),
    Conflict,
    Store(StoreError),
    Snapshot,
}

pub(super) async fn preflight_lifecycle_start(State(state): State<AppState>) -> Response {
    let store = state.store.clone();
    let repository_root = state.repository_root.clone();
    let watcher_uncertain = state.repository_watcher_health.uncertain();
    match tokio::task::spawn_blocking(move || {
        build_preflight(&store, &repository_root, watcher_uncertain)
    })
    .await
    {
        Ok(Ok(preflight)) => Json(preflight).into_response(),
        Ok(Err(error)) => error.into_response(),
        Err(_) => lifecycle_start_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "lifecycle_preflight_join_failed",
            "lifecycle start preflight failed",
        ),
    }
}

pub(super) async fn create_lifecycle(
    State(state): State<AppState>,
    body: Result<Json<LifecycleCreateBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => {
            return lifecycle_start_error(
                StatusCode::BAD_REQUEST,
                "invalid_body",
                "request body is invalid",
            );
        }
    };
    let store = state.store.clone();
    let repository_root = state.repository_root.clone();
    match tokio::task::spawn_blocking(move || create(&store, &repository_root, body)).await {
        Ok(Ok((created, response))) => {
            (if created { StatusCode::CREATED } else { StatusCode::OK }, Json(response))
                .into_response()
        }
        Ok(Err(error)) => error.into_response(),
        Err(_) => lifecycle_start_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "lifecycle_create_join_failed",
            "lifecycle creation failed",
        ),
    }
}

fn build_preflight(
    store: &RuntimeStore,
    repository_root: &std::path::Path,
    watcher_uncertain: bool,
) -> Result<LifecycleStartPreflightDto, LifecycleStartError> {
    let (_, snapshot) =
        capture_git_snapshot(repository_root).map_err(|_| LifecycleStartError::Snapshot)?;
    let active_profiles =
        store.active_lifecycle_role_profiles().map_err(LifecycleStartError::Store)?;
    let profiles = active_profiles
        .iter()
        .map(|profile| LifecycleStartProfileDto {
            profile_id: profile.profile_id.clone(),
            role: profile.definition.role,
            revision: profile.revision,
            definition_digest: profile.definition.definition_digest,
        })
        .collect::<Vec<_>>();
    let mut needs = Vec::new();
    for record in store.need_shadows(MAX_PREFLIGHT_NEEDS).map_err(LifecycleStartError::Store)? {
        if record.need.world.repository_lineage != snapshot.repository_id {
            continue;
        }
        let Some(route) = record.need_ir.route_hint.clone() else {
            continue;
        };
        let request = NeedRequest { key: route.clone(), body: record.need_ir.body.clone() };
        let fragment = need_fragment(&record.need, record.need.required.clone(), Vec::new());
        let Ok(plan) = compile_lifecycle_explore_action_plan(
            &request,
            &record.need,
            &fragment,
            snapshot.repository_id,
            snapshot.source_digest,
        ) else {
            continue;
        };
        let required_predicates = record
            .need
            .required
            .iter()
            .map(|obligation| obligation.predicate)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        needs.push(LifecycleStartNeedDto {
            need_id: record.need.id,
            route: route.to_string(),
            required_predicates,
            need_definition_digest: record.need.definition_digest(),
            action_plan_definition_digest: plan.definition_digest,
        });
    }
    needs.sort_by_key(|candidate| candidate.need_id);
    let test_plans = store
        .lifecycle_start_test_plan_candidates(snapshot.source_digest)
        .map_err(LifecycleStartError::Store)?
        .into_iter()
        .map(|candidate| LifecycleStartTestPlanDto {
            artifact_id: candidate.artifact_id,
            plan_digest: candidate.binding.plan_digest(),
            certificate_digest: candidate.binding.certificate_digest,
            issued_unix_ms: candidate.issued_unix_ms,
        })
        .collect::<Vec<_>>();
    let mut blockers = Vec::new();
    for (role, code) in [
        (CodexRole::Explorer, "missing_explorer_profile"),
        (CodexRole::Implementer, "missing_implementer_profile"),
        (CodexRole::TestRunner, "missing_test_profile"),
        (CodexRole::Reviewer, "missing_reviewer_profile"),
        (CodexRole::Verifier, "missing_verifier_profile"),
    ] {
        if !active_profiles.iter().any(|profile| profile.definition.role == role) {
            blockers.push(code);
        }
    }
    if needs.is_empty() {
        blockers.push("missing_eligible_need");
    }
    if test_plans.is_empty() {
        blockers.push("missing_certified_test_plan");
    }
    Ok(LifecycleStartPreflightDto {
        schema: PREFLIGHT_SCHEMA,
        repository_id: snapshot.repository_id,
        source_snapshot: snapshot.source_digest,
        watcher_uncertain,
        eligible: blockers.is_empty(),
        blockers,
        profiles,
        needs,
        test_plans,
        max_selected_test_plans: needle_core::MAX_LIFECYCLE_TEST_PLANS,
        default_budget: LifecycleCreateBudgetDto {
            max_worker_turns: 10,
            max_output_tokens: 10_000,
            max_cost_microusd: 100_000,
            max_concurrent_workers: 1,
        },
    })
}

fn create(
    store: &RuntimeStore,
    repository_root: &std::path::Path,
    body: LifecycleCreateBody,
) -> Result<(bool, LifecycleCreateDto), LifecycleStartError> {
    validate_operation_id(&body.operation_id)?;
    let (_, snapshot) =
        capture_git_snapshot(repository_root).map_err(|_| LifecycleStartError::Snapshot)?;
    if snapshot.source_digest != body.expected_source_snapshot {
        return Err(LifecycleStartError::StaleSource);
    }
    let request = body
        .change
        .validate_and_map(0)
        .map_err(|_| LifecycleStartError::Invalid("change request is invalid"))?;
    let active_profiles =
        store.active_lifecycle_role_profiles().map_err(LifecycleStartError::Store)?;
    let profiles = LifecycleWorkerProfiles {
        explore: select_profile(&active_profiles, &body.profiles.explore, CodexRole::Explorer)?,
        implement: select_profile(
            &active_profiles,
            &body.profiles.implement,
            CodexRole::Implementer,
        )?,
        test: select_profile(&active_profiles, &body.profiles.test, CodexRole::TestRunner)?,
        review: select_profile(&active_profiles, &body.profiles.review, CodexRole::Reviewer)?,
        verify: select_profile(&active_profiles, &body.profiles.verify, CodexRole::Verifier)?,
    };
    let need = store
        .need_shadow(&body.need_id)
        .map_err(LifecycleStartError::Store)?
        .ok_or(LifecycleStartError::Missing("selected Need was not found"))?;
    if need.need.world.repository_lineage != snapshot.repository_id {
        return Err(LifecycleStartError::Conflict);
    }
    let route = need.need_ir.route_hint.clone().ok_or(LifecycleStartError::Conflict)?;
    let need_request = NeedRequest { key: route, body: need.need_ir.body.clone() };
    let fragment = need_fragment(&need.need, need.need.required.clone(), Vec::new());
    let action_plan = compile_lifecycle_explore_action_plan(
        &need_request,
        &need.need,
        &fragment,
        snapshot.repository_id,
        snapshot.source_digest,
    )
    .map_err(|_| LifecycleStartError::Conflict)?;
    let test_plans = select_test_plans(store, snapshot.source_digest, body.test_plan_certificates)?;
    let spec = LifecycleSpec {
        worker_depth_limit: 1,
        profiles,
        budget: LifecycleBudget {
            max_worker_turns: body.budget.max_worker_turns,
            max_output_tokens: body.budget.max_output_tokens,
            max_cost_microusd: body.budget.max_cost_microusd,
            max_concurrent_workers: 1,
        },
        explore_action_plan: Some(action_plan.clone()),
        action_phase_plans: Some(
            needle_platform_codex::CodexLifecycleActionAdapter::phase_plans()
                .map_err(|_| LifecycleStartError::Invalid("action phase plans are unavailable"))?,
        ),
        test_plans,
    };
    let change_id = lifecycle_change_id(snapshot.repository_id, &body.operation_id);
    let result = store
        .create_lifecycle_with_request(
            &change_id,
            snapshot.repository_id,
            snapshot.source_digest,
            &request,
            spec,
        )
        .map_err(map_create_store_error)?;
    let response =
        creation_dto(change_id, result.projection, action_plan.definition_digest, result.created);
    Ok((result.created, response))
}

fn select_profile(
    active: &[RoleProfileRevision],
    selected: &LifecycleCreateProfileRef,
    expected_role: CodexRole,
) -> Result<RoleProfileProvenance, LifecycleStartError> {
    let revision = active
        .iter()
        .find(|candidate| {
            candidate.profile_id == selected.profile_id
                && candidate.definition.definition_digest == selected.definition_digest
        })
        .ok_or(LifecycleStartError::Missing("selected active profile was not found"))?;
    if revision.state != RoleProfileState::Active || revision.definition.role != expected_role {
        return Err(LifecycleStartError::Conflict);
    }
    RoleProfileProvenance::from_revision(revision).map_err(|_| LifecycleStartError::Conflict)
}

fn select_test_plans(
    store: &RuntimeStore,
    source_snapshot: Digest,
    selected: Vec<Digest>,
) -> Result<Vec<LifecycleTestPlanBinding>, LifecycleStartError> {
    if selected.len() > needle_core::MAX_LIFECYCLE_TEST_PLANS {
        return Err(LifecycleStartError::Invalid(
            "test_plan_certificates must select a bounded set",
        ));
    }
    if selected.is_empty() {
        return Ok(Vec::new());
    }
    let selected_len = selected.len();
    let selected = selected.into_iter().collect::<BTreeSet<_>>();
    if selected.len() != selected_len {
        return Err(LifecycleStartError::Invalid(
            "test plan selection contains duplicate certificates",
        ));
    }
    let candidates = store
        .lifecycle_start_test_plan_candidates(source_snapshot)
        .map_err(LifecycleStartError::Store)?;
    let by_certificate = candidates
        .into_iter()
        .map(|candidate| (candidate.binding.certificate_digest, candidate.binding))
        .collect::<BTreeMap<_, _>>();
    let mut bindings = selected
        .into_iter()
        .map(|certificate| {
            by_certificate.get(&certificate).cloned().ok_or(LifecycleStartError::Missing(
                "selected certified TestPlan was not found for the current source",
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    bindings.sort_by_key(LifecycleTestPlanBinding::plan_digest);
    if bindings.windows(2).any(|pair| pair[0].plan_digest() == pair[1].plan_digest()) {
        return Err(LifecycleStartError::Invalid("test plan selection contains duplicates"));
    }
    Ok(bindings)
}

fn validate_operation_id(value: &str) -> Result<(), LifecycleStartError> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LifecycleStartError::Invalid(
            "operation_id must contain exactly 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn lifecycle_change_id(repository_id: Digest, operation_id: &str) -> ChangeId {
    let mut hasher = CanonicalHasher::new(b"needle-lifecycle-start-operation-v1");
    hasher.field_digest(repository_id);
    hasher.field_str(operation_id);
    ChangeId::from_digest(hasher.finish())
}

fn creation_dto(
    change_id: ChangeId,
    projection: LifecycleProjection,
    action_plan_definition_digest: Digest,
    created: bool,
) -> LifecycleCreateDto {
    let lifecycle = projection.lifecycle;
    LifecycleCreateDto {
        schema: CREATE_SCHEMA,
        created,
        change_id,
        lifecycle_id: lifecycle.id,
        phase: lifecycle.phase,
        status: lifecycle.status,
        generation: lifecycle.generation,
        state_digest: projection.state_digest,
        source_snapshot: lifecycle.source_snapshot,
        action_plan_definition_digest,
    }
}

fn map_create_store_error(error: StoreError) -> LifecycleStartError {
    match error {
        StoreError::ChangeConflict(_)
        | StoreError::LifecycleConflict(_)
        | StoreError::RoleProfileConflict(_)
        | StoreError::RoleProfileNotFound(_) => LifecycleStartError::Conflict,
        other => LifecycleStartError::Store(other),
    }
}

impl LifecycleStartError {
    fn into_response(self) -> Response {
        match self {
            Self::Invalid(message) => {
                lifecycle_start_error(StatusCode::BAD_REQUEST, "invalid_lifecycle_start", message)
            }
            Self::StaleSource => lifecycle_start_error(
                StatusCode::PRECONDITION_FAILED,
                "stale_source",
                "repository source changed after preflight",
            ),
            Self::Missing(message) => {
                lifecycle_start_error(StatusCode::CONFLICT, "lifecycle_start_missing", message)
            }
            Self::Conflict => lifecycle_start_error(
                StatusCode::CONFLICT,
                "lifecycle_start_conflict",
                "lifecycle start inputs no longer match current validated state",
            ),
            Self::Store(error) => {
                drop(error);
                lifecycle_start_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "lifecycle_start_unavailable",
                    "lifecycle start is unavailable",
                )
            }
            Self::Snapshot => lifecycle_start_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "lifecycle_start_unavailable",
                "lifecycle start is unavailable",
            ),
        }
    }
}

fn lifecycle_start_error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> Response {
    (status, Json(LifecycleStartErrorDto { schema: ERROR_SCHEMA, code, message })).into_response()
}
