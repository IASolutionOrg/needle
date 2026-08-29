use axum::extract::DefaultBodyLimit;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use needle_core::{
    AcceptanceStatus, ApprovalDecisionSource, ArtifactId, ChangeApplyStatus, ChangeId, Digest,
    LifecycleArtifactKind, LifecycleEvent, LifecycleEventKind, LifecycleId, LifecyclePhase,
    LifecycleReason, LifecycleReviewVerdict, LifecycleStatus, LifecycleTerminalOutcome,
    VerificationStatus,
};
use needle_runtime::{
    LifecycleAdapterInvocationRecord, LifecycleAdapterInvocationState,
    LifecycleAdapterRecoveryRecord, LifecycleAdapterRecoverySource, LifecycleExecutionDisposition,
    LifecycleExploreShadowObservationPersistence, LifecycleExploreShadowObservationRecord,
    LifecycleExploreShadowResolutionKind, LifecycleProjection, LifecycleSummaryRecord,
    MAX_LIFECYCLE_EXPLORE_OBSERVATION_LIST_LIMIT, MAX_LIFECYCLE_LIST_LIMIT,
    ShadowActionResolutionAuthority, ShadowActionResolutionKind, StoreError,
    lifecycle_adapter_invocation_id,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::AppState;

const LIST_SCHEMA: &str = "needle.lifecycle-list/1";
const DETAIL_SCHEMA: &str = "needle.lifecycle-detail/1";
const EVENTS_SCHEMA: &str = "needle.lifecycle-events/1";
const ACTION_OBSERVATIONS_SCHEMA: &str = "needle.lifecycle-action-observations/1";
const STEP_SCHEMA: &str = "needle.lifecycle-step/1";
const ADAPTER_INVOCATION_SCHEMA: &str = "needle.lifecycle-adapter-invocation/1";
const ADAPTER_RECOVERY_SCHEMA: &str = "needle.lifecycle-adapter-recovery/1";
const ERROR_SCHEMA: &str = "needle.lifecycle-error/1";
const DEFAULT_LIMIT: usize = 50;
const MAX_STEP_BODY_BYTES: usize = 4 * 1024;
const MAX_ADAPTER_RECOVERY_BODY_BYTES: usize = 4 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleStepBody {
    expected_state_digest: Digest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleAdapterRecoveryBody {
    invocation_id: Digest,
    expected_state_digest: Digest,
    confirm_provider_stopped: bool,
}

#[derive(Debug, Serialize)]
struct LifecycleApiError {
    schema: &'static str,
    code: &'static str,
    message: &'static str,
}

#[derive(Clone, Copy, Debug)]
struct LifecycleRejection {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

enum PrepareLifecycleStepError {
    Store(StoreError),
    Rejection(LifecycleRejection),
}

impl PrepareLifecycleStepError {
    fn into_response(self) -> Response {
        match self {
            Self::Store(error) => store_error(error),
            Self::Rejection(rejection) => rejection.into_response(),
        }
    }
}

impl LifecycleRejection {
    fn into_response(self) -> Response {
        lifecycle_error(self.status, self.code, self.message)
    }
}

#[derive(Debug, Serialize)]
struct LifecycleUsageDto {
    worker_turns: u32,
    output_tokens: u64,
    cost_microusd: u64,
}

#[derive(Debug, Serialize)]
struct LifecycleReasonDto {
    code: String,
    detail_digest: Digest,
}

#[derive(Debug, Serialize)]
struct LifecycleSummaryDto {
    lifecycle_id: LifecycleId,
    change_id: ChangeId,
    source_snapshot: Digest,
    phase: LifecyclePhase,
    status: LifecycleStatus,
    state_digest: Digest,
    generation: u64,
    usage: LifecycleUsageDto,
    terminal_outcome: Option<LifecycleTerminalOutcome>,
    terminal_reason: Option<LifecycleReasonDto>,
    created_unix_ms: u64,
    updated_unix_ms: u64,
}

#[derive(Debug, Serialize)]
struct LifecycleBudgetDto {
    max_worker_turns: u32,
    max_output_tokens: u64,
    max_cost_microusd: u64,
    max_concurrent_workers: u8,
}

#[derive(Debug, Serialize)]
struct LifecycleProfileIdentityDto {
    phase: LifecyclePhase,
    profile_id: needle_core::RoleProfileId,
    revision: u64,
    definition_digest: Digest,
}

#[derive(Debug, Serialize)]
struct LifecycleTestPlanIdentityDto {
    plan_digest: Digest,
    certificate_digest: Digest,
}

#[derive(Debug, Serialize)]
struct LifecycleExplorationArtifactDto {
    kind: LifecycleArtifactKind,
    artifact_id: Digest,
    source_snapshot: Digest,
}

#[derive(Debug, Serialize)]
struct LifecyclePatchDto {
    patch_id: needle_core::PatchId,
    revision: u32,
}

#[derive(Debug, Serialize)]
struct LifecycleTestResultDto {
    plan_digest: Digest,
    certificate_digest: Digest,
    available: bool,
    executed: bool,
    passed: bool,
    evidence_id: Option<String>,
    action_evidence_artifact: Option<ArtifactId>,
    failure_code: Option<String>,
}

#[derive(Debug, Serialize)]
struct LifecycleAcceptanceReviewDto {
    criterion_digest: Digest,
    status: AcceptanceStatus,
    evidence_digest: Digest,
}

#[derive(Debug, Serialize)]
struct LifecycleReviewDto {
    review_id: Digest,
    patch_id: needle_core::PatchId,
    verdict: LifecycleReviewVerdict,
    acceptance_coverage: Vec<LifecycleAcceptanceReviewDto>,
    findings: Vec<LifecycleReasonDto>,
    reviewer_definition: Digest,
    created_unix_ms: u64,
}

#[derive(Debug, Serialize)]
struct LifecycleVerificationDto {
    verification_id: needle_core::VerificationArtifactId,
    patch_id: needle_core::PatchId,
    verdict: VerificationStatus,
}

#[derive(Debug, Serialize)]
struct LifecycleApprovalDto {
    approval_id: Digest,
    approved_state_digest: Digest,
    patch_id: needle_core::PatchId,
    verification_id: needle_core::VerificationArtifactId,
    decision_source: ApprovalDecisionSource,
    decided_unix_ms: u64,
}

#[derive(Debug, Serialize)]
struct LifecycleRecoveryDto {
    apply_id: needle_core::ChangeApplyId,
    patch_id: needle_core::PatchId,
    status: ChangeApplyStatus,
    pre_snapshot: Digest,
    post_snapshot: Option<Digest>,
    created_unix_ms: u64,
    completed_unix_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct LifecycleCleanupDto {
    status: &'static str,
    reason: LifecycleReasonDto,
}

#[derive(Debug, Serialize)]
struct LifecycleArtifactsDto {
    exploration: Vec<LifecycleExplorationArtifactDto>,
    patch: Option<LifecyclePatchDto>,
    tests: Vec<LifecycleTestResultDto>,
    review: Option<LifecycleReviewDto>,
    verification: Option<LifecycleVerificationDto>,
}

#[derive(Debug, Serialize)]
struct LifecycleDetailDto {
    lifecycle_id: LifecycleId,
    change_id: ChangeId,
    source_snapshot: Digest,
    phase: LifecyclePhase,
    status: LifecycleStatus,
    state_digest: Digest,
    generation: u64,
    worker_depth_limit: u8,
    profiles: Vec<LifecycleProfileIdentityDto>,
    test_plans: Vec<LifecycleTestPlanIdentityDto>,
    budget: LifecycleBudgetDto,
    usage: LifecycleUsageDto,
    artifacts: LifecycleArtifactsDto,
    explore_reuse: Option<needle_core::LifecycleExploreReuseCompletion>,
    repair_reserved: bool,
    repair_consumed: bool,
    terminal_outcome: Option<LifecycleTerminalOutcome>,
    terminal_reason: Option<LifecycleReasonDto>,
    approval: Option<LifecycleApprovalDto>,
    apply_id: Option<needle_core::ChangeApplyId>,
    cleanup: Option<LifecycleCleanupDto>,
    recovery: Option<LifecycleRecoveryDto>,
    created_unix_ms: u64,
    updated_unix_ms: u64,
}

#[derive(Debug, Serialize)]
struct LifecycleEventActionDto {
    kind: &'static str,
    reason: Option<LifecycleReasonDto>,
    apply_status: Option<ChangeApplyStatus>,
}

#[derive(Debug, Serialize)]
struct LifecycleEventDto {
    lifecycle_id: LifecycleId,
    change_id: ChangeId,
    sequence: u64,
    phase: LifecyclePhase,
    status: LifecycleStatus,
    source_snapshot: Digest,
    profile_definition_digest: Option<Digest>,
    patch_id: Option<needle_core::PatchId>,
    verification_id: Option<needle_core::VerificationArtifactId>,
    prior_state_digest: Option<Digest>,
    resulting_state_digest: Digest,
    action: LifecycleEventActionDto,
    created_unix_ms: u64,
}

#[derive(Debug, Serialize)]
struct LifecycleActionResolutionDto {
    request: Digest,
    action_contract: needle_core::ActionContractId,
    predicate: needle_core::PredicateKind,
    resolution: ShadowActionResolutionKind,
    artifacts: Vec<Digest>,
    validation_certificates: Vec<Digest>,
    selected_plan: Digest,
    sufficiency_certificate: Option<Digest>,
    covered_mask: u16,
    missing_mask: u16,
    definition_digest: Digest,
}

#[derive(Debug, Serialize)]
struct LifecycleActionObservationDto {
    observation_digest: Digest,
    lifecycle_id: LifecycleId,
    expected_state_digest: Digest,
    plan_definition_digest: Digest,
    planned_action_count: u16,
    resolution: needle_runtime::LifecycleExploreShadowResolutionKind,
    actions: Vec<LifecycleActionResolutionDto>,
    authority: ShadowActionResolutionAuthority,
    adapter_invocation_required: bool,
    recorded_unix_ms: u64,
}

#[derive(Debug, Serialize)]
struct LifecycleStepObservationDto {
    observation_digest: Digest,
    resolution: LifecycleExploreShadowResolutionKind,
    planned_action_count: u16,
    authority: ShadowActionResolutionAuthority,
    adapter_invocation_required: bool,
}

#[derive(Debug, Serialize)]
struct LifecycleStepDto {
    schema: &'static str,
    change_id: ChangeId,
    disposition: LifecycleExecutionDisposition,
    phase: LifecyclePhase,
    status: LifecycleStatus,
    generation: u64,
    state_digest: Digest,
    invocation_id: Option<Digest>,
    adapter_usage: needle_core::LifecycleUsage,
    observation: Option<LifecycleStepObservationDto>,
    observation_persistence: Option<LifecycleExploreShadowObservationPersistence>,
    reuse: Option<needle_runtime::LifecycleExploreReuseOutcome>,
}

#[derive(Debug, Serialize)]
struct LifecycleAdapterRecoveryRecordDto {
    recovery_digest: Digest,
    source: &'static str,
    recovered_unix_ms: u64,
}

#[derive(Debug, Serialize)]
struct LifecycleAdapterInvocationDto {
    invocation_id: Digest,
    lifecycle_id: LifecycleId,
    expected_state_digest: Digest,
    phase: LifecyclePhase,
    status: &'static str,
    request_digest: Digest,
    adapter_definition_digest: Digest,
    started_unix_ms: u64,
    completed_unix_ms: Option<u64>,
    recovery: Option<LifecycleAdapterRecoveryRecordDto>,
}

#[derive(Debug, Serialize)]
struct LifecycleAdapterInvocationResponseDto {
    schema: &'static str,
    change_id: ChangeId,
    invocation: Option<LifecycleAdapterInvocationDto>,
}

#[derive(Debug, Serialize)]
struct LifecycleAdapterRecoveryResponseDto {
    schema: &'static str,
    created: bool,
    change_id: ChangeId,
    lifecycle: LifecycleSummaryDto,
    invocation: LifecycleAdapterInvocationDto,
}

pub(super) fn routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route(
            "/api/v1/lifecycles",
            get(list_lifecycles)
                .post(super::lifecycle_start::create_lifecycle)
                .layer(DefaultBodyLimit::max(super::lifecycle_start::MAX_CREATE_BODY_BYTES)),
        )
        .route(
            "/api/v1/lifecycles/preflight",
            get(super::lifecycle_start::preflight_lifecycle_start),
        )
        .route("/api/v1/lifecycles/{id}", get(get_lifecycle))
        .route("/api/v1/lifecycles/{id}/events", get(get_lifecycle_events))
        .route(
            "/api/v1/lifecycles/{id}/action-observations",
            get(get_lifecycle_action_observations),
        )
        .route(
            "/api/v1/lifecycles/{id}/step",
            post(step_lifecycle).layer(DefaultBodyLimit::max(MAX_STEP_BODY_BYTES)),
        )
        .route(
            "/api/v1/lifecycles/{id}/apply",
            post(super::lifecycle_apply::apply_lifecycle)
                .layer(DefaultBodyLimit::max(super::lifecycle_apply::MAX_APPLY_BODY_BYTES)),
        )
        .route("/api/v1/lifecycles/{id}/adapter-invocation", get(get_lifecycle_adapter_invocation))
        .route(
            "/api/v1/lifecycles/{id}/adapter-invocation/recover",
            post(recover_lifecycle_adapter_invocation)
                .layer(DefaultBodyLimit::max(MAX_ADAPTER_RECOVERY_BODY_BYTES)),
        )
}

async fn list_lifecycles(
    State(state): State<AppState>,
    query: Result<Query<LimitQuery>, QueryRejection>,
) -> Response {
    let limit = match query {
        Ok(Query(query)) => match bounded_limit(query.limit) {
            Ok(limit) => limit,
            Err(rejection) => return rejection.into_response(),
        },
        Err(_) => {
            return lifecycle_error(StatusCode::BAD_REQUEST, "invalid_query", "query is invalid");
        }
    };
    match state.store.list_lifecycle_summaries(limit) {
        Ok(records) => {
            let items = records.into_iter().map(summary_dto).collect::<Vec<_>>();
            Json(json!({"schema": LIST_SCHEMA, "items": items, "limit": limit})).into_response()
        }
        Err(error) => store_error(error),
    }
}

async fn get_lifecycle(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let change_id = match parse_change_id(&id) {
        Ok(change_id) => change_id,
        Err(rejection) => return rejection.into_response(),
    };
    let projection = match state.store.replay_lifecycle(&change_id) {
        Ok(projection) => projection,
        Err(error) => return store_error(error),
    };
    let recovery = match state.store.latest_change_apply(&change_id) {
        Ok(record) => record.as_ref().map(recovery_dto),
        Err(error) => return store_error(error),
    };
    Json(json!({
        "schema": DETAIL_SCHEMA,
        "lifecycle": detail_dto(projection, recovery),
    }))
    .into_response()
}

async fn get_lifecycle_events(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let change_id = match parse_change_id(&id) {
        Ok(change_id) => change_id,
        Err(rejection) => return rejection.into_response(),
    };
    match state.store.replay_lifecycle_events(&change_id) {
        Ok(events) => {
            let items = events.iter().map(event_dto).collect::<Vec<_>>();
            Json(json!({
                "schema": EVENTS_SCHEMA,
                "change_id": change_id,
                "items": items,
                "limit": needle_core::MAX_LIFECYCLE_EVENTS,
            }))
            .into_response()
        }
        Err(error) => store_error(error),
    }
}

async fn get_lifecycle_action_observations(
    State(state): State<AppState>,
    Path(id): Path<String>,
    query: Result<Query<LimitQuery>, QueryRejection>,
) -> Response {
    let change_id = match parse_change_id(&id) {
        Ok(change_id) => change_id,
        Err(rejection) => return rejection.into_response(),
    };
    let limit = match query {
        Ok(Query(query)) => match bounded_action_observation_limit(query.limit) {
            Ok(limit) => limit,
            Err(rejection) => return rejection.into_response(),
        },
        Err(_) => {
            return lifecycle_error(StatusCode::BAD_REQUEST, "invalid_query", "query is invalid");
        }
    };
    let projection = match state.store.replay_lifecycle(&change_id) {
        Ok(projection) => projection,
        Err(error) => return store_error(error),
    };
    match state.store.list_lifecycle_explore_action_observations(projection.lifecycle.id, limit) {
        Ok(records) => {
            let items = records.into_iter().map(action_observation_dto).collect::<Vec<_>>();
            Json(json!({
                "schema": ACTION_OBSERVATIONS_SCHEMA,
                "change_id": change_id,
                "items": items,
                "limit": limit,
            }))
            .into_response()
        }
        Err(error) => store_error(error),
    }
}

async fn get_lifecycle_adapter_invocation(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    let change_id = match parse_change_id(&id) {
        Ok(change_id) => change_id,
        Err(rejection) => return rejection.into_response(),
    };
    let projection = match state.store.replay_lifecycle(&change_id) {
        Ok(projection) => projection,
        Err(error) => return store_error(error),
    };
    let invocation = match state.store.latest_lifecycle_adapter_invocation(projection.lifecycle.id)
    {
        Ok(invocation) => invocation.map(adapter_invocation_dto),
        Err(error) => return store_error(error),
    };
    Json(LifecycleAdapterInvocationResponseDto {
        schema: ADAPTER_INVOCATION_SCHEMA,
        change_id,
        invocation,
    })
    .into_response()
}

async fn recover_lifecycle_adapter_invocation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Result<Json<LifecycleAdapterRecoveryBody>, JsonRejection>,
) -> Response {
    let change_id = match parse_change_id(&id) {
        Ok(change_id) => change_id,
        Err(rejection) => return rejection.into_response(),
    };
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => {
            return lifecycle_error(
                StatusCode::BAD_REQUEST,
                "invalid_body",
                "request body is invalid",
            );
        }
    };
    if !body.confirm_provider_stopped {
        return lifecycle_error(
            StatusCode::BAD_REQUEST,
            "confirmation_required",
            "recovery requires confirmation that the provider invocation has stopped",
        );
    }
    let guard = match state.lifecycle_step_lock.clone().try_lock_owned() {
        Ok(guard) => guard,
        Err(_) => {
            return lifecycle_error(
                StatusCode::CONFLICT,
                "lifecycle_step_busy",
                "another lifecycle step is currently executing",
            );
        }
    };
    let store = state.store.clone();
    let change_id_for_recovery = change_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        let recovered = store.abort_lifecycle_adapter_invocation(
            &change_id_for_recovery,
            body.expected_state_digest,
            body.invocation_id,
            LifecycleAdapterRecoverySource::WebUser,
        )?;
        let invocation = store
            .latest_lifecycle_adapter_invocation(recovered.projection.lifecycle.id)?
            .ok_or_else(|| {
                StoreError::LifecycleAdapterInvocationCorruption(
                    "recovered invocation is unavailable".to_owned(),
                )
            })?;
        Ok::<_, StoreError>((recovered, invocation))
    })
    .await;
    let (recovered, invocation) = match result {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => return store_error(error),
        Err(_) => {
            return lifecycle_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "adapter_recovery_join_failed",
                "lifecycle adapter recovery task failed",
            );
        }
    };
    let status = if recovered.created { StatusCode::CREATED } else { StatusCode::OK };
    (
        status,
        Json(LifecycleAdapterRecoveryResponseDto {
            schema: ADAPTER_RECOVERY_SCHEMA,
            created: recovered.created,
            change_id,
            lifecycle: projection_summary_dto(&recovered.projection),
            invocation: adapter_invocation_dto(invocation),
        }),
    )
        .into_response()
}

async fn step_lifecycle(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Result<Json<LifecycleStepBody>, JsonRejection>,
) -> Response {
    let change_id = match parse_change_id(&id) {
        Ok(change_id) => change_id,
        Err(rejection) => return rejection.into_response(),
    };
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => {
            return lifecycle_error(
                StatusCode::BAD_REQUEST,
                "invalid_body",
                "request body is invalid",
            );
        }
    };
    let projection = match prepare_lifecycle_step(&state, &change_id, body.expected_state_digest) {
        Ok(projection) => projection,
        Err(error) => return error.into_response(),
    };
    let invocation_id = lifecycle_adapter_invocation_id(&projection);
    match state.store.lifecycle_adapter_invocation_state(invocation_id) {
        Ok(Some(LifecycleAdapterInvocationState::InProgress { .. })) => {
            return lifecycle_error(
                StatusCode::CONFLICT,
                "adapter_in_progress",
                "the lifecycle adapter invocation is already in progress",
            );
        }
        Ok(Some(LifecycleAdapterInvocationState::Aborted { .. })) => {
            return lifecycle_error(
                StatusCode::CONFLICT,
                "adapter_aborted",
                "the lifecycle adapter invocation was explicitly aborted",
            );
        }
        Ok(Some(LifecycleAdapterInvocationState::Completed { .. })) | Ok(None) => {}
        Err(error) => return store_error(error),
    }
    let guard = match state.lifecycle_step_lock.clone().try_lock_owned() {
        Ok(guard) => guard,
        Err(_) => {
            return lifecycle_error(
                StatusCode::CONFLICT,
                "lifecycle_step_busy",
                "another lifecycle step is currently executing",
            );
        }
    };
    if let Err(error) = prepare_lifecycle_step(&state, &change_id, body.expected_state_digest) {
        return error.into_response();
    }
    let host = state.lifecycle_step_host.clone();
    let change_id_for_host = change_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        host.step(&change_id_for_host)
    })
    .await;
    let outcome = match result {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(_)) => {
            return lifecycle_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "lifecycle_execution_failed",
                "lifecycle execution failed",
            );
        }
        Err(_) => {
            return lifecycle_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "lifecycle_execution_join_failed",
                "lifecycle execution task failed",
            );
        }
    };
    let lifecycle = outcome.projection.lifecycle;
    let observation =
        outcome.explore_action_observation.map(|observation| LifecycleStepObservationDto {
            observation_digest: observation.definition_digest,
            resolution: observation.resolution,
            planned_action_count: observation.planned_action_count,
            authority: observation.authority,
            adapter_invocation_required: observation.adapter_invocation_required,
        });
    Json(LifecycleStepDto {
        schema: STEP_SCHEMA,
        change_id,
        disposition: outcome.disposition,
        phase: lifecycle.phase,
        status: lifecycle.status,
        generation: lifecycle.generation,
        state_digest: outcome.projection.state_digest,
        invocation_id: outcome.invocation_id,
        adapter_usage: outcome.adapter_usage,
        observation,
        observation_persistence: outcome.explore_action_observation_persistence,
        reuse: outcome.explore_reuse,
    })
    .into_response()
}

fn prepare_lifecycle_step(
    state: &AppState,
    change_id: &ChangeId,
    expected_state_digest: Digest,
) -> Result<LifecycleProjection, PrepareLifecycleStepError> {
    let projection =
        state.store.replay_lifecycle(change_id).map_err(PrepareLifecycleStepError::Store)?;
    if projection.state_digest != expected_state_digest {
        return Err(PrepareLifecycleStepError::Rejection(LifecycleRejection {
            status: StatusCode::PRECONDITION_FAILED,
            code: "stale_state",
            message: "lifecycle state changed",
        }));
    }
    let planned = match projection.lifecycle.phase {
        LifecyclePhase::Explore => projection.lifecycle.spec.explore_action_plan.is_some(),
        LifecyclePhase::Implement
        | LifecyclePhase::Test
        | LifecyclePhase::Review
        | LifecyclePhase::Verify => projection
            .lifecycle
            .spec
            .action_phase_plans
            .as_ref()
            .and_then(|plans| plans.for_phase(projection.lifecycle.phase))
            .is_some(),
        LifecyclePhase::Apply => false,
    };
    let runnable_status = matches!(
        projection.lifecycle.status,
        LifecycleStatus::Active | LifecycleStatus::RepairReserved
    );
    if !planned || !runnable_status {
        return Err(PrepareLifecycleStepError::Rejection(LifecycleRejection {
            status: StatusCode::CONFLICT,
            code: "lifecycle_step_unavailable",
            message: "lifecycle is not in a runnable planned phase",
        }));
    }
    Ok(projection)
}

fn bounded_limit(limit: Option<usize>) -> Result<usize, LifecycleRejection> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 || limit > MAX_LIFECYCLE_LIST_LIMIT {
        return Err(LifecycleRejection {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_limit",
            message: "limit must be between 1 and 100",
        });
    }
    Ok(limit)
}

fn bounded_action_observation_limit(limit: Option<usize>) -> Result<usize, LifecycleRejection> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 || limit > MAX_LIFECYCLE_EXPLORE_OBSERVATION_LIST_LIMIT {
        return Err(LifecycleRejection {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_limit",
            message: "limit must be between 1 and 100",
        });
    }
    Ok(limit)
}

fn parse_change_id(id: &str) -> Result<ChangeId, LifecycleRejection> {
    ChangeId::parse(id).map_err(|_| LifecycleRejection {
        status: StatusCode::BAD_REQUEST,
        code: "invalid_change_id",
        message: "change ID is invalid",
    })
}

fn summary_dto(record: LifecycleSummaryRecord) -> LifecycleSummaryDto {
    LifecycleSummaryDto {
        lifecycle_id: record.lifecycle_id,
        change_id: record.change_id,
        source_snapshot: record.source_snapshot,
        phase: record.phase,
        status: record.status,
        state_digest: record.state_digest,
        generation: record.generation,
        usage: usage_dto(&record.usage),
        terminal_outcome: record.terminal_outcome,
        terminal_reason: record.terminal_reason.as_ref().map(reason_dto),
        created_unix_ms: record.created_unix_ms,
        updated_unix_ms: record.updated_unix_ms,
    }
}

fn projection_summary_dto(projection: &LifecycleProjection) -> LifecycleSummaryDto {
    let lifecycle = &projection.lifecycle;
    LifecycleSummaryDto {
        lifecycle_id: lifecycle.id,
        change_id: lifecycle.change_id.clone(),
        source_snapshot: lifecycle.source_snapshot,
        phase: lifecycle.phase,
        status: lifecycle.status,
        state_digest: projection.state_digest,
        generation: lifecycle.generation,
        usage: usage_dto(&lifecycle.usage),
        terminal_outcome: lifecycle.terminal_outcome,
        terminal_reason: lifecycle.terminal_reason.as_ref().map(reason_dto),
        created_unix_ms: lifecycle.created_unix_ms,
        updated_unix_ms: lifecycle.updated_unix_ms,
    }
}

fn adapter_invocation_dto(
    record: LifecycleAdapterInvocationRecord,
) -> LifecycleAdapterInvocationDto {
    let (
        status,
        request_digest,
        adapter_definition_digest,
        started_unix_ms,
        completed_unix_ms,
        recovery,
    ) = match record.state {
        LifecycleAdapterInvocationState::InProgress {
            request_digest,
            adapter_definition_digest,
            started_unix_ms,
        } => {
            ("in_progress", request_digest, adapter_definition_digest, started_unix_ms, None, None)
        }
        LifecycleAdapterInvocationState::Completed {
            request_digest,
            adapter_definition_digest,
            started_unix_ms,
            completed_unix_ms,
            ..
        } => (
            "completed",
            request_digest,
            adapter_definition_digest,
            started_unix_ms,
            Some(completed_unix_ms),
            None,
        ),
        LifecycleAdapterInvocationState::Aborted {
            request_digest,
            adapter_definition_digest,
            started_unix_ms,
            recovery,
        } => (
            "aborted",
            request_digest,
            adapter_definition_digest,
            started_unix_ms,
            None,
            Some(adapter_recovery_record_dto(&recovery)),
        ),
    };
    LifecycleAdapterInvocationDto {
        invocation_id: record.invocation_id,
        lifecycle_id: record.lifecycle_id,
        expected_state_digest: record.expected_state_digest,
        phase: record.phase,
        status,
        request_digest,
        adapter_definition_digest,
        started_unix_ms,
        completed_unix_ms,
        recovery,
    }
}

fn adapter_recovery_record_dto(
    recovery: &LifecycleAdapterRecoveryRecord,
) -> LifecycleAdapterRecoveryRecordDto {
    LifecycleAdapterRecoveryRecordDto {
        recovery_digest: recovery.recovery_digest,
        source: recovery.source.as_str(),
        recovered_unix_ms: recovery.recovered_unix_ms,
    }
}

fn action_observation_dto(
    record: LifecycleExploreShadowObservationRecord,
) -> LifecycleActionObservationDto {
    let observation = record.observation;
    let actions = observation
        .actions
        .into_iter()
        .map(|action| LifecycleActionResolutionDto {
            request: action.request.digest(),
            action_contract: action.action_contract,
            predicate: action.predicate,
            resolution: action.resolution,
            artifacts: action.artifacts.into_iter().map(|artifact| artifact.digest()).collect(),
            validation_certificates: action
                .validation_certificates
                .into_iter()
                .map(|certificate| certificate.digest())
                .collect(),
            selected_plan: action.selected_plan.0,
            sufficiency_certificate: action
                .sufficiency_certificate
                .map(|certificate| certificate.0),
            covered_mask: action.covered_mask,
            missing_mask: action.missing_mask,
            definition_digest: action.definition_digest,
        })
        .collect();
    LifecycleActionObservationDto {
        observation_digest: observation.definition_digest,
        lifecycle_id: observation.lifecycle,
        expected_state_digest: observation.expected_state_digest,
        plan_definition_digest: observation.plan_definition_digest,
        planned_action_count: observation.planned_action_count,
        resolution: observation.resolution,
        actions,
        authority: observation.authority,
        adapter_invocation_required: observation.adapter_invocation_required,
        recorded_unix_ms: record.recorded_unix_ms,
    }
}

fn detail_dto(
    projection: LifecycleProjection,
    recovery: Option<LifecycleRecoveryDto>,
) -> LifecycleDetailDto {
    let lifecycle = projection.lifecycle;
    let profiles = LifecyclePhase::ALL
        .into_iter()
        .take(5)
        .map(|phase| {
            let profile = lifecycle
                .spec
                .profiles
                .for_phase(phase)
                .expect("validated worker phases have frozen profiles");
            LifecycleProfileIdentityDto {
                phase,
                profile_id: profile.profile_id.clone(),
                revision: profile.revision,
                definition_digest: profile.definition_digest,
            }
        })
        .collect();
    let test_plans = lifecycle
        .spec
        .test_plans
        .iter()
        .map(|binding| LifecycleTestPlanIdentityDto {
            plan_digest: binding.plan_digest(),
            certificate_digest: binding.certificate_digest,
        })
        .collect();
    let artifacts = LifecycleArtifactsDto {
        exploration: lifecycle
            .exploration_artifacts
            .iter()
            .map(|artifact| LifecycleExplorationArtifactDto {
                kind: artifact.kind,
                artifact_id: artifact.id,
                source_snapshot: artifact.source_snapshot,
            })
            .collect(),
        patch: lifecycle
            .patch
            .as_ref()
            .map(|patch| LifecyclePatchDto { patch_id: patch.patch_id, revision: patch.revision }),
        tests: lifecycle
            .test_results
            .iter()
            .map(|result| LifecycleTestResultDto {
                plan_digest: result.plan_digest,
                certificate_digest: result.certificate_digest,
                available: result.available,
                executed: result.executed,
                passed: result.passed,
                evidence_id: result.evidence_id.clone(),
                action_evidence_artifact: result.action_evidence_artifact,
                failure_code: result.failure_code.clone(),
            })
            .collect(),
        review: lifecycle.review.as_ref().map(|review| LifecycleReviewDto {
            review_id: review.id,
            patch_id: review.patch_id,
            verdict: review.verdict,
            acceptance_coverage: review
                .acceptance_coverage
                .iter()
                .map(|coverage| LifecycleAcceptanceReviewDto {
                    criterion_digest: coverage.criterion_digest,
                    status: coverage.status,
                    evidence_digest: coverage.evidence_digest,
                })
                .collect(),
            findings: review.findings.iter().map(reason_dto).collect(),
            reviewer_definition: review.reviewer_definition,
            created_unix_ms: review.created_unix_ms,
        }),
        verification: lifecycle.verification.as_ref().map(|verification| {
            LifecycleVerificationDto {
                verification_id: verification.verification_id,
                patch_id: verification.patch_id,
                verdict: verification.verdict,
            }
        }),
    };
    let cleanup = lifecycle.terminal_reason.as_ref().and_then(|reason| {
        (reason.code == "adapter_cleanup_failed")
            .then(|| LifecycleCleanupDto { status: "failed", reason: reason_dto(reason) })
    });
    LifecycleDetailDto {
        lifecycle_id: lifecycle.id,
        change_id: lifecycle.change_id,
        source_snapshot: lifecycle.source_snapshot,
        phase: lifecycle.phase,
        status: lifecycle.status,
        state_digest: projection.state_digest,
        generation: lifecycle.generation,
        worker_depth_limit: lifecycle.spec.worker_depth_limit,
        profiles,
        test_plans,
        budget: LifecycleBudgetDto {
            max_worker_turns: lifecycle.spec.budget.max_worker_turns,
            max_output_tokens: lifecycle.spec.budget.max_output_tokens,
            max_cost_microusd: lifecycle.spec.budget.max_cost_microusd,
            max_concurrent_workers: lifecycle.spec.budget.max_concurrent_workers,
        },
        usage: usage_dto(&lifecycle.usage),
        artifacts,
        explore_reuse: lifecycle.explore_reuse,
        repair_reserved: lifecycle.repair_reserved,
        repair_consumed: lifecycle.repair_consumed,
        terminal_outcome: lifecycle.terminal_outcome,
        terminal_reason: lifecycle.terminal_reason.as_ref().map(reason_dto),
        approval: lifecycle.approval.as_ref().map(|approval| LifecycleApprovalDto {
            approval_id: approval.id,
            approved_state_digest: approval.approved_state_digest,
            patch_id: approval.patch_id,
            verification_id: approval.verification_id,
            decision_source: approval.decision_source,
            decided_unix_ms: approval.decided_unix_ms,
        }),
        apply_id: lifecycle.apply_id,
        cleanup,
        recovery,
        created_unix_ms: lifecycle.created_unix_ms,
        updated_unix_ms: lifecycle.updated_unix_ms,
    }
}

fn recovery_dto(record: &needle_core::ChangeApplyRecord) -> LifecycleRecoveryDto {
    LifecycleRecoveryDto {
        apply_id: record.id,
        patch_id: record.patch_id,
        status: record.status,
        pre_snapshot: record.pre_snapshot,
        post_snapshot: record.post_snapshot,
        created_unix_ms: record.created_unix_ms,
        completed_unix_ms: record.completed_unix_ms,
    }
}

fn usage_dto(usage: &needle_core::LifecycleUsage) -> LifecycleUsageDto {
    LifecycleUsageDto {
        worker_turns: usage.worker_turns,
        output_tokens: usage.output_tokens,
        cost_microusd: usage.cost_microusd,
    }
}

fn reason_dto(reason: &LifecycleReason) -> LifecycleReasonDto {
    LifecycleReasonDto { code: reason.code.clone(), detail_digest: reason.detail_digest }
}

fn event_dto(event: &LifecycleEvent) -> LifecycleEventDto {
    LifecycleEventDto {
        lifecycle_id: event.lifecycle_id,
        change_id: event.change_id.clone(),
        sequence: event.sequence,
        phase: event.phase,
        status: event.status,
        source_snapshot: event.source_snapshot,
        profile_definition_digest: event.profile_revision_digest,
        patch_id: event.patch_id,
        verification_id: event.verification_id,
        prior_state_digest: event.prior_state_digest,
        resulting_state_digest: event.resulting_state_digest,
        action: event_action_dto(&event.kind),
        created_unix_ms: event.created_unix_ms,
    }
}

fn event_action_dto(kind: &LifecycleEventKind) -> LifecycleEventActionDto {
    let (kind, reason, apply_status) = match kind {
        LifecycleEventKind::Created { .. } => ("created", None, None),
        LifecycleEventKind::Transitioned { transition } => match transition.as_ref() {
            needle_core::LifecycleTransition::CompleteExplore { .. } => {
                ("complete_explore", None, None)
            }
            needle_core::LifecycleTransition::CompleteExploreFromReuse { .. } => {
                ("complete_explore_from_reuse", None, None)
            }
            needle_core::LifecycleTransition::CompleteImplement { .. } => {
                ("complete_implement", None, None)
            }
            needle_core::LifecycleTransition::BindTestPlans { .. } => {
                ("bind_test_plans", None, None)
            }
            needle_core::LifecycleTransition::CompleteTest { .. } => ("complete_test", None, None),
            needle_core::LifecycleTransition::CompleteReview { .. } => {
                ("complete_review", None, None)
            }
            needle_core::LifecycleTransition::CompleteVerify { .. } => {
                ("complete_verify", None, None)
            }
            needle_core::LifecycleTransition::ConsumeRepair => ("consume_repair", None, None),
            needle_core::LifecycleTransition::ApproveApply { .. } => ("approve_apply", None, None),
            needle_core::LifecycleTransition::StartApply { .. } => ("start_apply", None, None),
            needle_core::LifecycleTransition::FinishApply { status, .. } => {
                ("finish_apply", None, Some(*status))
            }
            needle_core::LifecycleTransition::Cancel { reason } => {
                ("cancel", Some(reason_dto(reason)), None)
            }
            needle_core::LifecycleTransition::Fail { reason } => {
                ("fail", Some(reason_dto(reason)), None)
            }
        },
    };
    LifecycleEventActionDto { kind, reason, apply_status }
}

fn store_error(error: StoreError) -> Response {
    match error {
        StoreError::LifecycleNotFound(_) => {
            lifecycle_error(StatusCode::NOT_FOUND, "not_found", "lifecycle was not found")
        }
        StoreError::LifecycleQuery(_) | StoreError::LifecycleExploreObservationQuery(_) => {
            lifecycle_error(StatusCode::BAD_REQUEST, "invalid_limit", "lifecycle query is invalid")
        }
        StoreError::LifecycleAdapterInvocationValidation(_) => lifecycle_error(
            StatusCode::BAD_REQUEST,
            "invalid_adapter_invocation",
            "lifecycle adapter invocation is invalid",
        ),
        StoreError::LifecycleAdapterInvocationConflict(_) => lifecycle_error(
            StatusCode::CONFLICT,
            "adapter_invocation_conflict",
            "lifecycle adapter invocation conflicts with durable state",
        ),
        StoreError::LifecycleCorruption(_)
        | StoreError::LifecycleExploreObservationCorruption(_)
        | StoreError::LifecycleAdapterInvocationCorruption(_)
        | StoreError::Lifecycle(_)
        | StoreError::Json(_) => lifecycle_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "lifecycle_corruption",
            "stored lifecycle data is corrupt",
        ),
        _ => lifecycle_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            "lifecycle storage is unavailable",
        ),
    }
}

fn lifecycle_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(LifecycleApiError { schema: ERROR_SCHEMA, code, message })).into_response()
}

#[cfg(test)]
#[path = "lifecycles/tests.rs"]
mod tests;
