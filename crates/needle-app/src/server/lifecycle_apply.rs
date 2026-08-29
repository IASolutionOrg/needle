use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use needle_core::{
    ActionContractId, ArtifactId, CanonicalHasher, ChangeActionInput, ChangeActionInvocation,
    ChangeId, Digest, LifecyclePhase, LifecycleStatus, NeedExecution, NeedExecutionEnvelopeV1,
    PATCH_APPLY_ACTION_CONTRACT, PATCH_PROPOSE_ACTION_CONTRACT, PATCH_VERIFY_ACTION_CONTRACT,
    PatchActionInputRef, VerificationActionInputRef,
};
use needle_platform_codex::CodexChangeActionProvider;
use needle_runtime::{ActionExecutionService, ChangeActionOutput, RuntimeStore};
use serde::{Deserialize, Serialize};
use std::path::Path as FsPath;

use super::AppState;

pub(super) const MAX_APPLY_BODY_BYTES: usize = 4 * 1024;
const APPLY_SCHEMA: &str = "needle.lifecycle-apply/1";
const ERROR_SCHEMA: &str = "needle.lifecycle-error/1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LifecycleApplyBody {
    expected_state_digest: Digest,
    confirm: bool,
}

#[derive(Debug, Serialize)]
struct LifecycleApplyResponse {
    schema: &'static str,
    operation_id: Digest,
    change_id: ChangeId,
    phase: LifecyclePhase,
    status: LifecycleStatus,
    state_digest: Digest,
    artifact_id: Digest,
    validation_certificate_id: Digest,
    idempotent_replay: bool,
    receipt: needle_core::ApplyReceipt,
}

#[derive(Debug, Serialize)]
struct LifecycleApplyErrorResponse {
    schema: &'static str,
    code: &'static str,
    message: &'static str,
}

#[derive(Debug)]
enum LifecycleApplyError {
    NotFound,
    StaleState,
    Unavailable,
    Corrupt,
    Runtime,
}

pub(super) async fn apply_lifecycle(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Result<Json<LifecycleApplyBody>, JsonRejection>,
) -> Response {
    let change_id = match ChangeId::parse(&id) {
        Ok(change_id) => change_id,
        Err(_) => {
            return error(StatusCode::BAD_REQUEST, "invalid_change_id", "change ID is invalid");
        }
    };
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_body", "request body is invalid"),
    };
    if !body.confirm {
        return error(
            StatusCode::BAD_REQUEST,
            "confirmation_required",
            "Apply requires explicit confirmation",
        );
    }
    let guard = match state.apply_lock.clone().try_lock_owned() {
        Ok(guard) => guard,
        Err(_) => {
            return error(
                StatusCode::CONFLICT,
                "apply_busy",
                "another Apply operation is currently executing",
            );
        }
    };
    let store = state.store.clone();
    let data_directory = state.data_directory.clone();
    let repository_root = state.repository_root.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        execute_apply(
            &store,
            &data_directory,
            &repository_root,
            &change_id,
            body.expected_state_digest,
        )
    })
    .await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(LifecycleApplyError::NotFound)) => {
            error(StatusCode::NOT_FOUND, "not_found", "lifecycle was not found")
        }
        Ok(Err(LifecycleApplyError::StaleState)) => error(
            StatusCode::PRECONDITION_FAILED,
            "stale_state",
            "lifecycle approval state changed",
        ),
        Ok(Err(LifecycleApplyError::Unavailable)) => error(
            StatusCode::CONFLICT,
            "apply_unavailable",
            "lifecycle is not awaiting an applicable verified patch",
        ),
        Ok(Err(LifecycleApplyError::Corrupt)) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "lifecycle_corruption",
            "stored lifecycle Apply bindings are corrupt",
        ),
        Ok(Err(LifecycleApplyError::Runtime)) | Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "apply_failed",
            "lifecycle Apply execution failed",
        ),
    }
}

fn execute_apply(
    store: &RuntimeStore,
    data_directory: &FsPath,
    repository_root: &FsPath,
    change_id: &ChangeId,
    expected_state_digest: Digest,
) -> Result<LifecycleApplyResponse, LifecycleApplyError> {
    let projection = store.replay_lifecycle(change_id).map_err(|error| match error {
        needle_runtime::StoreError::LifecycleNotFound(_) => LifecycleApplyError::NotFound,
        _ => LifecycleApplyError::Corrupt,
    })?;
    if projection.lifecycle.phase != LifecyclePhase::Apply {
        return Err(LifecycleApplyError::Unavailable);
    }
    match projection.lifecycle.status {
        LifecycleStatus::AwaitingApproval => {
            if projection.state_digest != expected_state_digest {
                return Err(LifecycleApplyError::StaleState);
            }
        }
        LifecycleStatus::Approved | LifecycleStatus::Applying | LifecycleStatus::Completed => {
            if projection
                .lifecycle
                .approval
                .as_ref()
                .is_none_or(|approval| approval.approved_state_digest != expected_state_digest)
            {
                return Err(LifecycleApplyError::StaleState);
            }
        }
        _ => return Err(LifecycleApplyError::Unavailable),
    }
    let change = store
        .lifecycle_change_context(change_id)
        .map_err(|_| LifecycleApplyError::Corrupt)?
        .ok_or(LifecycleApplyError::Corrupt)?;
    if change.source_snapshot != projection.lifecycle.source_snapshot
        || change.request_digest != change.request.digest(change.source_snapshot)
    {
        return Err(LifecycleApplyError::Corrupt);
    }
    let plan = projection
        .lifecycle
        .spec
        .explore_action_plan
        .as_ref()
        .ok_or(LifecycleApplyError::Unavailable)?;
    if plan.repository_id() != change.repository_id
        || plan.source_snapshot() != Some(change.source_snapshot)
    {
        return Err(LifecycleApplyError::Corrupt);
    }
    let need = store
        .need_shadow(&plan.fragment.root_need)
        .map_err(|_| LifecycleApplyError::Corrupt)?
        .ok_or(LifecycleApplyError::Corrupt)?;
    if need.need.id != plan.fragment.root_need
        || need.need.world.repository_lineage != change.repository_id
    {
        return Err(LifecycleApplyError::Corrupt);
    }
    let patch = projection.lifecycle.patch.as_ref().ok_or(LifecycleApplyError::Unavailable)?;
    let verification =
        projection.lifecycle.verification.as_ref().ok_or(LifecycleApplyError::Unavailable)?;
    let patch_contract = ActionContractId::new(PATCH_PROPOSE_ACTION_CONTRACT)
        .map_err(|_| LifecycleApplyError::Corrupt)?;
    let patch_artifact = store
        .opaque_action_artifact_by_payload(&patch_contract, patch.patch_id.0)
        .map_err(|_| LifecycleApplyError::Corrupt)?
        .ok_or(LifecycleApplyError::Unavailable)?;
    let verification_contract = ActionContractId::new(PATCH_VERIFY_ACTION_CONTRACT)
        .map_err(|_| LifecycleApplyError::Corrupt)?;
    let verification_artifact = store
        .opaque_action_artifact_by_payload(&verification_contract, verification.verification_id.0)
        .map_err(|_| LifecycleApplyError::Corrupt)?
        .ok_or(LifecycleApplyError::Unavailable)?;
    let operation_id = apply_operation_id(
        change_id,
        expected_state_digest,
        patch.patch_id.0,
        verification.verification_id.0,
    );
    let input = ChangeActionInput::PatchApply {
        change_id: change_id.clone(),
        requirements_digest: change.request_digest,
        patch: PatchActionInputRef {
            artifact: ArtifactId::new(patch_artifact.id),
            patch: patch.patch_id,
        },
        verification: VerificationActionInputRef {
            artifact: ArtifactId::new(verification_artifact.id),
            verification: verification.verification_id,
        },
        expected_state_digest,
        confirm: true,
    };
    let envelope = NeedExecutionEnvelopeV1::new(
        operation_id,
        need.need_ir,
        NeedExecution::Action {
            action: ChangeActionInvocation {
                contract: ActionContractId::new(PATCH_APPLY_ACTION_CONTRACT)
                    .map_err(|_| LifecycleApplyError::Corrupt)?,
                input,
            },
        },
    );
    let settings = store.settings().map_err(|_| LifecycleApplyError::Runtime)?;
    let config = store
        .worker_config_for_provenance(
            &projection.lifecycle.spec.profiles.implement,
            settings.codex_executable,
        )
        .map_err(|_| LifecycleApplyError::Runtime)?;
    let provider = CodexChangeActionProvider::new(data_directory, repository_root, config);
    let result = ActionExecutionService::new(store.clone(), provider)
        .execute_action(&envelope, change.repository_id, change.source_snapshot)
        .map_err(|_| LifecycleApplyError::Runtime)?;
    let ChangeActionOutput::ApplyReceipt(receipt) = result.output else {
        return Err(LifecycleApplyError::Corrupt);
    };
    let current = store.replay_lifecycle(change_id).map_err(|_| LifecycleApplyError::Corrupt)?;
    Ok(LifecycleApplyResponse {
        schema: APPLY_SCHEMA,
        operation_id,
        change_id: change_id.clone(),
        phase: current.lifecycle.phase,
        status: current.lifecycle.status,
        state_digest: current.state_digest,
        artifact_id: result.artifact.id,
        validation_certificate_id: result.validation_certificate.digest(),
        idempotent_replay: result.idempotent_replay,
        receipt,
    })
}

fn apply_operation_id(
    change_id: &ChangeId,
    expected_state_digest: Digest,
    patch_id: Digest,
    verification_id: Digest,
) -> Digest {
    let mut hasher = CanonicalHasher::new(b"needle-lifecycle-web-apply-v1");
    hasher.field_str(change_id.as_str());
    hasher.field_digest(expected_state_digest);
    hasher.field_digest(patch_id);
    hasher.field_digest(verification_id);
    hasher.finish()
}

fn error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(LifecycleApplyErrorResponse { schema: ERROR_SCHEMA, code, message }))
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_operation_identity_is_exact_and_stable() {
        let change = ChangeId::from_digest(Digest::blake3(b"change"));
        let state = Digest::blake3(b"state");
        let patch = Digest::blake3(b"patch");
        let verification = Digest::blake3(b"verification");
        let first = apply_operation_id(&change, state, patch, verification);
        assert_eq!(first, apply_operation_id(&change, state, patch, verification));
        assert_ne!(
            first,
            apply_operation_id(&change, Digest::blake3(b"other-state"), patch, verification)
        );
    }
}
