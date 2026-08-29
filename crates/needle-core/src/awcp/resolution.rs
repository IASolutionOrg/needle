use super::{
    AwcpValidationError, MAX_AWCP_ARTIFACTS, MAX_AWCP_KNOWN_DEFINITIONS,
    MAX_AWCP_MISSING_OBLIGATIONS, MAX_AWCP_TICKET_TTL_MS, MAX_AWCP_WORKER_RESULT_BYTES,
    ResolutionTicketId, validate_bound, validate_nonzero_bound, validate_revision,
};
use crate::{
    ActionContractId, ActionRequest, ArtifactId, ArtifactRequestId, CanonicalHasher,
    CapabilityMode, Digest, EffectClass, MAX_NEED_INPUTS, MAX_REQUEST_BYTES,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionDefinitionHandle {
    pub id: ActionContractId,
    pub semantic_definition_digest: Digest,
    pub validation_definition_digest: Digest,
    pub operational_policy_digest: Digest,
    pub definition_digest: Digest,
    pub effect_class: EffectClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionSourceBinding {
    pub semantic_source_context_digest: Digest,
    pub repository_generation: Option<u64>,
    pub state_delta_digest: Option<Digest>,
    pub definition_set_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRequestProjection {
    pub request: ActionRequest,
    pub definition: ActionDefinitionHandle,
    pub semantic_inputs_digest: Digest,
    pub source_binding: ResolutionSourceBinding,
}

impl ActionRequestProjection {
    pub fn new(
        request: ActionRequest,
        definition: ActionDefinitionHandle,
        source_binding: ResolutionSourceBinding,
    ) -> Result<Self, AwcpValidationError> {
        let semantic_inputs_digest = semantic_inputs_digest(&request);
        let value = Self { request, definition, semantic_inputs_digest, source_binding };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn validate_shape(&self) -> Result<(), AwcpValidationError> {
        if self.request.contract != self.definition.id
            || self.request.contract_semantic_definition_digest
                != Some(self.definition.semantic_definition_digest)
            || self.request.contract_operational_policy_digest
                != self.definition.operational_policy_digest
        {
            return Err(AwcpValidationError::ActionDefinitionBinding);
        }
        if self.request.artifact_request.input_artifact_ids.len() > MAX_NEED_INPUTS {
            return Err(AwcpValidationError::Bound {
                field: "action.request.semantic_inputs",
                actual: self.request.artifact_request.input_artifact_ids.len(),
                maximum: MAX_NEED_INPUTS,
            });
        }
        let request_bytes = self.request.artifact_request.normalized_request.len();
        if request_bytes == 0 || request_bytes > MAX_REQUEST_BYTES {
            return Err(AwcpValidationError::Bound {
                field: "action.request.normalized_request",
                actual: request_bytes,
                maximum: MAX_REQUEST_BYTES,
            });
        }
        if self.semantic_inputs_digest != semantic_inputs_digest(&self.request) {
            return Err(AwcpValidationError::SemanticInputsDigest);
        }
        Ok(())
    }
}

pub fn semantic_inputs_digest(request: &ActionRequest) -> Digest {
    let mut hasher = CanonicalHasher::new(b"awcp-semantic-inputs-v1");
    hasher.field_u16(request.artifact_request.input_artifact_ids.len() as u16);
    for input in &request.artifact_request.input_artifact_ids {
        hasher.field_digest(*input);
    }
    hasher.finish()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerCapabilities {
    pub structured_output: bool,
    pub artifact_handles: bool,
    pub refresh: bool,
    pub cancellation: bool,
    pub usage_reporting: bool,
    pub sandbox_identity: bool,
    pub effect_receipts: bool,
    pub streaming: bool,
    pub independent_evidence_isolation: bool,
}

impl CallerCapabilities {
    pub const fn offline_complete() -> Self {
        Self {
            structured_output: true,
            artifact_handles: true,
            refresh: false,
            cancellation: true,
            usage_reporting: true,
            sandbox_identity: true,
            effect_receipts: false,
            streaming: false,
            independent_evidence_isolation: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegotiatedCapabilities {
    pub structured_output: bool,
    pub artifact_handles: bool,
    pub refresh: bool,
    pub cancellation: bool,
    pub usage_reporting: bool,
    pub sandbox_identity: bool,
    pub effect_receipts: bool,
    pub streaming: bool,
    pub independent_evidence_isolation: bool,
    pub effective_mode: CapabilityMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedLimits {
    pub max_candidates: u16,
    pub max_artifacts: u8,
    pub max_missing_obligations: u8,
    pub max_worker_result_bytes: u32,
}

impl AppliedLimits {
    pub const fn offline_default() -> Self {
        Self {
            max_candidates: 16,
            max_artifacts: MAX_AWCP_ARTIFACTS as u8,
            max_missing_obligations: MAX_AWCP_MISSING_OBLIGATIONS as u8,
            max_worker_result_bytes: MAX_AWCP_WORKER_RESULT_BYTES as u32,
        }
    }

    pub fn validate(self) -> Result<(), AwcpValidationError> {
        validate_nonzero_bound("limits.max_candidates", self.max_candidates as usize, 64)?;
        validate_nonzero_bound(
            "limits.max_artifacts",
            self.max_artifacts as usize,
            MAX_AWCP_ARTIFACTS,
        )?;
        validate_nonzero_bound(
            "limits.max_missing_obligations",
            self.max_missing_obligations as usize,
            MAX_AWCP_MISSING_OBLIGATIONS,
        )?;
        validate_nonzero_bound(
            "limits.max_worker_result_bytes",
            self.max_worker_result_bytes as usize,
            MAX_AWCP_WORKER_RESULT_BYTES,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionResolutionProjection {
    Exact,
    Project,
    Assemble,
    RefreshRequired,
    ComputeRequired,
    Partial,
    Bypass,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AwcpReasonCode {
    Resolved,
    ComputeRequired,
    CapabilityUnsupported,
    AuthorityInsufficient,
    NativeBypass,
    Rejected,
    AcceptedForValidation,
    ArtifactGranted,
    ExecutionRecorded,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionHint {
    DoNotStartWorker,
    StartFreshWorker { action_request: ArtifactRequestId },
    StartRefreshWorker { prior_artifact: ArtifactId, refresh_plan_digest: Digest },
    ContinueNative { reason: AwcpReasonCode },
    RequireApproval { approval_digest: Digest },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishAuthority {
    Forbidden,
    FreshResult,
    RefreshResult,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactHandle {
    pub id: ArtifactId,
    pub contract: ActionContractId,
    pub content_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofHandle {
    pub id: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObligationProjection {
    pub id: Digest,
    pub predicate_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveActionRequest {
    pub protocol_revision: u16,
    pub action: ActionRequestProjection,
    pub known_definitions: Vec<Digest>,
    pub caller_capabilities: CallerCapabilities,
    pub requested_limits: AppliedLimits,
}

impl ResolveActionRequest {
    pub fn validate_shape(&self) -> Result<(), AwcpValidationError> {
        validate_revision(self.protocol_revision)?;
        self.action.validate_shape()?;
        self.requested_limits.validate()?;
        validate_canonical_digests(
            "known_definitions",
            &self.known_definitions,
            MAX_AWCP_KNOWN_DEFINITIONS,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionTicket {
    pub id: ResolutionTicketId,
    pub protocol_revision: u16,
    pub action_request: ArtifactRequestId,
    pub action_contract: ActionContractId,
    pub semantic_definition_digest: Digest,
    pub validation_definition_digest: Digest,
    pub contract_operational_policy_digest: Digest,
    pub effective_dispatch_policy_digest: Digest,
    pub semantic_inputs_digest: Digest,
    pub source_binding: ResolutionSourceBinding,
    pub resolution_digest: Digest,
    pub allowed_effect: EffectClass,
    pub publish_authority: PublishAuthority,
    pub prior_artifact: Option<ArtifactId>,
    pub refresh_plan_digest: Option<Digest>,
    pub applied_limits: AppliedLimits,
    pub caller_identity_digest: Digest,
    pub nonce: Digest,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub authenticator: Digest,
}

impl ResolutionTicket {
    pub fn validate_shape(&self) -> Result<(), AwcpValidationError> {
        validate_revision(self.protocol_revision)?;
        self.applied_limits.validate()?;
        if self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms > MAX_AWCP_TICKET_TTL_MS
        {
            return Err(AwcpValidationError::TicketExpiry);
        }
        match self.publish_authority {
            PublishAuthority::Forbidden | PublishAuthority::FreshResult => {
                if self.prior_artifact.is_some() || self.refresh_plan_digest.is_some() {
                    return Err(AwcpValidationError::PublishAuthorityBinding);
                }
            }
            PublishAuthority::RefreshResult => {
                if self.prior_artifact.is_none() || self.refresh_plan_digest.is_none() {
                    return Err(AwcpValidationError::PublishAuthorityBinding);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveActionResponse {
    pub protocol_revision: u16,
    pub resolution: ActionResolutionProjection,
    pub artifacts: Vec<ArtifactHandle>,
    pub missing: Vec<ObligationProjection>,
    pub execution_hint: ExecutionHint,
    pub proof: Option<ProofHandle>,
    pub limits: AppliedLimits,
    pub negotiated_capabilities: NegotiatedCapabilities,
    pub ticket: ResolutionTicket,
}

impl ResolveActionResponse {
    pub fn validate_shape(&self) -> Result<(), AwcpValidationError> {
        validate_revision(self.protocol_revision)?;
        self.limits.validate()?;
        self.ticket.validate_shape()?;
        validate_bound("artifacts", self.artifacts.len(), self.limits.max_artifacts as usize)?;
        validate_bound(
            "missing",
            self.missing.len(),
            self.limits.max_missing_obligations as usize,
        )?;
        if self.artifacts.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err(AwcpValidationError::ArtifactOrdering);
        }
        Ok(())
    }
}

fn validate_canonical_digests(
    field: &'static str,
    values: &[Digest],
    maximum: usize,
) -> Result<(), AwcpValidationError> {
    validate_bound(field, values.len(), maximum)?;
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(AwcpValidationError::CanonicalSet(field));
    }
    Ok(())
}
