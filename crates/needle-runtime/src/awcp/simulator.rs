use super::protocol::{
    authenticate_ticket, intersect_limits, keyed_digest, negotiate, resolution_digest,
    resolution_execution, ticket_authenticator, ticket_identity_digest, validate_action_projection,
    validate_definition_handle, validate_live_ticket, validate_publication_binding,
};
use needle_core::{
    AWCP_PROTOCOL_REVISION, ActionDefinitionHandle, ActionRequestProjection,
    ActionResolutionProjection, AppliedLimits, ArtifactHandle, ArtifactId, AwcpErrorCode,
    AwcpErrorResponse, AwcpReasonCode, AwcpRequest, AwcpResponse, AwcpValidationError,
    CapabilityMode, Digest, EffectClass, ExecutionReportId, ExecutionStatus, GetArtifactRequest,
    GetArtifactResponse, MAX_AWCP_ARTIFACT_PROJECTION_BYTES, MAX_AWCP_ARTIFACTS,
    MAX_AWCP_MESSAGE_BYTES, MAX_AWCP_MISSING_OBLIGATIONS, MAX_AWCP_TICKET_TTL_MS,
    ObligationProjection, ProofHandle, PublishActionRequest, PublishActionResponse,
    PublishAuthority, PublishDisposition, ReportExecutionRequest, ReportExecutionResponse,
    ResolutionSourceBinding, ResolutionTicket, ResolutionTicketId, ResolveActionRequest,
    ResolveActionResponse,
};
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

pub const MAX_OFFLINE_AWCP_RESOLUTIONS: usize = 64;
pub const MAX_OFFLINE_AWCP_TICKETS: usize = 64;
pub const MAX_OFFLINE_AWCP_ARTIFACTS: usize = 64;
pub const MAX_OFFLINE_AWCP_GRANTS: usize = 512;
pub const MAX_OFFLINE_AWCP_REPORTS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedAwcpContext {
    pub caller_identity_digest: Digest,
    pub source_binding: ResolutionSourceBinding,
    pub effective_dispatch_policy_digest: Digest,
    pub allowed_effect: EffectClass,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OfflineArtifactProjection {
    pub handle: ArtifactHandle,
    pub projection: Value,
}

impl OfflineArtifactProjection {
    pub fn new(
        id: ArtifactId,
        contract: needle_core::ActionContractId,
        projection: Value,
    ) -> Result<Self, OfflineAwcpError> {
        let encoded = serde_json::to_vec(&projection)
            .map_err(|_| OfflineAwcpError::Code(AwcpErrorCode::InvalidWorkerResult))?;
        if encoded.len() > MAX_AWCP_ARTIFACT_PROJECTION_BYTES {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::BoundExceeded));
        }
        Ok(Self {
            handle: ArtifactHandle { id, contract, content_digest: Digest::blake3(&encoded) },
            projection,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OfflineActionResolution {
    pub action_request: needle_core::ArtifactRequestId,
    pub definition: ActionDefinitionHandle,
    pub source_binding: ResolutionSourceBinding,
    pub resolution: ActionResolutionProjection,
    pub artifacts: Vec<OfflineArtifactProjection>,
    pub missing: Vec<ObligationProjection>,
    pub proof: Option<ProofHandle>,
    pub effective_mode: CapabilityMode,
    pub limits: AppliedLimits,
    pub prior_artifact: Option<ArtifactId>,
    pub refresh_plan_digest: Option<Digest>,
}

impl OfflineActionResolution {
    pub fn exact(
        action: &ActionRequestProjection,
        artifact: OfflineArtifactProjection,
        proof: ProofHandle,
        effective_mode: CapabilityMode,
    ) -> Self {
        Self {
            action_request: action.request.semantic_id(),
            definition: action.definition.clone(),
            source_binding: action.source_binding,
            resolution: ActionResolutionProjection::Exact,
            artifacts: vec![artifact],
            missing: Vec::new(),
            proof: Some(proof),
            effective_mode,
            limits: AppliedLimits::offline_default(),
            prior_artifact: None,
            refresh_plan_digest: None,
        }
    }

    pub fn compute_required(
        action: &ActionRequestProjection,
        effective_mode: CapabilityMode,
    ) -> Self {
        Self {
            action_request: action.request.semantic_id(),
            definition: action.definition.clone(),
            source_binding: action.source_binding,
            resolution: ActionResolutionProjection::ComputeRequired,
            artifacts: Vec::new(),
            missing: Vec::new(),
            proof: None,
            effective_mode,
            limits: AppliedLimits::offline_default(),
            prior_artifact: None,
            refresh_plan_digest: None,
        }
    }

    fn validate(&self) -> Result<(), OfflineAwcpError> {
        self.limits
            .validate()
            .map_err(|error| OfflineAwcpError::Validation(error, AwcpErrorCode::BoundExceeded))?;
        if self.artifacts.len() > self.limits.max_artifacts as usize
            || self.artifacts.len() > MAX_AWCP_ARTIFACTS
            || self.missing.len() > self.limits.max_missing_obligations as usize
            || self.missing.len() > MAX_AWCP_MISSING_OBLIGATIONS
        {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::BoundExceeded));
        }
        if self.artifacts.windows(2).any(|pair| pair[0].handle.id >= pair[1].handle.id) {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::ResolutionDrift));
        }
        match self.resolution {
            ActionResolutionProjection::Exact
                if self.artifacts.len() != 1
                    || !self.missing.is_empty()
                    || self.proof.is_none() =>
            {
                return Err(OfflineAwcpError::Code(AwcpErrorCode::ResolutionDrift));
            }
            ActionResolutionProjection::Project | ActionResolutionProjection::Assemble
                if self.artifacts.is_empty()
                    || !self.missing.is_empty()
                    || self.proof.is_none() =>
            {
                return Err(OfflineAwcpError::Code(AwcpErrorCode::ResolutionDrift));
            }
            ActionResolutionProjection::ComputeRequired
            | ActionResolutionProjection::Bypass
            | ActionResolutionProjection::Rejected
                if !self.artifacts.is_empty()
                    || !self.missing.is_empty()
                    || self.proof.is_some() =>
            {
                return Err(OfflineAwcpError::Code(AwcpErrorCode::ResolutionDrift));
            }
            ActionResolutionProjection::RefreshRequired => {
                if self.prior_artifact.is_none() || self.refresh_plan_digest.is_none() {
                    return Err(OfflineAwcpError::Code(AwcpErrorCode::ResolutionDrift));
                }
            }
            _ => {}
        }
        if self.resolution != ActionResolutionProjection::RefreshRequired
            && (self.prior_artifact.is_some() || self.refresh_plan_digest.is_some())
        {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::ResolutionDrift));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct StoredTicket {
    ticket: ResolutionTicket,
    consumed: Option<ConsumedPublication>,
}

#[derive(Clone, Debug)]
struct ConsumedPublication {
    digest: Digest,
    response: PublishActionResponse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ReportKey {
    ticket: ResolutionTicketId,
    status: u8,
}

#[derive(Clone, Copy, Debug)]
struct StoredReport {
    digest: Digest,
    id: ExecutionReportId,
}

#[derive(Clone, Debug)]
struct ArtifactGrant {
    source_binding: ResolutionSourceBinding,
}

pub struct OfflineAwcpSimulator {
    secret: [u8; 32],
    ticket_counter: u64,
    resolutions: BTreeMap<needle_core::ArtifactRequestId, OfflineActionResolution>,
    tickets: BTreeMap<ResolutionTicketId, StoredTicket>,
    artifacts: BTreeMap<ArtifactId, OfflineArtifactProjection>,
    grants: BTreeMap<(Digest, ArtifactId), ArtifactGrant>,
    reports: BTreeMap<ReportKey, StoredReport>,
}

impl OfflineAwcpSimulator {
    pub fn new() -> Result<Self, OfflineAwcpError> {
        let mut secret = [0_u8; 32];
        getrandom::fill(&mut secret).map_err(|_| OfflineAwcpError::Entropy)?;
        Ok(Self::with_secret(secret))
    }

    /// Deterministic constructor for offline conformance fixtures. This must
    /// not be used as a transport credential source by a live adapter.
    pub(crate) fn with_secret(secret: [u8; 32]) -> Self {
        Self {
            secret,
            ticket_counter: 0,
            resolutions: BTreeMap::new(),
            tickets: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            grants: BTreeMap::new(),
            reports: BTreeMap::new(),
        }
    }

    pub fn register_resolution(
        &mut self,
        resolution: OfflineActionResolution,
    ) -> Result<(), OfflineAwcpError> {
        resolution.validate()?;
        validate_definition_handle(&resolution.definition)?;
        if !self.resolutions.contains_key(&resolution.action_request)
            && self.resolutions.len() >= MAX_OFFLINE_AWCP_RESOLUTIONS
        {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::CapacityExceeded));
        }
        for artifact in &resolution.artifacts {
            if artifact.handle.contract != resolution.definition.id {
                return Err(OfflineAwcpError::Code(AwcpErrorCode::DefinitionDrift));
            }
            let encoded = serde_json::to_vec(&artifact.projection)
                .map_err(|_| OfflineAwcpError::Code(AwcpErrorCode::InvalidWorkerResult))?;
            if encoded.len() > MAX_AWCP_ARTIFACT_PROJECTION_BYTES
                || artifact.handle.content_digest != Digest::blake3(&encoded)
            {
                return Err(OfflineAwcpError::Code(AwcpErrorCode::DefinitionDrift));
            }
            if !self.artifacts.contains_key(&artifact.handle.id)
                && self.artifacts.len() >= MAX_OFFLINE_AWCP_ARTIFACTS
            {
                return Err(OfflineAwcpError::Code(AwcpErrorCode::CapacityExceeded));
            }
            if let Some(existing) = self.artifacts.get(&artifact.handle.id)
                && existing != artifact
            {
                return Err(OfflineAwcpError::Code(AwcpErrorCode::DefinitionDrift));
            }
        }
        for artifact in &resolution.artifacts {
            self.artifacts.insert(artifact.handle.id, artifact.clone());
        }
        self.resolutions.insert(resolution.action_request, resolution);
        Ok(())
    }

    pub fn handle_bytes(
        &mut self,
        context: AuthenticatedAwcpContext,
        now_unix_ms: u64,
        message: &[u8],
    ) -> Vec<u8> {
        let response = if message.len() > MAX_AWCP_MESSAGE_BYTES {
            error_response(AwcpErrorCode::BoundExceeded)
        } else {
            match serde_json::from_slice::<AwcpRequest>(message) {
                Ok(request) => self.handle(context, now_unix_ms, request),
                Err(_) => error_response(AwcpErrorCode::MalformedMessage),
            }
        };
        let encoded = serde_json::to_vec(&response)
            .unwrap_or_else(|_| static_error_bytes(AwcpErrorCode::MalformedMessage));
        if encoded.len() <= MAX_AWCP_MESSAGE_BYTES {
            encoded
        } else {
            static_error_bytes(AwcpErrorCode::BoundExceeded)
        }
    }

    pub fn handle(
        &mut self,
        context: AuthenticatedAwcpContext,
        now_unix_ms: u64,
        request: AwcpRequest,
    ) -> AwcpResponse {
        let result = match request {
            AwcpRequest::ResolveAction(request) => self
                .resolve_action(context, now_unix_ms, *request)
                .map(|response| AwcpResponse::ResolveAction(Box::new(response))),
            AwcpRequest::PublishAction(request) => self
                .publish_action(context, now_unix_ms, *request)
                .map(|response| AwcpResponse::PublishAction(Box::new(response))),
            AwcpRequest::GetArtifact(request) => self
                .get_artifact(context, request)
                .map(|response| AwcpResponse::GetArtifact(Box::new(response))),
            AwcpRequest::ReportExecution(request) => self
                .report_execution(context, now_unix_ms, *request)
                .map(AwcpResponse::ReportExecution),
        };
        result.unwrap_or_else(|error| error_response(error.code()))
    }

    pub fn ticket_count(&self) -> usize {
        self.tickets.len()
    }

    pub fn report_count(&self) -> usize {
        self.reports.len()
    }

    fn resolve_action(
        &mut self,
        context: AuthenticatedAwcpContext,
        now_unix_ms: u64,
        request: ResolveActionRequest,
    ) -> Result<ResolveActionResponse, OfflineAwcpError> {
        self.prune_expired_tickets(now_unix_ms);
        request.validate_shape().map_err(map_validation)?;
        if request.action.source_binding != context.source_binding {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::SourceDrift));
        }
        if request.action.request.effective_dispatch_policy_digest
            != context.effective_dispatch_policy_digest
        {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::DispatchDrift));
        }
        if request.action.definition.effect_class != context.allowed_effect {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::EffectDrift));
        }
        validate_action_projection(&request.action)?;
        let request_id = request.action.request.semantic_id();
        let material = self
            .resolutions
            .get(&request_id)
            .cloned()
            .ok_or(OfflineAwcpError::Code(AwcpErrorCode::UnknownAction))?;
        if material.definition != request.action.definition {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::DefinitionDrift));
        }
        if material.source_binding != request.action.source_binding {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::SourceDrift));
        }
        material.validate()?;
        let limits = intersect_limits(request.requested_limits, material.limits);
        if material.artifacts.len() > limits.max_artifacts as usize
            || material.missing.len() > limits.max_missing_obligations as usize
        {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::BoundExceeded));
        }
        let negotiated = negotiate(request.caller_capabilities, material.effective_mode);
        let compatible = negotiated.structured_output
            && (material.artifacts.is_empty() || negotiated.artifact_handles);
        let (execution_hint, publish_authority) =
            resolution_execution(&material, compatible, negotiated.refresh, request_id);
        let resolution_digest =
            resolution_digest(&material, &execution_hint, publish_authority, limits, negotiated);
        let new_grants = material
            .artifacts
            .iter()
            .filter(|artifact| {
                !self.grants.contains_key(&(context.caller_identity_digest, artifact.handle.id))
            })
            .count();
        if self.grants.len().saturating_add(new_grants) > MAX_OFFLINE_AWCP_GRANTS {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::CapacityExceeded));
        }
        let ticket = self.issue_ticket(
            context,
            now_unix_ms,
            &request.action,
            &material,
            resolution_digest,
            publish_authority,
            limits,
        )?;
        for artifact in &material.artifacts {
            self.grants.insert(
                (context.caller_identity_digest, artifact.handle.id),
                ArtifactGrant { source_binding: context.source_binding },
            );
        }
        let response = ResolveActionResponse {
            protocol_revision: AWCP_PROTOCOL_REVISION,
            resolution: material.resolution,
            artifacts: material.artifacts.iter().map(|artifact| artifact.handle.clone()).collect(),
            missing: material.missing,
            execution_hint,
            proof: material.proof,
            limits,
            negotiated_capabilities: negotiated,
            ticket,
        };
        response.validate_shape().map_err(map_validation)?;
        Ok(response)
    }

    fn publish_action(
        &mut self,
        context: AuthenticatedAwcpContext,
        now_unix_ms: u64,
        request: PublishActionRequest,
    ) -> Result<PublishActionResponse, OfflineAwcpError> {
        request.validate_envelope().map_err(map_validation)?;
        let ticket_id = request.resolution_ticket.id;
        let stored = self
            .tickets
            .get(&ticket_id)
            .ok_or(OfflineAwcpError::Code(AwcpErrorCode::UnknownTicket))?;
        authenticate_ticket(&self.secret, &request.resolution_ticket)?;
        if request.resolution_ticket != stored.ticket {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::ResolutionDrift));
        }
        validate_live_ticket(context, now_unix_ms, &stored.ticket)?;
        validate_publication_binding(&request, &stored.ticket)?;
        if stored.ticket.publish_authority == PublishAuthority::Forbidden {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::PublishForbidden));
        }
        let publication_digest = request.publication_digest();
        if let Some(consumed) = &stored.consumed {
            return if consumed.digest == publication_digest {
                Ok(consumed.response.clone())
            } else {
                Err(OfflineAwcpError::Code(AwcpErrorCode::ConsumedTicket))
            };
        }

        // The ticket is authenticated and all resolve-time bindings match.
        // Only now may worker-result JSON be parsed and inspected.
        request
            .worker_result
            .validate_after_authentication(
                stored.ticket.applied_limits.max_worker_result_bytes as usize,
            )
            .map_err(|error| {
                OfflineAwcpError::Validation(error, AwcpErrorCode::InvalidWorkerResult)
            })?;
        let response = PublishActionResponse {
            protocol_revision: AWCP_PROTOCOL_REVISION,
            disposition: PublishDisposition::AcceptedForValidation,
            artifact: None,
            validation: None,
            reusable: false,
            reason: AwcpReasonCode::AcceptedForValidation,
            publication_digest,
        };
        self.tickets
            .get_mut(&ticket_id)
            .expect("ticket remains present during bounded publication")
            .consumed =
            Some(ConsumedPublication { digest: publication_digest, response: response.clone() });
        Ok(response)
    }

    fn get_artifact(
        &self,
        context: AuthenticatedAwcpContext,
        request: GetArtifactRequest,
    ) -> Result<GetArtifactResponse, OfflineAwcpError> {
        if request.protocol_revision != AWCP_PROTOCOL_REVISION {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::UnsupportedRevision));
        }
        let grant = self
            .grants
            .get(&(context.caller_identity_digest, request.artifact))
            .ok_or(OfflineAwcpError::Code(AwcpErrorCode::ArtifactForbidden))?;
        if grant.source_binding != context.source_binding {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::SourceDrift));
        }
        let artifact = self
            .artifacts
            .get(&request.artifact)
            .ok_or(OfflineAwcpError::Code(AwcpErrorCode::ArtifactForbidden))?;
        let response = GetArtifactResponse {
            protocol_revision: AWCP_PROTOCOL_REVISION,
            handle: artifact.handle.clone(),
            projection: artifact.projection.clone(),
        };
        response.validate_shape().map_err(map_validation)?;
        Ok(response)
    }

    fn report_execution(
        &mut self,
        context: AuthenticatedAwcpContext,
        now_unix_ms: u64,
        request: ReportExecutionRequest,
    ) -> Result<ReportExecutionResponse, OfflineAwcpError> {
        request.validate_shape().map_err(map_validation)?;
        let ticket = self
            .tickets
            .get(&request.resolution_ticket.id)
            .ok_or(OfflineAwcpError::Code(AwcpErrorCode::UnknownTicket))?;
        authenticate_ticket(&self.secret, &request.resolution_ticket)?;
        if request.resolution_ticket != ticket.ticket {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::ResolutionDrift));
        }
        validate_live_ticket(context, now_unix_ms, &ticket.ticket)?;
        if request.action_request != ticket.ticket.action_request {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::ResolutionDrift));
        }
        if request.observation.observed_effect != ticket.ticket.allowed_effect {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::EffectDrift));
        }
        let digest = request.digest();
        let key = ReportKey {
            ticket: request.resolution_ticket.id,
            status: execution_status_tag(request.status),
        };
        if let Some(existing) = self.reports.get(&key) {
            return if existing.digest == digest {
                Ok(ReportExecutionResponse {
                    protocol_revision: AWCP_PROTOCOL_REVISION,
                    report: existing.id,
                    reason: AwcpReasonCode::ExecutionRecorded,
                })
            } else {
                Err(OfflineAwcpError::Code(AwcpErrorCode::ExecutionReportConflict))
            };
        }
        if self.reports.len() >= MAX_OFFLINE_AWCP_REPORTS {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::CapacityExceeded));
        }
        let id = ExecutionReportId::new(digest);
        self.reports.insert(key, StoredReport { digest, id });
        Ok(ReportExecutionResponse {
            protocol_revision: AWCP_PROTOCOL_REVISION,
            report: id,
            reason: AwcpReasonCode::ExecutionRecorded,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_ticket(
        &mut self,
        context: AuthenticatedAwcpContext,
        now_unix_ms: u64,
        action: &ActionRequestProjection,
        resolution: &OfflineActionResolution,
        resolution_digest: Digest,
        publish_authority: PublishAuthority,
        limits: AppliedLimits,
    ) -> Result<ResolutionTicket, OfflineAwcpError> {
        if self.tickets.len() >= MAX_OFFLINE_AWCP_TICKETS {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::CapacityExceeded));
        }
        self.ticket_counter = self.ticket_counter.wrapping_add(1);
        if self.ticket_counter == 0 {
            return Err(OfflineAwcpError::Code(AwcpErrorCode::CapacityExceeded));
        }
        let nonce = keyed_digest(
            &self.secret,
            b"awcp-ticket-nonce-v1",
            &[
                &self.ticket_counter.to_le_bytes(),
                &now_unix_ms.to_le_bytes(),
                &action.request.semantic_id().digest().bytes(),
            ],
        );
        let expires_at_unix_ms = now_unix_ms.saturating_add(MAX_AWCP_TICKET_TTL_MS);
        let mut ticket = ResolutionTicket {
            id: ResolutionTicketId::new(Digest([0; 32])),
            protocol_revision: AWCP_PROTOCOL_REVISION,
            action_request: action.request.semantic_id(),
            action_contract: action.definition.id.clone(),
            semantic_definition_digest: action.definition.semantic_definition_digest,
            validation_definition_digest: action.definition.validation_definition_digest,
            contract_operational_policy_digest: action.definition.operational_policy_digest,
            effective_dispatch_policy_digest: action.request.effective_dispatch_policy_digest,
            semantic_inputs_digest: action.semantic_inputs_digest,
            source_binding: action.source_binding,
            resolution_digest,
            allowed_effect: action.definition.effect_class,
            publish_authority,
            prior_artifact: (publish_authority == PublishAuthority::RefreshResult)
                .then_some(resolution.prior_artifact)
                .flatten(),
            refresh_plan_digest: (publish_authority == PublishAuthority::RefreshResult)
                .then_some(resolution.refresh_plan_digest)
                .flatten(),
            applied_limits: limits,
            caller_identity_digest: context.caller_identity_digest,
            nonce,
            issued_at_unix_ms: now_unix_ms,
            expires_at_unix_ms,
            authenticator: Digest([0; 32]),
        };
        ticket.id = ResolutionTicketId::new(ticket_identity_digest(&ticket));
        ticket.authenticator = ticket_authenticator(&self.secret, &ticket);
        ticket.validate_shape().map_err(map_validation)?;
        self.tickets.insert(ticket.id, StoredTicket { ticket: ticket.clone(), consumed: None });
        Ok(ticket)
    }

    fn prune_expired_tickets(&mut self, now_unix_ms: u64) {
        self.tickets.retain(|_, stored| stored.ticket.expires_at_unix_ms > now_unix_ms);
    }
}

#[derive(Debug, Error)]
pub enum OfflineAwcpError {
    #[error("operating-system entropy is unavailable")]
    Entropy,
    #[error("AWCP validation failed: {0}")]
    Validation(AwcpValidationError, AwcpErrorCode),
    #[error("AWCP operation failed with {0:?}")]
    Code(AwcpErrorCode),
}

impl OfflineAwcpError {
    pub const fn code(&self) -> AwcpErrorCode {
        match self {
            Self::Entropy => AwcpErrorCode::RuntimeUnavailable,
            Self::Validation(_, code) | Self::Code(code) => *code,
        }
    }
}

pub(super) fn map_validation(error: AwcpValidationError) -> OfflineAwcpError {
    let code = match error {
        AwcpValidationError::Revision(_) => AwcpErrorCode::UnsupportedRevision,
        AwcpValidationError::Bound { .. } | AwcpValidationError::ZeroLimit => {
            AwcpErrorCode::BoundExceeded
        }
        AwcpValidationError::ActionDefinitionBinding
        | AwcpValidationError::SemanticInputsDigest => AwcpErrorCode::DefinitionDrift,
        AwcpValidationError::TicketExpiry => AwcpErrorCode::ExpiredTicket,
        AwcpValidationError::CredentialMaterial
        | AwcpValidationError::WorkerResultJson
        | AwcpValidationError::WorkerResultCanonical
        | AwcpValidationError::WorkerResultSchema => AwcpErrorCode::InvalidWorkerResult,
        AwcpValidationError::EffectReceipt => AwcpErrorCode::EffectDrift,
        AwcpValidationError::CanonicalSet(_)
        | AwcpValidationError::PublishAuthorityBinding
        | AwcpValidationError::ArtifactOrdering
        | AwcpValidationError::ObservationTime
        | AwcpValidationError::ArtifactProjectionJson
        | AwcpValidationError::PartitionManifestProjection
        | AwcpValidationError::PartitionManifestDigest => AwcpErrorCode::ResolutionDrift,
        AwcpValidationError::PartitionManifestAuthority => AwcpErrorCode::CapabilityUnsupported,
    };
    OfflineAwcpError::Validation(error, code)
}

fn error_response(code: AwcpErrorCode) -> AwcpResponse {
    AwcpResponse::Error(AwcpErrorResponse { protocol_revision: AWCP_PROTOCOL_REVISION, code })
}

fn static_error_bytes(code: AwcpErrorCode) -> Vec<u8> {
    serde_json::to_vec(&error_response(code)).expect("static AWCP error response serializes")
}

const fn execution_status_tag(value: ExecutionStatus) -> u8 {
    match value {
        ExecutionStatus::Started => 0,
        ExecutionStatus::Completed => 1,
        ExecutionStatus::Cancelled => 2,
        ExecutionStatus::Failed => 3,
        ExecutionStatus::Skipped => 4,
    }
}
