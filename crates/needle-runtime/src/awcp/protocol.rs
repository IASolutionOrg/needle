use super::simulator::{
    AuthenticatedAwcpContext, OfflineActionResolution, OfflineAwcpError, map_validation,
};
use crate::{BuiltInActionDefinition, built_in_action_contracts};
use needle_core::{
    ActionDefinitionHandle, ActionRequestProjection, ActionResolutionProjection, AppliedLimits,
    AwcpErrorCode, AwcpReasonCode, CanonicalHasher, CapabilityMode, Digest, EffectClass,
    ExecutionHint, NegotiatedCapabilities, PublishActionRequest, PublishAuthority,
    ResolutionSourceBinding, ResolutionTicket,
};

pub(super) fn validate_action_projection(
    action: &ActionRequestProjection,
) -> Result<(), OfflineAwcpError> {
    let definition = built_in_definition(&action.definition.id)
        .ok_or(OfflineAwcpError::Code(AwcpErrorCode::UnknownAction))?;
    if definition_handle(definition) != action.definition {
        return Err(OfflineAwcpError::Code(AwcpErrorCode::DefinitionDrift));
    }
    action
        .request
        .validate(&definition.contract)
        .map_err(|_| OfflineAwcpError::Code(AwcpErrorCode::DefinitionDrift))
}

pub(super) fn validate_definition_handle(
    handle: &ActionDefinitionHandle,
) -> Result<(), OfflineAwcpError> {
    let definition = built_in_definition(&handle.id)
        .ok_or(OfflineAwcpError::Code(AwcpErrorCode::UnknownAction))?;
    if definition_handle(definition) == *handle {
        Ok(())
    } else {
        Err(OfflineAwcpError::Code(AwcpErrorCode::DefinitionDrift))
    }
}

fn built_in_definition(
    id: &needle_core::ActionContractId,
) -> Option<&'static BuiltInActionDefinition> {
    built_in_action_contracts().iter().find(|definition| definition.contract.id == *id)
}

pub(crate) fn definition_handle(definition: &BuiltInActionDefinition) -> ActionDefinitionHandle {
    ActionDefinitionHandle {
        id: definition.contract.id.clone(),
        semantic_definition_digest: definition.contract.semantic_definition_digest,
        validation_definition_digest: definition.contract.validation_definition_digest,
        operational_policy_digest: definition.contract.operational_policy_digest,
        definition_digest: definition.contract.definition_digest,
        effect_class: definition.contract.effect_class,
    }
}

pub(super) fn intersect_limits(
    requested: AppliedLimits,
    available: AppliedLimits,
) -> AppliedLimits {
    AppliedLimits {
        max_candidates: requested.max_candidates.min(available.max_candidates),
        max_artifacts: requested.max_artifacts.min(available.max_artifacts),
        max_missing_obligations: requested
            .max_missing_obligations
            .min(available.max_missing_obligations),
        max_worker_result_bytes: requested
            .max_worker_result_bytes
            .min(available.max_worker_result_bytes),
    }
}

pub(super) fn negotiate(
    caller: needle_core::CallerCapabilities,
    effective_mode: CapabilityMode,
) -> NegotiatedCapabilities {
    NegotiatedCapabilities {
        structured_output: caller.structured_output,
        artifact_handles: caller.artifact_handles,
        refresh: caller.refresh,
        cancellation: caller.cancellation,
        usage_reporting: caller.usage_reporting,
        sandbox_identity: caller.sandbox_identity,
        effect_receipts: caller.effect_receipts,
        streaming: caller.streaming,
        independent_evidence_isolation: caller.independent_evidence_isolation,
        effective_mode,
    }
}

pub(super) fn resolution_execution(
    resolution: &OfflineActionResolution,
    compatible: bool,
    refresh_supported: bool,
    request: needle_core::ArtifactRequestId,
) -> (ExecutionHint, PublishAuthority) {
    if resolution.effective_mode == CapabilityMode::Disabled {
        return (
            ExecutionHint::ContinueNative { reason: AwcpReasonCode::AuthorityInsufficient },
            PublishAuthority::Forbidden,
        );
    }
    if !compatible {
        return (
            ExecutionHint::ContinueNative { reason: AwcpReasonCode::CapabilityUnsupported },
            PublishAuthority::Forbidden,
        );
    }
    match resolution.resolution {
        ActionResolutionProjection::Exact
        | ActionResolutionProjection::Project
        | ActionResolutionProjection::Assemble
            if resolution.effective_mode == CapabilityMode::Authoritative =>
        {
            (ExecutionHint::DoNotStartWorker, PublishAuthority::Forbidden)
        }
        ActionResolutionProjection::RefreshRequired
            if resolution.effective_mode == CapabilityMode::Authoritative && refresh_supported =>
        {
            (
                ExecutionHint::StartRefreshWorker {
                    prior_artifact: resolution
                        .prior_artifact
                        .expect("validated refresh has a prior artifact"),
                    refresh_plan_digest: resolution
                        .refresh_plan_digest
                        .expect("validated refresh has a plan"),
                },
                PublishAuthority::RefreshResult,
            )
        }
        ActionResolutionProjection::Bypass => (
            ExecutionHint::ContinueNative { reason: AwcpReasonCode::NativeBypass },
            PublishAuthority::Forbidden,
        ),
        ActionResolutionProjection::Rejected => (
            ExecutionHint::ContinueNative { reason: AwcpReasonCode::Rejected },
            PublishAuthority::Forbidden,
        ),
        _ => (
            ExecutionHint::StartFreshWorker { action_request: request },
            PublishAuthority::FreshResult,
        ),
    }
}

pub(super) fn resolution_digest(
    resolution: &OfflineActionResolution,
    hint: &ExecutionHint,
    publish_authority: PublishAuthority,
    limits: AppliedLimits,
    negotiated: NegotiatedCapabilities,
) -> Digest {
    let mut hasher = CanonicalHasher::new(b"awcp-resolution-v1");
    hasher.field_u8(resolution_tag(resolution.resolution));
    hasher.field_u16(resolution.artifacts.len() as u16);
    for artifact in &resolution.artifacts {
        hasher.field_digest(artifact.handle.id.digest());
        hasher.field_digest(artifact.handle.content_digest);
    }
    hasher.field_u16(resolution.missing.len() as u16);
    for obligation in &resolution.missing {
        hasher.field_digest(obligation.id);
        hasher.field_digest(obligation.predicate_digest);
    }
    match resolution.proof {
        Some(proof) => {
            hasher.field_u8(1);
            hasher.field_digest(proof.id);
        }
        None => hasher.field_u8(0),
    }
    hash_execution_hint(&mut hasher, hint);
    hasher.field_u8(publish_authority_tag(publish_authority));
    hash_limits(&mut hasher, limits);
    hasher.field_u8(capability_mode_tag(negotiated.effective_mode));
    hasher.field_u8(u8::from(negotiated.structured_output));
    hasher.field_u8(u8::from(negotiated.artifact_handles));
    hasher.field_u8(u8::from(negotiated.refresh));
    hasher.finish()
}

pub(super) fn validate_publication_binding(
    request: &PublishActionRequest,
    ticket: &ResolutionTicket,
) -> Result<(), OfflineAwcpError> {
    if request.protocol_revision != ticket.protocol_revision
        || request.action_request != ticket.action_request
        || request.action_contract.id != ticket.action_contract
        || request.action_contract.semantic_definition_digest != ticket.semantic_definition_digest
        || request.action_contract.validation_definition_digest
            != ticket.validation_definition_digest
        || request.action_contract.operational_policy_digest
            != ticket.contract_operational_policy_digest
        || request.action_contract.effect_class != ticket.allowed_effect
    {
        return Err(OfflineAwcpError::Code(AwcpErrorCode::DefinitionDrift));
    }
    if request.observation.observed_effect != ticket.allowed_effect {
        return Err(OfflineAwcpError::Code(AwcpErrorCode::EffectDrift));
    }
    validate_definition_handle(&request.action_contract)
}

pub(super) fn validate_live_ticket(
    context: AuthenticatedAwcpContext,
    now_unix_ms: u64,
    ticket: &ResolutionTicket,
) -> Result<(), OfflineAwcpError> {
    if ticket.caller_identity_digest != context.caller_identity_digest {
        return Err(OfflineAwcpError::Code(AwcpErrorCode::CallerDrift));
    }
    if ticket.source_binding != context.source_binding {
        return Err(OfflineAwcpError::Code(AwcpErrorCode::SourceDrift));
    }
    if ticket.effective_dispatch_policy_digest != context.effective_dispatch_policy_digest {
        return Err(OfflineAwcpError::Code(AwcpErrorCode::DispatchDrift));
    }
    if ticket.allowed_effect != context.allowed_effect {
        return Err(OfflineAwcpError::Code(AwcpErrorCode::EffectDrift));
    }
    if now_unix_ms < ticket.issued_at_unix_ms || now_unix_ms >= ticket.expires_at_unix_ms {
        return Err(OfflineAwcpError::Code(AwcpErrorCode::ExpiredTicket));
    }
    Ok(())
}

pub(super) fn authenticate_ticket(
    secret: &[u8; 32],
    ticket: &ResolutionTicket,
) -> Result<(), OfflineAwcpError> {
    ticket.validate_shape().map_err(map_validation)?;
    if ticket.id.digest() != ticket_identity_digest(ticket) {
        return Err(OfflineAwcpError::Code(AwcpErrorCode::ForgedTicket));
    }
    let expected = ticket_authenticator(secret, ticket).bytes();
    let actual = ticket.authenticator.bytes();
    if constant_time_eq::constant_time_eq(&expected, &actual) {
        Ok(())
    } else {
        Err(OfflineAwcpError::Code(AwcpErrorCode::ForgedTicket))
    }
}

pub(super) fn ticket_identity_digest(ticket: &ResolutionTicket) -> Digest {
    let mut hasher = CanonicalHasher::new(b"awcp-resolution-ticket-id-v1");
    hash_ticket_material(&mut hasher, ticket, false);
    hasher.finish()
}

pub(super) fn ticket_authenticator(secret: &[u8; 32], ticket: &ResolutionTicket) -> Digest {
    let mut hasher = CanonicalHasher::new(b"awcp-resolution-ticket-auth-v1");
    hash_ticket_material(&mut hasher, ticket, true);
    let material = hasher.finish().bytes();
    Digest(*blake3::keyed_hash(secret, &material).as_bytes())
}

fn hash_ticket_material(hasher: &mut CanonicalHasher, ticket: &ResolutionTicket, include_id: bool) {
    if include_id {
        hasher.field_digest(ticket.id.digest());
    }
    hasher.field_u16(ticket.protocol_revision);
    hasher.field_digest(ticket.action_request.digest());
    hasher.field_str(ticket.action_contract.as_str());
    hasher.field_digest(ticket.semantic_definition_digest);
    hasher.field_digest(ticket.validation_definition_digest);
    hasher.field_digest(ticket.contract_operational_policy_digest);
    hasher.field_digest(ticket.effective_dispatch_policy_digest);
    hasher.field_digest(ticket.semantic_inputs_digest);
    hash_source_binding(hasher, ticket.source_binding);
    hasher.field_digest(ticket.resolution_digest);
    hasher.field_u8(effect_tag(ticket.allowed_effect));
    hasher.field_u8(publish_authority_tag(ticket.publish_authority));
    hash_optional_artifact(hasher, ticket.prior_artifact);
    hash_optional_digest(hasher, ticket.refresh_plan_digest);
    hash_limits(hasher, ticket.applied_limits);
    hasher.field_digest(ticket.caller_identity_digest);
    hasher.field_digest(ticket.nonce);
    hasher.field_bytes(&ticket.issued_at_unix_ms.to_le_bytes());
    hasher.field_bytes(&ticket.expires_at_unix_ms.to_le_bytes());
}

pub(super) fn keyed_digest(secret: &[u8; 32], domain: &[u8], fields: &[&[u8]]) -> Digest {
    let mut hasher = blake3::Hasher::new_keyed(secret);
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    for field in fields {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    Digest(*hasher.finalize().as_bytes())
}

fn hash_source_binding(hasher: &mut CanonicalHasher, binding: ResolutionSourceBinding) {
    hasher.field_digest(binding.semantic_source_context_digest);
    match binding.repository_generation {
        Some(generation) => {
            hasher.field_u8(1);
            hasher.field_bytes(&generation.to_le_bytes());
        }
        None => hasher.field_u8(0),
    }
    hash_optional_digest(hasher, binding.state_delta_digest);
    hasher.field_digest(binding.definition_set_digest);
}

fn hash_limits(hasher: &mut CanonicalHasher, limits: AppliedLimits) {
    hasher.field_u16(limits.max_candidates);
    hasher.field_u8(limits.max_artifacts);
    hasher.field_u8(limits.max_missing_obligations);
    hasher.field_u32(limits.max_worker_result_bytes);
}

fn hash_execution_hint(hasher: &mut CanonicalHasher, hint: &ExecutionHint) {
    match hint {
        ExecutionHint::DoNotStartWorker => hasher.field_u8(0),
        ExecutionHint::StartFreshWorker { action_request } => {
            hasher.field_u8(1);
            hasher.field_digest(action_request.digest());
        }
        ExecutionHint::StartRefreshWorker { prior_artifact, refresh_plan_digest } => {
            hasher.field_u8(2);
            hasher.field_digest(prior_artifact.digest());
            hasher.field_digest(*refresh_plan_digest);
        }
        ExecutionHint::ContinueNative { reason } => {
            hasher.field_u8(3);
            hasher.field_u8(reason_tag(*reason));
        }
        ExecutionHint::RequireApproval { approval_digest } => {
            hasher.field_u8(4);
            hasher.field_digest(*approval_digest);
        }
    }
}

fn hash_optional_artifact(hasher: &mut CanonicalHasher, value: Option<needle_core::ArtifactId>) {
    match value {
        Some(value) => {
            hasher.field_u8(1);
            hasher.field_digest(value.digest());
        }
        None => hasher.field_u8(0),
    }
}

fn hash_optional_digest(hasher: &mut CanonicalHasher, value: Option<Digest>) {
    match value {
        Some(value) => {
            hasher.field_u8(1);
            hasher.field_digest(value);
        }
        None => hasher.field_u8(0),
    }
}

const fn resolution_tag(value: ActionResolutionProjection) -> u8 {
    match value {
        ActionResolutionProjection::Exact => 0,
        ActionResolutionProjection::Project => 1,
        ActionResolutionProjection::Assemble => 2,
        ActionResolutionProjection::RefreshRequired => 3,
        ActionResolutionProjection::ComputeRequired => 4,
        ActionResolutionProjection::Partial => 5,
        ActionResolutionProjection::Bypass => 6,
        ActionResolutionProjection::Rejected => 7,
    }
}

const fn publish_authority_tag(value: PublishAuthority) -> u8 {
    match value {
        PublishAuthority::Forbidden => 0,
        PublishAuthority::FreshResult => 1,
        PublishAuthority::RefreshResult => 2,
    }
}

const fn capability_mode_tag(value: CapabilityMode) -> u8 {
    match value {
        CapabilityMode::Disabled => 0,
        CapabilityMode::Shadow => 1,
        CapabilityMode::Advisory => 2,
        CapabilityMode::Authoritative => 3,
    }
}

const fn effect_tag(value: EffectClass) -> u8 {
    match value {
        EffectClass::PureEvidence => 0,
        EffectClass::DerivedAnalysis => 1,
        EffectClass::TransformProposal => 2,
        EffectClass::ExecutionEvidence => 3,
        EffectClass::ExternalRead => 4,
        EffectClass::ExternalEffect => 5,
    }
}

const fn reason_tag(value: AwcpReasonCode) -> u8 {
    match value {
        AwcpReasonCode::Resolved => 0,
        AwcpReasonCode::ComputeRequired => 1,
        AwcpReasonCode::CapabilityUnsupported => 2,
        AwcpReasonCode::AuthorityInsufficient => 3,
        AwcpReasonCode::NativeBypass => 4,
        AwcpReasonCode::Rejected => 5,
        AwcpReasonCode::AcceptedForValidation => 6,
        AwcpReasonCode::ArtifactGranted => 7,
        AwcpReasonCode::ExecutionRecorded => 8,
    }
}
