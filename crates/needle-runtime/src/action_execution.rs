use crate::{
    BuiltInActionCoverage, ChangeActionOutput, OpaqueActionCertificationInput, RuntimeStore,
    ShadowPartitionManifestPublication, StoreError, built_in_action_contracts,
    certify_review_action_artifact, certify_shadow_opaque_action_artifact,
};
use needle_core::{
    ActionRequest, Artifact, ArtifactId, ArtifactRequest, ArtifactValidationCertificateId,
    CacheScope, CapabilityMode, ChangeActionInput, DependencyManifest, Digest, HostUsage,
    LifecycleUsage, Need, NeedExecution, NeedExecutionEnvelopeV1, NeedFragment, SemanticWorld,
    built_in_route_contracts, compile_need, need_fragment,
};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct ChangeActionProviderContext<'a> {
    pub operation_id: Digest,
    pub need: &'a Need,
    pub fragment: &'a NeedFragment,
    pub request: &'a ActionRequest,
    pub input: &'a ChangeActionInput,
    pub definition_set_digest: Digest,
}

#[derive(Clone, Debug)]
pub struct ChangeActionProviderOutput {
    pub output: ChangeActionOutput,
    pub world: SemanticWorld,
    pub dependency_manifest: DependencyManifest,
    pub review_manifest: Option<ShadowPartitionManifestPublication>,
    pub review_transition: Option<needle_core::ManifestTransition>,
    pub usage: LifecycleUsage,
    pub host_usage: Option<HostUsage>,
}

pub trait ChangeActionProvider: Send + Sync {
    fn execute(
        &self,
        context: ChangeActionProviderContext<'_>,
    ) -> Result<ChangeActionProviderOutput, ChangeActionProviderError>;
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("change action provider failed: {message}")]
pub struct ChangeActionProviderError {
    pub message: String,
}

impl ChangeActionProviderError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionExecutionResult {
    pub operation_id: Digest,
    pub request: ActionRequest,
    pub output: ChangeActionOutput,
    pub artifact: Artifact,
    pub validation_certificate: ArtifactValidationCertificateId,
    pub partition_manifest: Option<needle_core::PartitionManifestId>,
    pub usage: LifecycleUsage,
    pub host_usage: Option<HostUsage>,
    pub authority: CapabilityMode,
    pub completion_reused: bool,
    pub idempotent_replay: bool,
}

pub struct ActionExecutionService<P> {
    store: RuntimeStore,
    provider: P,
}

impl<P> ActionExecutionService<P>
where
    P: ChangeActionProvider,
{
    pub fn new(store: RuntimeStore, provider: P) -> Self {
        Self { store, provider }
    }

    pub fn execute_action(
        &self,
        envelope: &NeedExecutionEnvelopeV1,
        repository_id: Digest,
        source_snapshot: Digest,
    ) -> Result<ActionExecutionResult, ActionExecutionError> {
        envelope.validate()?;
        if repository_id == Digest([0; 32]) || source_snapshot == Digest([0; 32]) {
            return Err(ActionExecutionError::RepositoryBinding);
        }
        let NeedExecution::Action { action } = &envelope.execution else {
            return Err(ActionExecutionError::OperationKind);
        };
        let compiled = compile_action_request(envelope, repository_id, source_snapshot)?;
        self.store.ensure_certified_action_inputs(
            &compiled
                .request
                .artifact_request
                .input_artifact_ids
                .iter()
                .copied()
                .map(ArtifactId::new)
                .collect::<Vec<_>>(),
        )?;
        match self.store.claim_action_execution_operation(
            envelope.operation_id,
            compiled.request.semantic_id(),
        )? {
            crate::store::ActionExecutionOperationClaim::Completed {
                artifact,
                validation_certificate,
                partition_manifest,
                usage,
                host_usage,
            } => {
                let artifact =
                    self.store.semantic_artifact(&artifact.to_string())?.ok_or_else(|| {
                        ActionExecutionError::OperationCorruption(
                            "completed operation artifact is missing".to_owned(),
                        )
                    })?;
                if artifact.request_id != compiled.request.semantic_id().digest() {
                    return Err(ActionExecutionError::OperationCorruption(
                        "completed operation artifact request binding changed".to_owned(),
                    ));
                }
                let output = ChangeActionOutput::from_artifact(&artifact)?;
                output.validate_for_execution(
                    envelope.operation_id,
                    &action.input,
                    &compiled.request,
                )?;
                return Ok(ActionExecutionResult {
                    operation_id: envelope.operation_id,
                    request: compiled.request,
                    output,
                    artifact,
                    validation_certificate,
                    partition_manifest,
                    usage,
                    host_usage,
                    authority: CapabilityMode::Shadow,
                    completion_reused: false,
                    idempotent_replay: true,
                });
            }
            crate::store::ActionExecutionOperationClaim::Execute { resumed: true }
                if !matches!(action.input, ChangeActionInput::PatchApply { .. }) =>
            {
                return Err(ActionExecutionError::OperationRecoveryRequired);
            }
            crate::store::ActionExecutionOperationClaim::Execute { resumed: _ } => {}
        }

        // All Phase 8 registrations remain Shadow. Shadow material can be
        // observed, but never suppresses the provider invocation.
        let provider = self.provider.execute(ChangeActionProviderContext {
            operation_id: envelope.operation_id,
            need: &compiled.need,
            fragment: &compiled.fragment,
            request: &compiled.request,
            input: &action.input,
            definition_set_digest: crate::active_definition_set().audit_digest,
        })?;
        if provider.world != compiled.need.world
            || provider.dependency_manifest.scope != CacheScope::SnapshotExact
        {
            return Err(ActionExecutionError::ProviderBinding);
        }
        provider.output.validate_for_execution(
            envelope.operation_id,
            &action.input,
            &compiled.request,
        )?;
        let output = provider.output;
        let usage = provider.usage;
        let host_usage = provider.host_usage;

        let result = match (
            &compiled.definition.coverage,
            output.clone(),
            provider.review_manifest,
            provider.review_transition,
        ) {
            (BuiltInActionCoverage::Opaque { .. }, output, None, None) => {
                let (request, publication) =
                    certify_shadow_opaque_action_artifact(OpaqueActionCertificationInput {
                        request: compiled.request,
                        source_payload_digest: output.source_payload_digest(),
                        output: output.clone(),
                        world: provider.world,
                        dependency_manifest: provider.dependency_manifest,
                        issued_unix_ms: crate::store::now_ms(),
                    })?;
                self.store.publish_shadow_opaque_action_execution(
                    envelope.operation_id,
                    &request,
                    &publication,
                    crate::store::ActionExecutionUsage::new(&usage, host_usage.as_ref()),
                )?;
                ActionExecutionResult {
                    operation_id: envelope.operation_id,
                    request,
                    output,
                    artifact: publication.artifact().clone(),
                    validation_certificate: publication.certificate().id,
                    partition_manifest: None,
                    usage: usage.clone(),
                    host_usage: host_usage.clone(),
                    authority: CapabilityMode::Shadow,
                    completion_reused: false,
                    idempotent_replay: false,
                }
            }
            (
                BuiltInActionCoverage::Partitioned { .. },
                ChangeActionOutput::Review(report),
                Some(manifest),
                transition,
            ) => {
                let publication = certify_review_action_artifact(
                    &compiled.request,
                    &report,
                    &provider.world,
                    provider.dependency_manifest,
                    &manifest,
                    crate::store::now_ms(),
                )?;
                self.store.publish_shadow_partitioned_action_execution(
                    envelope.operation_id,
                    &compiled.request,
                    &manifest,
                    &publication,
                    transition.as_ref(),
                    crate::store::ActionExecutionUsage::new(&usage, host_usage.as_ref()),
                )?;
                ActionExecutionResult {
                    operation_id: envelope.operation_id,
                    request: compiled.request,
                    output: ChangeActionOutput::Review(report),
                    artifact: publication.artifact().clone(),
                    validation_certificate: publication.certificate().id,
                    partition_manifest: Some(manifest.manifest.id),
                    usage: usage.clone(),
                    host_usage: host_usage.clone(),
                    authority: CapabilityMode::Shadow,
                    completion_reused: false,
                    idempotent_replay: false,
                }
            }
            _ => return Err(ActionExecutionError::ProviderCoverage),
        };
        Ok(result)
    }
}

struct CompiledActionRequest {
    definition: &'static crate::BuiltInActionDefinition,
    need: Need,
    fragment: NeedFragment,
    request: ActionRequest,
}

fn compile_action_request(
    envelope: &NeedExecutionEnvelopeV1,
    repository_id: Digest,
    source_snapshot: Digest,
) -> Result<CompiledActionRequest, ActionExecutionError> {
    let NeedExecution::Action { action } = &envelope.execution else {
        return Err(ActionExecutionError::OperationKind);
    };
    let route_key = envelope.need.route_hint.as_ref().ok_or(ActionExecutionError::Route)?;
    let route = built_in_route_contracts()
        .into_iter()
        .find(|candidate| &candidate.route == route_key)
        .ok_or(ActionExecutionError::Route)?;
    let need = compile_need(&envelope.need, repository_id, &route)
        .map_err(|error| ActionExecutionError::Need(error.to_string()))?;
    let definition = built_in_action_contracts()
        .iter()
        .find(|definition| definition.contract.id == action.contract)
        .ok_or(ActionExecutionError::ActionDefinition)?;
    let mut inputs = need.input_artifacts.clone();
    inputs.extend(action.input.artifact_inputs());
    inputs.sort_unstable();
    inputs.dedup();
    if inputs.len() > needle_core::MAX_NEED_INPUTS {
        return Err(ActionExecutionError::InputBound);
    }
    let mut obligations = need.required.clone();
    obligations.extend(need.preferred.clone());
    let fragment = need_fragment(&need, obligations, inputs);
    if !fragment.is_consistent() {
        return Err(ActionExecutionError::Fragment);
    }
    let request = ActionRequest::new_with_semantic_parameters(
        &definition.contract,
        ArtifactRequest {
            contract_id: definition.output_contract_id.to_owned(),
            contract_revision: definition.output_contract_revision,
            repository_id,
            source_snapshot_digest: source_snapshot,
            route_key: route_key.clone(),
            normalized_request: envelope.need.body.clone(),
            semantic_fragment_id: Some(fragment.id),
            input_artifact_ids: fragment
                .semantic_inputs
                .iter()
                .map(|input| input.digest())
                .collect(),
        },
        action.input.semantic_parameter_digest(source_snapshot),
        definition.contract.default_dispatch_policy,
        route_key.clone(),
        need.id,
    )
    .map_err(|error| ActionExecutionError::Request(error.to_string()))?;
    Ok(CompiledActionRequest { definition, need, fragment, request })
}

#[derive(Debug, Error)]
pub enum ActionExecutionError {
    #[error(transparent)]
    Envelope(#[from] needle_core::NeedExecutionValidationError),
    #[error("action execution requires a non-zero repository and source snapshot")]
    RepositoryBinding,
    #[error("ActionExecutionService only accepts execution=action")]
    OperationKind,
    #[error("Need execution route is not registered")]
    Route,
    #[error("Need compilation failed: {0}")]
    Need(String),
    #[error("action contract is not registered")]
    ActionDefinition,
    #[error("action semantic inputs exceed the hard bound")]
    InputBound,
    #[error("compiled action NeedFragment is inconsistent")]
    Fragment,
    #[error("action request compilation failed: {0}")]
    Request(String),
    #[error("provider output world, source, or dependency scope is not request-bound")]
    ProviderBinding,
    #[error("provider output does not match the action coverage contract")]
    ProviderCoverage,
    #[error("stored action execution operation is corrupt: {0}")]
    OperationCorruption(String),
    #[error(
        "action invocation is durably in progress; confirm the provider stopped and recover it instead of repeating the call"
    )]
    OperationRecoveryRequired,
    #[error(transparent)]
    Provider(#[from] ChangeActionProviderError),
    #[error(transparent)]
    Opaque(#[from] crate::OpaqueActionArtifactError),
    #[error(transparent)]
    Partitioned(#[from] crate::PartitionedActionArtifactError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[cfg(test)]
mod tests;
