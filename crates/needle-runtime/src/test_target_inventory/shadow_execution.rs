use super::{
    CargoTestTargetInventoryInput, CargoTestTargetRefreshAcquisition,
    CargoTestTargetRefreshFallback, CargoTestTargetRefreshInput, ShadowTestTargetInventoryRefresh,
    TestTargetInventoryRefreshDecision, TestTargetInventoryRefreshInput,
    TestTargetInventoryRuntimeError, TestTargetInventoryValidationCertificate,
    acquire_cargo_test_target_refresh_candidate, enumerate_cargo_test_targets,
    evaluate_test_target_inventory_refresh, resolve_test_target_inventory_refresh_or_full_compute,
    test_target_inventory_refresh_definition, validate_cargo_test_target_inventory,
};
use crate::{
    PartitionedActionHeadKey, RuntimeStore,
    ShadowEconomicallyAssessedPartitionedActionArtifactPublication,
    ShadowEconomicallySelectedRefreshedActionArtifactPublication, ShadowManifestContext,
    ShadowPartitionManifestError, ShadowPartitionManifestPublication,
    ShadowPartitionedActionArtifactPublication, ShadowPartitionedActionHeadAdvance,
    ShadowRefreshFallbackTrigger, ShadowRefreshResolution,
    ShadowRefreshedActionArtifactPublication, StoreError, built_in_action_for_artifact_kind,
    certify_test_target_inventory_action_artifact, certify_test_target_inventory_shadow_manifest,
};
use needle_core::{
    ActionRequest, ArtifactId, ArtifactKind, ArtifactValidationCertificateId, CapabilityMode,
    Digest, PartitionManifestId, RefreshAttempt, RefreshAttemptId, RefreshAttemptInput,
    RefreshCostEvidence, RefreshCostEvidenceBasis, RefreshCostEvidenceInput,
    RefreshEconomicAssessment, RefreshEconomicError, RefreshEconomicPolicy, RefreshOutcome,
    SemanticWorld, StateDelta, TestTargetInventory,
};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShadowRefreshCostEstimate {
    pub basis: RefreshCostEvidenceBasis,
    pub evidence_digest: Digest,
    pub pricing_revision: Option<Digest>,
    pub estimated_fresh_total_microusd: u64,
    pub estimated_refresh_total_microusd: u64,
    pub estimated_refresh_latency_micros: Option<u64>,
}

#[derive(Clone)]
pub struct ShadowCargoTestTargetRefreshExecutionInput<'a> {
    pub request: &'a ActionRequest,
    pub world: &'a SemanticWorld,
    pub definition_set_digest: Digest,
    pub prior_inventory: &'a TestTargetInventory,
    pub prior_validation: &'a TestTargetInventoryValidationCertificate,
    pub prior_manifest: &'a ShadowPartitionManifestPublication,
    pub prior_artifact: ArtifactId,
    pub current: CargoTestTargetInventoryInput<'a>,
    pub state_delta: &'a StateDelta,
    pub economic_policy: &'a RefreshEconomicPolicy,
    pub cost_estimate: Option<ShadowRefreshCostEstimate>,
    pub execution_scope_digest: Digest,
    pub execution_attempts: &'a [Digest],
    pub started_unix_ms: u64,
    pub observed_refresh_cost_microusd: Option<u64>,
    pub head: Option<ShadowTestTargetHeadExecutionContext<'a>>,
}

#[derive(Clone, Copy)]
pub struct ShadowTestTargetHeadExecutionContext<'a> {
    pub key: &'a PartitionedActionHeadKey,
    pub expected_prior_artifact: ArtifactId,
    pub repository_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowTestTargetPublicationReceipt {
    pub request: needle_core::ArtifactRequestId,
    pub artifact: ArtifactId,
    pub validation_certificate: ArtifactValidationCertificateId,
    pub descriptor_definition_digest: Digest,
    pub partition_manifest: PartitionManifestId,
    pub content_digest: Digest,
    pub authority: CapabilityMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShadowTestTargetRefreshExecutionFallback {
    Acquisition(CargoTestTargetRefreshFallback),
    Resolution(ShadowRefreshFallbackTrigger),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShadowTestTargetRefreshExecution {
    RefreshPublished {
        publication: ShadowTestTargetPublicationReceipt,
        attempt: RefreshAttemptId,
        assessment: Digest,
    },
    FullComputePublished {
        publication: ShadowTestTargetPublicationReceipt,
        trigger: ShadowTestTargetRefreshExecutionFallback,
        assessment: Option<Digest>,
    },
    PriorRemainsCurrent {
        publication: ShadowTestTargetPublicationReceipt,
        trigger: CargoTestTargetRefreshFallback,
    },
}

impl ShadowTestTargetRefreshExecution {
    pub const fn authority(&self) -> CapabilityMode {
        CapabilityMode::Shadow
    }
}

/// Execute the optional Cargo provider's first refresh contract in fixed
/// Shadow. The caller supplies a bounded provider snapshot; this function does
/// not launch Cargo and the generic partition kernel never interprets Cargo
/// keys or paths.
pub fn execute_shadow_cargo_test_target_refresh(
    store: &RuntimeStore,
    input: ShadowCargoTestTargetRefreshExecutionInput<'_>,
) -> Result<ShadowTestTargetRefreshExecution, ShadowTestTargetRefreshExecutionError> {
    let action = built_in_action_for_artifact_kind(&ArtifactKind::test_target_inventory())
        .ok_or(ShadowTestTargetRefreshExecutionError::ActionMissing)?;
    input
        .request
        .validate(&action.contract)
        .map_err(|error| ShadowTestTargetRefreshExecutionError::Request(error.to_string()))?;
    if input.economic_policy.action_operational_policy_digest
        != action.contract.operational_policy_digest
    {
        return Err(ShadowTestTargetRefreshExecutionError::PolicyBinding);
    }
    if store.partition_manifest_publication(input.prior_manifest.manifest.id)?.as_ref()
        != Some(input.prior_manifest)
    {
        return Err(ShadowTestTargetRefreshExecutionError::PriorPublication);
    }

    let acquisition = acquire_cargo_test_target_refresh_candidate(CargoTestTargetRefreshInput {
        current: input.current.clone(),
        prior_inventory: input.prior_inventory,
        prior_validation: input.prior_validation,
        state_delta: input.state_delta,
    })?;
    let candidate = match acquisition {
        CargoTestTargetRefreshAcquisition::Candidate { result } => result,
        CargoTestTargetRefreshAcquisition::FullCompute { reason } => {
            let fresh = compute_fresh(input.current.clone())?;
            if let Some(publication) = prior_receipt_if_unchanged(store, &input, &fresh)? {
                advance_unchanged_head(store, &input)?;
                return Ok(ShadowTestTargetRefreshExecution::PriorRemainsCurrent {
                    publication,
                    trigger: reason,
                });
            }
            let publication = publish_full_compute(store, &input, fresh, None)?;
            return Ok(ShadowTestTargetRefreshExecution::FullComputePublished {
                publication,
                trigger: ShadowTestTargetRefreshExecutionFallback::Acquisition(reason),
                assessment: None,
            });
        }
    };

    let manifest_issued_unix_ms = checked_now(input.started_unix_ms)?;
    let current_manifest = certify_test_target_inventory_shadow_manifest(
        ShadowManifestContext {
            request: input.request,
            world: input.world,
            definition_set_digest: input.definition_set_digest,
        },
        &candidate.inventory,
        &candidate.validation_certificate,
        manifest_issued_unix_ms,
    )?;
    let decision = evaluate_test_target_inventory_refresh(TestTargetInventoryRefreshInput {
        prior_inventory: input.prior_inventory,
        prior_validation: input.prior_validation,
        prior_publication: input.prior_manifest,
        current_inventory: &candidate.inventory,
        current_validation: &candidate.validation_certificate,
        current_publication: &current_manifest,
        state_delta: input.state_delta,
    })?;
    let evidence = evidence_for_decision(&input, &decision, &action.contract.id)?;
    let resolution = resolve_test_target_inventory_refresh_or_full_compute(
        input.request,
        &action.contract,
        decision,
        input.economic_policy,
        evidence.as_ref(),
        input.execution_scope_digest,
        || compute_fresh(input.current.clone()),
    )
    .map_err(|error| ShadowTestTargetRefreshExecutionError::Resolution(error.to_string()))?;

    match resolution {
        ShadowRefreshResolution::Refresh { result, assessment } => {
            publish_refresh(store, &input, *result, current_manifest, assessment)
        }
        ShadowRefreshResolution::FullCompute { result, trigger, assessment } => {
            let assessment_digest = assessment.as_ref().map(|value| value.definition_digest);
            let publication = publish_full_compute(store, &input, result, assessment.as_ref())?;
            Ok(ShadowTestTargetRefreshExecution::FullComputePublished {
                publication,
                trigger: ShadowTestTargetRefreshExecutionFallback::Resolution(trigger),
                assessment: assessment_digest,
            })
        }
    }
}

fn advance_unchanged_head(
    store: &RuntimeStore,
    input: &ShadowCargoTestTargetRefreshExecutionInput<'_>,
) -> Result<(), ShadowTestTargetRefreshExecutionError> {
    let Some(head) = input.head else { return Ok(()) };
    let validation_json = serde_json::to_vec(input.prior_validation)?;
    store.advance_existing_partitioned_action_head(ShadowPartitionedActionHeadAdvance {
        key: head.key.clone(),
        expected_prior_artifact: Some(head.expected_prior_artifact),
        repository_generation: head.repository_generation,
        source_validation_certificate_digest: input.prior_validation.certificate_digest,
        source_validation_validator_definition_digest: input
            .prior_validation
            .validator_definition_digest,
        source_validation_json: &validation_json,
        content_digest: input.prior_inventory.content_digest,
    })?;
    Ok(())
}

fn prior_receipt_if_unchanged(
    store: &RuntimeStore,
    input: &ShadowCargoTestTargetRefreshExecutionInput<'_>,
    fresh: &ValidatedInventory,
) -> Result<Option<ShadowTestTargetPublicationReceipt>, ShadowTestTargetRefreshExecutionError> {
    if fresh.inventory != *input.prior_inventory || fresh.validation != *input.prior_validation {
        return Ok(None);
    }
    let stored_artifact = store
        .semantic_artifact(&input.prior_artifact.to_string())?
        .ok_or(ShadowTestTargetRefreshExecutionError::PriorPublication)?;
    let expected = certify_test_target_inventory_action_artifact(
        input.request,
        input.prior_inventory,
        input.prior_validation,
        input.world,
        input.prior_manifest,
        stored_artifact.created_unix_ms,
    )?;
    let stored_certificate = store
        .action_artifact_validation_certificate(expected.certificate().id)?
        .ok_or(ShadowTestTargetRefreshExecutionError::PriorPublication)?;
    let stored_descriptor = store
        .stored_reuse_descriptor(expected.descriptor().definition_digest)?
        .ok_or(ShadowTestTargetRefreshExecutionError::PriorPublication)?;
    if ArtifactId::new(expected.artifact().id) != input.prior_artifact
        || *expected.artifact() != stored_artifact
        || *expected.certificate() != stored_certificate
        || *expected.descriptor() != stored_descriptor
    {
        return Err(ShadowTestTargetRefreshExecutionError::PriorPublication);
    }
    Ok(Some(publication_receipt(
        input.request,
        input.prior_manifest,
        &expected,
        input.prior_inventory,
    )))
}

fn evidence_for_decision(
    input: &ShadowCargoTestTargetRefreshExecutionInput<'_>,
    decision: &TestTargetInventoryRefreshDecision,
    action_contract: &needle_core::ActionContractId,
) -> Result<Option<RefreshCostEvidence>, ShadowTestTargetRefreshExecutionError> {
    let (Some(estimate), TestTargetInventoryRefreshDecision::Refresh { result }) =
        (input.cost_estimate, decision)
    else {
        return Ok(None);
    };
    Ok(Some(RefreshCostEvidence::new(RefreshCostEvidenceInput {
        request: input.request.semantic_id(),
        action_contract: action_contract.clone(),
        candidate_definition_digest: result.plan.definition_digest,
        operator_definition_digest: test_target_inventory_refresh_definition(),
        execution_scope_digest: input.execution_scope_digest,
        basis: estimate.basis,
        evidence_digest: estimate.evidence_digest,
        pricing_revision: estimate.pricing_revision,
        estimated_fresh_total_microusd: estimate.estimated_fresh_total_microusd,
        estimated_refresh_total_microusd: estimate.estimated_refresh_total_microusd,
        estimated_refresh_latency_micros: estimate.estimated_refresh_latency_micros,
    })?))
}

fn publish_refresh(
    store: &RuntimeStore,
    input: &ShadowCargoTestTargetRefreshExecutionInput<'_>,
    result: ShadowTestTargetInventoryRefresh,
    manifest: ShadowPartitionManifestPublication,
    assessment: RefreshEconomicAssessment,
) -> Result<ShadowTestTargetRefreshExecution, ShadowTestTargetRefreshExecutionError> {
    result.validate()?;
    if assessment.candidate_definition_digest != result.plan.definition_digest {
        return Err(ShadowTestTargetRefreshExecutionError::CandidateBinding);
    }
    store.publish_shadow_partition_manifest(&manifest)?;
    store.record_shadow_manifest_transition(&result.plan.transition)?;
    let completed_unix_ms = checked_now(input.started_unix_ms)?;
    let publication = certify_test_target_inventory_action_artifact(
        input.request,
        &result.reconstructed,
        &result.validation_certificate,
        input.world,
        &manifest,
        completed_unix_ms,
    )?;
    let attempt = RefreshAttempt::new(RefreshAttemptInput {
        request: input.request.semantic_id(),
        action_contract: input.request.contract.clone(),
        prior_artifact: input.prior_artifact,
        state_delta: result.plan.state_delta,
        prior_manifest: result.plan.prior_manifest,
        current_manifest: result.plan.current_manifest,
        manifest_transition: result.plan.transition.id,
        retained_partitions: result.plan.retained.clone(),
        refreshed_partitions: result.plan.refreshed.clone(),
        added_partitions: result.plan.added.clone(),
        removed_partitions: result.plan.removed.clone(),
        refresh_policy_definition_digest: input.economic_policy.refresh_policy_definition_digest,
        operator_definition_digest: test_target_inventory_refresh_definition(),
        execution_scope_digest: input.execution_scope_digest,
        execution_attempts: input.execution_attempts.to_vec(),
        started_unix_ms: input.started_unix_ms,
        completed_unix_ms,
        cost_microusd: input.observed_refresh_cost_microusd,
        outcome: RefreshOutcome::Succeeded {
            reconstructed_artifact: ArtifactId::new(publication.artifact().id),
            validation_certificate: publication.certificate().id,
        },
    })?;
    let receipt =
        publication_receipt(input.request, &manifest, &publication, &result.reconstructed);
    let economic_publication = ShadowEconomicallySelectedRefreshedActionArtifactPublication {
        refresh: ShadowRefreshedActionArtifactPublication {
            request: input.request,
            manifest: &manifest,
            result: &publication,
            attempt: &attempt,
        },
        assessment: &assessment,
    };
    if let Some(head) = input.head {
        let validation_json = serde_json::to_vec(&result.validation_certificate)?;
        store.publish_shadow_economically_selected_refreshed_action_artifact_and_advance_head(
            economic_publication,
            ShadowPartitionedActionHeadAdvance {
                key: head.key.clone(),
                expected_prior_artifact: Some(head.expected_prior_artifact),
                repository_generation: head.repository_generation,
                source_validation_certificate_digest: result
                    .validation_certificate
                    .certificate_digest,
                source_validation_validator_definition_digest: result
                    .validation_certificate
                    .validator_definition_digest,
                source_validation_json: &validation_json,
                content_digest: result.reconstructed.content_digest,
            },
        )?;
    } else {
        store
            .publish_shadow_economically_selected_refreshed_action_artifact(economic_publication)?;
    }
    Ok(ShadowTestTargetRefreshExecution::RefreshPublished {
        publication: receipt,
        attempt: attempt.id,
        assessment: assessment.definition_digest,
    })
}

fn publish_full_compute(
    store: &RuntimeStore,
    input: &ShadowCargoTestTargetRefreshExecutionInput<'_>,
    fresh: ValidatedInventory,
    assessment: Option<&RefreshEconomicAssessment>,
) -> Result<ShadowTestTargetPublicationReceipt, ShadowTestTargetRefreshExecutionError> {
    let completed_unix_ms = checked_now(input.started_unix_ms)?;
    let manifest = certify_test_target_inventory_shadow_manifest(
        ShadowManifestContext {
            request: input.request,
            world: input.world,
            definition_set_digest: input.definition_set_digest,
        },
        &fresh.inventory,
        &fresh.validation,
        completed_unix_ms,
    )?;
    store.publish_shadow_partition_manifest(&manifest)?;
    let publication = certify_test_target_inventory_action_artifact(
        input.request,
        &fresh.inventory,
        &fresh.validation,
        input.world,
        &manifest,
        completed_unix_ms,
    )?;
    let receipt = publication_receipt(input.request, &manifest, &publication, &fresh.inventory);
    let validation_json = input.head.map(|_| serde_json::to_vec(&fresh.validation)).transpose()?;
    if let Some(assessment) = assessment {
        let economic_publication = ShadowEconomicallyAssessedPartitionedActionArtifactPublication {
            request: input.request,
            manifest: &manifest,
            result: &publication,
            assessment,
        };
        if let (Some(head), Some(validation_json)) = (input.head, validation_json.as_deref()) {
            store
                .publish_shadow_economically_assessed_partitioned_action_artifact_and_advance_head(
                    economic_publication,
                    head_advance(head, &fresh, validation_json),
                )?;
        } else {
            store.publish_shadow_economically_assessed_partitioned_action_artifact(
                economic_publication,
            )?;
        }
    } else if let (Some(head), Some(validation_json)) = (input.head, validation_json.as_deref()) {
        store.publish_shadow_partitioned_action_artifact_and_advance_head(
            input.request,
            &manifest,
            &publication,
            head_advance(head, &fresh, validation_json),
        )?;
    } else {
        store.publish_shadow_partitioned_action_artifact(input.request, &manifest, &publication)?;
    }
    Ok(receipt)
}

fn head_advance<'a>(
    head: ShadowTestTargetHeadExecutionContext<'_>,
    fresh: &ValidatedInventory,
    validation_json: &'a [u8],
) -> ShadowPartitionedActionHeadAdvance<'a> {
    ShadowPartitionedActionHeadAdvance {
        key: head.key.clone(),
        expected_prior_artifact: Some(head.expected_prior_artifact),
        repository_generation: head.repository_generation,
        source_validation_certificate_digest: fresh.validation.certificate_digest,
        source_validation_validator_definition_digest: fresh.validation.validator_definition_digest,
        source_validation_json: validation_json,
        content_digest: fresh.inventory.content_digest,
    }
}

pub(super) fn publication_receipt(
    request: &ActionRequest,
    manifest: &ShadowPartitionManifestPublication,
    publication: &ShadowPartitionedActionArtifactPublication,
    inventory: &TestTargetInventory,
) -> ShadowTestTargetPublicationReceipt {
    ShadowTestTargetPublicationReceipt {
        request: request.semantic_id(),
        artifact: ArtifactId::new(publication.artifact().id),
        validation_certificate: publication.certificate().id,
        descriptor_definition_digest: publication.descriptor().definition_digest,
        partition_manifest: manifest.manifest.id,
        content_digest: inventory.content_digest,
        authority: CapabilityMode::Shadow,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ValidatedInventory {
    pub(super) inventory: TestTargetInventory,
    pub(super) validation: TestTargetInventoryValidationCertificate,
}

pub(super) fn compute_fresh(
    input: CargoTestTargetInventoryInput<'_>,
) -> Result<ValidatedInventory, TestTargetInventoryRuntimeError> {
    let inventory = enumerate_cargo_test_targets(input.clone())?;
    let validation = validate_cargo_test_target_inventory(input, &inventory)?;
    Ok(ValidatedInventory { inventory, validation })
}

pub(super) fn checked_now(
    started_unix_ms: u64,
) -> Result<u64, ShadowTestTargetRefreshExecutionError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShadowTestTargetRefreshExecutionError::Clock)?
        .as_millis()
        .try_into()
        .map_err(|_| ShadowTestTargetRefreshExecutionError::Clock)?;
    if now < started_unix_ms {
        return Err(ShadowTestTargetRefreshExecutionError::Timing);
    }
    Ok(now)
}

#[derive(Debug, Error)]
pub enum ShadowTestTargetRefreshExecutionError {
    #[error("the built-in test-target inventory action is missing")]
    ActionMissing,
    #[error("the action request is invalid: {0}")]
    Request(String),
    #[error("the refresh economic policy does not bind the action operational policy")]
    PolicyBinding,
    #[error("the selected economic assessment does not bind the validated refresh candidate")]
    CandidateBinding,
    #[error("the persisted prior partitioned publication is missing or does not match its inputs")]
    PriorPublication,
    #[error("the execution clock is unavailable")]
    Clock,
    #[error("the execution start time is later than completion")]
    Timing,
    #[error("refresh resolution failed: {0}")]
    Resolution(String),
    #[error(transparent)]
    Inventory(#[from] TestTargetInventoryRuntimeError),
    #[error(transparent)]
    Refresh(#[from] super::TestTargetInventoryRefreshError),
    #[error(transparent)]
    Manifest(#[from] ShadowPartitionManifestError),
    #[error(transparent)]
    Artifact(#[from] crate::PartitionedActionArtifactError),
    #[error(transparent)]
    Economics(#[from] RefreshEconomicError),
    #[error(transparent)]
    RefreshRecord(#[from] needle_core::RefreshRecordError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
