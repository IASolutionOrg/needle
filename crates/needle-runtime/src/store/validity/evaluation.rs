use super::super::definition_generations::read_definition_generation;
use super::super::generations::{read_delta, read_generation, read_head_generation};
use super::super::{RuntimeStore, StoreError};
use super::records::{
    current_definition_generation, insert_operational_validity_memo, load_artifact_pair,
    read_dependency_stamp, read_operational_validity_memo_for_state, validate_stored_pair,
};
use crate::{
    DependencyDeltaIntersection, DependencyLocatorSet, classify_dependency_delta,
    dependency_intersection_definition_digest, empty_input_artifact_state_digest,
};
use needle_core::{
    Artifact, ArtifactValidationCertificate, CanonicalHasher, DefinitionSetGeneration,
    DependencyStamp, DependencyStampId, Digest, EffectClass, FastValidityReason,
    FastValidityResult, OperationalValidityMemo, OperationalValidityMemoInput,
    OperationalValidityOutcome, RepositoryGeneration,
};
use rusqlite::TransactionBehavior;

impl RuntimeStore {
    /// Evaluates only repository-generation and registered-definition
    /// validity. Artifacts with inputs still fail closed in this method until
    /// the separate recursive input-state result is composed into the fast
    /// path. Positive results are memoized and may satisfy only the guarded
    /// action-native resolver freshness gate.
    pub fn evaluate_dependency_stamp(
        &self,
        id: DependencyStampId,
    ) -> Result<FastValidityResult, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stamp = read_dependency_stamp(&transaction, id)?.ok_or_else(|| {
            StoreError::DependencyValidityConflict(format!("dependency stamp {id} was not found"))
        })?;
        let (artifact, certificate, _) =
            load_artifact_pair(&transaction, stamp.artifact, stamp.validation_certificate)?;
        validate_stored_pair(&artifact, &certificate)?;
        validate_stamp_bindings(&stamp, &artifact, &certificate)?;

        let stamped_generation = read_generation(
            &transaction,
            stamp.repository_lineage,
            stamp.repository_context,
            stamp.repository_generation,
        )?
        .ok_or_else(|| {
            StoreError::DependencyValidityCorruption(
                "dependency stamp references a missing repository generation".to_owned(),
            )
        })?;
        if stamped_generation.digest != stamp.repository_generation_digest {
            return Err(StoreError::DependencyValidityCorruption(
                "dependency stamp repository generation digest does not match storage".to_owned(),
            ));
        }
        let current_generation_number =
            read_head_generation(&transaction, stamp.repository_lineage, stamp.repository_context)?
                .ok_or_else(|| {
                    StoreError::DependencyValidityCorruption(
                        "dependency stamp repository context lost its head".to_owned(),
                    )
                })?;
        let current_generation = read_generation(
            &transaction,
            stamp.repository_lineage,
            stamp.repository_context,
            current_generation_number,
        )?
        .ok_or_else(|| {
            StoreError::DependencyValidityCorruption(
                "current repository generation is missing".to_owned(),
            )
        })?;
        if current_generation.generation < stamp.repository_generation {
            transaction.commit()?;
            return Ok(revalidation(FastValidityReason::GenerationRegressed));
        }
        if !stamped_generation.reconciled || !current_generation.reconciled {
            transaction.commit()?;
            return Ok(revalidation(FastValidityReason::RepositoryGenerationUnreconciled));
        }

        let stamped_definitions =
            read_definition_generation(&transaction, stamp.definition_generation)?.ok_or_else(
                || {
                    StoreError::DependencyValidityCorruption(
                        "dependency stamp references a missing definition generation".to_owned(),
                    )
                },
            )?;
        validate_stamp_definition_bindings(&stamp, &stamped_definitions)?;
        let current_definitions =
            current_definition_generation(&transaction)?.ok_or_else(|| {
                StoreError::DependencyValidityCorruption(
                    "definition-set generation head is missing".to_owned(),
                )
            })?;
        if !definition_sets_match(&stamp, &current_definitions) {
            transaction.commit()?;
            return Ok(revalidation(FastValidityReason::DefinitionSetChanged));
        }
        if stamp.intersection_definition_digest != dependency_intersection_definition_digest() {
            transaction.commit()?;
            return Ok(revalidation(FastValidityReason::IntersectionDefinitionChanged));
        }
        if !certificate.input_artifacts.is_empty() {
            transaction.commit()?;
            return Ok(revalidation(FastValidityReason::ArtifactInputsRequireRecursiveValidation));
        }
        let Some(action) = crate::built_in_action_for_artifact_kind(&artifact.contract.kind) else {
            transaction.commit()?;
            return Ok(revalidation(FastValidityReason::UnsupportedEffectClass));
        };
        if !matches!(
            action.contract.effect_class,
            EffectClass::PureEvidence | EffectClass::DerivedAnalysis
        ) {
            transaction.commit()?;
            return Ok(revalidation(FastValidityReason::UnsupportedEffectClass));
        }

        let distance = current_generation.generation - stamp.repository_generation;
        if distance > crate::MAX_FAST_VALIDITY_DELTAS as u64 {
            transaction.commit()?;
            return Ok(revalidation(FastValidityReason::DeltaChainBound));
        }
        let input_state = empty_input_artifact_state_digest();
        let external_state = repository_only_external_version_state_digest();
        if let Some(memo) = read_operational_validity_memo_for_state(
            &transaction,
            stamp.id,
            current_generation.digest,
            current_definitions.digest,
            input_state,
            external_state,
            stamp.intersection_definition_digest,
        )? {
            validate_memo_bindings(&memo, &stamp, &current_generation, &current_definitions)?;
            transaction.commit()?;
            return Ok(result_from_memo(memo));
        }

        let locator_set = DependencyLocatorSet::from_manifest(&artifact.dependency_manifest)
            .map_err(|error| StoreError::DependencyValidityCorruption(error.to_string()))?;
        if locator_set.digest != stamp.dependency_locator_set_digest {
            return Err(StoreError::DependencyValidityCorruption(
                "dependency stamp locator set digest does not match the artifact".to_owned(),
            ));
        }
        let mut delta_chain = CanonicalHasher::new(b"repository-delta-chain-v1");
        hash_u64(&mut delta_chain, stamp.repository_generation);
        hash_u64(&mut delta_chain, current_generation.generation);
        hash_u64(&mut delta_chain, distance);
        for generation in (stamp.repository_generation + 1)..=current_generation.generation {
            let Some(delta) = read_delta(
                &transaction,
                stamp.repository_lineage,
                stamp.repository_context,
                generation,
            )?
            else {
                transaction.commit()?;
                return Ok(revalidation(FastValidityReason::DeltaUnavailable));
            };
            delta_chain.field_digest(delta.digest);
            match classify_dependency_delta(&locator_set, &delta).map_err(|error| {
                StoreError::DependencyValidityCorruption(format!(
                    "stored dependency delta could not be classified: {error}"
                ))
            })? {
                DependencyDeltaIntersection::Disjoint => {}
                DependencyDeltaIntersection::Intersects { .. } => {
                    transaction.commit()?;
                    return Ok(revalidation(FastValidityReason::DependencyIntersection));
                }
                DependencyDeltaIntersection::RequiresRevalidation { .. } => {
                    transaction.commit()?;
                    return Ok(revalidation(FastValidityReason::DeltaUncertain));
                }
            }
        }

        let outcome = if distance == 0 {
            OperationalValidityOutcome::Current
        } else {
            OperationalValidityOutcome::UnaffectedByDelta
        };
        let memo = OperationalValidityMemo::new(OperationalValidityMemoInput {
            dependency_stamp: stamp.id,
            artifact: stamp.artifact,
            validation_certificate: stamp.validation_certificate,
            repository_lineage: stamp.repository_lineage,
            repository_context: stamp.repository_context,
            source_generation: stamp.repository_generation,
            validated_through_generation: current_generation.generation,
            validated_through_generation_digest: current_generation.digest,
            definition_generation: current_definitions.generation,
            definition_generation_digest: current_definitions.digest,
            semantic_definition_set_digest: current_definitions.definition_set.semantic_set_digest,
            validation_definition_set_digest: current_definitions
                .definition_set
                .validation_set_digest,
            operational_definition_set_digest: current_definitions
                .definition_set
                .operational_set_digest,
            input_artifact_state_digest: input_state,
            external_version_state_digest: external_state,
            delta_chain_digest: delta_chain.finish(),
            intersection_definition_digest: stamp.intersection_definition_digest,
            outcome,
        })?;
        insert_operational_validity_memo(&transaction, &memo)?;
        transaction.commit()?;
        Ok(result_from_memo(memo))
    }
}

fn validate_stamp_bindings(
    stamp: &DependencyStamp,
    artifact: &Artifact,
    certificate: &ArtifactValidationCertificate,
) -> Result<(), StoreError> {
    let locator_set = DependencyLocatorSet::from_manifest(&artifact.dependency_manifest)
        .map_err(|error| StoreError::DependencyValidityCorruption(error.to_string()))?;
    if stamp.artifact.digest() != artifact.id
        || stamp.validation_certificate != certificate.id
        || stamp.repository_lineage != certificate.coverage.world.repository_lineage
        || stamp.dependency_manifest_digest != certificate.coverage.dependency_manifest_digest
        || stamp.dependency_locator_set_digest != locator_set.digest
        || stamp.intersection_definition_digest != locator_set.projection_definition_digest
        || stamp.semantic_world_digest != certificate.coverage.world.id()
    {
        return Err(StoreError::DependencyValidityCorruption(
            "dependency stamp does not bind to its artifact and certificate".to_owned(),
        ));
    }
    Ok(())
}

fn validate_stamp_definition_bindings(
    stamp: &DependencyStamp,
    definitions: &DefinitionSetGeneration,
) -> Result<(), StoreError> {
    if stamp.definition_generation != definitions.generation
        || stamp.definition_generation_digest != definitions.digest
        || stamp.semantic_definition_set_digest != definitions.definition_set.semantic_set_digest
        || stamp.validation_definition_set_digest
            != definitions.definition_set.validation_set_digest
        || stamp.operational_definition_set_digest
            != definitions.definition_set.operational_set_digest
    {
        return Err(StoreError::DependencyValidityCorruption(
            "dependency stamp does not bind to its definition generation".to_owned(),
        ));
    }
    Ok(())
}

fn definition_sets_match(stamp: &DependencyStamp, definitions: &DefinitionSetGeneration) -> bool {
    stamp.definition_generation_digest == definitions.digest
        && stamp.semantic_definition_set_digest == definitions.definition_set.semantic_set_digest
        && stamp.validation_definition_set_digest
            == definitions.definition_set.validation_set_digest
        && stamp.operational_definition_set_digest
            == definitions.definition_set.operational_set_digest
}

fn validate_memo_bindings(
    memo: &OperationalValidityMemo,
    stamp: &DependencyStamp,
    generation: &RepositoryGeneration,
    definitions: &DefinitionSetGeneration,
) -> Result<(), StoreError> {
    if memo.dependency_stamp != stamp.id
        || memo.artifact != stamp.artifact
        || memo.validation_certificate != stamp.validation_certificate
        || memo.repository_lineage != stamp.repository_lineage
        || memo.repository_context != stamp.repository_context
        || memo.source_generation != stamp.repository_generation
        || memo.validated_through_generation != generation.generation
        || memo.validated_through_generation_digest != generation.digest
        || memo.definition_generation != definitions.generation
        || memo.definition_generation_digest != definitions.digest
        || memo.semantic_definition_set_digest != definitions.definition_set.semantic_set_digest
        || memo.validation_definition_set_digest != definitions.definition_set.validation_set_digest
        || memo.operational_definition_set_digest
            != definitions.definition_set.operational_set_digest
        || memo.intersection_definition_digest != stamp.intersection_definition_digest
    {
        return Err(StoreError::DependencyValidityCorruption(
            "operational validity memo does not bind to current state".to_owned(),
        ));
    }
    Ok(())
}

fn revalidation(reason: FastValidityReason) -> FastValidityResult {
    FastValidityResult::RequiresRevalidation { reason }
}

fn result_from_memo(memo: OperationalValidityMemo) -> FastValidityResult {
    match memo.outcome {
        OperationalValidityOutcome::Current => FastValidityResult::Current { memo },
        OperationalValidityOutcome::UnaffectedByDelta => FastValidityResult::UnaffectedByDelta {
            updated_generation: memo.validated_through_generation,
            memo,
        },
    }
}

fn repository_only_external_version_state_digest() -> Digest {
    let mut hasher = CanonicalHasher::new(b"external-version-state-v1");
    hasher.field_str("not-applicable:repository-only-built-in-action");
    hasher.finish()
}

fn hash_u64(hasher: &mut CanonicalHasher, value: u64) {
    hasher.field_bytes(&value.to_le_bytes());
}
