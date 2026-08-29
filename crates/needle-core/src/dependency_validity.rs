use crate::{
    ArtifactId, ArtifactValidationCertificateId, CanonicalHasher, DependencyStampId, Digest,
    OperationalValidityMemoId, RepositoryContextId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEPENDENCY_STAMP_FORMAT_REVISION: u16 = 1;
pub const OPERATIONAL_VALIDITY_MEMO_FORMAT_REVISION: u16 = 1;
pub const MAX_DEPENDENCY_STAMP_WIRE_BYTES: usize = 16 * 1024;
pub const MAX_OPERATIONAL_VALIDITY_MEMO_WIRE_BYTES: usize = 24 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyStampInput {
    pub artifact: ArtifactId,
    pub validation_certificate: ArtifactValidationCertificateId,
    pub repository_lineage: Digest,
    pub repository_context: RepositoryContextId,
    pub repository_generation: u64,
    pub repository_generation_digest: Digest,
    pub dependency_manifest_digest: Digest,
    pub dependency_locator_set_digest: Digest,
    pub intersection_definition_digest: Digest,
    pub definition_generation: u64,
    pub definition_generation_digest: Digest,
    pub semantic_definition_set_digest: Digest,
    pub validation_definition_set_digest: Digest,
    pub operational_definition_set_digest: Digest,
    pub semantic_world_digest: Digest,
}

/// Immutable binding between one validated artifact and the exact local
/// repository/definition generations against which it was produced.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyStamp {
    pub format_revision: u16,
    pub id: DependencyStampId,
    pub artifact: ArtifactId,
    pub validation_certificate: ArtifactValidationCertificateId,
    pub repository_lineage: Digest,
    pub repository_context: RepositoryContextId,
    pub repository_generation: u64,
    pub repository_generation_digest: Digest,
    pub dependency_manifest_digest: Digest,
    pub dependency_locator_set_digest: Digest,
    pub intersection_definition_digest: Digest,
    pub definition_generation: u64,
    pub definition_generation_digest: Digest,
    pub semantic_definition_set_digest: Digest,
    pub validation_definition_set_digest: Digest,
    pub operational_definition_set_digest: Digest,
    pub semantic_world_digest: Digest,
}

impl DependencyStamp {
    pub fn new(input: DependencyStampInput) -> Self {
        let mut value = Self {
            format_revision: DEPENDENCY_STAMP_FORMAT_REVISION,
            id: DependencyStampId::new(Digest([0; 32])),
            artifact: input.artifact,
            validation_certificate: input.validation_certificate,
            repository_lineage: input.repository_lineage,
            repository_context: input.repository_context,
            repository_generation: input.repository_generation,
            repository_generation_digest: input.repository_generation_digest,
            dependency_manifest_digest: input.dependency_manifest_digest,
            dependency_locator_set_digest: input.dependency_locator_set_digest,
            intersection_definition_digest: input.intersection_definition_digest,
            definition_generation: input.definition_generation,
            definition_generation_digest: input.definition_generation_digest,
            semantic_definition_set_digest: input.semantic_definition_set_digest,
            validation_definition_set_digest: input.validation_definition_set_digest,
            operational_definition_set_digest: input.operational_definition_set_digest,
            semantic_world_digest: input.semantic_world_digest,
        };
        value.id = DependencyStampId::new(value.compute_digest());
        value
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, DependencyValidityRecordError> {
        if bytes.len() > MAX_DEPENDENCY_STAMP_WIRE_BYTES {
            return Err(DependencyValidityRecordError::WireBound {
                record: "dependency_stamp",
                actual: bytes.len(),
                maximum: MAX_DEPENDENCY_STAMP_WIRE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| DependencyValidityRecordError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DependencyValidityRecordError> {
        if self.format_revision != DEPENDENCY_STAMP_FORMAT_REVISION {
            return Err(DependencyValidityRecordError::FormatRevision {
                record: "dependency_stamp",
                actual: self.format_revision,
            });
        }
        if self.id.digest() != self.compute_digest() {
            return Err(DependencyValidityRecordError::Digest("dependency_stamp.id"));
        }
        Ok(())
    }

    pub fn is_canonical(&self) -> bool {
        self.validate().is_ok()
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"dependency-stamp-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.artifact.digest());
        hasher.field_digest(self.validation_certificate.digest());
        hasher.field_digest(self.repository_lineage);
        hasher.field_digest(self.repository_context.digest());
        hash_u64(&mut hasher, self.repository_generation);
        hasher.field_digest(self.repository_generation_digest);
        hasher.field_digest(self.dependency_manifest_digest);
        hasher.field_digest(self.dependency_locator_set_digest);
        hasher.field_digest(self.intersection_definition_digest);
        hash_u64(&mut hasher, self.definition_generation);
        hasher.field_digest(self.definition_generation_digest);
        hasher.field_digest(self.semantic_definition_set_digest);
        hasher.field_digest(self.validation_definition_set_digest);
        hasher.field_digest(self.operational_definition_set_digest);
        hasher.field_digest(self.semantic_world_digest);
        hasher.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalValidityOutcome {
    Current,
    UnaffectedByDelta,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalValidityMemoInput {
    pub dependency_stamp: DependencyStampId,
    pub artifact: ArtifactId,
    pub validation_certificate: ArtifactValidationCertificateId,
    pub repository_lineage: Digest,
    pub repository_context: RepositoryContextId,
    pub source_generation: u64,
    pub validated_through_generation: u64,
    pub validated_through_generation_digest: Digest,
    pub definition_generation: u64,
    pub definition_generation_digest: Digest,
    pub semantic_definition_set_digest: Digest,
    pub validation_definition_set_digest: Digest,
    pub operational_definition_set_digest: Digest,
    pub input_artifact_state_digest: Digest,
    pub external_version_state_digest: Digest,
    pub delta_chain_digest: Digest,
    pub intersection_definition_digest: Digest,
    pub outcome: OperationalValidityOutcome,
}

/// Revocable operational cache record. It is never artifact identity and is
/// usable only when every key field still matches current runtime state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalValidityMemo {
    pub format_revision: u16,
    pub id: OperationalValidityMemoId,
    pub dependency_stamp: DependencyStampId,
    pub artifact: ArtifactId,
    pub validation_certificate: ArtifactValidationCertificateId,
    pub repository_lineage: Digest,
    pub repository_context: RepositoryContextId,
    pub source_generation: u64,
    pub validated_through_generation: u64,
    pub validated_through_generation_digest: Digest,
    pub definition_generation: u64,
    pub definition_generation_digest: Digest,
    pub semantic_definition_set_digest: Digest,
    pub validation_definition_set_digest: Digest,
    pub operational_definition_set_digest: Digest,
    pub input_artifact_state_digest: Digest,
    pub external_version_state_digest: Digest,
    pub delta_chain_digest: Digest,
    pub intersection_definition_digest: Digest,
    pub outcome: OperationalValidityOutcome,
}

impl OperationalValidityMemo {
    pub fn new(input: OperationalValidityMemoInput) -> Result<Self, DependencyValidityRecordError> {
        let mut value = Self {
            format_revision: OPERATIONAL_VALIDITY_MEMO_FORMAT_REVISION,
            id: OperationalValidityMemoId::new(Digest([0; 32])),
            dependency_stamp: input.dependency_stamp,
            artifact: input.artifact,
            validation_certificate: input.validation_certificate,
            repository_lineage: input.repository_lineage,
            repository_context: input.repository_context,
            source_generation: input.source_generation,
            validated_through_generation: input.validated_through_generation,
            validated_through_generation_digest: input.validated_through_generation_digest,
            definition_generation: input.definition_generation,
            definition_generation_digest: input.definition_generation_digest,
            semantic_definition_set_digest: input.semantic_definition_set_digest,
            validation_definition_set_digest: input.validation_definition_set_digest,
            operational_definition_set_digest: input.operational_definition_set_digest,
            input_artifact_state_digest: input.input_artifact_state_digest,
            external_version_state_digest: input.external_version_state_digest,
            delta_chain_digest: input.delta_chain_digest,
            intersection_definition_digest: input.intersection_definition_digest,
            outcome: input.outcome,
        };
        value.validate_shape()?;
        value.id = OperationalValidityMemoId::new(value.compute_digest());
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, DependencyValidityRecordError> {
        if bytes.len() > MAX_OPERATIONAL_VALIDITY_MEMO_WIRE_BYTES {
            return Err(DependencyValidityRecordError::WireBound {
                record: "operational_validity_memo",
                actual: bytes.len(),
                maximum: MAX_OPERATIONAL_VALIDITY_MEMO_WIRE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| DependencyValidityRecordError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DependencyValidityRecordError> {
        self.validate_shape()?;
        if self.id.digest() != self.compute_digest() {
            return Err(DependencyValidityRecordError::Digest("operational_validity_memo.id"));
        }
        Ok(())
    }

    pub fn is_canonical(&self) -> bool {
        self.validate().is_ok()
    }

    fn validate_shape(&self) -> Result<(), DependencyValidityRecordError> {
        if self.format_revision != OPERATIONAL_VALIDITY_MEMO_FORMAT_REVISION {
            return Err(DependencyValidityRecordError::FormatRevision {
                record: "operational_validity_memo",
                actual: self.format_revision,
            });
        }
        let valid_generation_shape = match self.outcome {
            OperationalValidityOutcome::Current => {
                self.source_generation == self.validated_through_generation
            }
            OperationalValidityOutcome::UnaffectedByDelta => {
                self.source_generation < self.validated_through_generation
            }
        };
        if !valid_generation_shape {
            return Err(DependencyValidityRecordError::GenerationOutcome);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"operational-validity-memo-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.dependency_stamp.digest());
        hasher.field_digest(self.artifact.digest());
        hasher.field_digest(self.validation_certificate.digest());
        hasher.field_digest(self.repository_lineage);
        hasher.field_digest(self.repository_context.digest());
        hash_u64(&mut hasher, self.source_generation);
        hash_u64(&mut hasher, self.validated_through_generation);
        hasher.field_digest(self.validated_through_generation_digest);
        hash_u64(&mut hasher, self.definition_generation);
        hasher.field_digest(self.definition_generation_digest);
        hasher.field_digest(self.semantic_definition_set_digest);
        hasher.field_digest(self.validation_definition_set_digest);
        hasher.field_digest(self.operational_definition_set_digest);
        hasher.field_digest(self.input_artifact_state_digest);
        hasher.field_digest(self.external_version_state_digest);
        hasher.field_digest(self.delta_chain_digest);
        hasher.field_digest(self.intersection_definition_digest);
        hasher.field_u8(match self.outcome {
            OperationalValidityOutcome::Current => 0,
            OperationalValidityOutcome::UnaffectedByDelta => 1,
        });
        hasher.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastValidityReason {
    ArtifactInputsRequireRecursiveValidation,
    DefinitionSetChanged,
    DeltaChainBound,
    DependencyIntersection,
    DeltaUnavailable,
    DeltaUncertain,
    GenerationRegressed,
    IntersectionDefinitionChanged,
    RepositoryGenerationUnreconciled,
    UnsupportedEffectClass,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FastValidityResult {
    Current { memo: OperationalValidityMemo },
    UnaffectedByDelta { updated_generation: u64, memo: OperationalValidityMemo },
    RequiresRevalidation { reason: FastValidityReason },
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DependencyValidityRecordError {
    #[error("unsupported {record} format revision {actual}")]
    FormatRevision { record: &'static str, actual: u16 },
    #[error("{record} exceeds its wire bound: {actual} > {maximum}")]
    WireBound { record: &'static str, actual: usize, maximum: usize },
    #[error("canonical digest mismatch for {0}")]
    Digest(&'static str),
    #[error("operational validity outcome does not match its generation interval")]
    GenerationOutcome,
    #[error("dependency validity JSON is invalid: {0}")]
    Json(String),
}

fn hash_u64(hasher: &mut CanonicalHasher, value: u64) {
    hasher.field_bytes(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> Digest {
        Digest::blake3(label)
    }

    fn stamp() -> DependencyStamp {
        DependencyStamp::new(DependencyStampInput {
            artifact: ArtifactId::new(digest("artifact")),
            validation_certificate: ArtifactValidationCertificateId::new(digest("certificate")),
            repository_lineage: digest("lineage"),
            repository_context: RepositoryContextId::new(digest("context")),
            repository_generation: 4,
            repository_generation_digest: digest("generation"),
            dependency_manifest_digest: digest("manifest"),
            dependency_locator_set_digest: digest("locators"),
            intersection_definition_digest: digest("intersection"),
            definition_generation: 2,
            definition_generation_digest: digest("definition-generation"),
            semantic_definition_set_digest: digest("semantic-set"),
            validation_definition_set_digest: digest("validation-set"),
            operational_definition_set_digest: digest("operational-set"),
            semantic_world_digest: digest("world"),
        })
    }

    fn memo_input(stamp: &DependencyStamp) -> OperationalValidityMemoInput {
        OperationalValidityMemoInput {
            dependency_stamp: stamp.id,
            artifact: stamp.artifact,
            validation_certificate: stamp.validation_certificate,
            repository_lineage: stamp.repository_lineage,
            repository_context: stamp.repository_context,
            source_generation: stamp.repository_generation,
            validated_through_generation: stamp.repository_generation + 2,
            validated_through_generation_digest: digest("current-generation"),
            definition_generation: stamp.definition_generation,
            definition_generation_digest: stamp.definition_generation_digest,
            semantic_definition_set_digest: stamp.semantic_definition_set_digest,
            validation_definition_set_digest: stamp.validation_definition_set_digest,
            operational_definition_set_digest: stamp.operational_definition_set_digest,
            input_artifact_state_digest: digest("empty-input-state"),
            external_version_state_digest: digest("no-external-state"),
            delta_chain_digest: digest("delta-chain"),
            intersection_definition_digest: stamp.intersection_definition_digest,
            outcome: OperationalValidityOutcome::UnaffectedByDelta,
        }
    }

    #[test]
    fn dependency_stamp_round_trips_and_detects_tampering() {
        let canonical = stamp();
        assert!(canonical.is_canonical());
        let json = serde_json::to_vec(&canonical).unwrap();
        assert_eq!(DependencyStamp::decode_json(&json).unwrap(), canonical);

        let mut tampered = canonical;
        tampered.repository_generation += 1;
        assert_eq!(
            tampered.validate(),
            Err(DependencyValidityRecordError::Digest("dependency_stamp.id"))
        );
    }

    #[test]
    fn memo_round_trips_and_enforces_outcome_generation_shape() {
        let stamp = stamp();
        let memo = OperationalValidityMemo::new(memo_input(&stamp)).unwrap();
        let json = serde_json::to_vec(&memo).unwrap();
        assert_eq!(OperationalValidityMemo::decode_json(&json).unwrap(), memo);

        let mut invalid = memo_input(&stamp);
        invalid.outcome = OperationalValidityOutcome::Current;
        assert_eq!(
            OperationalValidityMemo::new(invalid),
            Err(DependencyValidityRecordError::GenerationOutcome)
        );
    }

    #[test]
    fn record_decoders_enforce_wire_bounds_before_json_decode() {
        assert!(matches!(
            DependencyStamp::decode_json(&vec![b'x'; MAX_DEPENDENCY_STAMP_WIRE_BYTES + 1]),
            Err(DependencyValidityRecordError::WireBound { record: "dependency_stamp", .. })
        ));
        assert!(matches!(
            OperationalValidityMemo::decode_json(&vec![
                b'x';
                MAX_OPERATIONAL_VALIDITY_MEMO_WIRE_BYTES + 1
            ]),
            Err(DependencyValidityRecordError::WireBound {
                record: "operational_validity_memo",
                ..
            })
        ));
    }

    #[test]
    fn dependency_validity_record_digests_are_stable() {
        let stamp = stamp();
        assert_eq!(
            stamp.id.digest(),
            Digest::parse("b3:ad99f2f651d8f46d370ca1ebfbb20fc2706a6be5d493b2c8cb4dad38bec3bb47")
                .unwrap()
        );
        let memo = OperationalValidityMemo::new(memo_input(&stamp)).unwrap();
        assert_eq!(
            memo.id.digest(),
            Digest::parse("b3:1aa945276f896742a0f7146ecd7694536cf265c89072c958c6be9f391abd6ac0")
                .unwrap()
        );
    }
}
