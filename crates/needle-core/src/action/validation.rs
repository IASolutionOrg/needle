use super::ActionContractId;
use crate::{
    ArtifactId, ArtifactValidationCertificateId, CanonicalHasher, CapabilityMode, CoverageManifest,
    Digest, MAX_NEED_INPUTS, MAX_NEED_IR_BYTES, PartitionManifestId,
};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use thiserror::Error;

pub const ACTION_ARTIFACT_VALIDATION_CERTIFICATE_FORMAT_REVISION: u16 = 1;
pub const MAX_ACTION_ARTIFACT_VALIDATION_CERTIFICATE_WIRE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionArtifactValidationCertificateInput {
    pub artifact: ArtifactId,
    pub input_artifacts: Vec<ArtifactId>,
    pub action_contract: ActionContractId,
    pub action_semantic_definition_digest: Digest,
    pub action_validation_definition_digest: Digest,
    pub output_contract_definition_digest: Digest,
    pub partition_manifest: PartitionManifestId,
    pub source_payload_digest: Digest,
    pub source_validation_certificate_digest: Digest,
    pub coverage: CoverageManifest,
    pub validator_definition_digest: Digest,
    pub issued_unix_ms: u64,
}

/// Action-aware validation envelope for a partitioned artifact.
///
/// It binds a normal immutable artifact to the action definitions, the
/// certified partition manifest, and the producer-specific validation proof.
/// Revision 1 is fixed to Shadow and grants no serving authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionArtifactValidationCertificate {
    pub format_revision: u16,
    pub id: ArtifactValidationCertificateId,
    pub artifact: ArtifactId,
    #[serde(deserialize_with = "deserialize_input_artifacts")]
    pub input_artifacts: Vec<ArtifactId>,
    pub action_contract: ActionContractId,
    pub action_semantic_definition_digest: Digest,
    pub action_validation_definition_digest: Digest,
    pub output_contract_definition_digest: Digest,
    pub partition_manifest: PartitionManifestId,
    pub source_payload_digest: Digest,
    pub source_validation_certificate_digest: Digest,
    pub coverage: CoverageManifest,
    pub validator_definition_digest: Digest,
    pub issued_unix_ms: u64,
    pub authority: CapabilityMode,
}

impl ActionArtifactValidationCertificate {
    pub fn new(
        mut input: ActionArtifactValidationCertificateInput,
    ) -> Result<Self, ActionArtifactValidationCertificateError> {
        input.input_artifacts.sort_unstable();
        let mut value = Self {
            format_revision: ACTION_ARTIFACT_VALIDATION_CERTIFICATE_FORMAT_REVISION,
            id: ArtifactValidationCertificateId::new(Digest([0; 32])),
            artifact: input.artifact,
            input_artifacts: input.input_artifacts,
            action_contract: input.action_contract,
            action_semantic_definition_digest: input.action_semantic_definition_digest,
            action_validation_definition_digest: input.action_validation_definition_digest,
            output_contract_definition_digest: input.output_contract_definition_digest,
            partition_manifest: input.partition_manifest,
            source_payload_digest: input.source_payload_digest,
            source_validation_certificate_digest: input.source_validation_certificate_digest,
            coverage: input.coverage,
            validator_definition_digest: input.validator_definition_digest,
            issued_unix_ms: input.issued_unix_ms,
            authority: CapabilityMode::Shadow,
        };
        value.validate_shape()?;
        value.id = ArtifactValidationCertificateId::new(value.compute_digest());
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, ActionArtifactValidationCertificateError> {
        if bytes.len() > MAX_ACTION_ARTIFACT_VALIDATION_CERTIFICATE_WIRE_BYTES {
            return Err(ActionArtifactValidationCertificateError::WireBound {
                actual: bytes.len(),
                maximum: MAX_ACTION_ARTIFACT_VALIDATION_CERTIFICATE_WIRE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ActionArtifactValidationCertificateError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ActionArtifactValidationCertificateError> {
        self.validate_shape()?;
        let expected = self.compute_digest();
        if self.id.digest() != expected {
            return Err(ActionArtifactValidationCertificateError::Digest {
                expected,
                actual: self.id.digest(),
            });
        }
        Ok(())
    }

    pub fn is_canonical(&self) -> bool {
        self.validate().is_ok()
    }

    fn validate_shape(&self) -> Result<(), ActionArtifactValidationCertificateError> {
        if self.format_revision != ACTION_ARTIFACT_VALIDATION_CERTIFICATE_FORMAT_REVISION {
            return Err(ActionArtifactValidationCertificateError::FormatRevision(
                self.format_revision,
            ));
        }
        if self.authority != CapabilityMode::Shadow {
            return Err(ActionArtifactValidationCertificateError::Authority);
        }
        if self.input_artifacts.len() > MAX_NEED_INPUTS {
            return Err(ActionArtifactValidationCertificateError::InputBound {
                actual: self.input_artifacts.len(),
                maximum: MAX_NEED_INPUTS,
            });
        }
        if self.input_artifacts.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ActionArtifactValidationCertificateError::InputCanonical);
        }
        if !self.coverage.entries.is_empty() {
            return Err(ActionArtifactValidationCertificateError::PredicateCoverage);
        }
        if [
            &self.coverage.world.source_selector,
            &self.coverage.world.platform,
            &self.coverage.world.features,
        ]
        .into_iter()
        .any(|value| value.len() > MAX_NEED_IR_BYTES)
        {
            return Err(ActionArtifactValidationCertificateError::WorldTextBound);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"action-artifact-validation-certificate-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.artifact.digest());
        hasher.field_u16(self.input_artifacts.len().try_into().unwrap_or(u16::MAX));
        for input in &self.input_artifacts {
            hasher.field_digest(input.digest());
        }
        hasher.field_str(self.action_contract.as_str());
        hasher.field_digest(self.action_semantic_definition_digest);
        hasher.field_digest(self.action_validation_definition_digest);
        hasher.field_digest(self.output_contract_definition_digest);
        hasher.field_digest(self.partition_manifest.digest());
        hasher.field_digest(self.source_payload_digest);
        hasher.field_digest(self.source_validation_certificate_digest);
        hasher.field_digest(self.coverage.world.id());
        hasher.field_digest(self.coverage.dependency_manifest_digest);
        hasher.field_digest(self.validator_definition_digest);
        hasher.field_bytes(&self.issued_unix_ms.to_le_bytes());
        hasher.field_u8(0);
        hasher.finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ActionArtifactValidationCertificateError {
    #[error("action artifact validation certificate format revision {0} is unsupported")]
    FormatRevision(u16),
    #[error(
        "action artifact validation certificate contains {actual} bytes; the maximum is {maximum}"
    )]
    WireBound { actual: usize, maximum: usize },
    #[error("action artifact validation certificate JSON is invalid: {0}")]
    Json(String),
    #[error(
        "action artifact validation certificate contains {actual} inputs; the maximum is {maximum}"
    )]
    InputBound { actual: usize, maximum: usize },
    #[error("action artifact validation certificate inputs must be strictly sorted and unique")]
    InputCanonical,
    #[error("partitioned action validation cannot carry predicate coverage entries")]
    PredicateCoverage,
    #[error("action artifact validation semantic-world text exceeds the canonical byte bound")]
    WorldTextBound,
    #[error("action artifact validation certificate authority must remain Shadow")]
    Authority,
    #[error(
        "action artifact validation certificate digest mismatch: expected {expected}, got {actual}"
    )]
    Digest { expected: Digest, actual: Digest },
}

fn deserialize_input_artifacts<'de, D>(deserializer: D) -> Result<Vec<ArtifactId>, D::Error>
where
    D: Deserializer<'de>,
{
    struct InputArtifactsVisitor;

    impl<'de> Visitor<'de> for InputArtifactsVisitor {
        type Value = Vec<ArtifactId>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_NEED_INPUTS} input artifacts")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence.size_hint().unwrap_or(0).min(MAX_NEED_INPUTS);
            let mut values = Vec::with_capacity(capacity);
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX_NEED_INPUTS {
                    return Err(serde::de::Error::custom(
                        "action artifact validation input bound exceeded",
                    ));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(InputArtifactsVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActionContractId, SemanticWorld};

    fn certificate() -> ActionArtifactValidationCertificate {
        ActionArtifactValidationCertificate::new(ActionArtifactValidationCertificateInput {
            artifact: ArtifactId::new(Digest::blake3(b"artifact")),
            input_artifacts: Vec::new(),
            action_contract: ActionContractId::new("needle.tests.inventory").unwrap(),
            action_semantic_definition_digest: Digest::blake3(b"semantic"),
            action_validation_definition_digest: Digest::blake3(b"validation"),
            output_contract_definition_digest: Digest::blake3(b"output"),
            partition_manifest: PartitionManifestId::new(Digest::blake3(b"manifest")),
            source_payload_digest: Digest::blake3(b"source-payload"),
            source_validation_certificate_digest: Digest::blake3(b"source-certificate"),
            coverage: CoverageManifest {
                entries: Vec::new(),
                world: SemanticWorld {
                    repository_lineage: Digest::blake3(b"repository"),
                    source_selector: "worktree".to_owned(),
                    platform: "windows".to_owned(),
                    features: "default".to_owned(),
                    configuration: None,
                    toolchain: None,
                },
                dependency_manifest_digest: Digest::blake3(b"dependencies"),
            },
            validator_definition_digest: Digest::blake3(b"validator"),
            issued_unix_ms: 42,
        })
        .unwrap()
    }

    #[test]
    fn action_certificate_round_trips_and_rejects_tampering() {
        let certificate = certificate();
        let json = serde_json::to_vec(&certificate).unwrap();
        assert_eq!(ActionArtifactValidationCertificate::decode_json(&json).unwrap(), certificate);
        let mut tampered = certificate;
        tampered.partition_manifest = PartitionManifestId::new(Digest::blake3(b"other"));
        assert!(matches!(
            tampered.validate(),
            Err(ActionArtifactValidationCertificateError::Digest { .. })
        ));
    }

    #[test]
    fn action_certificate_rejects_predicate_coverage_and_input_overflow() {
        let mut value = serde_json::to_value(certificate()).unwrap();
        value["input_artifacts"] = serde_json::Value::Array(
            (0..=MAX_NEED_INPUTS)
                .map(|index| {
                    serde_json::to_value(ArtifactId::new(Digest::blake3(index.to_le_bytes())))
                        .unwrap()
                })
                .collect(),
        );
        assert!(serde_json::from_value::<ActionArtifactValidationCertificate>(value).is_err());
    }
}
