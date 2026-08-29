use super::ActionContractId;
use crate::{
    ArtifactId, ArtifactValidationCertificateId, CanonicalHasher, CapabilityMode, Digest,
    MAX_NEED_INPUTS, MAX_NEED_IR_BYTES, SemanticWorld,
};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use thiserror::Error;

pub const ACTION_OUTPUT_VALIDATION_CERTIFICATE_FORMAT_REVISION: u16 = 1;
pub const MAX_ACTION_OUTPUT_VALIDATION_CERTIFICATE_WIRE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionOutputValidationCertificateInput {
    pub artifact: ArtifactId,
    pub input_artifacts: Vec<ArtifactId>,
    pub action_contract: ActionContractId,
    pub action_semantic_definition_digest: Digest,
    pub action_validation_definition_digest: Digest,
    pub output_contract_definition_digest: Digest,
    pub source_payload_digest: Digest,
    pub world: SemanticWorld,
    pub dependency_manifest_digest: Digest,
    pub validator_definition_digest: Digest,
    pub issued_unix_ms: u64,
}

/// Shadow-only certificate for an action output that has no predicate or
/// partition-manifest coverage. It proves exact output/input/world bindings;
/// it grants no resolver authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionOutputValidationCertificate {
    pub format_revision: u16,
    pub id: ArtifactValidationCertificateId,
    pub artifact: ArtifactId,
    #[serde(deserialize_with = "deserialize_input_artifacts")]
    pub input_artifacts: Vec<ArtifactId>,
    pub action_contract: ActionContractId,
    pub action_semantic_definition_digest: Digest,
    pub action_validation_definition_digest: Digest,
    pub output_contract_definition_digest: Digest,
    pub source_payload_digest: Digest,
    pub world: SemanticWorld,
    pub dependency_manifest_digest: Digest,
    pub validator_definition_digest: Digest,
    pub issued_unix_ms: u64,
    pub authority: CapabilityMode,
}

impl ActionOutputValidationCertificate {
    pub fn new(
        mut input: ActionOutputValidationCertificateInput,
    ) -> Result<Self, ActionOutputValidationCertificateError> {
        input.input_artifacts.sort_unstable();
        let mut value = Self {
            format_revision: ACTION_OUTPUT_VALIDATION_CERTIFICATE_FORMAT_REVISION,
            id: ArtifactValidationCertificateId::new(Digest([0; 32])),
            artifact: input.artifact,
            input_artifacts: input.input_artifacts,
            action_contract: input.action_contract,
            action_semantic_definition_digest: input.action_semantic_definition_digest,
            action_validation_definition_digest: input.action_validation_definition_digest,
            output_contract_definition_digest: input.output_contract_definition_digest,
            source_payload_digest: input.source_payload_digest,
            world: input.world,
            dependency_manifest_digest: input.dependency_manifest_digest,
            validator_definition_digest: input.validator_definition_digest,
            issued_unix_ms: input.issued_unix_ms,
            authority: CapabilityMode::Shadow,
        };
        value.validate_shape()?;
        value.id = ArtifactValidationCertificateId::new(value.compute_digest());
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, ActionOutputValidationCertificateError> {
        if bytes.len() > MAX_ACTION_OUTPUT_VALIDATION_CERTIFICATE_WIRE_BYTES {
            return Err(ActionOutputValidationCertificateError::WireBound);
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ActionOutputValidationCertificateError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ActionOutputValidationCertificateError> {
        self.validate_shape()?;
        if self.id.digest() != self.compute_digest() {
            return Err(ActionOutputValidationCertificateError::Digest);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ActionOutputValidationCertificateError> {
        if self.format_revision != ACTION_OUTPUT_VALIDATION_CERTIFICATE_FORMAT_REVISION {
            return Err(ActionOutputValidationCertificateError::FormatRevision);
        }
        if self.authority != CapabilityMode::Shadow {
            return Err(ActionOutputValidationCertificateError::Authority);
        }
        if self.input_artifacts.len() > MAX_NEED_INPUTS
            || self.input_artifacts.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ActionOutputValidationCertificateError::Inputs);
        }
        if [
            self.action_semantic_definition_digest,
            self.action_validation_definition_digest,
            self.output_contract_definition_digest,
            self.source_payload_digest,
            self.dependency_manifest_digest,
            self.validator_definition_digest,
        ]
        .contains(&Digest([0; 32]))
        {
            return Err(ActionOutputValidationCertificateError::Binding);
        }
        if [&self.world.source_selector, &self.world.platform, &self.world.features]
            .into_iter()
            .any(|value| value.len() > MAX_NEED_IR_BYTES)
        {
            return Err(ActionOutputValidationCertificateError::World);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"action-output-validation-certificate-v1");
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
        hasher.field_digest(self.source_payload_digest);
        hasher.field_digest(self.world.id());
        hasher.field_digest(self.dependency_manifest_digest);
        hasher.field_digest(self.validator_definition_digest);
        hasher.field_bytes(&self.issued_unix_ms.to_le_bytes());
        hasher.field_u8(0);
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ActionOutputValidationCertificateError {
    #[error("action output validation certificate format revision is unsupported")]
    FormatRevision,
    #[error("action output validation certificate exceeds its wire bound")]
    WireBound,
    #[error("action output validation certificate JSON is invalid: {0}")]
    Json(String),
    #[error("action output validation inputs must be bounded, sorted, and unique")]
    Inputs,
    #[error("action output validation binding is invalid")]
    Binding,
    #[error("action output validation semantic world is out of bounds")]
    World,
    #[error("action output validation authority must remain Shadow")]
    Authority,
    #[error("action output validation digest is invalid")]
    Digest,
}

fn deserialize_input_artifacts<'de, D>(deserializer: D) -> Result<Vec<ArtifactId>, D::Error>
where
    D: Deserializer<'de>,
{
    struct InputVisitor;

    impl<'de> Visitor<'de> for InputVisitor {
        type Value = Vec<ArtifactId>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_NEED_INPUTS} input artifacts")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_NEED_INPUTS));
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX_NEED_INPUTS {
                    return Err(serde::de::Error::custom("action output input bound exceeded"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(InputVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_is_shadow_canonical_and_tamper_evident() {
        let mut certificate =
            ActionOutputValidationCertificate::new(ActionOutputValidationCertificateInput {
                artifact: ArtifactId::new(Digest::blake3("artifact")),
                input_artifacts: vec![ArtifactId::new(Digest::blake3("input"))],
                action_contract: ActionContractId::new("needle.patch.propose").unwrap(),
                action_semantic_definition_digest: Digest::blake3("semantic"),
                action_validation_definition_digest: Digest::blake3("validation"),
                output_contract_definition_digest: Digest::blake3("output"),
                source_payload_digest: Digest::blake3("payload"),
                world: SemanticWorld {
                    repository_lineage: Digest::blake3("repository"),
                    source_selector: "current".to_owned(),
                    platform: "windows".to_owned(),
                    features: "default".to_owned(),
                    configuration: None,
                    toolchain: None,
                },
                dependency_manifest_digest: Digest::blake3("dependencies"),
                validator_definition_digest: Digest::blake3("validator"),
                issued_unix_ms: 100,
            })
            .unwrap();
        assert!(certificate.validate().is_ok());
        certificate.validator_definition_digest = Digest::blake3("changed");
        assert_eq!(certificate.validate(), Err(ActionOutputValidationCertificateError::Digest));
    }
}
