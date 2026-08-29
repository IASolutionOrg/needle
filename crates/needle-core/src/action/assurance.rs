use super::{ActionCapabilityClass, ActionCapabilityClassId};
use crate::{
    ArtifactId, ArtifactRequestId, ArtifactValidationCertificateId, CanonicalHasher,
    CapabilityMode, Digest, LifecycleId,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

pub const ACTION_ASSURANCE_FORMAT_REVISION: u16 = 1;
pub const ACTION_CAPABILITY_DECISION_FORMAT_REVISION: u16 = 1;
pub const MAX_ACTION_ASSURANCE_WIRE_BYTES: usize = 64 * 1024;
pub const MAX_ACTION_CAPABILITY_DECISION_WIRE_BYTES: usize = 64 * 1024;
pub const MAX_ACTION_CAPABILITY_DECIDER_BYTES: usize = 128;

macro_rules! digest_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Digest);

        impl $name {
            pub const fn new(digest: Digest) -> Self {
                Self(digest)
            }

            pub const fn digest(self) -> Digest {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

digest_id!(ActionAssuranceEvidenceId);
digest_id!(ActionCapabilityDecisionId);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionAssuranceEvidenceKind {
    ProviderBackedFresh,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionAssuranceEvidenceInput {
    pub capability_class: ActionCapabilityClassId,
    pub capability_definition_digest: Digest,
    pub action_request: ArtifactRequestId,
    pub artifact: ArtifactId,
    pub validation_certificate: ArtifactValidationCertificateId,
    pub repository: Digest,
    pub source_snapshot: Digest,
    pub lifecycle: LifecycleId,
    pub adapter_invocation: Digest,
    pub evidence_kind: ActionAssuranceEvidenceKind,
    pub execution_evidence_digest: Digest,
    pub observed_unix_ms: u64,
}

/// Immutable evidence accepted for one exact action capability class.
///
/// This record does not promote the capability. Promotion is a separate,
/// explicit `ActionCapabilityDecision` bound to this evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionAssuranceEvidence {
    pub format_revision: u16,
    pub id: ActionAssuranceEvidenceId,
    pub capability_class: ActionCapabilityClassId,
    pub capability_definition_digest: Digest,
    pub action_request: ArtifactRequestId,
    pub artifact: ArtifactId,
    pub validation_certificate: ArtifactValidationCertificateId,
    pub repository: Digest,
    pub source_snapshot: Digest,
    pub lifecycle: LifecycleId,
    pub adapter_invocation: Digest,
    pub evidence_kind: ActionAssuranceEvidenceKind,
    pub execution_evidence_digest: Digest,
    pub observed_unix_ms: u64,
    pub definition_digest: Digest,
}

impl ActionAssuranceEvidence {
    pub fn new(input: ActionAssuranceEvidenceInput) -> Result<Self, ActionAssuranceError> {
        let mut value = Self {
            format_revision: ACTION_ASSURANCE_FORMAT_REVISION,
            id: ActionAssuranceEvidenceId::new(Digest([0; 32])),
            capability_class: input.capability_class,
            capability_definition_digest: input.capability_definition_digest,
            action_request: input.action_request,
            artifact: input.artifact,
            validation_certificate: input.validation_certificate,
            repository: input.repository,
            source_snapshot: input.source_snapshot,
            lifecycle: input.lifecycle,
            adapter_invocation: input.adapter_invocation,
            evidence_kind: input.evidence_kind,
            execution_evidence_digest: input.execution_evidence_digest,
            observed_unix_ms: input.observed_unix_ms,
            definition_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.definition_digest = value.compute_definition_digest();
        value.id = evidence_id(value.definition_digest);
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, ActionAssuranceError> {
        if bytes.len() > MAX_ACTION_ASSURANCE_WIRE_BYTES {
            return Err(ActionAssuranceError::WireBound {
                actual: bytes.len(),
                maximum: MAX_ACTION_ASSURANCE_WIRE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ActionAssuranceError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ActionAssuranceError> {
        self.validate_shape()?;
        if self.definition_digest != self.compute_definition_digest() {
            return Err(ActionAssuranceError::DefinitionDigest);
        }
        if self.id != evidence_id(self.definition_digest) {
            return Err(ActionAssuranceError::EvidenceIdentity);
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        capability: &ActionCapabilityClass,
    ) -> Result<(), ActionAssuranceError> {
        self.validate()?;
        capability
            .validate()
            .map_err(|error| ActionAssuranceError::Capability(error.to_string()))?;
        if self.capability_class != capability.id
            || self.capability_definition_digest != capability.definition_digest
        {
            return Err(ActionAssuranceError::CapabilityBinding);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ActionAssuranceError> {
        if self.format_revision != ACTION_ASSURANCE_FORMAT_REVISION {
            return Err(ActionAssuranceError::EvidenceFormatRevision(self.format_revision));
        }
        if self.capability_class.digest() == Digest([0; 32])
            || self.capability_definition_digest == Digest([0; 32])
            || self.action_request.digest() == Digest([0; 32])
            || self.artifact.digest() == Digest([0; 32])
            || self.validation_certificate.digest() == Digest([0; 32])
            || self.repository == Digest([0; 32])
            || self.source_snapshot == Digest([0; 32])
            || self.lifecycle.0 == Digest([0; 32])
            || self.adapter_invocation == Digest([0; 32])
            || self.execution_evidence_digest == Digest([0; 32])
            || self.observed_unix_ms == 0
        {
            return Err(ActionAssuranceError::EvidenceShape);
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"action-assurance-evidence-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.capability_class.digest());
        hasher.field_digest(self.capability_definition_digest);
        hasher.field_digest(self.action_request.digest());
        hasher.field_digest(self.artifact.digest());
        hasher.field_digest(self.validation_certificate.digest());
        hasher.field_digest(self.repository);
        hasher.field_digest(self.source_snapshot);
        hasher.field_digest(self.lifecycle.0);
        hasher.field_digest(self.adapter_invocation);
        hasher.field_u8(evidence_kind_tag(self.evidence_kind));
        hasher.field_digest(self.execution_evidence_digest);
        hasher.field_bytes(&self.observed_unix_ms.to_le_bytes());
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionCapabilityDecisionInput {
    pub capability_class: ActionCapabilityClassId,
    pub capability_definition_digest: Digest,
    pub evidence: ActionAssuranceEvidenceId,
    pub evidence_definition_digest: Digest,
    pub previous_decision: Option<ActionCapabilityDecisionId>,
    pub selected_mode: CapabilityMode,
    pub automatic_resolver_consumption_approved: bool,
    pub automatic_lifecycle_consumption_approved: bool,
    pub decider_id: String,
    pub decided_unix_ms: u64,
}

/// Append-only operator decision over one exact capability and evidence record.
///
/// The optional previous decision forms a linear, reversible history. A mode
/// change is not part of capability identity and never rewrites evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCapabilityDecision {
    pub format_revision: u16,
    pub id: ActionCapabilityDecisionId,
    pub capability_class: ActionCapabilityClassId,
    pub capability_definition_digest: Digest,
    pub evidence: ActionAssuranceEvidenceId,
    pub evidence_definition_digest: Digest,
    pub previous_decision: Option<ActionCapabilityDecisionId>,
    pub selected_mode: CapabilityMode,
    pub automatic_resolver_consumption_approved: bool,
    pub automatic_lifecycle_consumption_approved: bool,
    pub decider_id: String,
    pub decided_unix_ms: u64,
    pub definition_digest: Digest,
}

impl ActionCapabilityDecision {
    pub fn new(input: ActionCapabilityDecisionInput) -> Result<Self, ActionAssuranceError> {
        let mut value = Self {
            format_revision: ACTION_CAPABILITY_DECISION_FORMAT_REVISION,
            id: ActionCapabilityDecisionId::new(Digest([0; 32])),
            capability_class: input.capability_class,
            capability_definition_digest: input.capability_definition_digest,
            evidence: input.evidence,
            evidence_definition_digest: input.evidence_definition_digest,
            previous_decision: input.previous_decision,
            selected_mode: input.selected_mode,
            automatic_resolver_consumption_approved: input.automatic_resolver_consumption_approved,
            automatic_lifecycle_consumption_approved: input
                .automatic_lifecycle_consumption_approved,
            decider_id: input.decider_id,
            decided_unix_ms: input.decided_unix_ms,
            definition_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.definition_digest = value.compute_definition_digest();
        value.id = decision_id(value.definition_digest);
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, ActionAssuranceError> {
        if bytes.len() > MAX_ACTION_CAPABILITY_DECISION_WIRE_BYTES {
            return Err(ActionAssuranceError::WireBound {
                actual: bytes.len(),
                maximum: MAX_ACTION_CAPABILITY_DECISION_WIRE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ActionAssuranceError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ActionAssuranceError> {
        self.validate_shape()?;
        if self.definition_digest != self.compute_definition_digest() {
            return Err(ActionAssuranceError::DefinitionDigest);
        }
        if self.id != decision_id(self.definition_digest) {
            return Err(ActionAssuranceError::DecisionIdentity);
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        capability: &ActionCapabilityClass,
        evidence: &ActionAssuranceEvidence,
    ) -> Result<(), ActionAssuranceError> {
        self.validate()?;
        evidence.validate_for(capability)?;
        if self.capability_class != capability.id
            || self.capability_definition_digest != capability.definition_digest
            || self.evidence != evidence.id
            || self.evidence_definition_digest != evidence.definition_digest
            || self.decided_unix_ms < evidence.observed_unix_ms
        {
            return Err(ActionAssuranceError::DecisionBinding);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ActionAssuranceError> {
        if self.format_revision != ACTION_CAPABILITY_DECISION_FORMAT_REVISION {
            return Err(ActionAssuranceError::DecisionFormatRevision(self.format_revision));
        }
        if self.capability_class.digest() == Digest([0; 32])
            || self.capability_definition_digest == Digest([0; 32])
            || self.evidence.digest() == Digest([0; 32])
            || self.evidence_definition_digest == Digest([0; 32])
            || self.decider_id.is_empty()
            || self.decider_id.trim() != self.decider_id
            || self.decider_id.len() > MAX_ACTION_CAPABILITY_DECIDER_BYTES
            || self.decider_id.chars().any(char::is_control)
            || self.decided_unix_ms == 0
            || (self.automatic_lifecycle_consumption_approved
                && !self.automatic_resolver_consumption_approved)
            || (self.selected_mode != CapabilityMode::Authoritative
                && (self.automatic_resolver_consumption_approved
                    || self.automatic_lifecycle_consumption_approved))
        {
            return Err(ActionAssuranceError::DecisionShape);
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"action-capability-decision-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.capability_class.digest());
        hasher.field_digest(self.capability_definition_digest);
        hasher.field_digest(self.evidence.digest());
        hasher.field_digest(self.evidence_definition_digest);
        match self.previous_decision {
            Some(previous) => {
                hasher.field_u8(1);
                hasher.field_digest(previous.digest());
            }
            None => hasher.field_u8(0),
        }
        hasher.field_u8(capability_mode_tag(self.selected_mode));
        hasher.field_u8(self.automatic_resolver_consumption_approved as u8);
        hasher.field_u8(self.automatic_lifecycle_consumption_approved as u8);
        hasher.field_str(&self.decider_id);
        hasher.field_bytes(&self.decided_unix_ms.to_le_bytes());
        hasher.finish()
    }
}

fn evidence_id(definition_digest: Digest) -> ActionAssuranceEvidenceId {
    let mut hasher = CanonicalHasher::new(b"action-assurance-evidence-id-v1");
    hasher.field_digest(definition_digest);
    ActionAssuranceEvidenceId::new(hasher.finish())
}

fn decision_id(definition_digest: Digest) -> ActionCapabilityDecisionId {
    let mut hasher = CanonicalHasher::new(b"action-capability-decision-id-v1");
    hasher.field_digest(definition_digest);
    ActionCapabilityDecisionId::new(hasher.finish())
}

const fn evidence_kind_tag(value: ActionAssuranceEvidenceKind) -> u8 {
    match value {
        ActionAssuranceEvidenceKind::ProviderBackedFresh => 0,
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

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ActionAssuranceError {
    #[error("action assurance evidence format revision {0} is unsupported")]
    EvidenceFormatRevision(u16),
    #[error("action capability decision format revision {0} is unsupported")]
    DecisionFormatRevision(u16),
    #[error("action assurance evidence shape is invalid")]
    EvidenceShape,
    #[error("action capability decision shape is invalid")]
    DecisionShape,
    #[error("action assurance definition digest is inconsistent")]
    DefinitionDigest,
    #[error("action assurance evidence identity is inconsistent")]
    EvidenceIdentity,
    #[error("action capability decision identity is inconsistent")]
    DecisionIdentity,
    #[error("action capability is invalid: {0}")]
    Capability(String),
    #[error("action assurance evidence does not bind the current capability")]
    CapabilityBinding,
    #[error("action capability decision does not bind its capability and evidence")]
    DecisionBinding,
    #[error("action assurance JSON is invalid: {0}")]
    Json(String),
    #[error("action assurance wire has {actual} bytes; maximum is {maximum}")]
    WireBound { actual: usize, maximum: usize },
}

#[cfg(test)]
#[path = "assurance/tests.rs"]
mod tests;
