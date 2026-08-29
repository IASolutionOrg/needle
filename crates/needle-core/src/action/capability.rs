use super::{ActionContractId, DispatchPolicy, EffectClass, ReuseMode};
use crate::{
    CanonicalHasher, CapabilityMode, Digest, ManifestClosure, PartitionPolicyId, PartitionSchemeId,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

pub const ACTION_CAPABILITY_FORMAT_REVISION: u16 = 1;
pub const MAX_ACTION_CAPABILITY_WIRE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActionCapabilityClassId(Digest);

impl ActionCapabilityClassId {
    pub const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }
}

impl fmt::Debug for ActionCapabilityClassId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ActionCapabilityClassId").field(&self.0).finish()
    }
}

impl fmt::Display for ActionCapabilityClassId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionSubjectAuthorityClass {
    NotApplicable,
    Exact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionWorldPolicyClass {
    Exact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionManifestProvenancePolicy {
    pub request_bound: bool,
    pub producer_authored: bool,
    pub provider_attested: bool,
    pub derived: bool,
}

impl ActionManifestProvenancePolicy {
    pub const fn request_bound_and_derived() -> Self {
        Self {
            request_bound: true,
            producer_authored: false,
            provider_attested: false,
            derived: true,
        }
    }

    const fn bits(self) -> u8 {
        self.request_bound as u8
            | ((self.producer_authored as u8) << 1)
            | ((self.provider_attested as u8) << 2)
            | ((self.derived as u8) << 3)
    }

    const fn is_empty(self) -> bool {
        self.bits() == 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionCapabilityClassInput {
    pub action_contract: ActionContractId,
    pub action_semantic_definition_digest: Digest,
    pub action_validation_definition_digest: Digest,
    pub action_operational_policy_digest: Digest,
    pub effect_class: EffectClass,
    pub reuse_mode: ReuseMode,
    pub subject_authority: ActionSubjectAuthorityClass,
    pub world_policy: ActionWorldPolicyClass,
    pub partition_policy: Option<PartitionPolicyId>,
    pub partition_policy_definition_digest: Option<Digest>,
    pub partition_scheme: Option<PartitionSchemeId>,
    pub partition_scheme_definition_digest: Option<Digest>,
    pub partition_registry_definition_digest: Option<Digest>,
    pub manifest_provenance: ActionManifestProvenancePolicy,
    pub manifest_closure: Option<ManifestClosure>,
    pub dispatch_policy: DispatchPolicy,
    pub definition_set_digest: Digest,
    pub mode: CapabilityMode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCapabilityClass {
    pub format_revision: u16,
    pub id: ActionCapabilityClassId,
    pub action_contract: ActionContractId,
    pub action_semantic_definition_digest: Digest,
    pub action_validation_definition_digest: Digest,
    pub action_operational_policy_digest: Digest,
    pub effect_class: EffectClass,
    pub reuse_mode: ReuseMode,
    pub subject_authority: ActionSubjectAuthorityClass,
    pub world_policy: ActionWorldPolicyClass,
    pub partition_policy: Option<PartitionPolicyId>,
    pub partition_policy_definition_digest: Option<Digest>,
    pub partition_scheme: Option<PartitionSchemeId>,
    pub partition_scheme_definition_digest: Option<Digest>,
    pub partition_registry_definition_digest: Option<Digest>,
    pub manifest_provenance: ActionManifestProvenancePolicy,
    pub manifest_closure: Option<ManifestClosure>,
    pub dispatch_policy: DispatchPolicy,
    pub definition_set_digest: Digest,
    pub mode: CapabilityMode,
    pub definition_digest: Digest,
}

impl ActionCapabilityClass {
    pub fn new(input: ActionCapabilityClassInput) -> Result<Self, ActionCapabilityError> {
        let mut value = Self {
            format_revision: ACTION_CAPABILITY_FORMAT_REVISION,
            id: ActionCapabilityClassId::new(Digest([0; 32])),
            action_contract: input.action_contract,
            action_semantic_definition_digest: input.action_semantic_definition_digest,
            action_validation_definition_digest: input.action_validation_definition_digest,
            action_operational_policy_digest: input.action_operational_policy_digest,
            effect_class: input.effect_class,
            reuse_mode: input.reuse_mode,
            subject_authority: input.subject_authority,
            world_policy: input.world_policy,
            partition_policy: input.partition_policy,
            partition_policy_definition_digest: input.partition_policy_definition_digest,
            partition_scheme: input.partition_scheme,
            partition_scheme_definition_digest: input.partition_scheme_definition_digest,
            partition_registry_definition_digest: input.partition_registry_definition_digest,
            manifest_provenance: input.manifest_provenance,
            manifest_closure: input.manifest_closure,
            dispatch_policy: input.dispatch_policy,
            definition_set_digest: input.definition_set_digest,
            mode: input.mode,
            definition_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.definition_digest = value.compute_definition_digest();
        value.id = compute_id(value.definition_digest);
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, ActionCapabilityError> {
        if bytes.len() > MAX_ACTION_CAPABILITY_WIRE_BYTES {
            return Err(ActionCapabilityError::WireBound {
                actual: bytes.len(),
                maximum: MAX_ACTION_CAPABILITY_WIRE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ActionCapabilityError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ActionCapabilityError> {
        self.validate_shape()?;
        if self.definition_digest != self.compute_definition_digest() {
            return Err(ActionCapabilityError::DefinitionDigest);
        }
        if self.id != compute_id(self.definition_digest) {
            return Err(ActionCapabilityError::Identity);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ActionCapabilityError> {
        if self.format_revision != ACTION_CAPABILITY_FORMAT_REVISION {
            return Err(ActionCapabilityError::FormatRevision(self.format_revision));
        }
        if [
            self.action_semantic_definition_digest,
            self.action_validation_definition_digest,
            self.action_operational_policy_digest,
            self.definition_set_digest,
        ]
        .contains(&Digest([0; 32]))
        {
            return Err(ActionCapabilityError::Digest);
        }
        if self.effect_class == EffectClass::ExternalEffect || self.reuse_mode == ReuseMode::Never {
            return Err(ActionCapabilityError::EffectBoundary);
        }
        let partition_fields = [
            self.partition_policy.is_some(),
            self.partition_policy_definition_digest.is_some(),
            self.partition_scheme.is_some(),
            self.partition_scheme_definition_digest.is_some(),
            self.partition_registry_definition_digest.is_some(),
            self.manifest_closure.is_some(),
        ];
        let partitioned = partition_fields.iter().all(|present| *present);
        if partition_fields.iter().any(|present| *present) && !partitioned {
            return Err(ActionCapabilityError::PartitionBinding);
        }
        if partitioned {
            if [
                self.partition_policy_definition_digest,
                self.partition_scheme_definition_digest,
                self.partition_registry_definition_digest,
            ]
            .contains(&Some(Digest([0; 32])))
                || self.manifest_provenance.is_empty()
            {
                return Err(ActionCapabilityError::PartitionBinding);
            }
        } else if !self.manifest_provenance.is_empty() {
            return Err(ActionCapabilityError::PartitionBinding);
        }
        if self.reuse_mode == ReuseMode::Refresh
            && (!partitioned || self.manifest_closure != Some(ManifestClosure::Closed))
        {
            return Err(ActionCapabilityError::RefreshBinding);
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"action-capability-class-definition-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(self.action_contract.as_str());
        hasher.field_digest(self.action_semantic_definition_digest);
        hasher.field_digest(self.action_validation_definition_digest);
        hasher.field_digest(self.action_operational_policy_digest);
        hasher.field_u8(effect_tag(self.effect_class));
        hasher.field_u8(reuse_tag(self.reuse_mode));
        hasher.field_u8(subject_authority_tag(self.subject_authority));
        hasher.field_u8(world_policy_tag(self.world_policy));
        match (
            &self.partition_policy,
            self.partition_policy_definition_digest,
            &self.partition_scheme,
            self.partition_scheme_definition_digest,
            self.partition_registry_definition_digest,
            self.manifest_closure,
        ) {
            (
                Some(policy),
                Some(policy_digest),
                Some(scheme),
                Some(scheme_digest),
                Some(registry),
                Some(closure),
            ) => {
                hasher.field_u8(1);
                hasher.field_str(policy.as_str());
                hasher.field_digest(policy_digest);
                hasher.field_str(scheme.as_str());
                hasher.field_digest(scheme_digest);
                hasher.field_digest(registry);
                hasher.field_u8(self.manifest_provenance.bits());
                hasher.field_u8(closure_tag(closure));
            }
            _ => hasher.field_u8(0),
        }
        hasher.field_digest(self.dispatch_policy.digest());
        hasher.field_digest(self.definition_set_digest);
        hasher.finish()
    }
}

fn compute_id(definition_digest: Digest) -> ActionCapabilityClassId {
    let mut hasher = CanonicalHasher::new(b"action-capability-class-id-v1");
    hasher.field_digest(definition_digest);
    ActionCapabilityClassId::new(hasher.finish())
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

const fn reuse_tag(value: ReuseMode) -> u8 {
    match value {
        ReuseMode::Exact => 0,
        ReuseMode::Project => 1,
        ReuseMode::Assemble => 2,
        ReuseMode::Refresh => 3,
        ReuseMode::Never => 4,
    }
}

const fn subject_authority_tag(value: ActionSubjectAuthorityClass) -> u8 {
    match value {
        ActionSubjectAuthorityClass::NotApplicable => 0,
        ActionSubjectAuthorityClass::Exact => 1,
    }
}

const fn world_policy_tag(value: ActionWorldPolicyClass) -> u8 {
    match value {
        ActionWorldPolicyClass::Exact => 0,
    }
}

const fn closure_tag(value: ManifestClosure) -> u8 {
    match value {
        ManifestClosure::Open => 0,
        ManifestClosure::Closed => 1,
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ActionCapabilityError {
    #[error("action capability format revision {0} is unsupported")]
    FormatRevision(u16),
    #[error("action capability contains a zero authority digest")]
    Digest,
    #[error("action capability effect/reuse combination cannot be promoted")]
    EffectBoundary,
    #[error("action capability partition dimensions are incomplete or inconsistent")]
    PartitionBinding,
    #[error("refresh capability requires a complete closed partition binding")]
    RefreshBinding,
    #[error("action capability definition digest is inconsistent")]
    DefinitionDigest,
    #[error("action capability identity is inconsistent")]
    Identity,
    #[error("action capability JSON is invalid: {0}")]
    Json(String),
    #[error("action capability wire has {actual} bytes; maximum is {maximum}")]
    WireBound { actual: usize, maximum: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> Digest {
        Digest::blake3(label.as_bytes())
    }

    fn input(mode: CapabilityMode) -> ActionCapabilityClassInput {
        ActionCapabilityClassInput {
            action_contract: ActionContractId::new("needle.tests.inventory").unwrap(),
            action_semantic_definition_digest: digest("semantic"),
            action_validation_definition_digest: digest("validation"),
            action_operational_policy_digest: digest("operational"),
            effect_class: EffectClass::PureEvidence,
            reuse_mode: ReuseMode::Refresh,
            subject_authority: ActionSubjectAuthorityClass::NotApplicable,
            world_policy: ActionWorldPolicyClass::Exact,
            partition_policy: Some(
                PartitionPolicyId::new("needle.tests.inventory.partition-policy").unwrap(),
            ),
            partition_policy_definition_digest: Some(digest("partition-policy")),
            partition_scheme: Some(
                PartitionSchemeId::new("needle.tests.inventory.target").unwrap(),
            ),
            partition_scheme_definition_digest: Some(digest("partition-scheme")),
            partition_registry_definition_digest: Some(digest("partition-registry")),
            manifest_provenance: ActionManifestProvenancePolicy::request_bound_and_derived(),
            manifest_closure: Some(ManifestClosure::Closed),
            dispatch_policy: DispatchPolicy {
                completion: super::super::CompletionPolicy::ReuseAllowed,
                evidence: super::super::EvidencePolicy::Standard,
                prior_artifacts: super::super::PriorArtifactPolicy::ContractDefined,
                persistence: super::super::PersistencePolicy::Persistent,
            },
            definition_set_digest: digest("definition-set"),
            mode,
        }
    }

    #[test]
    fn class_round_trip_is_digest_bound_and_mode_is_separate() {
        let shadow = ActionCapabilityClass::new(input(CapabilityMode::Shadow)).unwrap();
        shadow.validate().unwrap();
        let authoritative =
            ActionCapabilityClass::new(input(CapabilityMode::Authoritative)).unwrap();
        assert_eq!(shadow.id, authoritative.id);
        assert_eq!(shadow.definition_digest, authoritative.definition_digest);
        let bytes = serde_json::to_vec(&shadow).unwrap();
        assert_eq!(ActionCapabilityClass::decode_json(&bytes).unwrap(), shadow);
        let mut tampered = shadow;
        tampered.definition_set_digest = digest("tampered");
        assert_eq!(tampered.validate(), Err(ActionCapabilityError::DefinitionDigest));
    }

    #[test]
    fn refresh_requires_complete_closed_partition_dimensions() {
        let mut missing = input(CapabilityMode::Shadow);
        missing.partition_scheme = None;
        assert_eq!(
            ActionCapabilityClass::new(missing),
            Err(ActionCapabilityError::PartitionBinding)
        );
        let mut open = input(CapabilityMode::Shadow);
        open.manifest_closure = Some(ManifestClosure::Open);
        assert_eq!(ActionCapabilityClass::new(open), Err(ActionCapabilityError::RefreshBinding));
    }

    #[test]
    fn class_decode_is_bounded() {
        let oversized = vec![b' '; MAX_ACTION_CAPABILITY_WIRE_BYTES + 1];
        assert!(matches!(
            ActionCapabilityClass::decode_json(&oversized),
            Err(ActionCapabilityError::WireBound { .. })
        ));
    }
}
