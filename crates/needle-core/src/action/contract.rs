use super::{
    ACTION_FORMAT_REVISION, ActionContractId, CompletionPolicy, DispatchPolicy, ReuseMode,
    ReuseModeSet, ReuseModeSetError,
};
use crate::{CanonicalHasher, Digest};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectClass {
    PureEvidence,
    DerivedAnalysis,
    TransformProposal,
    ExecutionEvidence,
    ExternalRead,
    ExternalEffect,
}

impl EffectClass {
    const fn tag(self) -> u8 {
        match self {
            Self::PureEvidence => 0,
            Self::DerivedAnalysis => 1,
            Self::TransformProposal => 2,
            Self::ExecutionEvidence => 3,
            Self::ExternalRead => 4,
            Self::ExternalEffect => 5,
        }
    }
}

/// Constructor input for immutable definition material not yet expanded into
/// first-class partition, refresh, admission, and world-policy types.
///
/// Each source digest addresses an immutable, domain-appropriate definition
/// bundle. Runtime request state must never be hidden in these values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionContractInput {
    pub id: ActionContractId,
    pub semantic_authority_source_digest: Digest,
    pub validation_authority_source_digest: Digest,
    pub operational_authority_source_digest: Digest,
    pub effect_class: EffectClass,
    pub reuse_modes: Vec<ReuseMode>,
    pub default_dispatch_policy: DispatchPolicy,
}

/// Shadow-only action product definition.
///
/// This record introduces the v0.5 authority boundaries but is not registered
/// with the resolver and cannot authorize reuse in this slice.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionContract {
    pub format_revision: u16,
    pub id: ActionContractId,
    pub semantic_authority_source_digest: Digest,
    pub validation_authority_source_digest: Digest,
    pub operational_authority_source_digest: Digest,
    pub effect_class: EffectClass,
    pub reuse_modes: ReuseModeSet,
    pub default_dispatch_policy: DispatchPolicy,
    pub semantic_definition_digest: Digest,
    pub validation_definition_digest: Digest,
    pub operational_policy_digest: Digest,
    pub definition_digest: Digest,
}

impl ActionContract {
    pub fn new(input: ActionContractInput) -> Result<Self, ActionValidationError> {
        let reuse_modes = ReuseModeSet::new(input.reuse_modes)?;
        let mut contract = Self {
            format_revision: ACTION_FORMAT_REVISION,
            id: input.id,
            semantic_authority_source_digest: input.semantic_authority_source_digest,
            validation_authority_source_digest: input.validation_authority_source_digest,
            operational_authority_source_digest: input.operational_authority_source_digest,
            effect_class: input.effect_class,
            reuse_modes,
            default_dispatch_policy: input.default_dispatch_policy,
            semantic_definition_digest: Digest([0; 32]),
            validation_definition_digest: Digest([0; 32]),
            operational_policy_digest: Digest([0; 32]),
            definition_digest: Digest([0; 32]),
        };
        contract.validate_policy_shape()?;
        contract.semantic_definition_digest = contract.compute_semantic_definition_digest();
        contract.validation_definition_digest = contract.compute_validation_definition_digest();
        contract.operational_policy_digest = contract.compute_operational_policy_digest();
        contract.definition_digest = contract.compute_definition_digest();
        Ok(contract)
    }

    pub fn validate(&self) -> Result<(), ActionValidationError> {
        if self.format_revision != ACTION_FORMAT_REVISION {
            return Err(ActionValidationError::FormatRevision(self.format_revision));
        }
        self.validate_policy_shape()?;
        check_digest(
            DigestAuthority::Semantic,
            self.compute_semantic_definition_digest(),
            self.semantic_definition_digest,
        )?;
        check_digest(
            DigestAuthority::Validation,
            self.compute_validation_definition_digest(),
            self.validation_definition_digest,
        )?;
        check_digest(
            DigestAuthority::Operational,
            self.compute_operational_policy_digest(),
            self.operational_policy_digest,
        )?;
        check_digest(
            DigestAuthority::CompleteRecord,
            self.compute_definition_digest(),
            self.definition_digest,
        )?;
        Ok(())
    }

    pub fn is_canonical(&self) -> bool {
        self.validate().is_ok()
    }

    fn validate_policy_shape(&self) -> Result<(), ActionValidationError> {
        self.validate_dispatch_policy(self.default_dispatch_policy)?;
        let never = self.reuse_modes.contains(ReuseMode::Never);
        if self.effect_class == EffectClass::ExternalEffect && !never {
            return Err(ActionValidationError::ExternalEffectRequiresNever);
        }
        Ok(())
    }

    pub(crate) fn validate_dispatch_policy(
        &self,
        dispatch_policy: DispatchPolicy,
    ) -> Result<(), ActionValidationError> {
        if self.reuse_modes.contains(ReuseMode::Never)
            && dispatch_policy.completion != CompletionPolicy::FreshRequired
        {
            return Err(ActionValidationError::NeverRequiresFresh);
        }
        Ok(())
    }

    fn compute_semantic_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"action-contract-semantic-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.semantic_authority_source_digest);
        hasher.field_u8(self.effect_class.tag());
        hasher.finish()
    }

    fn compute_validation_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"action-contract-validation-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.validation_authority_source_digest);
        hasher.field_u8(self.reuse_modes.bits());
        hasher.finish()
    }

    fn compute_operational_policy_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"action-contract-operational-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.operational_authority_source_digest);
        hasher.field_digest(self.default_dispatch_policy.digest());
        hasher.finish()
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"action-contract-record-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(self.id.as_str());
        hasher.field_digest(self.semantic_definition_digest);
        hasher.field_digest(self.validation_definition_digest);
        hasher.field_digest(self.operational_policy_digest);
        hasher.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestAuthority {
    Semantic,
    Validation,
    Operational,
    CompleteRecord,
}

impl fmt::Display for DigestAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Semantic => "semantic",
            Self::Validation => "validation",
            Self::Operational => "operational",
            Self::CompleteRecord => "complete-record",
        })
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ActionValidationError {
    #[error(transparent)]
    ReuseModes(#[from] ReuseModeSetError),
    #[error("action contract format revision {0} is unsupported")]
    FormatRevision(u16),
    #[error("reuse mode `never` requires fresh completion")]
    NeverRequiresFresh,
    #[error("external-effect actions require reuse mode `never`")]
    ExternalEffectRequiresNever,
    #[error("{authority} digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { authority: DigestAuthority, expected: Digest, actual: Digest },
    #[error("action request contract does not match its definition")]
    RequestContractMismatch,
    #[error("action request semantic policy does not match its definition")]
    RequestSemanticPolicyMismatch,
    #[error("action request revisions 2 and 3 require a semantic need fragment")]
    RequestSemanticFragmentRequired,
    #[error("action request revision 3 requires a non-zero semantic parameter digest")]
    RequestSemanticParameterRequired,
    #[error("action request semantic parameter does not match its format revision")]
    RequestSemanticParameterMismatch,
    #[error("action request operational policy does not match its definition")]
    RequestOperationalPolicyMismatch,
    #[error("action request contains {actual} semantic inputs; the hard maximum is {maximum}")]
    RequestInputBound { actual: usize, maximum: usize },
    #[error("action request semantic inputs must be strictly sorted and unique")]
    RequestInputsNotCanonical,
    #[error("action request effective dispatch policy digest is invalid")]
    EffectiveDispatchPolicyMismatch,
    #[error("action request contains a non-canonical {field} route key")]
    RequestRoute { field: &'static str },
}

fn check_digest(
    authority: DigestAuthority,
    expected: Digest,
    actual: Digest,
) -> Result<(), ActionValidationError> {
    if expected == actual {
        Ok(())
    } else {
        Err(ActionValidationError::DigestMismatch { authority, expected, actual })
    }
}
