use crate::{
    ActionContractId, ArtifactId, CanonicalHasher, ChangeId, ChangeRequest,
    ChangeRequestValidationError, Digest, LifecycleBudget, MAX_NEED_INPUTS,
    NEED_IR_FORMAT_REVISION, NeedIr, PatchId, VerificationArtifactId,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

pub const NEED_EXECUTION_SCHEMA_V1: &str = "needle.need-execution/1";
pub const NEED_EXECUTION_OUTCOME_SCHEMA_V1: &str = "needle.need-execution-outcome/1";
pub const MAX_NEED_EXECUTION_WIRE_BYTES: usize = 128 * 1024;
pub const MAX_EXECUTION_ARTIFACT_INPUTS: usize = MAX_NEED_INPUTS;

pub const PATCH_PROPOSE_ACTION_CONTRACT: &str = "needle.patch.propose";
pub const TESTS_EXECUTE_ACTION_CONTRACT: &str = "needle.tests.execute";
pub const REVIEW_DIFF_ACTION_CONTRACT: &str = "needle.review.diff";
pub const PATCH_VERIFY_ACTION_CONTRACT: &str = "needle.patch.verify";
pub const PATCH_APPLY_ACTION_CONTRACT: &str = "needle.patch.apply";

/// Public, versioned execution envelope. `execution` is deliberately outside
/// `NeedIr`, so orchestration intent cannot fragment semantic Need identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NeedExecutionEnvelopeV1 {
    pub schema: String,
    pub operation_id: Digest,
    pub need: NeedIr,
    pub execution: NeedExecution,
}

impl NeedExecutionEnvelopeV1 {
    pub fn new(operation_id: Digest, need: NeedIr, execution: NeedExecution) -> Self {
        Self { schema: NEED_EXECUTION_SCHEMA_V1.to_owned(), operation_id, need, execution }
    }

    pub fn semantic_need_digest(&self) -> Digest {
        self.need.transport_digest()
    }

    /// Canonical identity of one structured invocation, excluding the
    /// caller-supplied idempotency key itself. This deliberately keeps
    /// orchestration mode outside Need and artifact semantic identity while
    /// allowing durable operation records to reject reuse of an operation id
    /// with different material.
    pub fn operational_request_digest(
        &self,
        repository_id: Digest,
        source_snapshot: Digest,
    ) -> Digest {
        let mut hasher = CanonicalHasher::new(b"needle-need-execution-operation-v1");
        hasher.field_str(&self.schema);
        hasher.field_digest(repository_id);
        hasher.field_digest(source_snapshot);
        hasher.field_digest(self.semantic_need_digest());
        match &self.execution {
            NeedExecution::Resolve => hasher.field_u8(0),
            NeedExecution::Action { action } => {
                hasher.field_u8(1);
                hasher.field_str(action.contract.as_str());
                hasher.field_digest(action.input.semantic_parameter_digest(source_snapshot));
                hasher.field_u8(u8::from(matches!(
                    action.input,
                    ChangeActionInput::PatchApply { confirm: true, .. }
                )));
            }
            NeedExecution::Lifecycle { lifecycle } => {
                hasher.field_u8(2);
                hasher.field_digest(lifecycle.change.digest(source_snapshot));
                match &lifecycle.budget_override {
                    Some(budget) => {
                        hasher.field_u8(1);
                        hasher.field_u32(budget.max_worker_turns);
                        hasher.field_bytes(&budget.max_output_tokens.to_le_bytes());
                        hasher.field_bytes(&budget.max_cost_microusd.to_le_bytes());
                        hasher.field_u8(budget.max_concurrent_workers);
                    }
                    None => hasher.field_u8(0),
                }
            }
        }
        hasher.finish()
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, NeedExecutionValidationError> {
        if bytes.len() > MAX_NEED_EXECUTION_WIRE_BYTES {
            return Err(NeedExecutionValidationError::WireBound {
                actual: bytes.len(),
                maximum: MAX_NEED_EXECUTION_WIRE_BYTES,
            });
        }
        let envelope: Self = serde_json::from_slice(bytes)
            .map_err(|error| NeedExecutionValidationError::Json(error.to_string()))?;
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<(), NeedExecutionValidationError> {
        if self.schema != NEED_EXECUTION_SCHEMA_V1 {
            return Err(NeedExecutionValidationError::Schema);
        }
        if self.operation_id == Digest([0; 32]) {
            return Err(NeedExecutionValidationError::OperationId);
        }
        validate_need_ir_shape(&self.need)?;
        self.execution.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NeedExecution {
    Resolve,
    Action { action: ChangeActionInvocation },
    Lifecycle { lifecycle: LifecycleExecutionRequest },
}

impl NeedExecution {
    fn validate(&self) -> Result<(), NeedExecutionValidationError> {
        match self {
            Self::Resolve => Ok(()),
            Self::Action { action } => action.validate(),
            Self::Lifecycle { lifecycle } => lifecycle.validate(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeActionInvocation {
    pub contract: ActionContractId,
    pub input: ChangeActionInput,
}

impl ChangeActionInvocation {
    pub fn validate(&self) -> Result<(), NeedExecutionValidationError> {
        let expected = self.input.contract_id();
        if self.contract.as_str() != expected {
            return Err(NeedExecutionValidationError::ActionContract);
        }
        self.input.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChangeActionInput {
    PatchPropose {
        change: ChangeRequest,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prior_patch: Option<PatchActionInputRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        repair_verification: Option<VerificationActionInputRef>,
    },
    TestsExecute {
        change_id: ChangeId,
        requirements_digest: Digest,
        patch: PatchActionInputRef,
        test_plan_artifact: ArtifactId,
    },
    ReviewDiff {
        change_id: ChangeId,
        requirements_digest: Digest,
        patch: PatchActionInputRef,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        prior_review_artifacts: Vec<ArtifactId>,
    },
    PatchVerify {
        change_id: ChangeId,
        requirements_digest: Digest,
        patch: PatchActionInputRef,
        test_evidence_artifacts: Vec<ArtifactId>,
    },
    PatchApply {
        change_id: ChangeId,
        requirements_digest: Digest,
        patch: PatchActionInputRef,
        verification: VerificationActionInputRef,
        expected_state_digest: Digest,
        confirm: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchActionInputRef {
    pub artifact: ArtifactId,
    pub patch: PatchId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationActionInputRef {
    pub artifact: ArtifactId,
    pub verification: VerificationArtifactId,
}

impl ChangeActionInput {
    pub const fn contract_id(&self) -> &'static str {
        match self {
            Self::PatchPropose { .. } => PATCH_PROPOSE_ACTION_CONTRACT,
            Self::TestsExecute { .. } => TESTS_EXECUTE_ACTION_CONTRACT,
            Self::ReviewDiff { .. } => REVIEW_DIFF_ACTION_CONTRACT,
            Self::PatchVerify { .. } => PATCH_VERIFY_ACTION_CONTRACT,
            Self::PatchApply { .. } => PATCH_APPLY_ACTION_CONTRACT,
        }
    }

    pub fn change_id(&self, source_snapshot: Digest) -> ChangeId {
        match self {
            Self::PatchPropose { change, .. } => {
                ChangeId::from_digest(change.digest(source_snapshot))
            }
            Self::TestsExecute { change_id, .. }
            | Self::ReviewDiff { change_id, .. }
            | Self::PatchVerify { change_id, .. }
            | Self::PatchApply { change_id, .. } => change_id.clone(),
        }
    }

    pub fn requirements_digest(&self, source_snapshot: Digest) -> Digest {
        match self {
            Self::PatchPropose { change, .. } => change.digest(source_snapshot),
            Self::TestsExecute { requirements_digest, .. }
            | Self::ReviewDiff { requirements_digest, .. }
            | Self::PatchVerify { requirements_digest, .. }
            | Self::PatchApply { requirements_digest, .. } => *requirements_digest,
        }
    }

    /// Canonical digest of the contract-specific semantic parameters. It is
    /// bound by ActionRequest revision 3; approval and orchestration mode stay
    /// outside this digest.
    pub fn semantic_parameter_digest(&self, source_snapshot: Digest) -> Digest {
        let mut hasher = CanonicalHasher::new(b"needle-change-action-parameters-v1");
        hasher.field_str(self.contract_id());
        match self {
            Self::PatchPropose { change, prior_patch, repair_verification } => {
                hasher.field_digest(change.digest(source_snapshot));
                hash_optional_patch(&mut hasher, *prior_patch);
                hash_optional_verification(&mut hasher, *repair_verification);
            }
            Self::TestsExecute { change_id, requirements_digest, patch, test_plan_artifact } => {
                hasher.field_str(change_id.as_str());
                hasher.field_digest(*requirements_digest);
                hash_patch(&mut hasher, *patch);
                hasher.field_digest(test_plan_artifact.digest());
            }
            Self::ReviewDiff { change_id, requirements_digest, patch, prior_review_artifacts } => {
                hasher.field_str(change_id.as_str());
                hasher.field_digest(*requirements_digest);
                hash_patch(&mut hasher, *patch);
                hash_artifacts(&mut hasher, prior_review_artifacts);
            }
            Self::PatchVerify {
                change_id,
                requirements_digest,
                patch,
                test_evidence_artifacts,
            } => {
                hasher.field_str(change_id.as_str());
                hasher.field_digest(*requirements_digest);
                hash_patch(&mut hasher, *patch);
                hash_artifacts(&mut hasher, test_evidence_artifacts);
            }
            Self::PatchApply {
                change_id,
                requirements_digest,
                patch,
                verification,
                expected_state_digest,
                confirm: _,
            } => {
                hasher.field_str(change_id.as_str());
                hasher.field_digest(*requirements_digest);
                hash_patch(&mut hasher, *patch);
                hash_verification(&mut hasher, *verification);
                hasher.field_digest(*expected_state_digest);
            }
        }
        hasher.finish()
    }

    pub fn artifact_inputs(&self) -> Vec<ArtifactId> {
        let mut values = match self {
            Self::PatchPropose { change, prior_patch, repair_verification } => {
                let mut values = change.artifact_ids.clone();
                values.extend(prior_patch.iter().map(|value| value.artifact));
                values.extend(repair_verification.iter().map(|value| value.artifact));
                values
            }
            Self::TestsExecute { patch, test_plan_artifact, .. } => {
                vec![patch.artifact, *test_plan_artifact]
            }
            Self::ReviewDiff { patch, prior_review_artifacts, .. } => {
                let mut values = Vec::with_capacity(1 + prior_review_artifacts.len());
                values.push(patch.artifact);
                values.extend_from_slice(prior_review_artifacts);
                values
            }
            Self::PatchVerify { patch, test_evidence_artifacts, .. } => {
                let mut values = Vec::with_capacity(1 + test_evidence_artifacts.len());
                values.push(patch.artifact);
                values.extend_from_slice(test_evidence_artifacts);
                values
            }
            Self::PatchApply { patch, verification, .. } => {
                vec![patch.artifact, verification.artifact]
            }
        };
        values.sort_unstable();
        values.dedup();
        values
    }

    fn validate(&self) -> Result<(), NeedExecutionValidationError> {
        match self {
            Self::PatchPropose { change, prior_patch, repair_verification } => {
                change.validate_for_execution()?;
                if prior_patch.is_some() != repair_verification.is_some() {
                    return Err(NeedExecutionValidationError::RepairBinding);
                }
                let mut repair_inputs = Vec::with_capacity(2);
                repair_inputs.extend(prior_patch.iter().map(|value| value.artifact));
                repair_inputs.extend(repair_verification.iter().map(|value| value.artifact));
                validate_artifact_inputs_with_optional(&change.artifact_ids, &repair_inputs)?;
            }
            Self::TestsExecute { requirements_digest, patch, test_plan_artifact, .. } => {
                validate_requirements(*requirements_digest)?;
                validate_artifact_inputs(&[patch.artifact, *test_plan_artifact], false)?;
            }
            Self::ReviewDiff { requirements_digest, patch, prior_review_artifacts, .. } => {
                validate_requirements(*requirements_digest)?;
                validate_artifact_inputs_with_optional(&[patch.artifact], prior_review_artifacts)?;
            }
            Self::PatchVerify { requirements_digest, patch, test_evidence_artifacts, .. } => {
                validate_requirements(*requirements_digest)?;
                validate_artifact_inputs_with_required(&[patch.artifact], test_evidence_artifacts)?;
            }
            Self::PatchApply {
                requirements_digest,
                patch,
                verification,
                expected_state_digest,
                confirm,
                ..
            } => {
                validate_requirements(*requirements_digest)?;
                if !confirm || *expected_state_digest == Digest([0; 32]) {
                    return Err(NeedExecutionValidationError::ApplyApproval);
                }
                validate_artifact_inputs(&[patch.artifact, verification.artifact], false)?;
            }
        }
        Ok(())
    }
}

fn validate_requirements(value: Digest) -> Result<(), NeedExecutionValidationError> {
    if value == Digest([0; 32]) {
        Err(NeedExecutionValidationError::RequirementsDigest)
    } else {
        Ok(())
    }
}

fn hash_patch(hasher: &mut CanonicalHasher, value: PatchActionInputRef) {
    hasher.field_digest(value.artifact.digest());
    hasher.field_digest(value.patch.0);
}

fn hash_optional_patch(hasher: &mut CanonicalHasher, value: Option<PatchActionInputRef>) {
    hasher.field_u8(u8::from(value.is_some()));
    if let Some(value) = value {
        hash_patch(hasher, value);
    }
}

fn hash_verification(hasher: &mut CanonicalHasher, value: VerificationActionInputRef) {
    hasher.field_digest(value.artifact.digest());
    hasher.field_digest(value.verification.0);
}

fn hash_optional_verification(
    hasher: &mut CanonicalHasher,
    value: Option<VerificationActionInputRef>,
) {
    hasher.field_u8(u8::from(value.is_some()));
    if let Some(value) = value {
        hash_verification(hasher, value);
    }
}

fn hash_artifacts(hasher: &mut CanonicalHasher, values: &[ArtifactId]) {
    let mut values = values.to_vec();
    values.sort_unstable();
    hasher.field_u16(values.len().try_into().unwrap_or(u16::MAX));
    for value in values {
        hasher.field_digest(value.digest());
    }
}

fn validate_artifact_inputs_with_required(
    required: &[ArtifactId],
    additional: &[ArtifactId],
) -> Result<(), NeedExecutionValidationError> {
    if additional.is_empty() {
        return Err(NeedExecutionValidationError::ArtifactInputs);
    }
    validate_artifact_inputs_with_optional(required, additional)
}

fn validate_artifact_inputs_with_optional(
    required: &[ArtifactId],
    additional: &[ArtifactId],
) -> Result<(), NeedExecutionValidationError> {
    if required.len() + additional.len() > MAX_EXECUTION_ARTIFACT_INPUTS {
        return Err(NeedExecutionValidationError::ArtifactInputs);
    }
    let mut unique = BTreeSet::new();
    if required.iter().chain(additional).copied().any(|value| !unique.insert(value)) {
        return Err(NeedExecutionValidationError::ArtifactInputs);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleExecutionRequest {
    pub change: ChangeRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_override: Option<LifecycleBudget>,
}

impl LifecycleExecutionRequest {
    fn validate(&self) -> Result<(), NeedExecutionValidationError> {
        self.change.validate_for_execution()?;
        if let Some(budget) = &self.budget_override
            && (budget.max_worker_turns == 0
                || budget.max_output_tokens == 0
                || budget.max_cost_microusd == 0
                || budget.max_concurrent_workers != 1)
        {
            return Err(NeedExecutionValidationError::LifecycleBudget);
        }
        Ok(())
    }
}

fn validate_artifact_inputs(
    values: &[ArtifactId],
    allow_empty: bool,
) -> Result<(), NeedExecutionValidationError> {
    if (!allow_empty && values.is_empty()) || values.len() > MAX_EXECUTION_ARTIFACT_INPUTS {
        return Err(NeedExecutionValidationError::ArtifactInputs);
    }
    let mut unique = BTreeSet::new();
    if values.iter().copied().any(|value| !unique.insert(value)) {
        return Err(NeedExecutionValidationError::ArtifactInputs);
    }
    Ok(())
}

fn validate_need_ir_shape(need: &NeedIr) -> Result<(), NeedExecutionValidationError> {
    if need.format_revision != NEED_IR_FORMAT_REVISION
        || need.route_hint.is_none()
        || need.body.trim().is_empty()
        || need.body.len() > crate::MAX_NEED_IR_BYTES
        || need.subjects.len() > crate::MAX_NEED_SUBJECTS
        || need.required.len() > crate::MAX_REQUIRED_OBLIGATIONS
        || need.preferred.len() > crate::MAX_PREFERRED_OBLIGATIONS
        || need.semantic_constraints.len() > crate::MAX_SEMANTIC_CONSTRAINTS
        || need.input_artifacts.len() > crate::MAX_NEED_INPUTS
        || need.world.len() > crate::MAX_OBLIGATION_FACETS
        || need.projection.len() > crate::MAX_OBLIGATION_FACETS
        || need
            .required
            .iter()
            .chain(&need.preferred)
            .any(|obligation| obligation.facets.len() > crate::MAX_OBLIGATION_FACETS)
    {
        return Err(NeedExecutionValidationError::Need);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NeedExecutionValidationError {
    #[error("Need execution envelope contains {actual} bytes; the maximum is {maximum}")]
    WireBound { actual: usize, maximum: usize },
    #[error("Need execution envelope JSON is invalid: {0}")]
    Json(String),
    #[error("Need execution schema is unsupported")]
    Schema,
    #[error("Need execution operation id must be non-zero")]
    OperationId,
    #[error("Need execution contains an invalid or out-of-bounds NeedIR")]
    Need,
    #[error("action contract does not match its typed input")]
    ActionContract,
    #[error("repair proposal must bind both the prior patch and repair verification")]
    RepairBinding,
    #[error("action artifact inputs are missing, duplicated, or out of bounds")]
    ArtifactInputs,
    #[error("action requirements digest must be non-zero")]
    RequirementsDigest,
    #[error("Apply requires explicit confirmation and a non-zero expected state digest")]
    ApplyApproval,
    #[error("lifecycle budget override is invalid")]
    LifecycleBudget,
    #[error(transparent)]
    Change(#[from] ChangeRequestValidationError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AllowedPath, AllowedPathScope, Facet, NeedKey, ObligationExpression, PredicateKind,
        SubjectExpression, SubjectKind,
    };

    fn need() -> NeedIr {
        NeedIr {
            route_hint: Some(NeedKey::new("locate.implementation").unwrap()),
            subjects: vec![SubjectExpression {
                kind: SubjectKind::Symbol,
                canonical_name: "NeedExecutionEnvelopeV1".to_owned(),
            }],
            required: vec![ObligationExpression {
                predicate: PredicateKind::ImplementationLocation,
                facets: vec![Facet { key: "selection".to_owned(), value: "primary".to_owned() }],
            }],
            preferred: Vec::new(),
            semantic_constraints: Vec::new(),
            world: Vec::new(),
            input_artifacts: Vec::new(),
            projection: Vec::new(),
            body: "Locate the execution envelope.".to_owned(),
            format_revision: NEED_IR_FORMAT_REVISION,
        }
    }

    fn change() -> ChangeRequest {
        ChangeRequest {
            task: "Add execution support.".to_owned(),
            acceptance_criteria: vec!["The request is validated.".to_owned()],
            allowed_paths: vec![AllowedPath {
                path: "crates/needle-core/src".to_owned(),
                scope: AllowedPathScope::Subtree,
            }],
            artifact_ids: Vec::new(),
            claim_ids: Vec::new(),
            constraints: Vec::new(),
        }
    }

    #[test]
    fn execution_intent_does_not_change_need_identity() {
        let operation = Digest::blake3("operation");
        let resolve = NeedExecutionEnvelopeV1::new(operation, need(), NeedExecution::Resolve);
        let lifecycle = NeedExecutionEnvelopeV1::new(
            operation,
            need(),
            NeedExecution::Lifecycle {
                lifecycle: LifecycleExecutionRequest { change: change(), budget_override: None },
            },
        );
        assert_eq!(resolve.semantic_need_digest(), lifecycle.semantic_need_digest());
        assert_ne!(
            resolve
                .operational_request_digest(Digest::blake3("repository"), Digest::blake3("source")),
            lifecycle
                .operational_request_digest(Digest::blake3("repository"), Digest::blake3("source"))
        );
        assert!(resolve.validate().is_ok());
        assert!(lifecycle.validate().is_ok());
    }

    #[test]
    fn action_input_is_closed_and_contract_bound() {
        let mut envelope = NeedExecutionEnvelopeV1::new(
            Digest::blake3("operation"),
            need(),
            NeedExecution::Action {
                action: ChangeActionInvocation {
                    contract: ActionContractId::new(PATCH_PROPOSE_ACTION_CONTRACT).unwrap(),
                    input: ChangeActionInput::PatchPropose {
                        change: change(),
                        prior_patch: None,
                        repair_verification: None,
                    },
                },
            },
        );
        assert!(envelope.validate().is_ok());
        let encoded = serde_json::to_value(&envelope).unwrap();
        let encoded = serde_json::to_vec(&encoded).unwrap();
        assert!(NeedExecutionEnvelopeV1::decode_json(&encoded).is_ok());

        let NeedExecution::Action { action } = &mut envelope.execution else { unreachable!() };
        action.contract = ActionContractId::new(TESTS_EXECUTE_ACTION_CONTRACT).unwrap();
        assert_eq!(envelope.validate(), Err(NeedExecutionValidationError::ActionContract));
    }

    #[test]
    fn execution_wire_is_closed_and_bounded_before_decode() {
        let envelope = NeedExecutionEnvelopeV1::new(
            Digest::blake3("operation"),
            need(),
            NeedExecution::Resolve,
        );
        let mut value = serde_json::to_value(envelope).unwrap();
        value["unknown"] = serde_json::json!(true);
        let unknown = serde_json::to_vec(&value).unwrap();
        assert!(matches!(
            NeedExecutionEnvelopeV1::decode_json(&unknown),
            Err(NeedExecutionValidationError::Json(_))
        ));
        let oversized = vec![b' '; MAX_NEED_EXECUTION_WIRE_BYTES + 1];
        assert_eq!(
            NeedExecutionEnvelopeV1::decode_json(&oversized),
            Err(NeedExecutionValidationError::WireBound {
                actual: MAX_NEED_EXECUTION_WIRE_BYTES + 1,
                maximum: MAX_NEED_EXECUTION_WIRE_BYTES,
            })
        );
    }

    #[test]
    fn repair_apply_and_artifact_bounds_fail_closed() {
        let repair = ChangeActionInput::PatchPropose {
            change: change(),
            prior_patch: Some(PatchActionInputRef {
                artifact: ArtifactId::new(Digest::blake3("patch-artifact")),
                patch: PatchId(Digest::blake3("patch")),
            }),
            repair_verification: None,
        };
        assert_eq!(repair.validate(), Err(NeedExecutionValidationError::RepairBinding));

        let apply = ChangeActionInput::PatchApply {
            change_id: ChangeId::from_digest(Digest::blake3("change")),
            requirements_digest: Digest::blake3("requirements"),
            patch: PatchActionInputRef {
                artifact: ArtifactId::new(Digest::blake3("patch-artifact")),
                patch: PatchId(Digest::blake3("patch")),
            },
            verification: VerificationActionInputRef {
                artifact: ArtifactId::new(Digest::blake3("verification-artifact")),
                verification: VerificationArtifactId(Digest::blake3("verification")),
            },
            expected_state_digest: Digest::blake3("state"),
            confirm: false,
        };
        assert_eq!(apply.validate(), Err(NeedExecutionValidationError::ApplyApproval));

        let duplicate = ArtifactId::new(Digest::blake3("artifact"));
        let tests = ChangeActionInput::TestsExecute {
            change_id: ChangeId::from_digest(Digest::blake3("change")),
            requirements_digest: Digest::blake3("requirements"),
            patch: PatchActionInputRef {
                artifact: duplicate,
                patch: PatchId(Digest::blake3("patch")),
            },
            test_plan_artifact: duplicate,
        };
        assert_eq!(tests.validate(), Err(NeedExecutionValidationError::ArtifactInputs));
    }

    #[test]
    fn change_request_rejects_unsafe_or_duplicate_inputs() {
        let mut request = change();
        request.allowed_paths[0].path = "../outside".to_owned();
        assert_eq!(
            request.validate_for_execution(),
            Err(ChangeRequestValidationError::AllowedPaths)
        );
    }

    #[test]
    fn typed_action_parameter_digest_binds_plan_and_requirements() {
        let patch = PatchActionInputRef {
            artifact: ArtifactId::new(Digest::blake3("patch-artifact")),
            patch: PatchId(Digest::blake3("patch")),
        };
        let first = ArtifactId::new(Digest::blake3("first-plan"));
        let second = ArtifactId::new(Digest::blake3("second-plan"));
        let left = ChangeActionInput::TestsExecute {
            change_id: ChangeId::from_digest(Digest::blake3("change")),
            requirements_digest: Digest::blake3("requirements"),
            patch,
            test_plan_artifact: first,
        };
        let same = ChangeActionInput::TestsExecute {
            change_id: ChangeId::from_digest(Digest::blake3("change")),
            requirements_digest: Digest::blake3("requirements"),
            patch,
            test_plan_artifact: first,
        };
        assert_eq!(
            left.semantic_parameter_digest(Digest::blake3("source")),
            same.semantic_parameter_digest(Digest::blake3("other-source"))
        );

        let changed = ChangeActionInput::TestsExecute {
            change_id: ChangeId::from_digest(Digest::blake3("change")),
            requirements_digest: Digest::blake3("requirements"),
            patch,
            test_plan_artifact: second,
        };
        assert_ne!(
            left.semantic_parameter_digest(Digest::blake3("source")),
            changed.semantic_parameter_digest(Digest::blake3("source"))
        );

        let changed_requirements = ChangeActionInput::TestsExecute {
            change_id: ChangeId::from_digest(Digest::blake3("change")),
            requirements_digest: Digest::blake3("changed-requirements"),
            patch,
            test_plan_artifact: first,
        };
        assert_ne!(
            left.semantic_parameter_digest(Digest::blake3("source")),
            changed_requirements.semantic_parameter_digest(Digest::blake3("source"))
        );
    }
}
