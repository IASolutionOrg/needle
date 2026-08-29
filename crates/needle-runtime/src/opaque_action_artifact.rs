use crate::{BuiltInActionCoverage, built_in_action_for_artifact_kind};
use needle_core::{
    ActionOutputValidationCertificate, ActionOutputValidationCertificateInput, ActionRequest,
    ApplyReceipt, Artifact, ArtifactContract, ArtifactId, ArtifactKind, CacheScope,
    ChangeActionInput, DependencyManifest, Digest, PatchArtifact, ReviewReport, SemanticWorld,
    TestExecutionEvidence, VerificationArtifact,
};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChangeActionOutput {
    PatchProposal(PatchArtifact),
    TestExecution(TestExecutionEvidence),
    Review(ReviewReport),
    PatchVerification(VerificationArtifact),
    ApplyReceipt(ApplyReceipt),
}

impl ChangeActionOutput {
    pub fn from_artifact(artifact: &Artifact) -> Result<Self, OpaqueActionArtifactError> {
        let output = match artifact.contract.kind.0.as_str() {
            "patch-proposal" => {
                Self::PatchProposal(serde_json::from_value(artifact.payload.clone())?)
            }
            "test-execution" => {
                Self::TestExecution(serde_json::from_value(artifact.payload.clone())?)
            }
            "review-report" => Self::Review(serde_json::from_value(artifact.payload.clone())?),
            "patch-verification" => {
                Self::PatchVerification(serde_json::from_value(artifact.payload.clone())?)
            }
            "apply-receipt" => {
                Self::ApplyReceipt(serde_json::from_value(artifact.payload.clone())?)
            }
            _ => return Err(OpaqueActionArtifactError::ActionCoverage),
        };
        output.validate()?;
        Ok(output)
    }

    pub fn artifact_kind(&self) -> ArtifactKind {
        match self {
            Self::PatchProposal(_) => ArtifactKind::patch_proposal(),
            Self::TestExecution(_) => ArtifactKind::test_execution(),
            Self::Review(_) => ArtifactKind::review_report(),
            Self::PatchVerification(_) => ArtifactKind::patch_verification(),
            Self::ApplyReceipt(_) => ArtifactKind::apply_receipt(),
        }
    }

    fn validate(&self) -> Result<(), OpaqueActionArtifactError> {
        match self {
            Self::PatchProposal(patch) if patch.is_canonical() => Ok(()),
            Self::TestExecution(evidence) => evidence
                .validate()
                .map_err(|error| OpaqueActionArtifactError::Payload(error.to_string())),
            Self::Review(report) => report
                .validate()
                .map_err(|error| OpaqueActionArtifactError::Payload(error.to_string())),
            Self::PatchVerification(verification) if verification.is_canonical() => Ok(()),
            Self::ApplyReceipt(receipt) => receipt
                .validate()
                .map_err(|error| OpaqueActionArtifactError::Payload(error.to_string())),
            _ => Err(OpaqueActionArtifactError::Payload(
                "change action output is not canonical".to_owned(),
            )),
        }
    }

    pub fn source_payload_digest(&self) -> Digest {
        match self {
            Self::PatchProposal(value) => value.id.0,
            Self::TestExecution(value) => value.id.0,
            Self::Review(value) => value.id,
            Self::PatchVerification(value) => value.id.0,
            Self::ApplyReceipt(value) => value.id,
        }
    }

    pub fn validate_for_execution(
        &self,
        operation_id: Digest,
        input: &ChangeActionInput,
        request: &ActionRequest,
    ) -> Result<(), OpaqueActionArtifactError> {
        self.validate()?;
        let source = request.artifact_request.source_snapshot_digest;
        let change_id = input.change_id(source);
        let requirements = input.requirements_digest(source);
        let request_id = request.semantic_id();
        let bound = match (self, input) {
            (Self::PatchProposal(output), ChangeActionInput::PatchPropose { prior_patch, .. }) => {
                output.change_id == change_id
                    && output.source_snapshot == source
                    && prior_patch.is_none_or(|prior| prior.patch != output.id)
            }
            (
                Self::TestExecution(output),
                ChangeActionInput::TestsExecute { patch, test_plan_artifact, .. },
            ) => {
                output.action_request == request_id
                    && output.change_id == change_id
                    && output.patch_id == patch.patch
                    && output.test_plan_artifact == *test_plan_artifact
                    && output.source_snapshot == source
            }
            (Self::Review(output), ChangeActionInput::ReviewDiff { patch, .. }) => {
                output.action_request == request_id
                    && output.change_id == change_id
                    && output.patch_id == patch.patch
                    && output.requirements_digest == requirements
            }
            (
                Self::PatchVerification(output),
                ChangeActionInput::PatchVerify { patch, test_evidence_artifacts, .. },
            ) => {
                output.change_id == change_id
                    && output.patch_id == patch.patch
                    && output.action_request == Some(request_id)
                    && output.requirements_digest == Some(requirements)
                    && output.input_test_evidence_artifacts == *test_evidence_artifacts
            }
            (
                Self::ApplyReceipt(output),
                ChangeActionInput::PatchApply { patch, expected_state_digest, .. },
            ) => {
                output.operation_id == operation_id
                    && output.change_id == change_id
                    && output.patch_id == patch.patch
                    && output.expected_state_digest == *expected_state_digest
                    && output.source_before == source
            }
            _ => false,
        };
        if bound { Ok(()) } else { Err(OpaqueActionArtifactError::ExecutionBinding) }
    }

    pub fn to_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        match self {
            Self::PatchProposal(value) => serde_json::to_value(value),
            Self::TestExecution(value) => serde_json::to_value(value),
            Self::Review(value) => serde_json::to_value(value),
            Self::PatchVerification(value) => serde_json::to_value(value),
            Self::ApplyReceipt(value) => serde_json::to_value(value),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowOpaqueActionArtifactPublication {
    artifact: Artifact,
    certificate: ActionOutputValidationCertificate,
}

impl ShadowOpaqueActionArtifactPublication {
    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }

    pub fn certificate(&self) -> &ActionOutputValidationCertificate {
        &self.certificate
    }

    pub fn validate(&self, request: &ActionRequest) -> Result<(), OpaqueActionArtifactError> {
        let action = built_in_action_for_artifact_kind(&self.artifact.contract.kind)
            .ok_or(OpaqueActionArtifactError::ActionMissing)?;
        if !matches!(action.coverage, BuiltInActionCoverage::Opaque { .. }) {
            return Err(OpaqueActionArtifactError::ActionCoverage);
        }
        request
            .validate(&action.contract)
            .map_err(|error| OpaqueActionArtifactError::Request(error.to_string()))?;
        let expected_contract = ArtifactContract::semantic_with_schema(
            action.output_contract_id,
            action.output_contract_revision,
            action.artifact_kind.clone(),
            action.output_schema_id,
            CacheScope::SnapshotExact,
        );
        if self.artifact.request_id != request.semantic_id().digest()
            || self.artifact.contract != expected_contract
            || self.artifact.dependency_manifest.scope != CacheScope::SnapshotExact
            || Artifact::compute_content_id(&self.artifact.contract, &self.artifact.payload)
                .map_err(OpaqueActionArtifactError::Json)?
                .digest()
                != self.artifact.id
        {
            return Err(OpaqueActionArtifactError::ArtifactBinding);
        }
        self.certificate
            .validate()
            .map_err(|error| OpaqueActionArtifactError::Certificate(error.to_string()))?;
        let mut inputs = request
            .artifact_request
            .input_artifact_ids
            .iter()
            .copied()
            .map(ArtifactId::new)
            .collect::<Vec<_>>();
        inputs.sort_unstable();
        let manifest_digest =
            crate::semantic_validation::manifest_digest(&self.artifact.dependency_manifest);
        if self.certificate.artifact.digest() != self.artifact.id
            || self.certificate.input_artifacts != inputs
            || self.certificate.action_contract != action.contract.id
            || self.certificate.action_semantic_definition_digest
                != action.contract.semantic_definition_digest
            || self.certificate.action_validation_definition_digest
                != action.contract.validation_definition_digest
            || self.certificate.output_contract_definition_digest
                != action.output_contract_definition_digest
            || self.certificate.dependency_manifest_digest != manifest_digest
            || self.certificate.world.repository_lineage != request.artifact_request.repository_id
            || self.certificate.validator_definition_digest != action.validator_definition_digest
            || self.certificate.issued_unix_ms != self.artifact.created_unix_ms
        {
            return Err(OpaqueActionArtifactError::CertificateBinding);
        }
        validate_typed_payload(&self.artifact)?;
        Ok(())
    }
}

pub struct OpaqueActionCertificationInput {
    pub request: ActionRequest,
    pub output: ChangeActionOutput,
    pub world: SemanticWorld,
    pub dependency_manifest: DependencyManifest,
    pub source_payload_digest: needle_core::Digest,
    pub issued_unix_ms: u64,
}

pub fn certify_shadow_opaque_action_artifact(
    input: OpaqueActionCertificationInput,
) -> Result<(ActionRequest, ShadowOpaqueActionArtifactPublication), OpaqueActionArtifactError> {
    input.output.validate()?;
    let kind = input.output.artifact_kind();
    let action =
        built_in_action_for_artifact_kind(&kind).ok_or(OpaqueActionArtifactError::ActionMissing)?;
    if !matches!(action.coverage, BuiltInActionCoverage::Opaque { .. })
        || input.request.contract != action.contract.id
    {
        return Err(OpaqueActionArtifactError::ActionCoverage);
    }
    input
        .request
        .validate(&action.contract)
        .map_err(|error| OpaqueActionArtifactError::Request(error.to_string()))?;
    if input.world.repository_lineage != input.request.artifact_request.repository_id
        || input.dependency_manifest.scope != CacheScope::SnapshotExact
    {
        return Err(OpaqueActionArtifactError::WorldBinding);
    }
    let contract = ArtifactContract::semantic_with_schema(
        action.output_contract_id,
        action.output_contract_revision,
        kind,
        action.output_schema_id,
        CacheScope::SnapshotExact,
    );
    let payload = input.output.to_value()?;
    let artifact_id = Artifact::compute_content_id(&contract, &payload)?;
    let dependency_manifest_digest =
        crate::semantic_validation::manifest_digest(&input.dependency_manifest);
    let certificate =
        ActionOutputValidationCertificate::new(ActionOutputValidationCertificateInput {
            artifact: artifact_id,
            input_artifacts: input
                .request
                .artifact_request
                .input_artifact_ids
                .iter()
                .copied()
                .map(ArtifactId::new)
                .collect(),
            action_contract: action.contract.id.clone(),
            action_semantic_definition_digest: action.contract.semantic_definition_digest,
            action_validation_definition_digest: action.contract.validation_definition_digest,
            output_contract_definition_digest: action.output_contract_definition_digest,
            source_payload_digest: input.source_payload_digest,
            world: input.world,
            dependency_manifest_digest,
            validator_definition_digest: action.validator_definition_digest,
            issued_unix_ms: input.issued_unix_ms,
        })
        .map_err(|error| OpaqueActionArtifactError::Certificate(error.to_string()))?;
    let publication = ShadowOpaqueActionArtifactPublication {
        artifact: Artifact {
            id: artifact_id.digest(),
            request_id: input.request.semantic_id().digest(),
            contract,
            payload,
            dependency_manifest: input.dependency_manifest,
            validations: Vec::new(),
            created_unix_ms: input.issued_unix_ms,
        },
        certificate,
    };
    publication.validate(&input.request)?;
    Ok((input.request, publication))
}

fn validate_typed_payload(artifact: &Artifact) -> Result<(), OpaqueActionArtifactError> {
    match artifact.contract.kind.0.as_str() {
        "patch-proposal" => {
            decode_and_validate::<PatchArtifact>(artifact, |value| value.is_canonical())
        }
        "test-execution" => {
            decode_and_validate::<TestExecutionEvidence>(artifact, |value| value.validate().is_ok())
        }
        "patch-verification" => {
            decode_and_validate::<VerificationArtifact>(artifact, |value| value.is_canonical())
        }
        "apply-receipt" => {
            decode_and_validate::<ApplyReceipt>(artifact, |value| value.validate().is_ok())
        }
        _ => Err(OpaqueActionArtifactError::ActionCoverage),
    }
}

fn decode_and_validate<T: serde::de::DeserializeOwned>(
    artifact: &Artifact,
    validate: impl FnOnce(&T) -> bool,
) -> Result<(), OpaqueActionArtifactError> {
    let value: T = serde_json::from_value(artifact.payload.clone())?;
    if validate(&value) {
        Ok(())
    } else {
        Err(OpaqueActionArtifactError::Payload("stored action payload is not canonical".to_owned()))
    }
}

#[derive(Debug, Error)]
pub enum OpaqueActionArtifactError {
    #[error("opaque action definition is missing")]
    ActionMissing,
    #[error("action does not declare opaque output coverage")]
    ActionCoverage,
    #[error("opaque action request is invalid: {0}")]
    Request(String),
    #[error("opaque action world or dependency scope does not match the request")]
    WorldBinding,
    #[error("opaque action artifact binding is invalid")]
    ArtifactBinding,
    #[error("change action output does not bind the typed execution input")]
    ExecutionBinding,
    #[error("opaque action certificate binding is invalid")]
    CertificateBinding,
    #[error("opaque action certificate is invalid: {0}")]
    Certificate(String),
    #[error("opaque action payload is invalid: {0}")]
    Payload(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
