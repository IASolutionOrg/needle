use crate::action_contracts::{BuiltInActionDefinition, built_in_action_for_artifact_kind};
use crate::dependency_validity::dependency_manifest_is_bounded;
use crate::semantic_validation::{manifest_digest, validation_certificate_id};
use arrayvec::ArrayVec;
use needle_core::{
    Artifact, ArtifactId, ArtifactRequest, ArtifactRequestId, ArtifactValidationCertificate,
    CacheScope, CapabilityMode, Digest, MAX_NEED_INPUTS, MAX_NEED_IR_BYTES, MAX_PROOF_ARTIFACTS,
    ReuseDescriptor, ReuseDescriptorError, ReuseDescriptorInput,
    SEMANTIC_ARTIFACT_RESULT_SCHEMA_ID, SemanticWorkerArtifact, validate_reuse_descriptor_coverage,
};
use std::io::{self, Write};
use thiserror::Error;

pub const MAX_REUSE_DESCRIPTOR_CERTIFICATE_EVIDENCE: usize = MAX_PROOF_ARTIFACTS;
const MAX_REUSE_DESCRIPTOR_PAYLOAD_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum ReuseDescriptorDerivationError {
    #[error("semantic request contains {actual} inputs; the maximum is {maximum}")]
    RequestInputBound { actual: usize, maximum: usize },
    #[error("validation certificate contains {actual} inputs; the maximum is {maximum}")]
    CertificateInputBound { actual: usize, maximum: usize },
    #[error("validation certificate contains {actual} evidence ids; the maximum is {maximum}")]
    CertificateEvidenceBound { actual: usize, maximum: usize },
    #[error("semantic request text exceeds the descriptor derivation bound")]
    RequestTextBound,
    #[error("validation certificate evidence text exceeds the descriptor derivation bound")]
    CertificateEvidenceTextBound,
    #[error("semantic artifact payload exceeds the descriptor derivation bound")]
    ArtifactPayloadBound,
    #[error("artifact dependency manifest exceeds the descriptor derivation bound")]
    DependencyManifestBound,
    #[error("semantic request identity does not match the artifact origin")]
    RequestIdentity,
    #[error("artifact and validation certificate identities do not match")]
    ArtifactIdentity,
    #[error("artifact kind has no built-in action contract")]
    UnknownArtifactKind,
    #[error("built-in action definition is not canonical Shadow material")]
    ActionDefinition,
    #[error("semantic request or artifact output contract does not match the built-in action")]
    OutputContract,
    #[error("semantic artifact payload is not canonical for its output contract")]
    ArtifactPayload,
    #[error("validation certificate uses a stale or mismatched validator definition")]
    ValidatorDefinition,
    #[error("semantic request inputs do not match validation certificate inputs")]
    InputBinding,
    #[error("semantic request repository does not match validation coverage")]
    SemanticWorld,
    #[error("artifact dependency manifest does not match certified dependency checks")]
    DependencyManifest,
    #[error("validation coverage contains a predicate outside the built-in action contract")]
    CoveragePredicate,
    #[error("validation certificate id is not canonical")]
    ValidationCertificate,
    #[error(transparent)]
    Descriptor(#[from] ReuseDescriptorError),
    #[error("semantic artifact payload could not be decoded: {0}")]
    Json(#[from] serde_json::Error),
}

/// Derives a non-authoritative descriptor from already-validated v0.4 records.
///
/// This function performs structural and definition checks only. It does not
/// read the repository, replay input certificates, consult effective
/// capability state, or establish freshness.
pub fn derive_shadow_reuse_descriptor(
    request: &ArtifactRequest,
    artifact: &Artifact,
    certificate: &ArtifactValidationCertificate,
) -> Result<ReuseDescriptor, ReuseDescriptorDerivationError> {
    validate_request_bounds(request)?;
    if certificate.coverage.world.repository_lineage != request.repository_id {
        return Err(ReuseDescriptorDerivationError::SemanticWorld);
    }
    let descriptor = derive_shadow_reuse_descriptor_from_validated_pair(artifact, certificate)?;

    let action = built_in_action_for_artifact_kind(&artifact.contract.kind)
        .ok_or(ReuseDescriptorDerivationError::UnknownArtifactKind)?;
    if request.contract_id != action.output_contract_id
        || request.contract_revision != action.output_contract_revision
    {
        return Err(ReuseDescriptorDerivationError::OutputContract);
    }

    let exact_request = request.semantic_id();
    if exact_request != descriptor.exact_request {
        return Err(ReuseDescriptorDerivationError::RequestIdentity);
    }
    if !inputs_match(request, certificate) {
        return Err(ReuseDescriptorDerivationError::InputBinding);
    }
    Ok(descriptor)
}

/// Derives a Shadow descriptor from a structurally validated artifact and its
/// validation certificate without re-reading the originating request.
///
/// The caller remains responsible for freshness and effective capability.
pub(crate) fn derive_shadow_reuse_descriptor_from_validated_pair(
    artifact: &Artifact,
    certificate: &ArtifactValidationCertificate,
) -> Result<ReuseDescriptor, ReuseDescriptorDerivationError> {
    validate_pair_bounds(artifact, certificate)?;

    let action = built_in_action_for_artifact_kind(&artifact.contract.kind)
        .ok_or(ReuseDescriptorDerivationError::UnknownArtifactKind)?;
    let predicate =
        action.predicate().ok_or(ReuseDescriptorDerivationError::UnknownArtifactKind)?;
    validate_action_and_output(artifact, action)?;
    if certificate.artifact.digest() != artifact.id {
        return Err(ReuseDescriptorDerivationError::ArtifactIdentity);
    }

    validate_payload(artifact, action)?;

    if certificate.validator_definition != action.validator_definition_digest {
        return Err(ReuseDescriptorDerivationError::ValidatorDefinition);
    }
    validate_reuse_descriptor_coverage(&certificate.coverage)?;

    let current_manifest_digest = manifest_digest(&artifact.dependency_manifest);
    if artifact.dependency_manifest.dependencies.is_empty()
        || (artifact.dependency_manifest.scope == CacheScope::WorktreeSemantic
            && !artifact.dependency_manifest.supports_worktree_semantic())
        || artifact.contract.cache_scope != artifact.dependency_manifest.scope
        || certificate.coverage.dependency_manifest_digest != current_manifest_digest
        || certificate.dependency_checks_digest != current_manifest_digest
    {
        return Err(ReuseDescriptorDerivationError::DependencyManifest);
    }
    if certificate.coverage.entries.iter().any(|entry| entry.obligation.predicate != predicate) {
        return Err(ReuseDescriptorDerivationError::CoveragePredicate);
    }

    let descriptor = ReuseDescriptor::new(ReuseDescriptorInput {
        artifact: ArtifactId::new(artifact.id),
        exact_request: ArtifactRequestId::new(artifact.request_id),
        action_contract: action.contract.id.clone(),
        action_semantic_definition_digest: action.contract.semantic_definition_digest,
        action_validation_definition_digest: action.contract.validation_definition_digest,
        output_contract_definition_digest: action.output_contract_definition_digest,
        validator_definition_digest: certificate.validator_definition,
        validation_certificate: certificate.id,
        coverage: certificate.coverage.clone(),
    })?;

    let expected_certificate = validation_certificate_id(
        certificate.artifact,
        &certificate.input_artifacts,
        &certificate.evidence_ids,
        &certificate.coverage,
        certificate.validator_definition,
        certificate.test_plan_evidence,
    );
    if certificate.id != expected_certificate {
        return Err(ReuseDescriptorDerivationError::ValidationCertificate);
    }
    Ok(descriptor)
}

fn validate_request_bounds(
    request: &ArtifactRequest,
) -> Result<(), ReuseDescriptorDerivationError> {
    if request.input_artifact_ids.len() > MAX_NEED_INPUTS {
        return Err(ReuseDescriptorDerivationError::RequestInputBound {
            actual: request.input_artifact_ids.len(),
            maximum: MAX_NEED_INPUTS,
        });
    }
    if request.normalized_request.len() > MAX_NEED_IR_BYTES {
        return Err(ReuseDescriptorDerivationError::RequestTextBound);
    }
    Ok(())
}

fn validate_pair_bounds(
    artifact: &Artifact,
    certificate: &ArtifactValidationCertificate,
) -> Result<(), ReuseDescriptorDerivationError> {
    if certificate.input_artifacts.len() > MAX_NEED_INPUTS {
        return Err(ReuseDescriptorDerivationError::CertificateInputBound {
            actual: certificate.input_artifacts.len(),
            maximum: MAX_NEED_INPUTS,
        });
    }
    if certificate.evidence_ids.len() > MAX_REUSE_DESCRIPTOR_CERTIFICATE_EVIDENCE {
        return Err(ReuseDescriptorDerivationError::CertificateEvidenceBound {
            actual: certificate.evidence_ids.len(),
            maximum: MAX_REUSE_DESCRIPTOR_CERTIFICATE_EVIDENCE,
        });
    }
    if certificate.evidence_ids.iter().any(|evidence| evidence.len() > MAX_NEED_IR_BYTES) {
        return Err(ReuseDescriptorDerivationError::CertificateEvidenceTextBound);
    }
    if !payload_is_bounded(&artifact.payload) {
        return Err(ReuseDescriptorDerivationError::ArtifactPayloadBound);
    }
    if !dependency_manifest_is_bounded(&artifact.dependency_manifest) {
        return Err(ReuseDescriptorDerivationError::DependencyManifestBound);
    }
    Ok(())
}

fn payload_is_bounded(payload: &serde_json::Value) -> bool {
    struct BoundedWriter {
        remaining: usize,
    }

    impl Write for BoundedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.remaining {
                return Err(io::Error::other("semantic artifact payload bound exceeded"));
            }
            self.remaining -= bytes.len();
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    serde_json::to_writer(
        &mut BoundedWriter { remaining: MAX_REUSE_DESCRIPTOR_PAYLOAD_BYTES },
        payload,
    )
    .is_ok()
}

fn validate_action_and_output(
    artifact: &Artifact,
    action: &BuiltInActionDefinition,
) -> Result<(), ReuseDescriptorDerivationError> {
    if action.initial_mode != CapabilityMode::Shadow || !action.contract.is_canonical() {
        return Err(ReuseDescriptorDerivationError::ActionDefinition);
    }
    if artifact.contract.id != action.output_contract_id
        || artifact.contract.revision != action.output_contract_revision
        || artifact.contract.kind != *action.artifact_kind()
        || artifact.contract.schema_id != SEMANTIC_ARTIFACT_RESULT_SCHEMA_ID
        || artifact.contract.definition_digest != action.output_contract_definition_digest
    {
        return Err(ReuseDescriptorDerivationError::OutputContract);
    }
    Ok(())
}

fn validate_payload(
    artifact: &Artifact,
    action: &BuiltInActionDefinition,
) -> Result<(), ReuseDescriptorDerivationError> {
    let payload: SemanticWorkerArtifact = serde_json::from_value(artifact.payload.clone())?;
    if payload.kind() != *action.artifact_kind()
        || payload
            .canonical_artifact_id(action.output_contract_definition_digest)
            .map(|id| id.digest())
            != Some(artifact.id)
    {
        return Err(ReuseDescriptorDerivationError::ArtifactPayload);
    }
    Ok(())
}

fn inputs_match(request: &ArtifactRequest, certificate: &ArtifactValidationCertificate) -> bool {
    let mut request_inputs = ArrayVec::<Digest, MAX_NEED_INPUTS>::new();
    let mut certificate_inputs = ArrayVec::<Digest, MAX_NEED_INPUTS>::new();
    for input in &request.input_artifact_ids {
        request_inputs
            .try_push(*input)
            .expect("request input bound is validated before comparison");
    }
    for input in &certificate.input_artifacts {
        certificate_inputs
            .try_push(input.digest())
            .expect("certificate input bound is validated before comparison");
    }
    request_inputs.sort_unstable();
    certificate_inputs.sort_unstable();
    request_inputs.windows(2).all(|pair| pair[0] < pair[1])
        && certificate_inputs.windows(2).all(|pair| pair[0] < pair[1])
        && request_inputs == certificate_inputs
}

#[cfg(test)]
mod tests {
    use super::*;
    use needle_core::{
        ArtifactContract, ArtifactKind, CoverageEntry, CoverageManifest, Dependency,
        DependencyManifest, Facet, LocationRole, NeedFragmentId, NeedKey, Obligation,
        PredicateKind, SemanticLocation, SemanticWorld, SubjectId,
    };
    use serde_json::json;

    fn fixture(
        kind: ArtifactKind,
        scope: CacheScope,
    ) -> (ArtifactRequest, Artifact, ArtifactValidationCertificate) {
        let action = built_in_action_for_artifact_kind(&kind).unwrap();
        let request = ArtifactRequest {
            contract_id: action.output_contract_id.to_owned(),
            contract_revision: action.output_contract_revision,
            repository_id: Digest::blake3(b"repository"),
            source_snapshot_digest: Digest::blake3(b"source"),
            route_key: NeedKey::new("locate.implementation").unwrap(),
            normalized_request: "find implementation".to_owned(),
            semantic_fragment_id: Some(NeedFragmentId::new(Digest::blake3(b"fragment"))),
            input_artifact_ids: Vec::new(),
        };
        let payload = payload_for(&kind);
        let contract = ArtifactContract::semantic(
            action.output_contract_id,
            action.output_contract_revision,
            kind.clone(),
            scope,
        );
        let artifact_id = payload.canonical_artifact_id(contract.definition_digest).unwrap();
        let obligation = Obligation::new(
            action.predicate().expect("semantic fixture action"),
            SubjectId::new(Digest::blake3(b"subject")),
            facets_for(action.predicate().expect("semantic fixture action")),
        );
        let dependency_manifest = DependencyManifest {
            scope,
            observed_files_complete: scope == CacheScope::WorktreeSemantic,
            dependencies: vec![Dependency {
                path: "src/lib.rs".to_owned(),
                content_digest: Digest::blake3(b"repository evidence"),
                byte_start: None,
                byte_end: None,
                claims: vec![obligation.id.to_string()],
            }],
            gaps: Vec::new(),
        };
        let dependency_manifest_digest = manifest_digest(&dependency_manifest);
        let coverage = CoverageManifest {
            entries: vec![CoverageEntry {
                obligation,
                evidence: vec!["src/lib.rs:item".to_owned()],
            }],
            world: SemanticWorld {
                repository_lineage: Digest::blake3(b"repository"),
                source_selector: "worktree".to_owned(),
                platform: "windows".to_owned(),
                features: "default".to_owned(),
                configuration: None,
                toolchain: None,
            },
            dependency_manifest_digest,
        };
        let validator_definition = crate::validator_definition(&kind);
        let certificate_id =
            validation_certificate_id(artifact_id, &[], &[], &coverage, validator_definition, None);
        let certificate = ArtifactValidationCertificate {
            id: certificate_id,
            artifact: artifact_id,
            input_artifacts: Vec::new(),
            evidence_ids: Vec::new(),
            test_plan_evidence: None,
            coverage,
            validator_definition,
            dependency_checks_digest: dependency_manifest_digest,
            issued_unix_ms: 1,
        };
        let artifact = Artifact {
            id: artifact_id.digest(),
            request_id: request.semantic_id().digest(),
            contract,
            payload: serde_json::to_value(payload).unwrap(),
            dependency_manifest,
            validations: Vec::new(),
            created_unix_ms: 1,
        };
        (request, artifact, certificate)
    }

    fn payload_for(kind: &ArtifactKind) -> SemanticWorkerArtifact {
        match kind.0.as_str() {
            "code-location" => SemanticWorkerArtifact::CodeLocation {
                locations: vec![SemanticLocation {
                    role: LocationRole::Primary,
                    path: "src/lib.rs".to_owned(),
                    symbol: Some("item".to_owned()),
                    byte_start: Some(0),
                    byte_end: Some(1),
                }],
                gaps: Vec::new(),
            },
            "behavior-trace" => SemanticWorkerArtifact::BehaviorTrace {
                scenario: "default".to_owned(),
                steps: Vec::new(),
                gaps: Vec::new(),
            },
            "test-plan" => SemanticWorkerArtifact::TestPlan {
                runner: "cargo".to_owned(),
                argv: vec!["cargo".to_owned(), "test".to_owned(), "item".to_owned()],
                cwd_relative: ".".to_owned(),
                identifiers: vec!["item".to_owned()],
                selection: "representative".to_owned(),
                evidence_paths: vec!["tests/item.rs".to_owned()],
            },
            _ => panic!("unsupported fixture kind"),
        }
    }

    fn facets_for(predicate: PredicateKind) -> Vec<Facet> {
        match predicate {
            PredicateKind::ImplementationLocation => vec![
                Facet { key: "granularity".to_owned(), value: "exact-location".to_owned() },
                Facet { key: "polarity".to_owned(), value: "positive".to_owned() },
                Facet { key: "selection".to_owned(), value: "primary".to_owned() },
            ],
            PredicateKind::RuntimeFlow => vec![
                Facet { key: "completeness".to_owned(), value: "contract-complete".to_owned() },
                Facet { key: "granularity".to_owned(), value: "stepwise".to_owned() },
                Facet { key: "scenario".to_owned(), value: "default".to_owned() },
            ],
            PredicateKind::FocusedTests => vec![
                Facet { key: "completeness".to_owned(), value: "open-world".to_owned() },
                Facet { key: "polarity".to_owned(), value: "positive".to_owned() },
                Facet { key: "selection".to_owned(), value: "representative".to_owned() },
            ],
        }
    }

    #[test]
    fn projector_derives_all_built_ins_for_both_current_scopes() {
        for kind in [
            ArtifactKind::code_location(),
            ArtifactKind::behavior_trace(),
            ArtifactKind::test_plan(),
        ] {
            for scope in [CacheScope::SnapshotExact, CacheScope::WorktreeSemantic] {
                let (request, artifact, certificate) = fixture(kind.clone(), scope);
                let descriptor =
                    derive_shadow_reuse_descriptor(&request, &artifact, &certificate).unwrap();
                assert_eq!(descriptor.exact_request, request.semantic_id());
                assert_ne!(descriptor.exact_request.digest(), request.id());
                assert_eq!(descriptor.artifact.digest(), artifact.id);
                assert_eq!(descriptor.validation_certificate, certificate.id);
                assert!(descriptor.is_canonical());
                assert_eq!(
                    derive_shadow_reuse_descriptor_from_validated_pair(&artifact, &certificate)
                        .unwrap(),
                    descriptor
                );
            }
        }
    }

    #[test]
    fn projector_rejects_identity_definition_and_manifest_drift() {
        let (request, artifact, certificate) =
            fixture(ArtifactKind::code_location(), CacheScope::SnapshotExact);

        let mut changed = artifact.clone();
        changed.request_id = request.id();
        assert!(matches!(
            derive_shadow_reuse_descriptor(&request, &changed, &certificate),
            Err(ReuseDescriptorDerivationError::RequestIdentity)
        ));

        let mut changed = artifact.clone();
        changed.contract.definition_digest = Digest::blake3(b"changed-output");
        assert!(matches!(
            derive_shadow_reuse_descriptor(&request, &changed, &certificate),
            Err(ReuseDescriptorDerivationError::OutputContract)
        ));

        let mut changed = certificate.clone();
        changed.validator_definition = Digest::blake3(b"changed-validator");
        assert!(matches!(
            derive_shadow_reuse_descriptor(&request, &artifact, &changed),
            Err(ReuseDescriptorDerivationError::ValidatorDefinition)
        ));

        let mut changed = certificate.clone();
        changed.coverage.dependency_manifest_digest = Digest::blake3(b"changed-manifest");
        assert!(matches!(
            derive_shadow_reuse_descriptor(&request, &artifact, &changed),
            Err(ReuseDescriptorDerivationError::DependencyManifest)
        ));

        let mut changed = certificate.clone();
        changed.coverage.world.repository_lineage = Digest::blake3(b"other-repository");
        assert!(matches!(
            derive_shadow_reuse_descriptor(&request, &artifact, &changed),
            Err(ReuseDescriptorDerivationError::SemanticWorld)
        ));

        let mut changed_artifact = artifact.clone();
        changed_artifact.dependency_manifest.dependencies.clear();
        let changed_manifest = manifest_digest(&changed_artifact.dependency_manifest);
        let mut changed_certificate = certificate.clone();
        changed_certificate.coverage.dependency_manifest_digest = changed_manifest;
        changed_certificate.dependency_checks_digest = changed_manifest;
        changed_certificate.id = validation_certificate_id(
            changed_certificate.artifact,
            &changed_certificate.input_artifacts,
            &changed_certificate.evidence_ids,
            &changed_certificate.coverage,
            changed_certificate.validator_definition,
            changed_certificate.test_plan_evidence,
        );
        assert!(matches!(
            derive_shadow_reuse_descriptor(&request, &changed_artifact, &changed_certificate),
            Err(ReuseDescriptorDerivationError::DependencyManifest)
        ));

        let mut changed = certificate;
        changed.id = needle_core::ArtifactValidationCertificateId::new(Digest::blake3(b"changed"));
        assert!(matches!(
            derive_shadow_reuse_descriptor(&request, &artifact, &changed),
            Err(ReuseDescriptorDerivationError::ValidationCertificate)
        ));
    }

    #[test]
    fn projector_rejects_bounds_and_unknown_kinds_before_identity_work() {
        let (mut request, artifact, certificate) =
            fixture(ArtifactKind::code_location(), CacheScope::SnapshotExact);
        request.input_artifact_ids =
            (0..=MAX_NEED_INPUTS).map(|index| Digest::blake3(index.to_le_bytes())).collect();
        assert!(matches!(
            derive_shadow_reuse_descriptor(&request, &artifact, &certificate),
            Err(ReuseDescriptorDerivationError::RequestInputBound { .. })
        ));

        let mut unknown = artifact;
        unknown.contract.kind = ArtifactKind("unknown".to_owned());
        assert!(matches!(
            derive_shadow_reuse_descriptor(&fixture_request(), &unknown, &certificate),
            Err(ReuseDescriptorDerivationError::UnknownArtifactKind)
        ));
    }

    #[test]
    fn projector_rejects_oversized_work_before_hashing_or_cloning() {
        let (request, artifact, certificate) =
            fixture(ArtifactKind::code_location(), CacheScope::SnapshotExact);

        let mut changed_request = request.clone();
        changed_request.normalized_request = "x".repeat(MAX_NEED_IR_BYTES + 1);
        assert!(matches!(
            derive_shadow_reuse_descriptor(&changed_request, &artifact, &certificate),
            Err(ReuseDescriptorDerivationError::RequestTextBound)
        ));

        let mut changed_artifact = artifact.clone();
        changed_artifact.payload = json!({
            "oversized": "x".repeat(MAX_REUSE_DESCRIPTOR_PAYLOAD_BYTES + 1)
        });
        assert!(matches!(
            derive_shadow_reuse_descriptor(&request, &changed_artifact, &certificate),
            Err(ReuseDescriptorDerivationError::ArtifactPayloadBound)
        ));

        let mut changed_artifact = artifact.clone();
        changed_artifact.dependency_manifest.dependencies =
            vec![
                changed_artifact.dependency_manifest.dependencies[0].clone();
                crate::dependency_validity::MAX_DEPENDENCY_MANIFEST_ENTRIES + 1
            ];
        assert!(matches!(
            derive_shadow_reuse_descriptor(&request, &changed_artifact, &certificate),
            Err(ReuseDescriptorDerivationError::DependencyManifestBound)
        ));

        let mut changed_certificate = certificate;
        changed_certificate.evidence_ids = vec!["x".repeat(MAX_NEED_IR_BYTES + 1)];
        assert!(matches!(
            derive_shadow_reuse_descriptor(&request, &artifact, &changed_certificate),
            Err(ReuseDescriptorDerivationError::CertificateEvidenceTextBound)
        ));
    }

    #[test]
    fn projector_rejects_duplicate_semantic_inputs() {
        let (mut request, mut artifact, mut certificate) =
            fixture(ArtifactKind::code_location(), CacheScope::SnapshotExact);
        let input = ArtifactId::new(Digest::blake3(b"input"));
        request.input_artifact_ids = vec![input.digest(), input.digest()];
        artifact.request_id = request.semantic_id().digest();
        certificate.input_artifacts = vec![input, input];
        certificate.id = validation_certificate_id(
            certificate.artifact,
            &certificate.input_artifacts,
            &certificate.evidence_ids,
            &certificate.coverage,
            certificate.validator_definition,
            certificate.test_plan_evidence,
        );
        assert!(matches!(
            derive_shadow_reuse_descriptor(&request, &artifact, &certificate),
            Err(ReuseDescriptorDerivationError::InputBinding)
        ));
    }

    fn fixture_request() -> ArtifactRequest {
        fixture(ArtifactKind::code_location(), CacheScope::SnapshotExact).0
    }

    #[test]
    fn projector_output_is_not_a_freshness_or_authority_record() {
        let (request, artifact, certificate) =
            fixture(ArtifactKind::code_location(), CacheScope::SnapshotExact);
        let descriptor = derive_shadow_reuse_descriptor(&request, &artifact, &certificate).unwrap();
        let value = serde_json::to_value(descriptor).unwrap();
        for forbidden in [
            "fresh",
            "authority",
            "capability_class",
            "partitions",
            "refresh_capability",
            "operational_policy_digest",
        ] {
            assert_eq!(value.get(forbidden), None, "unexpected field {forbidden}");
        }
        assert_ne!(value, json!({}));
    }
}
