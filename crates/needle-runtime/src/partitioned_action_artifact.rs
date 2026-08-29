use crate::{
    BuiltInActionCoverage, ShadowPartitionManifestPublication,
    TestTargetInventoryValidationCertificate, built_in_action_for_artifact_kind,
};
use needle_core::{
    ActionArtifactValidationCertificate, ActionArtifactValidationCertificateInput, ActionRequest,
    Artifact, ArtifactContract, ArtifactId, ArtifactKind, CacheScope, CoverageManifest,
    DependencyManifest, PartitionedReuseDescriptorInput, ReuseDescriptor, ReviewReport,
    SemanticInputBinding, SemanticWorld, TestTargetInventory,
};
use thiserror::Error;

const OPAQUE_PARTITION_DEPENDENCY_GAP: &str = "opaque-partition-manifest-authority";

/// Canonical Shadow publication material for a partitioned action artifact.
///
/// This is a pure envelope. Persisting it or using its manifest for planning
/// remains an explicit runtime decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowPartitionedActionArtifactPublication {
    pub(crate) artifact: Artifact,
    pub(crate) certificate: ActionArtifactValidationCertificate,
    pub(crate) descriptor: ReuseDescriptor,
}

impl ShadowPartitionedActionArtifactPublication {
    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }

    pub fn certificate(&self) -> &ActionArtifactValidationCertificate {
        &self.certificate
    }

    pub fn descriptor(&self) -> &ReuseDescriptor {
        &self.descriptor
    }

    pub fn validate(
        &self,
        request: &ActionRequest,
        manifest: &ShadowPartitionManifestPublication,
    ) -> Result<(), PartitionedActionArtifactError> {
        manifest
            .validate()
            .map_err(|error| PartitionedActionArtifactError::Manifest(error.to_string()))?;
        let action = built_in_action_for_artifact_kind(&self.artifact.contract.kind)
            .ok_or(PartitionedActionArtifactError::ActionMissing)?;
        if !matches!(action.coverage, BuiltInActionCoverage::Partitioned { .. }) {
            return Err(PartitionedActionArtifactError::ActionCoverage);
        }
        request
            .validate(&action.contract)
            .map_err(|error| PartitionedActionArtifactError::Request(error.to_string()))?;
        let request_id = request.semantic_id();
        let expected_contract = ArtifactContract::semantic_with_schema(
            action.output_contract_id,
            action.output_contract_revision,
            action.artifact_kind.clone(),
            action.output_schema_id,
            CacheScope::SnapshotExact,
        );
        if self.artifact.request_id != request_id.digest()
            || self.artifact.contract != expected_contract
            || self.artifact.contract.definition_digest != action.output_contract_definition_digest
            || self.artifact.dependency_manifest.scope != self.artifact.contract.cache_scope
            || Artifact::compute_content_id(&self.artifact.contract, &self.artifact.payload)
                .map_err(PartitionedActionArtifactError::Json)?
                .digest()
                != self.artifact.id
        {
            return Err(PartitionedActionArtifactError::ArtifactBinding);
        }

        self.certificate.validate()?;
        let mut request_inputs = request
            .artifact_request
            .input_artifact_ids
            .iter()
            .copied()
            .map(ArtifactId::new)
            .collect::<Vec<_>>();
        request_inputs.sort_unstable();
        let dependency_manifest_digest =
            crate::semantic_validation::manifest_digest(&self.artifact.dependency_manifest);
        if self.certificate.artifact.digest() != self.artifact.id
            || self.certificate.input_artifacts != request_inputs
            || self.certificate.action_contract != action.contract.id
            || self.certificate.action_semantic_definition_digest
                != action.contract.semantic_definition_digest
            || self.certificate.action_validation_definition_digest
                != action.contract.validation_definition_digest
            || self.certificate.output_contract_definition_digest
                != action.output_contract_definition_digest
            || self.certificate.partition_manifest != manifest.manifest.id
            || self.certificate.source_payload_digest != manifest.certificate.source_payload_digest
            || self.certificate.source_validation_certificate_digest
                != manifest.certificate.source_validation_certificate_digest
            || self.certificate.validator_definition_digest != action.validator_definition_digest
            || self.certificate.coverage.dependency_manifest_digest != dependency_manifest_digest
            || self.certificate.coverage.world.id()
                != manifest.manifest.binding.semantic_world_digest
            || self.certificate.coverage.world.repository_lineage
                != manifest.manifest.binding.repository
            || self.certificate.coverage.world.source_selector
                != manifest.manifest.binding.source_selector
            || self.certificate.issued_unix_ms != self.artifact.created_unix_ms
        {
            return Err(PartitionedActionArtifactError::CertificateBinding);
        }

        self.descriptor.validate()?;
        if self.descriptor.artifact.digest() != self.artifact.id
            || self.descriptor.exact_request != request_id
            || self.descriptor.origin_request != request_id
            || self.descriptor.action_contract != action.contract.id
            || self.descriptor.action_semantic_definition_digest
                != action.contract.semantic_definition_digest
            || self.descriptor.action_validation_definition_digest
                != action.contract.validation_definition_digest
            || self.descriptor.output_contract_definition_digest
                != action.output_contract_definition_digest
            || self.descriptor.validator_definition_digest != action.validator_definition_digest
            || self.descriptor.validation_certificate != self.certificate.id
            || self.descriptor.partition_manifest != Some(manifest.manifest.id)
            || self.descriptor.coverage != self.certificate.coverage
        {
            return Err(PartitionedActionArtifactError::DescriptorBinding);
        }

        let binding = &manifest.manifest.binding;
        if binding.action_request != request_id
            || binding.action_contract != action.contract.id
            || binding.output_contract.as_str() != action.output_contract_id
            || binding.repository != request.artifact_request.repository_id
            || binding.semantic_input_set_digest
                != needle_core::semantic_input_set_digest(
                    &request
                        .artifact_request
                        .input_artifact_ids
                        .iter()
                        .copied()
                        .map(|artifact| SemanticInputBinding::ByArtifact {
                            artifact: ArtifactId::new(artifact),
                        })
                        .collect::<Vec<_>>(),
                )
                .map_err(|error| PartitionedActionArtifactError::Request(error.to_string()))?
        {
            return Err(PartitionedActionArtifactError::ManifestBinding);
        }
        Ok(())
    }
}

pub fn certify_test_target_inventory_action_artifact(
    request: &ActionRequest,
    inventory: &TestTargetInventory,
    source_certificate: &TestTargetInventoryValidationCertificate,
    world: &SemanticWorld,
    manifest: &ShadowPartitionManifestPublication,
    issued_unix_ms: u64,
) -> Result<ShadowPartitionedActionArtifactPublication, PartitionedActionArtifactError> {
    inventory.validate()?;
    source_certificate
        .validate()
        .map_err(|error| PartitionedActionArtifactError::SourceCertificate(error.to_string()))?;
    if source_certificate.inventory != inventory.content_digest
        || world.repository_lineage != inventory.repository_lineage
        || world.source_selector != inventory.source_selector
        || manifest.certificate.source_payload_digest != inventory.content_digest
        || manifest.certificate.source_validation_certificate_digest
            != source_certificate.certificate_digest
    {
        return Err(PartitionedActionArtifactError::SourceBinding);
    }

    let action = built_in_action_for_artifact_kind(&ArtifactKind::test_target_inventory())
        .ok_or(PartitionedActionArtifactError::ActionMissing)?;
    request
        .validate(&action.contract)
        .map_err(|error| PartitionedActionArtifactError::Request(error.to_string()))?;
    let contract = ArtifactContract::semantic_with_schema(
        action.output_contract_id,
        action.output_contract_revision,
        action.artifact_kind.clone(),
        action.output_schema_id,
        CacheScope::SnapshotExact,
    );
    let payload = serde_json::to_value(inventory)?;
    let artifact_id = Artifact::compute_content_id(&contract, &payload)?;
    let dependency_manifest = DependencyManifest {
        scope: CacheScope::SnapshotExact,
        observed_files_complete: false,
        dependencies: Vec::new(),
        gaps: vec![OPAQUE_PARTITION_DEPENDENCY_GAP.to_owned()],
    };
    let dependency_manifest_digest =
        crate::semantic_validation::manifest_digest(&dependency_manifest);
    let coverage =
        CoverageManifest { entries: Vec::new(), world: world.clone(), dependency_manifest_digest };
    let certificate =
        ActionArtifactValidationCertificate::new(ActionArtifactValidationCertificateInput {
            artifact: artifact_id,
            input_artifacts: request
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
            partition_manifest: manifest.manifest.id,
            source_payload_digest: inventory.content_digest,
            source_validation_certificate_digest: source_certificate.certificate_digest,
            coverage: coverage.clone(),
            validator_definition_digest: action.validator_definition_digest,
            issued_unix_ms,
        })?;
    let descriptor = ReuseDescriptor::new_partitioned(PartitionedReuseDescriptorInput {
        artifact: artifact_id,
        exact_request: request.semantic_id(),
        action_contract: action.contract.id.clone(),
        action_semantic_definition_digest: action.contract.semantic_definition_digest,
        action_validation_definition_digest: action.contract.validation_definition_digest,
        output_contract_definition_digest: action.output_contract_definition_digest,
        validator_definition_digest: action.validator_definition_digest,
        validation_certificate: certificate.id,
        coverage,
        partition_manifest: manifest.manifest.id,
    })?;
    let publication = ShadowPartitionedActionArtifactPublication {
        artifact: Artifact {
            id: artifact_id.digest(),
            request_id: request.semantic_id().digest(),
            contract,
            payload,
            dependency_manifest,
            validations: Vec::new(),
            created_unix_ms: issued_unix_ms,
        },
        certificate,
        descriptor,
    };
    publication.validate(request, manifest)?;
    Ok(publication)
}

pub fn certify_review_action_artifact(
    request: &ActionRequest,
    report: &ReviewReport,
    world: &SemanticWorld,
    dependency_manifest: DependencyManifest,
    manifest: &ShadowPartitionManifestPublication,
    issued_unix_ms: u64,
) -> Result<ShadowPartitionedActionArtifactPublication, PartitionedActionArtifactError> {
    report
        .validate()
        .map_err(|error| PartitionedActionArtifactError::SourceCertificate(error.to_string()))?;
    if report.action_request != request.semantic_id()
        || report.manifest != Some(manifest.manifest.id)
        || world.repository_lineage != request.artifact_request.repository_id
        || dependency_manifest.scope != CacheScope::SnapshotExact
        || manifest.certificate.source_payload_digest != report.id
    {
        return Err(PartitionedActionArtifactError::SourceBinding);
    }
    let action = built_in_action_for_artifact_kind(&ArtifactKind::review_report())
        .ok_or(PartitionedActionArtifactError::ActionMissing)?;
    request
        .validate(&action.contract)
        .map_err(|error| PartitionedActionArtifactError::Request(error.to_string()))?;
    let contract = ArtifactContract::semantic_with_schema(
        action.output_contract_id,
        action.output_contract_revision,
        action.artifact_kind.clone(),
        action.output_schema_id,
        CacheScope::SnapshotExact,
    );
    let payload = serde_json::to_value(report)?;
    let artifact_id = Artifact::compute_content_id(&contract, &payload)?;
    let dependency_manifest_digest =
        crate::semantic_validation::manifest_digest(&dependency_manifest);
    let coverage =
        CoverageManifest { entries: Vec::new(), world: world.clone(), dependency_manifest_digest };
    let certificate =
        ActionArtifactValidationCertificate::new(ActionArtifactValidationCertificateInput {
            artifact: artifact_id,
            input_artifacts: request
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
            partition_manifest: manifest.manifest.id,
            source_payload_digest: report.id,
            source_validation_certificate_digest: manifest
                .certificate
                .source_validation_certificate_digest,
            coverage: coverage.clone(),
            validator_definition_digest: action.validator_definition_digest,
            issued_unix_ms,
        })?;
    let descriptor = ReuseDescriptor::new_partitioned(PartitionedReuseDescriptorInput {
        artifact: artifact_id,
        exact_request: request.semantic_id(),
        action_contract: action.contract.id.clone(),
        action_semantic_definition_digest: action.contract.semantic_definition_digest,
        action_validation_definition_digest: action.contract.validation_definition_digest,
        output_contract_definition_digest: action.output_contract_definition_digest,
        validator_definition_digest: action.validator_definition_digest,
        validation_certificate: certificate.id,
        coverage,
        partition_manifest: manifest.manifest.id,
    })?;
    let publication = ShadowPartitionedActionArtifactPublication {
        artifact: Artifact {
            id: artifact_id.digest(),
            request_id: request.semantic_id().digest(),
            contract,
            payload,
            dependency_manifest,
            validations: Vec::new(),
            created_unix_ms: issued_unix_ms,
        },
        certificate,
        descriptor,
    };
    publication.validate(request, manifest)?;
    Ok(publication)
}

#[derive(Debug, Error)]
pub enum PartitionedActionArtifactError {
    #[error("partitioned action definition is missing")]
    ActionMissing,
    #[error("action does not declare partitioned coverage")]
    ActionCoverage,
    #[error("partitioned action request is invalid: {0}")]
    Request(String),
    #[error("partitioned action artifact binding is invalid")]
    ArtifactBinding,
    #[error("partitioned action certificate binding is invalid")]
    CertificateBinding,
    #[error("partitioned action descriptor binding is invalid")]
    DescriptorBinding,
    #[error("partitioned action manifest binding is invalid")]
    ManifestBinding,
    #[error("partitioned source artifact and certificate do not match")]
    SourceBinding,
    #[error("partitioned source certificate is invalid: {0}")]
    SourceCertificate(String),
    #[error("partition manifest publication is invalid: {0}")]
    Manifest(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Inventory(#[from] needle_core::TestTargetInventoryError),
    #[error(transparent)]
    Certificate(#[from] needle_core::ActionArtifactValidationCertificateError),
    #[error(transparent)]
    Descriptor(#[from] needle_core::ReuseDescriptorError),
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        ShadowManifestContext, certify_test_target_inventory_shadow_manifest,
        test_target_inventory_validator_definition,
    };
    use needle_core::{
        ActionRequest, ArtifactRequest, CanonicalHasher, DerivationRuleId, ManifestProvenance,
        ManifestTransition, NeedFragmentId, NeedId, NeedKey, PartitionKeyMapping, PartitionRef,
        RefreshAttempt, RefreshAttemptInput, RefreshOutcome, TestTargetDeclaration,
        TestTargetEcosystem, TestTargetInventoryScope, TestTargetKind, TestTargetLocator,
        TestTargetLocatorKind, TestTargetPackageKey, TestTargetPartition, TestTargetPartitionKey,
    };

    pub(crate) fn fixture() -> (
        ActionRequest,
        TestTargetInventory,
        TestTargetInventoryValidationCertificate,
        SemanticWorld,
        ShadowPartitionManifestPublication,
    ) {
        let action =
            built_in_action_for_artifact_kind(&ArtifactKind::test_target_inventory()).unwrap();
        let repository = needle_core::Digest::blake3(b"repository");
        let request = ActionRequest::new(
            &action.contract,
            ArtifactRequest {
                contract_id: action.output_contract_id.to_owned(),
                contract_revision: action.output_contract_revision,
                repository_id: repository,
                source_snapshot_digest: needle_core::Digest::blake3(b"source"),
                route_key: NeedKey::new("tests.inventory").unwrap(),
                normalized_request: "enumerate tests".to_owned(),
                semantic_fragment_id: Some(NeedFragmentId::new(needle_core::Digest::blake3(
                    b"fragment",
                ))),
                input_artifact_ids: Vec::new(),
            },
            action.contract.default_dispatch_policy,
            NeedKey::new("tests.inventory").unwrap(),
            NeedId::new(needle_core::Digest::blake3(b"need")),
        )
        .unwrap();
        let package = TestTargetPackageKey::new("alpha", "crates/alpha/Cargo.toml").unwrap();
        let locator = TestTargetLocator::new(
            TestTargetLocatorKind::ManifestContent,
            "crates/alpha/Cargo.toml",
            needle_core::Digest::blake3(b"manifest-content"),
        )
        .unwrap();
        let partition = TestTargetPartition::new(
            TestTargetPartitionKey {
                ecosystem: TestTargetEcosystem::Cargo,
                workspace: "Cargo.toml".to_owned(),
                package: package.clone(),
                target_kind: TestTargetKind::Test,
                target_name: "alpha".to_owned(),
            },
            "tests/alpha.rs",
            TestTargetDeclaration::Conventional,
            vec!["bin".to_owned()],
            Vec::new(),
            "2024",
            false,
            vec![locator.id],
        )
        .unwrap();
        let inventory = TestTargetInventory::new(
            repository,
            "worktree",
            TestTargetInventoryScope::all(),
            crate::cargo_test_target_adapter_definition(),
            needle_core::Digest::blake3(b"metadata"),
            vec![package],
            vec![locator],
            vec![partition],
        )
        .unwrap();
        let certificate = source_certificate(&inventory);
        let world = SemanticWorld {
            repository_lineage: repository,
            source_selector: "worktree".to_owned(),
            platform: "windows".to_owned(),
            features: "default".to_owned(),
            configuration: None,
            toolchain: None,
        };
        let manifest = certify_test_target_inventory_shadow_manifest(
            ShadowManifestContext {
                request: &request,
                world: &world,
                definition_set_digest: needle_core::Digest::blake3(b"definitions"),
            },
            &inventory,
            &certificate,
            42,
        )
        .unwrap();
        (request, inventory, certificate, world, manifest)
    }

    pub(crate) struct RefreshPublicationFixture {
        pub request: ActionRequest,
        pub prior_manifest: ShadowPartitionManifestPublication,
        pub prior: ShadowPartitionedActionArtifactPublication,
        pub current_manifest: ShadowPartitionManifestPublication,
        pub current: ShadowPartitionedActionArtifactPublication,
        pub transition: ManifestTransition,
        pub attempt: RefreshAttempt,
    }

    pub(crate) fn refresh_publication_fixture() -> RefreshPublicationFixture {
        let (request, prior_inventory, prior_source, world, prior_manifest) = fixture();
        let prior = certify_test_target_inventory_action_artifact(
            &request,
            &prior_inventory,
            &prior_source,
            &world,
            &prior_manifest,
            42,
        )
        .unwrap();
        let beta_package = TestTargetPackageKey::new("beta", "crates/beta/Cargo.toml").unwrap();
        let beta_locator = TestTargetLocator::new(
            TestTargetLocatorKind::ManifestContent,
            "crates/beta/Cargo.toml",
            needle_core::Digest::blake3(b"beta-manifest-content"),
        )
        .unwrap();
        let beta_partition = TestTargetPartition::new(
            TestTargetPartitionKey {
                ecosystem: TestTargetEcosystem::Cargo,
                workspace: "Cargo.toml".to_owned(),
                package: beta_package.clone(),
                target_kind: TestTargetKind::Test,
                target_name: "beta".to_owned(),
            },
            "tests/beta.rs",
            TestTargetDeclaration::Conventional,
            vec!["bin".to_owned()],
            Vec::new(),
            "2024",
            false,
            vec![beta_locator.id],
        )
        .unwrap();
        let current_inventory = TestTargetInventory::new(
            prior_inventory.repository_lineage,
            prior_inventory.source_selector.clone(),
            prior_inventory.scope.clone(),
            prior_inventory.adapter_definition_digest,
            needle_core::Digest::blake3(b"current-metadata"),
            prior_inventory.package_universe.iter().cloned().chain([beta_package]).collect(),
            prior_inventory.collection_dependencies.iter().cloned().chain([beta_locator]).collect(),
            prior_inventory.partitions.iter().cloned().chain([beta_partition]).collect(),
        )
        .unwrap();
        let current_source = source_certificate(&current_inventory);
        let current_manifest = certify_test_target_inventory_shadow_manifest(
            ShadowManifestContext {
                request: &request,
                world: &world,
                definition_set_digest: needle_core::Digest::blake3(b"definitions"),
            },
            &current_inventory,
            &current_source,
            84,
        )
        .unwrap();
        let current = certify_test_target_inventory_action_artifact(
            &request,
            &current_inventory,
            &current_source,
            &world,
            &current_manifest,
            84,
        )
        .unwrap();
        let retained_key = prior_manifest.manifest.entries[0].key.digest;
        let added_key = current_manifest
            .manifest
            .entries
            .iter()
            .find(|entry| entry.key.digest != retained_key)
            .unwrap()
            .key
            .digest;
        let retained = PartitionKeyMapping {
            prior: PartitionRef::new(prior_manifest.manifest.id, retained_key),
            current: PartitionRef::new(current_manifest.manifest.id, retained_key),
        };
        let definition = crate::built_in_partition_for_action(&request.contract).unwrap();
        let transition = ManifestTransition::new(
            prior_manifest.manifest.id,
            current_manifest.manifest.id,
            needle_core::Digest::blake3(b"state-delta"),
            vec![retained],
            ManifestProvenance::derived(
                DerivationRuleId::new(needle_core::Digest::blake3(b"transition-rule")),
                vec![prior_manifest.manifest.id, current_manifest.manifest.id],
            )
            .unwrap(),
            definition.policy.manifest_validator.clone(),
        )
        .unwrap();
        let attempt = RefreshAttempt::new(RefreshAttemptInput {
            request: request.semantic_id(),
            action_contract: request.contract.clone(),
            prior_artifact: ArtifactId::new(prior.artifact.id),
            state_delta: transition.state_delta,
            prior_manifest: prior_manifest.manifest.id,
            current_manifest: current_manifest.manifest.id,
            manifest_transition: transition.id,
            retained_partitions: vec![retained],
            refreshed_partitions: Vec::new(),
            added_partitions: vec![PartitionRef::new(current_manifest.manifest.id, added_key)],
            removed_partitions: Vec::new(),
            refresh_policy_definition_digest: needle_core::Digest::blake3(b"refresh-policy"),
            operator_definition_digest: needle_core::Digest::blake3(b"refresh-operator"),
            execution_scope_digest: needle_core::Digest::blake3(b"execution-scope"),
            execution_attempts: Vec::new(),
            started_unix_ms: 50,
            completed_unix_ms: 84,
            cost_microusd: Some(10),
            outcome: RefreshOutcome::Succeeded {
                reconstructed_artifact: ArtifactId::new(current.artifact.id),
                validation_certificate: current.certificate.id,
            },
        })
        .unwrap();
        RefreshPublicationFixture {
            request,
            prior_manifest,
            prior,
            current_manifest,
            current,
            transition,
            attempt,
        }
    }

    fn source_certificate(
        inventory: &TestTargetInventory,
    ) -> TestTargetInventoryValidationCertificate {
        let mut dependency_hasher =
            CanonicalHasher::new(b"test-target-inventory-dependency-set-v1");
        for locator in &inventory.collection_dependencies {
            dependency_hasher.field_digest(locator.id);
        }
        let dependency_set_digest = dependency_hasher.finish();
        let mut certificate = TestTargetInventoryValidationCertificate {
            format_revision: 1,
            inventory: inventory.content_digest,
            validator_definition_digest: test_target_inventory_validator_definition(),
            adapter_definition_digest: crate::cargo_test_target_adapter_definition(),
            metadata_digest: inventory.metadata_digest,
            dependency_set_digest,
            certificate_digest: needle_core::Digest([0; 32]),
        };
        let mut hasher = CanonicalHasher::new(b"test-target-inventory-certificate-v1");
        hasher.field_u16(certificate.format_revision);
        hasher.field_digest(certificate.inventory);
        hasher.field_digest(certificate.validator_definition_digest);
        hasher.field_digest(certificate.adapter_definition_digest);
        hasher.field_digest(certificate.metadata_digest);
        hasher.field_digest(certificate.dependency_set_digest);
        certificate.certificate_digest = hasher.finish();
        certificate
    }

    #[test]
    fn test_inventory_projects_to_partition_bound_action_records() {
        let (request, inventory, source, world, manifest) = fixture();
        let publication = certify_test_target_inventory_action_artifact(
            &request, &inventory, &source, &world, &manifest, 42,
        )
        .unwrap();
        assert!(publication.certificate.is_canonical());
        assert!(publication.descriptor.is_canonical());
        assert_eq!(publication.descriptor.partition_manifest, Some(manifest.manifest.id));
        assert_eq!(publication.certificate.partition_manifest, manifest.manifest.id);
        assert_eq!(
            publication.artifact.contract.schema_id,
            needle_core::TEST_TARGET_INVENTORY_SCHEMA_ID
        );
        publication.validate(&request, &manifest).unwrap();
    }

    #[test]
    fn test_inventory_projection_rejects_source_certificate_drift() {
        let (request, inventory, mut source, world, manifest) = fixture();
        source.certificate_digest = needle_core::Digest::blake3(b"tampered");
        assert!(
            certify_test_target_inventory_action_artifact(
                &request, &inventory, &source, &world, &manifest, 42,
            )
            .is_err()
        );
    }
}
