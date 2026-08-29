use super::*;
use crate::{
    ArchitectureBriefValidationCertificate, ChangeImpactValidationCertificate,
    TestTargetInventoryValidationCertificate, architecture_brief_analysis_definition,
    architecture_brief_validator_definition, cargo_test_target_adapter_definition,
    change_impact_analysis_definition, change_impact_validator_definition,
    test_target_inventory_validator_definition,
};
use needle_core::{
    ActionRequest, ArchitectureBrief, ArchitectureBriefScope, ArchitecturePackageBrief,
    ArtifactRequest, CanonicalHasher, CapabilityMode, ChangeImpact, ChangeImpactAssessment,
    ChangeImpactChangeSet, ChangeImpactDisposition, ChangeImpactFile, ChangeImpactRequirement,
    ChangeImpactScope, Digest, NeedFragmentId, NeedId, NeedKey, PatchArtifact, PatchFile,
    PatchOperation, ReuseMode, SemanticWorld, Subject, SubjectKind, TestTargetDeclaration,
    TestTargetEcosystem, TestTargetInventory, TestTargetInventoryScope, TestTargetKind,
    TestTargetLocator, TestTargetLocatorKind, TestTargetPackageKey, TestTargetPartition,
    TestTargetPartitionKey,
};
use std::collections::BTreeSet;

#[test]
fn registry_is_complete_bijective_shadow_only_and_action_bound() {
    let definitions = built_in_partition_definitions();
    assert_eq!(definitions.len(), BUILT_IN_PARTITION_DEFINITION_COUNT);
    assert_eq!(
        definitions
            .iter()
            .map(|definition| definition.action_contract.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        BUILT_IN_PARTITION_DEFINITION_COUNT
    );
    assert_eq!(
        definitions
            .iter()
            .map(|definition| definition.scheme.id.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        BUILT_IN_PARTITION_DEFINITION_COUNT
    );

    for definition in definitions {
        definition.validate().unwrap();
        assert_eq!(definition.initial_mode, CapabilityMode::Shadow);
        let action = built_in_action_contracts()
            .iter()
            .find(|action| action.contract.id == definition.action_contract)
            .unwrap();
        definition.validate_against_action(action).unwrap();
        assert!(action.contract.reuse_modes.contains(ReuseMode::Exact));
        assert!(action.contract.reuse_modes.contains(ReuseMode::Project));
        assert!(action.contract.reuse_modes.contains(ReuseMode::Assemble));
        assert_eq!(
            action.contract.reuse_modes.contains(ReuseMode::Refresh),
            matches!(
                action.contract.id.as_str(),
                "needle.tests.inventory" | needle_core::REVIEW_DIFF_ACTION_CONTRACT
            )
        );
    }
}

#[test]
fn registry_lookups_are_exact_and_unknown_values_fail_closed() {
    for definition in built_in_partition_definitions() {
        assert_eq!(built_in_partition_for_action(&definition.action_contract), Some(definition));
        assert_eq!(built_in_partition_for_scheme(&definition.scheme.id), Some(definition));
    }
    assert!(
        built_in_partition_for_action(&ActionContractId::new("needle.unknown.action").unwrap())
            .is_none()
    );
    assert!(
        built_in_partition_for_scheme(&PartitionSchemeId::new("needle.unknown.scheme").unwrap())
            .is_none()
    );
}

#[test]
fn canonical_policy_digests_do_not_replace_declared_action_authority() {
    for definition in built_in_partition_definitions() {
        assert_ne!(
            definition.policy.definition_digest,
            definition.declared_policy_authority_digest
        );
        let action = built_in_action_contracts()
            .iter()
            .find(|action| action.contract.id == definition.action_contract)
            .unwrap();
        assert_eq!(
            action.coverage.definition_digest(),
            definition.declared_policy_authority_digest
        );
    }
}

#[test]
fn reference_adapters_emit_closed_shadow_manifests_with_empty_predicate_coverage() {
    let repository = digest("repository");
    let source = "source-v1";
    let semantic_world = world(repository, source);

    let inventory = inventory(repository, source);
    let inventory_request = action_request("needle.tests.inventory", repository, source);
    let inventory_manifest = derive_test_target_inventory_shadow_manifest(
        context(&inventory_request, &semantic_world),
        &inventory,
        &inventory_certificate(&inventory),
    )
    .unwrap();
    assert_manifest(&inventory_manifest, &inventory_request, 1);

    let architecture = architecture_brief(repository, source);
    let architecture_request = action_request("needle.architecture.describe", repository, source);
    let architecture_manifest = derive_architecture_brief_shadow_manifest(
        context(&architecture_request, &semantic_world),
        &architecture,
        &architecture_certificate(&architecture),
    )
    .unwrap();
    assert_manifest(&architecture_manifest, &architecture_request, 1);

    let impact = change_impact(repository, source);
    let impact_request = action_request("needle.change.impact", repository, source);
    let impact_manifest = derive_change_impact_shadow_manifest(
        context(&impact_request, &semantic_world),
        &impact,
        &change_impact_certificate(&impact),
    )
    .unwrap();
    assert_manifest(&impact_manifest, &impact_request, 1);
}

#[test]
fn adapters_are_deterministic_and_fail_closed_on_world_or_certificate_mismatch() {
    let repository = digest("repository");
    let source = "source-v1";
    let semantic_world = world(repository, source);
    let inventory = inventory(repository, source);
    let request = action_request("needle.tests.inventory", repository, source);
    let certificate = inventory_certificate(&inventory);
    let first = derive_test_target_inventory_shadow_manifest(
        context(&request, &semantic_world),
        &inventory,
        &certificate,
    )
    .unwrap();
    let second = derive_test_target_inventory_shadow_manifest(
        context(&request, &semantic_world),
        &inventory,
        &certificate,
    )
    .unwrap();
    assert_eq!(first, second);

    let wrong_world = world(repository, "source-v2");
    assert!(matches!(
        derive_test_target_inventory_shadow_manifest(
            context(&request, &wrong_world),
            &inventory,
            &certificate,
        ),
        Err(ShadowPartitionManifestError::Binding)
    ));

    let mut tampered = certificate.clone();
    tampered.inventory = digest("tampered");
    assert!(matches!(
        derive_test_target_inventory_shadow_manifest(
            context(&request, &semantic_world),
            &inventory,
            &tampered,
        ),
        Err(ShadowPartitionManifestError::Certificate(_))
    ));

    let mut oversized_world = semantic_world.clone();
    oversized_world.platform = "x".repeat(needle_core::MAX_NEED_IR_BYTES + 1);
    assert!(matches!(
        derive_test_target_inventory_shadow_manifest(
            context(&request, &oversized_world),
            &inventory,
            &certificate,
        ),
        Err(ShadowPartitionManifestError::Binding)
    ));

    let mut oversized_request = request.clone();
    oversized_request.artifact_request.normalized_request =
        "x".repeat(needle_core::MAX_NEED_IR_BYTES + 1);
    assert!(matches!(
        derive_test_target_inventory_shadow_manifest(
            context(&oversized_request, &semantic_world),
            &inventory,
            &certificate,
        ),
        Err(ShadowPartitionManifestError::Binding)
    ));
}

#[test]
fn empty_inventory_emits_a_closed_zero_entry_manifest() {
    let repository = digest("repository");
    let source = "source-v1";
    let semantic_world = world(repository, source);
    let request = action_request("needle.tests.inventory", repository, source);
    let inventory = TestTargetInventory::new(
        repository,
        source,
        TestTargetInventoryScope::all(),
        cargo_test_target_adapter_definition(),
        digest("empty-metadata"),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let certificate = inventory_certificate(&inventory);
    let manifest = derive_test_target_inventory_shadow_manifest(
        context(&request, &semantic_world),
        &inventory,
        &certificate,
    )
    .unwrap();
    assert_manifest(&manifest, &request, 0);
}

#[test]
fn certified_publication_is_shadow_only_and_source_bound() {
    let repository = digest("repository");
    let source = "source-v1";
    let semantic_world = world(repository, source);
    let inventory = inventory(repository, source);
    let request = action_request("needle.tests.inventory", repository, source);
    let source_certificate = inventory_certificate(&inventory);
    let publication = certify_test_target_inventory_shadow_manifest(
        context(&request, &semantic_world),
        &inventory,
        &source_certificate,
        42,
    )
    .unwrap();
    publication.validate().unwrap();
    assert_eq!(publication.certificate.issued_mode, CapabilityMode::Shadow);
    assert_eq!(publication.certificate.source_payload_digest, inventory.content_digest);
    assert_eq!(
        publication.certificate.source_validation_certificate_digest,
        source_certificate.certificate_digest
    );
    let awcp = publication.awcp_projection().unwrap();
    awcp.validate_shape().unwrap();
    assert_eq!(awcp.manifest, publication.manifest.id);
    assert_eq!(awcp.authority, CapabilityMode::Shadow);
    let encoded = serde_json::to_vec(&awcp).unwrap();
    assert!(encoded.len() <= needle_core::MAX_AWCP_MESSAGE_BYTES);
    assert_eq!(needle_core::AwcpPartitionManifestProjection::decode_json(&encoded).unwrap(), awcp);

    let mut authority_tamper = awcp.clone();
    authority_tamper.authority = CapabilityMode::Authoritative;
    assert_eq!(
        authority_tamper.validate_shape(),
        Err(needle_core::AwcpValidationError::PartitionManifestAuthority)
    );

    let mut tampered = publication.clone();
    tampered.certificate.source_payload_digest = digest("tampered");
    assert!(tampered.validate().is_err());
}

fn digest(value: impl AsRef<[u8]>) -> Digest {
    Digest::blake3(value)
}

fn world(repository: Digest, source: &str) -> SemanticWorld {
    SemanticWorld {
        repository_lineage: repository,
        source_selector: source.to_owned(),
        platform: "any".to_owned(),
        features: "default".to_owned(),
        configuration: None,
        toolchain: None,
    }
}

fn context<'a>(request: &'a ActionRequest, world: &'a SemanticWorld) -> ShadowManifestContext<'a> {
    ShadowManifestContext { request, world, definition_set_digest: digest("definition-set") }
}

fn action_request(action_id: &str, repository: Digest, source: &str) -> ActionRequest {
    let definition = built_in_action_contracts()
        .iter()
        .find(|definition| definition.contract.id.as_str() == action_id)
        .unwrap();
    let fragment = NeedFragmentId::new(digest(format!("fragment-{action_id}")));
    let route = NeedKey::new(action_id).unwrap();
    ActionRequest::new(
        &definition.contract,
        ArtifactRequest {
            contract_id: definition.output_contract_id.to_owned(),
            contract_revision: definition.output_contract_revision,
            repository_id: repository,
            source_snapshot_digest: digest(source),
            route_key: route.clone(),
            normalized_request: format!("derive {action_id}"),
            semantic_fragment_id: Some(fragment),
            input_artifact_ids: Vec::new(),
        },
        definition.contract.default_dispatch_policy,
        route,
        NeedId::new(fragment.digest()),
    )
    .unwrap()
}

fn inventory(repository: Digest, source: &str) -> TestTargetInventory {
    let package =
        TestTargetPackageKey::new("needle-core", "crates/needle-core/Cargo.toml").unwrap();
    let locator = TestTargetLocator::new(
        TestTargetLocatorKind::ManifestContent,
        "crates/needle-core/Cargo.toml",
        digest("manifest"),
    )
    .unwrap();
    let partition = TestTargetPartition::new(
        TestTargetPartitionKey {
            ecosystem: TestTargetEcosystem::Cargo,
            workspace: ".".to_owned(),
            package: package.clone(),
            target_kind: TestTargetKind::Lib,
            target_name: "needle_core".to_owned(),
        },
        "crates/needle-core/src/lib.rs",
        TestTargetDeclaration::Manifest,
        vec!["lib".to_owned()],
        Vec::new(),
        "2024",
        true,
        vec![locator.id],
    )
    .unwrap();
    TestTargetInventory::new(
        repository,
        source,
        TestTargetInventoryScope::all(),
        cargo_test_target_adapter_definition(),
        digest("metadata"),
        vec![package],
        vec![locator],
        vec![partition],
    )
    .unwrap()
}

fn inventory_certificate(
    inventory: &TestTargetInventory,
) -> TestTargetInventoryValidationCertificate {
    let mut dependencies = CanonicalHasher::new(b"test-target-inventory-dependency-set-v1");
    for locator in &inventory.collection_dependencies {
        dependencies.field_digest(locator.id);
    }
    let mut certificate = TestTargetInventoryValidationCertificate {
        format_revision: 1,
        inventory: inventory.content_digest,
        validator_definition_digest: test_target_inventory_validator_definition(),
        adapter_definition_digest: inventory.adapter_definition_digest,
        metadata_digest: inventory.metadata_digest,
        dependency_set_digest: dependencies.finish(),
        certificate_digest: Digest([0; 32]),
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

fn architecture_brief(repository: Digest, source: &str) -> ArchitectureBrief {
    let package =
        TestTargetPackageKey::new("needle-core", "crates/needle-core/Cargo.toml").unwrap();
    let package_brief = ArchitecturePackageBrief::new(
        package.clone(),
        "",
        Vec::new(),
        Vec::new(),
        vec!["No authoritative prose in fixture".to_owned()],
    )
    .unwrap();
    ArchitectureBrief::new(
        repository,
        source,
        "Cargo.toml",
        ArchitectureBriefScope::all(),
        architecture_brief_analysis_definition(),
        vec![package],
        Vec::new(),
        vec![package_brief],
    )
    .unwrap()
}

fn architecture_certificate(brief: &ArchitectureBrief) -> ArchitectureBriefValidationCertificate {
    let mut certificate = ArchitectureBriefValidationCertificate {
        format_revision: 1,
        brief: brief.content_digest,
        analysis_definition_digest: architecture_brief_analysis_definition(),
        validator_definition_digest: architecture_brief_validator_definition(),
        package_universe_digest: brief.package_universe_digest(),
        evidence_checks_digest: digest("architecture-evidence"),
        id: Digest([0; 32]),
    };
    let mut hasher = CanonicalHasher::new(b"architecture-brief-validation-certificate-v1");
    hasher.field_u16(certificate.format_revision);
    hasher.field_digest(certificate.brief);
    hasher.field_digest(certificate.analysis_definition_digest);
    hasher.field_digest(certificate.validator_definition_digest);
    hasher.field_digest(certificate.package_universe_digest);
    hasher.field_digest(certificate.evidence_checks_digest);
    certificate.id = hasher.finish();
    certificate
}

fn change_impact(repository: Digest, source: &str) -> ChangeImpact {
    let before = digest("before");
    let after = digest("after");
    let file = ChangeImpactFile::new(
        "crates/needle-core/src/lib.rs",
        PatchOperation::Update,
        Some(before),
        Some(after),
        10,
        11,
    )
    .unwrap();
    let patch_file = PatchFile {
        path: file.path.clone(),
        operation: file.operation,
        before_digest: file.before_digest,
        after_digest: file.after_digest,
        before_bytes: file.before_bytes,
        after_bytes: file.after_bytes,
    };
    let source_snapshot = digest(source);
    let change_set = ChangeImpactChangeSet::new(
        PatchArtifact::compute_id(source_snapshot, &[patch_file]),
        source_snapshot,
        vec![file],
    )
    .unwrap();
    let requirement = ChangeImpactRequirement::new("Determine the affected surface").unwrap();
    let subject = Subject::exact(repository, SubjectKind::Module, "needle_core");
    let assessment = ChangeImpactAssessment::new(
        needle_core::ChangeImpactComponentKey { requirement: requirement.id, subject: subject.id },
        ChangeImpactDisposition::Unknown,
        Vec::new(),
        "Unknown until authoritative analysis",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    ChangeImpact::new(
        repository,
        source,
        change_set,
        ChangeImpactScope::all(),
        change_impact_analysis_definition(),
        vec![requirement],
        Vec::new(),
        vec![subject],
        Vec::new(),
        None,
        None,
        Vec::new(),
        vec![assessment],
        vec!["No structural evidence in fixture".to_owned()],
    )
    .unwrap()
}

fn change_impact_certificate(impact: &ChangeImpact) -> ChangeImpactValidationCertificate {
    let mut certificate = ChangeImpactValidationCertificate {
        format_revision: 1,
        impact: impact.content_digest,
        change_set_digest: impact.change_set.digest,
        scope_digest: impact.scope.digest(),
        analysis_definition_digest: change_impact_analysis_definition(),
        validator_definition_digest: change_impact_validator_definition(),
        input_binding_digest: digest("change-input-binding"),
        evidence_checks_digest: digest("change-evidence"),
        test_inventory_digest: None,
        id: Digest([0; 32]),
    };
    let mut hasher = CanonicalHasher::new(b"change-impact-validation-certificate-v1");
    hasher.field_u16(certificate.format_revision);
    hasher.field_digest(certificate.impact);
    hasher.field_digest(certificate.change_set_digest);
    hasher.field_digest(certificate.scope_digest);
    hasher.field_digest(certificate.analysis_definition_digest);
    hasher.field_digest(certificate.validator_definition_digest);
    hasher.field_digest(certificate.input_binding_digest);
    hasher.field_digest(certificate.evidence_checks_digest);
    hasher.field_u8(0);
    certificate.id = hasher.finish();
    certificate
}

fn assert_manifest(
    manifest: &needle_core::PartitionManifest,
    request: &ActionRequest,
    count: usize,
) {
    assert_eq!(manifest.binding.action_request, request.semantic_id());
    assert_eq!(manifest.entries.len(), count);
    assert!(manifest.entries.iter().all(|entry| entry.coverage.entries.is_empty()));
    assert_eq!(manifest.closure, needle_core::ManifestClosure::Closed);
    let definition = built_in_partition_for_action(&request.contract).unwrap();
    definition.policy.accepts(manifest, &definition.scheme).unwrap();
}
