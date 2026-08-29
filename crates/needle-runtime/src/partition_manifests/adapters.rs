use super::{BuiltInPartitionDefinition, built_in_partition_for_action};
use crate::{
    ArchitectureBriefValidationCertificate, ChangeImpactValidationCertificate,
    TestTargetInventoryValidationCertificate, cargo_test_target_partition_opaque_key,
};
use needle_core::{
    ActionRequest, ArtifactId, CanonicalHasher, ChangeImpact, CoverageManifest, Digest,
    ManifestBinding, ManifestClosure, ManifestProvenance, OpaquePartitionKey, PartitionEntry,
    PartitionManifest, PartitionManifestError, PartitionManifestValidationCertificate,
    PartitionRole, ReviewFinding, ReviewReport, SemanticInputBinding, SemanticWorld,
    TestTargetInventory, semantic_input_set_digest,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Clone, Copy, Debug)]
pub struct ShadowManifestContext<'a> {
    pub request: &'a ActionRequest,
    pub world: &'a SemanticWorld,
    pub definition_set_digest: Digest,
}

#[derive(Debug, Error)]
pub enum ShadowPartitionManifestError {
    #[error("partition definition is missing for the action")]
    DefinitionMissing,
    #[error("action request is invalid: {0}")]
    Request(String),
    #[error("action request, semantic world, and artifact bindings do not match")]
    Binding,
    #[error("{0} artifact is invalid")]
    Artifact(&'static str),
    #[error("{0} validation certificate is invalid or does not bind the artifact")]
    Certificate(&'static str),
    #[error("partition manifest would exceed its {maximum}-byte policy bound")]
    WireBound { maximum: usize },
    #[error(transparent)]
    Manifest(#[from] PartitionManifestError),
    #[error("partition manifest serialization failed: {0}")]
    Serialization(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowPartitionManifestPublication {
    pub manifest: PartitionManifest,
    pub certificate: PartitionManifestValidationCertificate,
}

impl ShadowPartitionManifestPublication {
    pub fn awcp_projection(
        &self,
    ) -> Result<needle_core::AwcpPartitionManifestProjection, needle_core::AwcpValidationError>
    {
        let definition = built_in_partition_for_action(&self.manifest.binding.action_contract)
            .ok_or(needle_core::AwcpValidationError::PartitionManifestProjection)?;
        needle_core::AwcpPartitionManifestProjection::new(
            &self.manifest,
            &self.certificate,
            &definition.scheme,
            &definition.policy,
        )
    }

    pub fn validate(&self) -> Result<(), ShadowPartitionManifestError> {
        let definition = built_in_partition_for_action(&self.manifest.binding.action_contract)
            .ok_or(ShadowPartitionManifestError::DefinitionMissing)?;
        definition
            .validate()
            .map_err(|error| ShadowPartitionManifestError::Request(error.to_string()))?;
        if self.manifest.binding.output_contract != definition.output_contract_id
            || self.certificate.declared_policy_authority_digest
                != definition.declared_policy_authority_digest
            || self.certificate.validator_definition_digest
                != definition.validator_definition_digest
            || self.certificate.adapter_definition_digest != definition.adapter_definition_digest
            || self.certificate.issued_mode != definition.initial_mode
        {
            return Err(ShadowPartitionManifestError::Binding);
        }
        self.certificate.validate_against_manifest(
            &self.manifest,
            &definition.scheme,
            &definition.policy,
        )?;
        Ok(())
    }

    pub fn from_parts(
        manifest: PartitionManifest,
        certificate: PartitionManifestValidationCertificate,
    ) -> Result<Self, ShadowPartitionManifestError> {
        let value = Self { manifest, certificate };
        value.validate()?;
        Ok(value)
    }
}

pub fn derive_test_target_inventory_shadow_manifest(
    context: ShadowManifestContext<'_>,
    inventory: &TestTargetInventory,
    certificate: &TestTargetInventoryValidationCertificate,
) -> Result<PartitionManifest, ShadowPartitionManifestError> {
    inventory
        .validate()
        .map_err(|_| ShadowPartitionManifestError::Artifact("test-target inventory"))?;
    certificate
        .validate()
        .map_err(|_| ShadowPartitionManifestError::Certificate("test-target inventory"))?;
    let definition = prepare_definition(context, "needle.tests.inventory")?;
    if certificate.inventory != inventory.content_digest
        || certificate.validator_definition_digest != definition.validator_definition_digest
        || certificate.adapter_definition_digest != inventory.adapter_definition_digest
        || certificate.adapter_definition_digest != definition.adapter_definition_digest
        || certificate.metadata_digest != inventory.metadata_digest
        || certificate.dependency_set_digest != inventory_dependency_digest(inventory)
    {
        return Err(ShadowPartitionManifestError::Certificate("test-target inventory"));
    }
    ensure_world_cloning_bound(context.world, inventory.partitions.len(), definition)?;
    let common = common_entry_binding(context)?;
    let binding = prepare_binding(
        context,
        definition,
        inventory.repository_lineage,
        &inventory.source_selector,
        &common,
    )?;
    let entries = inventory
        .partitions
        .iter()
        .map(|partition| {
            build_entry(
                definition,
                cargo_test_target_partition_opaque_key(&partition.key),
                partition.content_digest,
                certificate.dependency_set_digest,
                context.world,
                &common,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    finish_manifest(context.request.semantic_id(), definition, binding, entries)
}

pub fn derive_architecture_brief_shadow_manifest(
    context: ShadowManifestContext<'_>,
    brief: &needle_core::ArchitectureBrief,
    certificate: &ArchitectureBriefValidationCertificate,
) -> Result<PartitionManifest, ShadowPartitionManifestError> {
    brief.validate().map_err(|_| ShadowPartitionManifestError::Artifact("architecture brief"))?;
    certificate
        .validate()
        .map_err(|_| ShadowPartitionManifestError::Certificate("architecture brief"))?;
    let definition = prepare_definition(context, "needle.architecture.describe")?;
    if certificate.brief != brief.content_digest
        || certificate.analysis_definition_digest != definition.adapter_definition_digest
        || certificate.validator_definition_digest != definition.validator_definition_digest
        || certificate.package_universe_digest != brief.package_universe_digest()
    {
        return Err(ShadowPartitionManifestError::Certificate("architecture brief"));
    }
    ensure_world_cloning_bound(context.world, brief.packages.len(), definition)?;
    let common = common_entry_binding(context)?;
    let binding = prepare_binding(
        context,
        definition,
        brief.repository_lineage,
        &brief.source_selector,
        &common,
    )?;
    let entries = brief
        .packages
        .iter()
        .map(|package| {
            let mut hasher = CanonicalHasher::new(b"architecture-package-opaque-key-v1");
            hasher.field_str(&package.package.name);
            hasher.field_str(&package.package.manifest_path);
            build_entry(
                definition,
                hasher.finish(),
                package.content_digest,
                certificate.evidence_checks_digest,
                context.world,
                &common,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    finish_manifest(context.request.semantic_id(), definition, binding, entries)
}

pub fn derive_change_impact_shadow_manifest(
    context: ShadowManifestContext<'_>,
    impact: &ChangeImpact,
    certificate: &ChangeImpactValidationCertificate,
) -> Result<PartitionManifest, ShadowPartitionManifestError> {
    impact.validate().map_err(|_| ShadowPartitionManifestError::Artifact("change impact"))?;
    certificate
        .validate()
        .map_err(|_| ShadowPartitionManifestError::Certificate("change impact"))?;
    let definition = prepare_definition(context, "needle.change.impact")?;
    if certificate.impact != impact.content_digest
        || certificate.change_set_digest != impact.change_set.digest
        || certificate.scope_digest != impact.scope.digest()
        || certificate.analysis_definition_digest != definition.adapter_definition_digest
        || certificate.validator_definition_digest != definition.validator_definition_digest
        || certificate.test_inventory_digest != impact.test_inventory_digest
    {
        return Err(ShadowPartitionManifestError::Certificate("change impact"));
    }
    ensure_world_cloning_bound(context.world, impact.assessments.len(), definition)?;
    let common = common_entry_binding(context)?;
    let binding = prepare_binding(
        context,
        definition,
        impact.repository_lineage,
        &impact.source_selector,
        &common,
    )?;
    let dependency_digest = change_impact_dependency_digest(certificate);
    let entries = impact
        .assessments
        .iter()
        .map(|assessment| {
            let mut hasher = CanonicalHasher::new(b"change-impact-component-opaque-key-v1");
            hasher.field_digest(assessment.key.requirement.digest());
            hasher.field_digest(assessment.key.subject.digest());
            build_entry(
                definition,
                hasher.finish(),
                assessment.content_digest,
                dependency_digest,
                context.world,
                &common,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    finish_manifest(context.request.semantic_id(), definition, binding, entries)
}

pub fn certify_test_target_inventory_shadow_manifest(
    context: ShadowManifestContext<'_>,
    inventory: &TestTargetInventory,
    certificate: &TestTargetInventoryValidationCertificate,
    issued_unix_ms: u64,
) -> Result<ShadowPartitionManifestPublication, ShadowPartitionManifestError> {
    let manifest = derive_test_target_inventory_shadow_manifest(context, inventory, certificate)?;
    finish_publication(
        manifest,
        inventory.content_digest,
        certificate.certificate_digest,
        issued_unix_ms,
    )
}

pub fn certify_architecture_brief_shadow_manifest(
    context: ShadowManifestContext<'_>,
    brief: &needle_core::ArchitectureBrief,
    certificate: &ArchitectureBriefValidationCertificate,
    issued_unix_ms: u64,
) -> Result<ShadowPartitionManifestPublication, ShadowPartitionManifestError> {
    let manifest = derive_architecture_brief_shadow_manifest(context, brief, certificate)?;
    finish_publication(manifest, brief.content_digest, certificate.id, issued_unix_ms)
}

pub fn certify_change_impact_shadow_manifest(
    context: ShadowManifestContext<'_>,
    impact: &ChangeImpact,
    certificate: &ChangeImpactValidationCertificate,
    issued_unix_ms: u64,
) -> Result<ShadowPartitionManifestPublication, ShadowPartitionManifestError> {
    let manifest = derive_change_impact_shadow_manifest(context, impact, certificate)?;
    finish_publication(manifest, impact.content_digest, certificate.id, issued_unix_ms)
}

pub fn derive_review_shadow_manifest(
    context: ShadowManifestContext<'_>,
    findings: &[ReviewFinding],
    dependency_digest: Digest,
) -> Result<PartitionManifest, ShadowPartitionManifestError> {
    let definition = prepare_definition(context, needle_core::REVIEW_DIFF_ACTION_CONTRACT)?;
    if dependency_digest == Digest([0; 32])
        || findings.len() > needle_core::MAX_REVIEW_FINDINGS
        || findings.iter().any(|finding| {
            !ReviewFinding::new(
                finding.rule.clone(),
                finding.severity,
                finding.path.clone(),
                finding.line,
                finding.message.clone(),
                finding.evidence_digest,
            )
            .is_ok_and(|canonical| canonical == *finding)
        })
    {
        return Err(ShadowPartitionManifestError::Artifact("review report"));
    }
    ensure_world_cloning_bound(context.world, findings.len(), definition)?;
    let common = common_entry_binding(context)?;
    let binding = prepare_binding(
        context,
        definition,
        context.world.repository_lineage,
        &context.world.source_selector,
        &common,
    )?;
    let entries = findings
        .iter()
        .map(|finding| {
            build_entry(
                definition,
                review_finding_partition_key(finding),
                finding.id,
                dependency_digest,
                context.world,
                &common,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    finish_manifest(context.request.semantic_id(), definition, binding, entries)
}

/// Provider-owned opaque key for one review file/rule partition. The generic
/// partition kernel stores and compares only the resulting digest.
pub fn review_finding_partition_key(finding: &ReviewFinding) -> Digest {
    let mut hasher = CanonicalHasher::new(b"review-file-rule-opaque-key-v1");
    hasher.field_str(&finding.path);
    hasher.field_str(&finding.rule);
    hasher.finish()
}

pub fn certify_review_shadow_manifest(
    manifest: PartitionManifest,
    report: &ReviewReport,
    source_validation_certificate_digest: Digest,
    issued_unix_ms: u64,
) -> Result<ShadowPartitionManifestPublication, ShadowPartitionManifestError> {
    report.validate().map_err(|_| ShadowPartitionManifestError::Artifact("review report"))?;
    if report.manifest != Some(manifest.id)
        || report.action_request != manifest.binding.action_request
        || source_validation_certificate_digest == Digest([0; 32])
    {
        return Err(ShadowPartitionManifestError::Binding);
    }
    finish_publication(manifest, report.id, source_validation_certificate_digest, issued_unix_ms)
}

struct CommonEntryBinding {
    semantic_inputs: Vec<SemanticInputBinding>,
    validated_inputs: Vec<ArtifactId>,
}

fn prepare_definition(
    context: ShadowManifestContext<'_>,
    expected_action: &str,
) -> Result<&'static BuiltInPartitionDefinition, ShadowPartitionManifestError> {
    if context.request.contract.as_str() != expected_action
        || context.request.artifact_request.normalized_request.len()
            > needle_core::MAX_NEED_IR_BYTES
    {
        return Err(ShadowPartitionManifestError::Binding);
    }
    let definition = built_in_partition_for_action(&context.request.contract)
        .ok_or(ShadowPartitionManifestError::DefinitionMissing)?;
    definition
        .validate()
        .map_err(|error| ShadowPartitionManifestError::Request(error.to_string()))?;
    let action = crate::built_in_action_contracts()
        .iter()
        .find(|action| action.contract.id == context.request.contract)
        .ok_or(ShadowPartitionManifestError::DefinitionMissing)?;
    context
        .request
        .validate(&action.contract)
        .map_err(|error| ShadowPartitionManifestError::Request(error.to_string()))?;
    if context.request.artifact_request.contract_id != definition.output_contract_id
        || context.request.artifact_request.contract_revision != definition.output_contract_revision
    {
        return Err(ShadowPartitionManifestError::Binding);
    }
    Ok(definition)
}

fn prepare_binding(
    context: ShadowManifestContext<'_>,
    definition: &BuiltInPartitionDefinition,
    repository: Digest,
    source_selector: &str,
    common: &CommonEntryBinding,
) -> Result<ManifestBinding, ShadowPartitionManifestError> {
    if context.request.artifact_request.repository_id != repository
        || context.world.repository_lineage != repository
        || context.world.source_selector != source_selector
    {
        return Err(ShadowPartitionManifestError::Binding);
    }
    ManifestBinding::new(
        context.request.semantic_id(),
        context.request.contract.clone(),
        definition.output_contract_id,
        semantic_input_set_digest(&common.semantic_inputs)?,
        context.world.id(),
        repository,
        source_selector,
        context.definition_set_digest,
    )
    .map_err(Into::into)
}

fn common_entry_binding(
    context: ShadowManifestContext<'_>,
) -> Result<CommonEntryBinding, ShadowPartitionManifestError> {
    let validated_inputs = context
        .request
        .artifact_request
        .input_artifact_ids
        .iter()
        .copied()
        .map(ArtifactId::new)
        .collect::<Vec<_>>();
    let semantic_inputs = validated_inputs
        .iter()
        .copied()
        .map(|artifact| SemanticInputBinding::ByArtifact { artifact })
        .collect::<Vec<_>>();
    semantic_input_set_digest(&semantic_inputs)?;
    Ok(CommonEntryBinding { semantic_inputs, validated_inputs })
}

fn build_entry(
    definition: &BuiltInPartitionDefinition,
    opaque_key: Digest,
    payload_digest: Digest,
    dependency_digest: Digest,
    world: &SemanticWorld,
    common: &CommonEntryBinding,
) -> Result<PartitionEntry, ShadowPartitionManifestError> {
    Ok(PartitionEntry::new(
        OpaquePartitionKey::new(&definition.scheme, opaque_key.bytes().to_vec(), None)?,
        PartitionRole::Component,
        payload_digest,
        CoverageManifest {
            entries: Vec::new(),
            world: world.clone(),
            dependency_manifest_digest: dependency_digest,
        },
        dependency_digest,
        common.semantic_inputs.clone(),
        common.validated_inputs.clone(),
    )?)
}

fn finish_manifest(
    request: needle_core::ArtifactRequestId,
    definition: &BuiltInPartitionDefinition,
    binding: ManifestBinding,
    entries: Vec<PartitionEntry>,
) -> Result<PartitionManifest, ShadowPartitionManifestError> {
    let manifest = PartitionManifest::new(
        &definition.scheme,
        binding,
        ManifestProvenance::RequestBound { request },
        ManifestClosure::Closed,
        entries,
        None,
    )?;
    definition.policy.accepts(&manifest, &definition.scheme)?;
    let bytes = serde_json::to_vec(&manifest)
        .map_err(|error| ShadowPartitionManifestError::Serialization(error.to_string()))?;
    let maximum = usize::try_from(definition.policy.maximum_manifest_bytes).unwrap_or(usize::MAX);
    if bytes.len() > maximum {
        return Err(ShadowPartitionManifestError::WireBound { maximum });
    }
    Ok(manifest)
}

fn finish_publication(
    manifest: PartitionManifest,
    source_payload_digest: Digest,
    source_validation_certificate_digest: Digest,
    issued_unix_ms: u64,
) -> Result<ShadowPartitionManifestPublication, ShadowPartitionManifestError> {
    let definition = built_in_partition_for_action(&manifest.binding.action_contract)
        .ok_or(ShadowPartitionManifestError::DefinitionMissing)?;
    let certificate = PartitionManifestValidationCertificate::new(
        &manifest,
        &definition.scheme,
        &definition.policy,
        definition.declared_policy_authority_digest,
        definition.validator_definition_digest,
        definition.adapter_definition_digest,
        source_payload_digest,
        source_validation_certificate_digest,
        issued_unix_ms,
    )?;
    ShadowPartitionManifestPublication::from_parts(manifest, certificate)
}

fn ensure_world_cloning_bound(
    world: &SemanticWorld,
    entries: usize,
    definition: &BuiltInPartitionDefinition,
) -> Result<(), ShadowPartitionManifestError> {
    let world_bytes = world
        .source_selector
        .len()
        .saturating_add(world.platform.len())
        .saturating_add(world.features.len());
    let maximum = usize::try_from(definition.policy.maximum_manifest_bytes).unwrap_or(usize::MAX);
    if [world.source_selector.as_str(), world.platform.as_str(), world.features.as_str()]
        .into_iter()
        .any(|value| {
            value.len() > needle_core::MAX_NEED_IR_BYTES || value.chars().any(char::is_control)
        })
    {
        return Err(ShadowPartitionManifestError::Binding);
    }
    if world_bytes.saturating_mul(entries) > maximum {
        return Err(ShadowPartitionManifestError::WireBound { maximum });
    }
    Ok(())
}

fn inventory_dependency_digest(inventory: &TestTargetInventory) -> Digest {
    let mut hasher = CanonicalHasher::new(b"test-target-inventory-dependency-set-v1");
    for locator in &inventory.collection_dependencies {
        hasher.field_digest(locator.id);
    }
    hasher.finish()
}

fn change_impact_dependency_digest(certificate: &ChangeImpactValidationCertificate) -> Digest {
    let mut hasher = CanonicalHasher::new(b"change-impact-partition-dependencies-v1");
    hasher.field_digest(certificate.input_binding_digest);
    hasher.field_digest(certificate.evidence_checks_digest);
    match certificate.test_inventory_digest {
        Some(digest) => {
            hasher.field_u8(1);
            hasher.field_digest(digest);
        }
        None => hasher.field_u8(0),
    }
    hasher.finish()
}
