use crate::{
    BuiltInActionCoverage, BuiltInActionDefinition, architecture_brief_analysis_definition,
    architecture_brief_partition_policy_definition, architecture_brief_validator_definition,
    built_in_action_contracts, cargo_test_target_adapter_definition,
    change_impact_analysis_definition, change_impact_partition_policy_definition,
    change_impact_validator_definition, test_target_inventory_partition_policy_definition,
    test_target_inventory_validator_definition,
};
use needle_core::{
    ActionContractId, CanonicalHasher, CapabilityMode, Digest, ManifestClosurePolicy,
    PartitionKeyScope, PartitionManifestError, PartitionOverlapPolicy, PartitionPolicy,
    PartitionPolicyId, PartitionScheme, PartitionSchemeId, PartitionSchemeKind, ProviderId,
    SchemaId, ValidatorId, review_partition_policy_definition, review_provider_adapter_definition,
    review_report_validator_definition,
};
use std::sync::OnceLock;
use thiserror::Error;

mod adapters;

#[cfg(test)]
mod tests;

pub use adapters::{
    ShadowManifestContext, ShadowPartitionManifestError, ShadowPartitionManifestPublication,
    certify_architecture_brief_shadow_manifest, certify_change_impact_shadow_manifest,
    certify_review_shadow_manifest, certify_test_target_inventory_shadow_manifest,
    derive_architecture_brief_shadow_manifest, derive_change_impact_shadow_manifest,
    derive_review_shadow_manifest, derive_test_target_inventory_shadow_manifest,
    review_finding_partition_key,
};

pub const BUILT_IN_PARTITION_DEFINITION_COUNT: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltInPartitionDefinition {
    pub action_contract: ActionContractId,
    pub output_contract_id: &'static str,
    pub output_contract_revision: u32,
    pub output_contract_definition_digest: Digest,
    pub scheme: PartitionScheme,
    pub policy: PartitionPolicy,
    pub declared_policy_authority_digest: Digest,
    pub validator_definition_digest: Digest,
    pub adapter_definition_digest: Digest,
    pub initial_mode: CapabilityMode,
    pub definition_digest: Digest,
}

impl BuiltInPartitionDefinition {
    pub fn validate(&self) -> Result<(), BuiltInPartitionDefinitionError> {
        self.scheme.validate()?;
        self.policy.validate()?;
        if self.policy.allowed_schemes.as_slice() != [self.scheme.id.clone()]
            || self.initial_mode != CapabilityMode::Shadow
        {
            return Err(BuiltInPartitionDefinitionError::RegistryBinding);
        }
        if self.definition_digest != self.compute_definition_digest() {
            return Err(BuiltInPartitionDefinitionError::DefinitionDigest);
        }
        let action = built_in_action_contracts()
            .iter()
            .find(|definition| definition.contract.id == self.action_contract)
            .ok_or(BuiltInPartitionDefinitionError::ActionMissing)?;
        self.validate_against_action(action)
    }

    pub fn validate_against_action(
        &self,
        action: &BuiltInActionDefinition,
    ) -> Result<(), BuiltInPartitionDefinitionError> {
        let BuiltInActionCoverage::Partitioned { policy_definition_digest } = action.coverage
        else {
            return Err(BuiltInPartitionDefinitionError::ActionCoverage);
        };
        if action.contract.id != self.action_contract
            || action.output_contract_id != self.output_contract_id
            || action.output_contract_revision != self.output_contract_revision
            || action.output_contract_definition_digest != self.output_contract_definition_digest
            || policy_definition_digest != self.declared_policy_authority_digest
            || action.validator_definition_digest != self.validator_definition_digest
            || action.initial_mode != self.initial_mode
        {
            return Err(BuiltInPartitionDefinitionError::RegistryBinding);
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"built-in-partition-definition-v1");
        hasher.field_str(self.action_contract.as_str());
        hasher.field_str(self.output_contract_id);
        hasher.field_u32(self.output_contract_revision);
        hasher.field_digest(self.output_contract_definition_digest);
        hasher.field_digest(self.scheme.definition_digest);
        hasher.field_digest(self.policy.definition_digest);
        hasher.field_digest(self.declared_policy_authority_digest);
        hasher.field_digest(self.validator_definition_digest);
        hasher.field_digest(self.adapter_definition_digest);
        hasher.field_u8(capability_mode_tag(self.initial_mode));
        hasher.finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BuiltInPartitionDefinitionError {
    #[error("partition definition has no matching built-in action")]
    ActionMissing,
    #[error("built-in action does not declare partitioned coverage")]
    ActionCoverage,
    #[error("partition definition does not match its action catalog authority")]
    RegistryBinding,
    #[error("partition definition digest is invalid")]
    DefinitionDigest,
    #[error(transparent)]
    Manifest(#[from] PartitionManifestError),
}

pub fn built_in_partition_definitions()
-> &'static [BuiltInPartitionDefinition; BUILT_IN_PARTITION_DEFINITION_COUNT] {
    static DEFINITIONS: OnceLock<
        [BuiltInPartitionDefinition; BUILT_IN_PARTITION_DEFINITION_COUNT],
    > = OnceLock::new();
    DEFINITIONS.get_or_init(|| {
        [
            build_test_target_inventory_definition(),
            build_architecture_brief_definition(),
            build_change_impact_definition(),
            build_review_definition(),
        ]
    })
}

pub fn built_in_partition_for_action(
    action: &ActionContractId,
) -> Option<&'static BuiltInPartitionDefinition> {
    built_in_partition_definitions().iter().find(|definition| &definition.action_contract == action)
}

pub fn built_in_partition_for_scheme(
    scheme: &PartitionSchemeId,
) -> Option<&'static BuiltInPartitionDefinition> {
    built_in_partition_definitions().iter().find(|definition| &definition.scheme.id == scheme)
}

fn build_test_target_inventory_definition() -> BuiltInPartitionDefinition {
    build_definition(
        "needle.tests.inventory",
        needle_core::TEST_TARGET_INVENTORY_OUTPUT_CONTRACT_ID,
        needle_core::TEST_TARGET_INVENTORY_OUTPUT_CONTRACT_REVISION,
        PartitionScheme::new(
            PartitionSchemeId::new("needle.tests.inventory.target").expect("static scheme id"),
            PartitionSchemeKind::ProviderDefined {
                provider: ProviderId::new("needle.provider.cargo-metadata")
                    .expect("static provider id"),
            },
            PartitionKeyScope::ProviderStable,
            SchemaId::new("needle.opaque.cargo-test-target.v1").expect("static schema id"),
            32,
        )
        .expect("static test inventory scheme"),
        "needle.tests.inventory.partition-policy",
        "needle.validator.test-target-inventory-manifest.v1",
        needle_core::MAX_TEST_TARGETS,
        needle_core::MAX_TEST_TARGET_INVENTORY_WIRE_BYTES,
        test_target_inventory_partition_policy_definition(),
        test_target_inventory_validator_definition(),
        cargo_test_target_adapter_definition(),
    )
}

fn build_architecture_brief_definition() -> BuiltInPartitionDefinition {
    build_definition(
        "needle.architecture.describe",
        needle_core::ARCHITECTURE_BRIEF_OUTPUT_CONTRACT_ID,
        needle_core::ARCHITECTURE_BRIEF_OUTPUT_CONTRACT_REVISION,
        PartitionScheme::new(
            PartitionSchemeId::new("needle.architecture.package").expect("static scheme id"),
            PartitionSchemeKind::ContractDefined,
            PartitionKeyScope::ManifestLocal,
            SchemaId::new("needle.opaque.architecture-package.v1").expect("static schema id"),
            32,
        )
        .expect("static architecture scheme"),
        "needle.architecture.partition-policy",
        "needle.validator.architecture-brief-manifest.v1",
        needle_core::MAX_ARCHITECTURE_PACKAGES,
        needle_core::MAX_ARCHITECTURE_BRIEF_WIRE_BYTES,
        architecture_brief_partition_policy_definition(),
        architecture_brief_validator_definition(),
        architecture_brief_analysis_definition(),
    )
}

fn build_change_impact_definition() -> BuiltInPartitionDefinition {
    build_definition(
        "needle.change.impact",
        needle_core::CHANGE_IMPACT_OUTPUT_CONTRACT_ID,
        needle_core::CHANGE_IMPACT_OUTPUT_CONTRACT_REVISION,
        PartitionScheme::new(
            PartitionSchemeId::new("needle.change-impact.component").expect("static scheme id"),
            PartitionSchemeKind::ContractDefined,
            PartitionKeyScope::ManifestLocal,
            SchemaId::new("needle.opaque.change-impact-component.v1").expect("static schema id"),
            32,
        )
        .expect("static change-impact scheme"),
        "needle.change-impact.partition-policy",
        "needle.validator.change-impact-manifest.v1",
        needle_core::MAX_CHANGE_IMPACT_COMPONENTS,
        needle_core::MAX_CHANGE_IMPACT_WIRE_BYTES,
        change_impact_partition_policy_definition(),
        change_impact_validator_definition(),
        change_impact_analysis_definition(),
    )
}

fn build_review_definition() -> BuiltInPartitionDefinition {
    build_definition(
        needle_core::REVIEW_DIFF_ACTION_CONTRACT,
        needle_core::REVIEW_REPORT_OUTPUT_CONTRACT_ID,
        needle_core::REVIEW_REPORT_OUTPUT_CONTRACT_REVISION,
        PartitionScheme::new(
            PartitionSchemeId::new("needle.review.file-rule").expect("static scheme id"),
            PartitionSchemeKind::ProviderDefined {
                provider: ProviderId::new("needle.provider.review").expect("static provider id"),
            },
            PartitionKeyScope::ProviderStable,
            SchemaId::new("needle.opaque.review-file-rule.v1").expect("static schema id"),
            needle_core::MAX_REVIEW_FINDINGS.try_into().expect("review finding bound fits u16"),
        )
        .expect("static review scheme"),
        "needle.review.diff.partition-policy",
        "needle.validator.review-report-manifest.v1",
        needle_core::MAX_REVIEW_FINDINGS,
        needle_core::MAX_REVIEW_REPORT_WIRE_BYTES,
        review_partition_policy_definition(),
        review_report_validator_definition(),
        review_provider_adapter_definition(),
    )
}

#[allow(clippy::too_many_arguments)]
fn build_definition(
    action_contract: &'static str,
    output_contract_id: &'static str,
    output_contract_revision: u32,
    scheme: PartitionScheme,
    policy_id: &'static str,
    validator_id: &'static str,
    maximum_partitions: usize,
    maximum_manifest_bytes: usize,
    declared_policy_authority_digest: Digest,
    validator_definition_digest: Digest,
    adapter_definition_digest: Digest,
) -> BuiltInPartitionDefinition {
    let action = built_in_action_contracts()
        .iter()
        .find(|definition| definition.contract.id.as_str() == action_contract)
        .expect("partitioned built-in action exists");
    let policy = PartitionPolicy::new(
        PartitionPolicyId::new(policy_id).expect("static policy id"),
        vec![scheme.id.clone()],
        ValidatorId::new(validator_id).expect("static validator id"),
        maximum_partitions.try_into().expect("partition maximum fits u16"),
        maximum_manifest_bytes.try_into().expect("manifest maximum fits u32"),
        PartitionOverlapPolicy::ValidatorDefined,
        ManifestClosurePolicy::ClosedRequired,
    )
    .expect("static partition policy");
    let mut definition = BuiltInPartitionDefinition {
        action_contract: action.contract.id.clone(),
        output_contract_id,
        output_contract_revision,
        output_contract_definition_digest: action.output_contract_definition_digest,
        scheme,
        policy,
        declared_policy_authority_digest,
        validator_definition_digest,
        adapter_definition_digest,
        initial_mode: CapabilityMode::Shadow,
        definition_digest: Digest([0; 32]),
    };
    definition.definition_digest = definition.compute_definition_digest();
    definition.validate().expect("static partition definition");
    definition
}

const fn capability_mode_tag(mode: CapabilityMode) -> u8 {
    match mode {
        CapabilityMode::Disabled => 0,
        CapabilityMode::Shadow => 1,
        CapabilityMode::Advisory => 2,
        CapabilityMode::Authoritative => 3,
    }
}
