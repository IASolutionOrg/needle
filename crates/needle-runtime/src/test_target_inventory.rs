mod cargo_adapter;
mod projection;
mod refresh;
mod shadow_execution;
mod shadow_host;

use needle_core::{CanonicalHasher, Digest, TestTargetInventory, TestTargetPartitionKey};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

pub use cargo_adapter::{
    CargoTestTargetRefreshAcquisition, CargoTestTargetRefreshCandidate,
    CargoTestTargetRefreshFallback, CargoTestTargetRefreshInput,
    acquire_cargo_test_target_refresh_candidate, cargo_test_target_refresh_acquisition_definition,
    enumerate_cargo_test_targets,
};
pub use projection::{assemble_test_target_inventories, project_test_target_inventory};
pub use refresh::{
    ShadowTestTargetInventoryRefresh, TestTargetInventoryRefreshDecision,
    TestTargetInventoryRefreshError, TestTargetInventoryRefreshFallback,
    TestTargetInventoryRefreshInput, TestTargetInventoryRefreshPlan,
    evaluate_test_target_inventory_refresh, resolve_test_target_inventory_refresh_or_full_compute,
    test_target_inventory_refresh_definition,
};
pub use shadow_execution::{
    ShadowCargoTestTargetRefreshExecutionInput, ShadowRefreshCostEstimate,
    ShadowTestTargetHeadExecutionContext, ShadowTestTargetPublicationReceipt,
    ShadowTestTargetRefreshExecution, ShadowTestTargetRefreshExecutionError,
    ShadowTestTargetRefreshExecutionFallback, execute_shadow_cargo_test_target_refresh,
};
pub use shadow_host::{
    ShadowCargoTestTargetHostError, ShadowCargoTestTargetHostExecution,
    ShadowCargoTestTargetHostInput, ShadowCargoTestTargetHostRebaseline,
    cargo_test_target_provider_context_digest, execute_shadow_cargo_test_target_host,
};

pub const CARGO_TEST_TARGET_ADAPTER_REVISION: u32 = 2;
pub const MAX_CARGO_METADATA_INPUT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CARGO_VERSION_BYTES: usize = 128;
pub const MAX_TEST_TARGET_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_TEST_TARGET_DIRECTORY_ENTRIES: usize = 4_096;

#[derive(Clone)]
pub struct CargoTestTargetInventoryInput<'a> {
    pub repository_root: &'a Path,
    pub repository_lineage: Digest,
    pub source_selector: &'a str,
    pub scope: needle_core::TestTargetInventoryScope,
    pub metadata_json: &'a [u8],
    pub cargo_version: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestTargetInventoryValidationCertificate {
    pub format_revision: u16,
    pub inventory: Digest,
    pub validator_definition_digest: Digest,
    pub adapter_definition_digest: Digest,
    pub metadata_digest: Digest,
    pub dependency_set_digest: Digest,
    pub certificate_digest: Digest,
}

impl TestTargetInventoryValidationCertificate {
    fn new(inventory: &TestTargetInventory) -> Self {
        let dependency_set_digest = dependency_set_digest(inventory);
        let mut value = Self {
            format_revision: 1,
            inventory: inventory.content_digest,
            validator_definition_digest: test_target_inventory_validator_definition(),
            adapter_definition_digest: inventory.adapter_definition_digest,
            metadata_digest: inventory.metadata_digest,
            dependency_set_digest,
            certificate_digest: Digest([0; 32]),
        };
        value.certificate_digest = value.compute_digest();
        value
    }

    pub fn validate(&self) -> Result<(), TestTargetInventoryRuntimeError> {
        if self.format_revision != 1
            || self.validator_definition_digest != test_target_inventory_validator_definition()
            || self.adapter_definition_digest != cargo_test_target_adapter_definition()
            || self.certificate_digest != self.compute_digest()
        {
            return Err(TestTargetInventoryRuntimeError::Certificate);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"test-target-inventory-certificate-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.inventory);
        hasher.field_digest(self.validator_definition_digest);
        hasher.field_digest(self.adapter_definition_digest);
        hasher.field_digest(self.metadata_digest);
        hasher.field_digest(self.dependency_set_digest);
        hasher.finish()
    }
}

pub fn cargo_test_target_adapter_definition() -> Digest {
    let mut hasher = CanonicalHasher::new(b"cargo-test-target-adapter-definition-v1");
    hasher.field_u32(CARGO_TEST_TARGET_ADAPTER_REVISION);
    hasher.field_str("cargo-metadata-format-1");
    hasher.field_str("target-scoped-metadata-dependencies");
    hasher.field_u32(MAX_CARGO_METADATA_INPUT_BYTES as u32);
    hasher.field_u32(needle_core::MAX_TEST_TARGETS as u32);
    hasher.field_u32(needle_core::MAX_TEST_TARGET_PACKAGES as u32);
    hasher.finish()
}

/// Provider-owned stable key material used by the opaque Cargo target scheme.
/// The generic partition kernel never interprets these fields.
pub fn cargo_test_target_partition_opaque_key(key: &TestTargetPartitionKey) -> Digest {
    let mut hasher = CanonicalHasher::new(b"test-target-partition-opaque-key-v1");
    hasher.field_u8(0);
    hasher.field_str(&key.workspace);
    hasher.field_str(&key.package.name);
    hasher.field_str(&key.package.manifest_path);
    hasher.field_str(key.target_kind.as_str());
    hasher.field_str(&key.target_name);
    hasher.finish()
}

pub fn test_target_inventory_partition_policy_definition() -> Digest {
    let mut hasher = CanonicalHasher::new(b"test-target-inventory-partition-policy-v1");
    hasher.field_str("ecosystem");
    hasher.field_str("workspace");
    hasher.field_str("package");
    hasher.field_str("target-kind");
    hasher.field_str("target-name");
    hasher.field_str("manifest-path");
    hasher.field_str("project:package,target-kind,target-name");
    hasher.field_str("assemble:disjoint-package-partitions");
    hasher.finish()
}

pub fn test_target_inventory_validator_definition() -> Digest {
    let mut hasher = CanonicalHasher::new(b"test-target-inventory-validator-definition-v1");
    hasher.field_str(needle_core::TEST_TARGET_INVENTORY_SCHEMA_ID);
    hasher.field_digest(cargo_test_target_adapter_definition());
    hasher.field_digest(test_target_inventory_partition_policy_definition());
    hasher.field_digest(cargo_test_target_refresh_acquisition_definition());
    hasher.finish()
}

pub fn validate_cargo_test_target_inventory(
    input: CargoTestTargetInventoryInput<'_>,
    candidate: &TestTargetInventory,
) -> Result<TestTargetInventoryValidationCertificate, TestTargetInventoryRuntimeError> {
    candidate.validate()?;
    let expected = enumerate_cargo_test_targets(input)?;
    if &expected != candidate {
        return Err(TestTargetInventoryRuntimeError::Mismatch);
    }
    let certificate = TestTargetInventoryValidationCertificate::new(candidate);
    certificate.validate()?;
    Ok(certificate)
}

fn dependency_set_digest(inventory: &TestTargetInventory) -> Digest {
    let mut hasher = CanonicalHasher::new(b"test-target-inventory-dependency-set-v1");
    for locator in &inventory.collection_dependencies {
        hasher.field_digest(locator.id);
    }
    hasher.finish()
}

#[derive(Debug, Error)]
pub enum TestTargetInventoryRuntimeError {
    #[error("cargo metadata input contains {actual} bytes; the maximum is {maximum}")]
    MetadataBound { actual: usize, maximum: usize },
    #[error("cargo version is empty or exceeds the adapter bound")]
    CargoVersionBound,
    #[error("cargo metadata is malformed: {0}")]
    Metadata(String),
    #[error("cargo metadata workspace does not match the repository root")]
    WorkspaceRoot,
    #[error("cargo metadata contains an unsupported target: {0}")]
    UnsupportedTarget(String),
    #[error("cargo workspace membership uses an unsupported pattern: {0}")]
    UnsupportedWorkspacePattern(String),
    #[error("repository locator `{0}` is outside the root or not valid UTF-8")]
    UnsafeLocator(String),
    #[error("repository locator `{0}` is missing")]
    MissingLocator(String),
    #[error("repository locator `{path}` exceeds {maximum} bytes")]
    LocatorBound { path: String, maximum: usize },
    #[error("repository directory `{path}` contains more than {maximum} entries")]
    DirectoryBound { path: String, maximum: usize },
    #[error("repository I/O failed for `{path}`: {message}")]
    Io { path: String, message: String },
    #[error("test-target inventory candidate differs from deterministic enumeration")]
    Mismatch,
    #[error("test-target inventory projection scope is invalid")]
    ProjectionScope,
    #[error("test-target inventory assembly inputs are incompatible or overlapping")]
    Assembly,
    #[error("test-target inventory validation certificate is invalid")]
    Certificate,
    #[error(transparent)]
    Inventory(#[from] needle_core::TestTargetInventoryError),
}

#[cfg(test)]
mod tests;
