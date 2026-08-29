use super::{TestTargetInventoryRuntimeError, cargo_test_target_adapter_definition};
use needle_core::{
    MAX_TEST_TARGET_PACKAGES, TestTargetInventory, TestTargetInventoryScope, TestTargetPackageKey,
};
use std::collections::BTreeSet;

pub fn project_test_target_inventory(
    source: &TestTargetInventory,
    scope: TestTargetInventoryScope,
) -> Result<TestTargetInventory, TestTargetInventoryRuntimeError> {
    source.validate()?;
    scope.validate()?;
    if !scope.is_projection_of(&source.scope)
        || scope
            .packages
            .iter()
            .any(|package| source.package_universe.binary_search(package).is_err())
    {
        return Err(TestTargetInventoryRuntimeError::ProjectionScope);
    }
    let partitions = source
        .partitions
        .iter()
        .filter(|partition| scope.matches(&partition.key))
        .cloned()
        .collect();
    TestTargetInventory::new(
        source.repository_lineage,
        source.source_selector.clone(),
        scope,
        source.adapter_definition_digest,
        source.metadata_digest,
        source.package_universe.clone(),
        source.collection_dependencies.clone(),
        partitions,
    )
    .map_err(Into::into)
}

pub fn assemble_test_target_inventories(
    inputs: &[TestTargetInventory],
    scope: TestTargetInventoryScope,
) -> Result<TestTargetInventory, TestTargetInventoryRuntimeError> {
    if inputs.len() < 2 || inputs.len() > MAX_TEST_TARGET_PACKAGES {
        return Err(TestTargetInventoryRuntimeError::Assembly);
    }
    scope.validate()?;
    let first = &inputs[0];
    first.validate()?;
    if first.adapter_definition_digest != cargo_test_target_adapter_definition() {
        return Err(TestTargetInventoryRuntimeError::Assembly);
    }

    let mut packages = BTreeSet::<TestTargetPackageKey>::new();
    let mut partitions = Vec::new();
    for input in inputs {
        input.validate()?;
        if input.repository_lineage != first.repository_lineage
            || input.source_selector != first.source_selector
            || input.adapter_definition_digest != first.adapter_definition_digest
            || input.metadata_digest != first.metadata_digest
            || input.package_universe != first.package_universe
            || input.collection_dependencies != first.collection_dependencies
            || input.scope.packages.is_empty()
            || input.scope.target_kinds != scope.target_kinds
            || input.scope.target_names != scope.target_names
        {
            return Err(TestTargetInventoryRuntimeError::Assembly);
        }
        for package in &input.scope.packages {
            if !packages.insert(package.clone()) {
                return Err(TestTargetInventoryRuntimeError::Assembly);
            }
        }
        partitions.extend(input.partitions.iter().cloned());
    }

    let assembled_packages = packages.into_iter().collect::<Vec<_>>();
    let expected_packages =
        if scope.packages.is_empty() { &first.package_universe } else { &scope.packages };
    if &assembled_packages != expected_packages {
        return Err(TestTargetInventoryRuntimeError::Assembly);
    }
    partitions.sort_by(|left, right| left.key.cmp(&right.key));
    if !partitions.windows(2).all(|pair| pair[0].key < pair[1].key) {
        return Err(TestTargetInventoryRuntimeError::Assembly);
    }

    TestTargetInventory::new(
        first.repository_lineage,
        first.source_selector.clone(),
        scope,
        first.adapter_definition_digest,
        first.metadata_digest,
        first.package_universe.clone(),
        first.collection_dependencies.clone(),
        partitions,
    )
    .map_err(Into::into)
}
