use super::{
    TestTargetInventoryRuntimeError, TestTargetInventoryValidationCertificate,
    cargo_test_target_partition_opaque_key,
};
use crate::{
    ShadowPartitionManifestError, ShadowPartitionManifestPublication, ShadowRefreshCandidate,
    ShadowRefreshResolution, ShadowRefreshResolverError, ShadowRefreshResolverInput,
    built_in_partition_for_action, resolve_shadow_refresh_or_full_compute,
};
use needle_core::{
    ActionContract, ActionRequest, CanonicalHasher, CapabilityMode, DependencyLocator,
    DerivationRuleId, Digest, MAX_TEST_TARGETS, ManifestProvenance, ManifestTransition,
    OpaquePartitionKey, PartitionKeyMapping, PartitionManifestError, PartitionRef, PartitionRole,
    RefreshCostEvidence, RefreshEconomicPolicy, RepositoryGenerationError, StateDelta,
    TestTargetInventory, TestTargetLocator, TestTargetLocatorKind, TestTargetPartition,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use thiserror::Error;

pub const TEST_TARGET_INVENTORY_REFRESH_FORMAT_REVISION: u16 = 1;

/// Borrowed evidence required by the offline Cargo reference refresh operator.
/// Both publications must already be server-certified Shadow records.
#[derive(Clone, Copy)]
pub struct TestTargetInventoryRefreshInput<'a> {
    pub prior_inventory: &'a TestTargetInventory,
    pub prior_validation: &'a TestTargetInventoryValidationCertificate,
    pub prior_publication: &'a ShadowPartitionManifestPublication,
    pub current_inventory: &'a TestTargetInventory,
    pub current_validation: &'a TestTargetInventoryValidationCertificate,
    pub current_publication: &'a ShadowPartitionManifestPublication,
    pub state_delta: &'a StateDelta,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestTargetInventoryRefreshFallback {
    NoManifestChange,
    IncompleteDelta,
    ChangedInputArtifacts,
    ChangedDefinitions,
    ChangedSemanticWorld,
    ProviderOpaqueDelta,
    NoRetainedPartitions,
}

impl TestTargetInventoryRefreshFallback {
    pub fn evidence_digest(self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"test-target-inventory-refresh-fallback-v1");
        hasher.field_digest(test_target_inventory_refresh_definition());
        hasher.field_u8(match self {
            Self::NoManifestChange => 0,
            Self::IncompleteDelta => 1,
            Self::ChangedInputArtifacts => 2,
            Self::ChangedDefinitions => 3,
            Self::ChangedSemanticWorld => 4,
            Self::ProviderOpaqueDelta => 5,
            Self::NoRetainedPartitions => 6,
        });
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestTargetInventoryRefreshPlan {
    pub format_revision: u16,
    pub prior_manifest: needle_core::PartitionManifestId,
    pub current_manifest: needle_core::PartitionManifestId,
    pub transition: ManifestTransition,
    pub state_delta: Digest,
    pub retained: Vec<PartitionKeyMapping>,
    pub refreshed: Vec<PartitionRef>,
    pub added: Vec<PartitionRef>,
    pub removed: Vec<PartitionRef>,
    pub definition_digest: Digest,
}

impl TestTargetInventoryRefreshPlan {
    pub fn validate(&self) -> Result<(), TestTargetInventoryRefreshError> {
        let transition_current =
            self.transition.mappings.iter().map(|mapping| mapping.current).collect::<BTreeSet<_>>();
        let retained_current =
            self.retained.iter().map(|mapping| mapping.current).collect::<BTreeSet<_>>();
        let refreshed = self.refreshed.iter().copied().collect::<BTreeSet<_>>();
        let added = self.added.iter().copied().collect::<BTreeSet<_>>();
        if self.format_revision != TEST_TARGET_INVENTORY_REFRESH_FORMAT_REVISION
            || self.prior_manifest == self.current_manifest
            || self.transition.prior != self.prior_manifest
            || self.transition.current != self.current_manifest
            || self.transition.state_delta != self.state_delta
            || self.retained.is_empty()
            || self.retained.len() > MAX_TEST_TARGETS
            || self.refreshed.len() > MAX_TEST_TARGETS
            || self.added.len() > MAX_TEST_TARGETS
            || self.removed.len() > MAX_TEST_TARGETS
            || !strictly_sorted(&self.retained)
            || !strictly_sorted(&self.refreshed)
            || !strictly_sorted(&self.added)
            || !strictly_sorted(&self.removed)
            || self.retained.iter().any(|mapping| {
                mapping.prior.manifest != self.prior_manifest
                    || mapping.current.manifest != self.current_manifest
            })
            || self
                .refreshed
                .iter()
                .chain(&self.added)
                .any(|partition| partition.manifest != self.current_manifest)
            || self.removed.iter().any(|partition| partition.manifest != self.prior_manifest)
            || self.transition.mappings.len() != self.retained.len() + self.refreshed.len()
            || self
                .retained
                .iter()
                .any(|mapping| self.transition.mappings.binary_search(mapping).is_err())
            || transition_current != retained_current.union(&refreshed).copied().collect()
            || !retained_current.is_disjoint(&refreshed)
            || !retained_current.is_disjoint(&added)
            || !refreshed.is_disjoint(&added)
        {
            return Err(TestTargetInventoryRefreshError::Plan);
        }
        self.transition.validate()?;
        if self.definition_digest != self.compute_definition_digest() {
            return Err(TestTargetInventoryRefreshError::Plan);
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"test-target-inventory-refresh-plan-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.prior_manifest.digest());
        hasher.field_digest(self.current_manifest.digest());
        hasher.field_digest(self.transition.definition_digest);
        hasher.field_digest(self.state_delta);
        hash_mappings(&mut hasher, &self.retained);
        hash_refs(&mut hasher, &self.refreshed);
        hash_refs(&mut hasher, &self.added);
        hash_refs(&mut hasher, &self.removed);
        hasher.field_digest(test_target_inventory_refresh_definition());
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowTestTargetInventoryRefresh {
    pub plan: TestTargetInventoryRefreshPlan,
    pub reconstructed: TestTargetInventory,
    pub validation_certificate: TestTargetInventoryValidationCertificate,
    pub fresh_oracle_digest: Digest,
    pub authority: CapabilityMode,
}

impl ShadowTestTargetInventoryRefresh {
    pub fn validate(&self) -> Result<(), TestTargetInventoryRefreshError> {
        self.plan.validate()?;
        self.reconstructed.validate().map_err(TestTargetInventoryRuntimeError::from)?;
        self.validation_certificate.validate()?;
        if self.authority != CapabilityMode::Shadow
            || self.validation_certificate.inventory != self.reconstructed.content_digest
            || self.fresh_oracle_digest != self.reconstructed.content_digest
        {
            return Err(TestTargetInventoryRefreshError::Result);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum TestTargetInventoryRefreshDecision {
    Refresh { result: Box<ShadowTestTargetInventoryRefresh> },
    FullCompute { reason: TestTargetInventoryRefreshFallback },
}

#[derive(Debug, Error)]
pub enum TestTargetInventoryRefreshError {
    #[error("test-target refresh evidence does not share one exact action binding")]
    Binding,
    #[error("test-target refresh source certificate does not bind its inventory or publication")]
    SourceCertificate,
    #[error("test-target refresh manifest entries do not bind the typed inventory partitions")]
    ManifestEntries,
    #[error("test-target refresh plan is not canonical")]
    Plan,
    #[error("test-target refresh reconstruction differs from fresh deterministic enumeration")]
    Reconstruction,
    #[error("test-target refresh result is not canonical")]
    Result,
    #[error(transparent)]
    Inventory(#[from] TestTargetInventoryRuntimeError),
    #[error(transparent)]
    Publication(#[from] ShadowPartitionManifestError),
    #[error(transparent)]
    Manifest(#[from] PartitionManifestError),
    #[error(transparent)]
    Delta(#[from] RepositoryGenerationError),
}

/// Evaluate one bounded, deterministic Shadow refresh against an already
/// enumerated current oracle. This is an offline conformance operator: it does
/// not query storage, invoke Cargo, select authority, or alter resolver state.
pub fn evaluate_test_target_inventory_refresh(
    input: TestTargetInventoryRefreshInput<'_>,
) -> Result<TestTargetInventoryRefreshDecision, TestTargetInventoryRefreshError> {
    validate_refresh_input(&input)?;

    if input.prior_publication.manifest.id == input.current_publication.manifest.id {
        return Ok(full_compute(TestTargetInventoryRefreshFallback::NoManifestChange));
    }
    if !input.state_delta.complete {
        return Ok(full_compute(TestTargetInventoryRefreshFallback::IncompleteDelta));
    }
    if !input.state_delta.changed_input_artifacts.is_empty() {
        return Ok(full_compute(TestTargetInventoryRefreshFallback::ChangedInputArtifacts));
    }
    if !input.state_delta.changed_definitions.is_empty() {
        return Ok(full_compute(TestTargetInventoryRefreshFallback::ChangedDefinitions));
    }
    if !input.state_delta.semantic_world_changes.is_empty() {
        return Ok(full_compute(TestTargetInventoryRefreshFallback::ChangedSemanticWorld));
    }
    if input
        .state_delta
        .changed_locators
        .iter()
        .any(|locator| matches!(locator, DependencyLocator::ProviderOpaque { .. }))
    {
        return Ok(full_compute(TestTargetInventoryRefreshFallback::ProviderOpaqueDelta));
    }

    let definition =
        built_in_partition_for_action(&input.current_publication.manifest.binding.action_contract)
            .ok_or(TestTargetInventoryRefreshError::Binding)?;
    let prior_partitions = bind_manifest_entries(
        input.prior_inventory,
        input.prior_validation,
        input.prior_publication,
        &definition.scheme,
    )?;
    let current_partitions = bind_manifest_entries(
        input.current_inventory,
        input.current_validation,
        input.current_publication,
        &definition.scheme,
    )?;
    let prior_locators = locator_index(input.prior_inventory);

    let prior_manifest = &input.prior_publication.manifest;
    let current_manifest = &input.current_publication.manifest;
    let mut retained = Vec::new();
    let mut refreshed = Vec::new();
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut mappings = Vec::new();
    let mut prior_index = 0;
    let mut current_index = 0;
    while prior_index < prior_manifest.entries.len()
        || current_index < current_manifest.entries.len()
    {
        match (prior_manifest.entries.get(prior_index), current_manifest.entries.get(current_index))
        {
            (Some(prior), Some(current)) => match prior.key.digest.cmp(&current.key.digest) {
                std::cmp::Ordering::Less => {
                    removed.push(PartitionRef::new(prior_manifest.id, prior.key.digest));
                    prior_index += 1;
                }
                std::cmp::Ordering::Greater => {
                    added.push(PartitionRef::new(current_manifest.id, current.key.digest));
                    current_index += 1;
                }
                std::cmp::Ordering::Equal => {
                    let mapping = PartitionKeyMapping {
                        prior: PartitionRef::new(prior_manifest.id, prior.key.digest),
                        current: PartitionRef::new(current_manifest.id, current.key.digest),
                    };
                    let prior_partition = prior_partitions
                        .get(&prior.key.digest)
                        .ok_or(TestTargetInventoryRefreshError::ManifestEntries)?;
                    let current_partition = current_partitions
                        .get(&current.key.digest)
                        .ok_or(TestTargetInventoryRefreshError::ManifestEntries)?;
                    if *prior_partition == *current_partition
                        && partition_is_delta_disjoint(
                            prior_partition,
                            &prior_locators,
                            input.state_delta,
                        )?
                    {
                        retained.push(mapping);
                    } else {
                        refreshed.push(mapping.current);
                    }
                    mappings.push(mapping);
                    prior_index += 1;
                    current_index += 1;
                }
            },
            (Some(prior), None) => {
                removed.push(PartitionRef::new(prior_manifest.id, prior.key.digest));
                prior_index += 1;
            }
            (None, Some(current)) => {
                added.push(PartitionRef::new(current_manifest.id, current.key.digest));
                current_index += 1;
            }
            (None, None) => break,
        }
    }

    if retained.is_empty() {
        return Ok(full_compute(TestTargetInventoryRefreshFallback::NoRetainedPartitions));
    }

    let transition = ManifestTransition::new(
        prior_manifest.id,
        current_manifest.id,
        input.state_delta.digest,
        mappings,
        ManifestProvenance::derived(
            DerivationRuleId::new(test_target_inventory_refresh_definition()),
            vec![prior_manifest.id, current_manifest.id],
        )?,
        definition.policy.manifest_validator.clone(),
    )?;
    let mut plan = TestTargetInventoryRefreshPlan {
        format_revision: TEST_TARGET_INVENTORY_REFRESH_FORMAT_REVISION,
        prior_manifest: prior_manifest.id,
        current_manifest: current_manifest.id,
        transition,
        state_delta: input.state_delta.digest,
        retained,
        refreshed,
        added,
        removed,
        definition_digest: Digest([0; 32]),
    };
    plan.definition_digest = plan.compute_definition_digest();
    plan.validate()?;

    let retained_current =
        plan.retained.iter().map(|mapping| mapping.current.key_digest).collect::<BTreeSet<_>>();
    let reconstructed_partitions = current_manifest
        .entries
        .iter()
        .map(|entry| {
            if retained_current.contains(&entry.key.digest) {
                prior_partitions.get(&entry.key.digest)
            } else {
                current_partitions.get(&entry.key.digest)
            }
            .copied()
            .cloned()
            .ok_or(TestTargetInventoryRefreshError::ManifestEntries)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let reconstructed = TestTargetInventory::new(
        input.current_inventory.repository_lineage,
        input.current_inventory.source_selector.clone(),
        input.current_inventory.scope.clone(),
        input.current_inventory.adapter_definition_digest,
        input.current_inventory.metadata_digest,
        input.current_inventory.package_universe.clone(),
        input.current_inventory.collection_dependencies.clone(),
        reconstructed_partitions,
    )
    .map_err(TestTargetInventoryRuntimeError::from)?;
    if reconstructed != *input.current_inventory
        || input.current_validation.inventory != reconstructed.content_digest
    {
        return Err(TestTargetInventoryRefreshError::Reconstruction);
    }

    Ok(TestTargetInventoryRefreshDecision::Refresh {
        result: Box::new(ShadowTestTargetInventoryRefresh {
            plan,
            fresh_oracle_digest: input.current_inventory.content_digest,
            reconstructed,
            validation_certificate: input.current_validation.clone(),
            authority: CapabilityMode::Shadow,
        }),
    })
}

/// Apply provider-neutral economic admission to an already validated Shadow
/// refresh decision. Any validity or economic rejection invokes the supplied
/// full-compute path exactly once. This function grants no reuse authority.
#[allow(clippy::too_many_arguments)]
pub fn resolve_test_target_inventory_refresh_or_full_compute<FullComputeResult, FullComputeError>(
    request: &ActionRequest,
    contract: &ActionContract,
    decision: TestTargetInventoryRefreshDecision,
    policy: &RefreshEconomicPolicy,
    evidence: Option<&RefreshCostEvidence>,
    execution_scope_digest: Digest,
    full_compute: impl FnOnce() -> Result<FullComputeResult, FullComputeError>,
) -> Result<
    ShadowRefreshResolution<Box<ShadowTestTargetInventoryRefresh>, FullComputeResult>,
    ShadowRefreshResolverError<FullComputeError>,
>
where
    FullComputeError: std::error::Error + Send + Sync + 'static,
{
    let candidate = match decision {
        TestTargetInventoryRefreshDecision::Refresh { result } => {
            result
                .validate()
                .map_err(|error| ShadowRefreshResolverError::Candidate(error.to_string()))?;
            ShadowRefreshCandidate::Ready {
                definition_digest: result.plan.definition_digest,
                result,
            }
        }
        TestTargetInventoryRefreshDecision::FullCompute { reason } => {
            ShadowRefreshCandidate::FullCompute { reason_digest: reason.evidence_digest() }
        }
    };
    resolve_shadow_refresh_or_full_compute(
        ShadowRefreshResolverInput {
            request,
            contract,
            operator_definition_digest: test_target_inventory_refresh_definition(),
            execution_scope_digest,
            policy,
            evidence,
        },
        candidate,
        full_compute,
    )
}

pub fn test_target_inventory_refresh_definition() -> Digest {
    static DIGEST: OnceLock<Digest> = OnceLock::new();
    *DIGEST.get_or_init(|| {
        let mut hasher = CanonicalHasher::new(b"test-target-inventory-refresh-definition-v1");
        hasher.field_u16(TEST_TARGET_INVENTORY_REFRESH_FORMAT_REVISION);
        hasher.field_digest(super::cargo_test_target_adapter_definition());
        hasher.field_digest(super::cargo_test_target_refresh_acquisition_definition());
        hasher.field_str("explicit-provider-stable-key-mappings");
        hasher.field_str("complete-adjacent-state-delta-required");
        hasher.field_str("input-definition-world-and-provider-delta-fallback");
        hasher.field_str("directory-locator-change-conservatively-invalidates");
        hasher.field_str("retained-partition-content-and-locator-equality");
        hasher.field_str("whole-result-equals-fresh-enumeration");
        hasher.finish()
    })
}

fn validate_refresh_input(
    input: &TestTargetInventoryRefreshInput<'_>,
) -> Result<(), TestTargetInventoryRefreshError> {
    input.prior_inventory.validate().map_err(TestTargetInventoryRuntimeError::from)?;
    input.current_inventory.validate().map_err(TestTargetInventoryRuntimeError::from)?;
    input.prior_validation.validate()?;
    input.current_validation.validate()?;
    input.prior_publication.validate()?;
    input.current_publication.validate()?;
    input.state_delta.validate()?;

    let prior_binding = &input.prior_publication.manifest.binding;
    let current_binding = &input.current_publication.manifest.binding;
    if input.prior_inventory.repository_lineage != input.current_inventory.repository_lineage
        || input.prior_inventory.source_selector != input.current_inventory.source_selector
        || input.prior_inventory.scope != input.current_inventory.scope
        || input.prior_inventory.adapter_definition_digest
            != input.current_inventory.adapter_definition_digest
        || input.state_delta.repository_lineage != input.current_inventory.repository_lineage
        || prior_binding.action_request != current_binding.action_request
        || prior_binding.action_contract != current_binding.action_contract
        || prior_binding.output_contract != current_binding.output_contract
        || prior_binding.semantic_input_set_digest != current_binding.semantic_input_set_digest
        || prior_binding.semantic_world_digest != current_binding.semantic_world_digest
        || prior_binding.repository != current_binding.repository
        || prior_binding.source_selector != current_binding.source_selector
        || prior_binding.definition_set_digest != current_binding.definition_set_digest
        || prior_binding.repository != input.prior_inventory.repository_lineage
        || prior_binding.source_selector != input.prior_inventory.source_selector
    {
        return Err(TestTargetInventoryRefreshError::Binding);
    }
    validate_source_certificate(
        input.prior_inventory,
        input.prior_validation,
        input.prior_publication,
    )?;
    validate_source_certificate(
        input.current_inventory,
        input.current_validation,
        input.current_publication,
    )?;
    Ok(())
}

fn validate_source_certificate(
    inventory: &TestTargetInventory,
    validation: &TestTargetInventoryValidationCertificate,
    publication: &ShadowPartitionManifestPublication,
) -> Result<(), TestTargetInventoryRefreshError> {
    if validation.inventory != inventory.content_digest
        || validation.adapter_definition_digest != inventory.adapter_definition_digest
        || validation.metadata_digest != inventory.metadata_digest
        || publication.certificate.source_payload_digest != inventory.content_digest
        || publication.certificate.source_validation_certificate_digest
            != validation.certificate_digest
    {
        return Err(TestTargetInventoryRefreshError::SourceCertificate);
    }
    Ok(())
}

fn bind_manifest_entries<'a>(
    inventory: &'a TestTargetInventory,
    validation: &TestTargetInventoryValidationCertificate,
    publication: &ShadowPartitionManifestPublication,
    scheme: &needle_core::PartitionScheme,
) -> Result<BTreeMap<Digest, &'a TestTargetPartition>, TestTargetInventoryRefreshError> {
    if publication.manifest.entries.len() != inventory.partitions.len() {
        return Err(TestTargetInventoryRefreshError::ManifestEntries);
    }
    let mut values = BTreeMap::new();
    for partition in &inventory.partitions {
        let key = OpaquePartitionKey::new(
            scheme,
            cargo_test_target_partition_opaque_key(&partition.key).bytes().to_vec(),
            None,
        )?;
        let entry = publication
            .manifest
            .entries
            .binary_search_by_key(&key.digest, |entry| entry.key.digest)
            .ok()
            .and_then(|index| publication.manifest.entries.get(index))
            .ok_or(TestTargetInventoryRefreshError::ManifestEntries)?;
        if entry.role != PartitionRole::Component
            || entry.payload_digest != partition.content_digest
            || entry.dependencies != validation.dependency_set_digest
            || values.insert(key.digest, partition).is_some()
        {
            return Err(TestTargetInventoryRefreshError::ManifestEntries);
        }
    }
    Ok(values)
}

fn locator_index(inventory: &TestTargetInventory) -> BTreeMap<Digest, &TestTargetLocator> {
    inventory.collection_dependencies.iter().map(|locator| (locator.id, locator)).collect()
}

fn partition_is_delta_disjoint(
    partition: &TestTargetPartition,
    locators: &BTreeMap<Digest, &TestTargetLocator>,
    delta: &StateDelta,
) -> Result<bool, TestTargetInventoryRefreshError> {
    for locator_id in &partition.locator_ids {
        let locator =
            locators.get(locator_id).ok_or(TestTargetInventoryRefreshError::ManifestEntries)?;
        match locator.kind {
            TestTargetLocatorKind::AdapterInput => {}
            TestTargetLocatorKind::DirectoryEntries
            | TestTargetLocatorKind::TargetDirectoryEntries => {
                if !delta.changed_locators.is_empty() {
                    return Ok(false);
                }
            }
            TestTargetLocatorKind::ManifestContent | TestTargetLocatorKind::FilePresence => {
                let dependency = DependencyLocator::repository_path(&locator.path)?;
                if delta.changed_locators.binary_search(&dependency).is_ok() {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

fn full_compute(reason: TestTargetInventoryRefreshFallback) -> TestTargetInventoryRefreshDecision {
    TestTargetInventoryRefreshDecision::FullCompute { reason }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn hash_mappings(hasher: &mut CanonicalHasher, mappings: &[PartitionKeyMapping]) {
    hasher.field_u32(mappings.len().try_into().unwrap_or(u32::MAX));
    for mapping in mappings {
        hash_ref(hasher, mapping.prior);
        hash_ref(hasher, mapping.current);
    }
}

fn hash_refs(hasher: &mut CanonicalHasher, partitions: &[PartitionRef]) {
    hasher.field_u32(partitions.len().try_into().unwrap_or(u32::MAX));
    for partition in partitions {
        hash_ref(hasher, *partition);
    }
}

fn hash_ref(hasher: &mut CanonicalHasher, partition: PartitionRef) {
    hasher.field_digest(partition.manifest.digest());
    hasher.field_digest(partition.key_digest);
}
