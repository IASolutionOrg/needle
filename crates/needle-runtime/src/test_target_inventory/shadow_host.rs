use super::shadow_execution::{checked_now, compute_fresh, publication_receipt};
use super::{
    CargoTestTargetInventoryInput, MAX_CARGO_VERSION_BYTES,
    ShadowCargoTestTargetRefreshExecutionInput, ShadowRefreshCostEstimate,
    ShadowTestTargetHeadExecutionContext, ShadowTestTargetPublicationReceipt,
    ShadowTestTargetRefreshExecution, TestTargetInventoryRuntimeError,
    TestTargetInventoryValidationCertificate, cargo_test_target_adapter_definition,
    execute_shadow_cargo_test_target_refresh,
};
use crate::{
    PartitionedActionArtifactError, PartitionedActionHeadKey, RuntimeStore, ShadowManifestContext,
    ShadowPartitionManifestError, ShadowPartitionedActionHeadAdvance, StoreError,
    active_definition_set, built_in_action_for_artifact_kind,
    certify_test_target_inventory_action_artifact, certify_test_target_inventory_shadow_manifest,
};
use needle_core::{
    ActionRequest, ArtifactKind, ArtifactRequest, CanonicalHasher, CapabilityMode, Digest,
    NeedFragmentId, NeedId, NeedKey, RefreshEconomicPolicy, RepositoryGeneration, SemanticWorld,
    StateDelta, TestTargetInventory, TestTargetInventoryScope,
};
use std::path::Path;
use thiserror::Error;

const TEST_TARGET_ACTION_ID: &str = "needle.tests.inventory";
const TEST_TARGET_REQUEST_TEXT: &str = "enumerate repository test targets";
const MAX_PLATFORM_BYTES: usize = 128;

#[derive(Clone)]
pub struct ShadowCargoTestTargetHostInput<'a> {
    pub repository_root: &'a Path,
    pub generation: &'a RepositoryGeneration,
    pub delta: Option<&'a StateDelta>,
    pub source_selector: &'a str,
    pub scope: TestTargetInventoryScope,
    pub metadata_json: &'a [u8],
    pub cargo_version: &'a str,
    pub platform: &'a str,
    pub economic_policy: &'a RefreshEconomicPolicy,
    pub cost_estimate: Option<ShadowRefreshCostEstimate>,
    pub execution_scope_digest: Digest,
    pub execution_attempts: &'a [Digest],
    pub started_unix_ms: u64,
    pub observed_refresh_cost_microusd: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShadowCargoTestTargetHostRebaseline {
    GenerationGap,
    MissingAdjacentDelta,
    DefinitionSetChanged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShadowCargoTestTargetHostExecution {
    BootstrapPublished {
        publication: ShadowTestTargetPublicationReceipt,
        repository_generation: u64,
    },
    PriorRemainsCurrent {
        publication: ShadowTestTargetPublicationReceipt,
        repository_generation: u64,
    },
    RefreshExecuted {
        execution: ShadowTestTargetRefreshExecution,
        from_repository_generation: u64,
        to_repository_generation: u64,
    },
    RebaselinePublished {
        publication: ShadowTestTargetPublicationReceipt,
        repository_generation: u64,
        trigger: ShadowCargoTestTargetHostRebaseline,
    },
}

impl ShadowCargoTestTargetHostExecution {
    pub const fn authority(&self) -> CapabilityMode {
        CapabilityMode::Shadow
    }
}

pub fn cargo_test_target_provider_context_digest(
    cargo_version: &str,
    platform: &str,
) -> Result<Digest, ShadowCargoTestTargetHostError> {
    if cargo_version.is_empty()
        || cargo_version.len() > MAX_CARGO_VERSION_BYTES
        || cargo_version.chars().any(char::is_control)
    {
        return Err(ShadowCargoTestTargetHostError::ProviderContext("cargo version"));
    }
    if platform.is_empty()
        || platform.len() > MAX_PLATFORM_BYTES
        || platform.chars().any(char::is_control)
    {
        return Err(ShadowCargoTestTargetHostError::ProviderContext("platform"));
    }
    let mut hasher = CanonicalHasher::new(b"cargo-test-target-provider-context-v1");
    hasher.field_digest(cargo_test_target_adapter_definition());
    hasher.field_str(cargo_version);
    hasher.field_str(platform);
    Ok(hasher.finish())
}

pub fn execute_shadow_cargo_test_target_host(
    store: &RuntimeStore,
    input: ShadowCargoTestTargetHostInput<'_>,
) -> Result<ShadowCargoTestTargetHostExecution, ShadowCargoTestTargetHostError> {
    input.generation.validate()?;
    let action = built_in_action_for_artifact_kind(&ArtifactKind::test_target_inventory())
        .ok_or(ShadowCargoTestTargetHostError::ActionMissing)?;
    if input.economic_policy.action_operational_policy_digest
        != action.contract.operational_policy_digest
    {
        return Err(ShadowCargoTestTargetHostError::PolicyBinding);
    }
    let provider_context =
        cargo_test_target_provider_context_digest(input.cargo_version, input.platform)?;
    let key = PartitionedActionHeadKey::new(
        action.contract.id.clone(),
        input.generation.repository_lineage,
        input.generation.repository_context,
        input.source_selector,
        provider_context,
        input.scope.digest(),
    )?;
    let request = request_for_head(&key)?;
    let world = world_for_input(&input);
    let definition_set_digest = active_definition_set().audit_digest;
    let current = CargoTestTargetInventoryInput {
        repository_root: input.repository_root,
        repository_lineage: input.generation.repository_lineage,
        source_selector: input.source_selector,
        scope: input.scope.clone(),
        metadata_json: input.metadata_json,
        cargo_version: input.cargo_version,
    };

    let Some(base) = store.partitioned_action_head_base(&key)? else {
        let publication = publish_baseline(
            store,
            BaselineInput {
                request: &request,
                world: &world,
                definition_set_digest,
                current,
                key,
                expected_prior_artifact: None,
                repository_generation: input.generation.generation,
                started_unix_ms: input.started_unix_ms,
            },
        )?;
        return Ok(ShadowCargoTestTargetHostExecution::BootstrapPublished {
            publication,
            repository_generation: input.generation.generation,
        });
    };

    if base.request != request || base.publication.certificate().coverage.world != world {
        return Err(ShadowCargoTestTargetHostError::HeadBinding);
    }
    let (prior_inventory, prior_validation) = decode_prior(&base)?;
    let prior_receipt =
        publication_receipt(&base.request, &base.manifest, &base.publication, &prior_inventory);
    if base.head.repository_generation == input.generation.generation {
        return Ok(ShadowCargoTestTargetHostExecution::PriorRemainsCurrent {
            publication: prior_receipt,
            repository_generation: input.generation.generation,
        });
    }
    if base.head.repository_generation > input.generation.generation {
        return Err(ShadowCargoTestTargetHostError::GenerationRegression {
            head: base.head.repository_generation,
            observed: input.generation.generation,
        });
    }

    let rebaseline = if base.manifest.manifest.binding.definition_set_digest
        != definition_set_digest
    {
        Some(ShadowCargoTestTargetHostRebaseline::DefinitionSetChanged)
    } else if base.head.repository_generation.checked_add(1) != Some(input.generation.generation) {
        Some(ShadowCargoTestTargetHostRebaseline::GenerationGap)
    } else if !delta_binds(input.delta, input.generation, base.head.repository_generation)? {
        Some(ShadowCargoTestTargetHostRebaseline::MissingAdjacentDelta)
    } else {
        None
    };
    if let Some(trigger) = rebaseline {
        let publication = publish_baseline(
            store,
            BaselineInput {
                request: &request,
                world: &world,
                definition_set_digest,
                current,
                key,
                expected_prior_artifact: Some(base.head.artifact),
                repository_generation: input.generation.generation,
                started_unix_ms: input.started_unix_ms,
            },
        )?;
        return Ok(ShadowCargoTestTargetHostExecution::RebaselinePublished {
            publication,
            repository_generation: input.generation.generation,
            trigger,
        });
    }

    let delta = input.delta.expect("adjacent delta binding checked above");
    let execution = execute_shadow_cargo_test_target_refresh(
        store,
        ShadowCargoTestTargetRefreshExecutionInput {
            request: &base.request,
            world: &world,
            definition_set_digest,
            prior_inventory: &prior_inventory,
            prior_validation: &prior_validation,
            prior_manifest: &base.manifest,
            prior_artifact: base.head.artifact,
            current,
            state_delta: delta,
            economic_policy: input.economic_policy,
            cost_estimate: input.cost_estimate,
            execution_scope_digest: input.execution_scope_digest,
            execution_attempts: input.execution_attempts,
            started_unix_ms: input.started_unix_ms,
            observed_refresh_cost_microusd: input.observed_refresh_cost_microusd,
            head: Some(ShadowTestTargetHeadExecutionContext {
                key: &key,
                expected_prior_artifact: base.head.artifact,
                repository_generation: input.generation.generation,
            }),
        },
    )?;
    Ok(ShadowCargoTestTargetHostExecution::RefreshExecuted {
        execution,
        from_repository_generation: base.head.repository_generation,
        to_repository_generation: input.generation.generation,
    })
}

struct BaselineInput<'a> {
    request: &'a ActionRequest,
    world: &'a SemanticWorld,
    definition_set_digest: Digest,
    current: CargoTestTargetInventoryInput<'a>,
    key: PartitionedActionHeadKey,
    expected_prior_artifact: Option<needle_core::ArtifactId>,
    repository_generation: u64,
    started_unix_ms: u64,
}

fn publish_baseline(
    store: &RuntimeStore,
    input: BaselineInput<'_>,
) -> Result<ShadowTestTargetPublicationReceipt, ShadowCargoTestTargetHostError> {
    let fresh = compute_fresh(input.current)?;
    let issued_unix_ms = checked_now(input.started_unix_ms)?;
    let manifest = certify_test_target_inventory_shadow_manifest(
        ShadowManifestContext {
            request: input.request,
            world: input.world,
            definition_set_digest: input.definition_set_digest,
        },
        &fresh.inventory,
        &fresh.validation,
        issued_unix_ms,
    )?;
    store.publish_shadow_partition_manifest(&manifest)?;
    let publication = certify_test_target_inventory_action_artifact(
        input.request,
        &fresh.inventory,
        &fresh.validation,
        input.world,
        &manifest,
        issued_unix_ms,
    )?;
    let validation_json = serde_json::to_vec(&fresh.validation)?;
    store.publish_shadow_partitioned_action_artifact_and_advance_head(
        input.request,
        &manifest,
        &publication,
        ShadowPartitionedActionHeadAdvance {
            key: input.key,
            expected_prior_artifact: input.expected_prior_artifact,
            repository_generation: input.repository_generation,
            source_validation_certificate_digest: fresh.validation.certificate_digest,
            source_validation_validator_definition_digest: fresh
                .validation
                .validator_definition_digest,
            source_validation_json: &validation_json,
            content_digest: fresh.inventory.content_digest,
        },
    )?;
    Ok(publication_receipt(input.request, &manifest, &publication, &fresh.inventory))
}

fn request_for_head(
    key: &PartitionedActionHeadKey,
) -> Result<ActionRequest, ShadowCargoTestTargetHostError> {
    let action = built_in_action_for_artifact_kind(&ArtifactKind::test_target_inventory())
        .ok_or(ShadowCargoTestTargetHostError::ActionMissing)?;
    let route = NeedKey::new(TEST_TARGET_ACTION_ID)
        .map_err(|error| ShadowCargoTestTargetHostError::Request(error.to_string()))?;
    let mut hasher = CanonicalHasher::new(b"test-target-inventory-host-request-v1");
    hasher.field_digest(key.id);
    let fragment = NeedFragmentId::new(hasher.finish());
    ActionRequest::new(
        &action.contract,
        ArtifactRequest {
            contract_id: action.output_contract_id.to_owned(),
            contract_revision: action.output_contract_revision,
            repository_id: key.repository_lineage,
            source_snapshot_digest: key.id,
            route_key: route.clone(),
            normalized_request: TEST_TARGET_REQUEST_TEXT.to_owned(),
            semantic_fragment_id: Some(fragment),
            input_artifact_ids: Vec::new(),
        },
        action.contract.default_dispatch_policy,
        route,
        NeedId::new(fragment.digest()),
    )
    .map_err(|error| ShadowCargoTestTargetHostError::Request(error.to_string()))
}

fn world_for_input(input: &ShadowCargoTestTargetHostInput<'_>) -> SemanticWorld {
    SemanticWorld {
        repository_lineage: input.generation.repository_lineage,
        source_selector: input.source_selector.to_owned(),
        platform: input.platform.to_owned(),
        features: "default".to_owned(),
        configuration: None,
        toolchain: Some(Digest::blake3(input.cargo_version.as_bytes())),
    }
}

fn delta_binds(
    delta: Option<&StateDelta>,
    generation: &RepositoryGeneration,
    from_generation: u64,
) -> Result<bool, ShadowCargoTestTargetHostError> {
    let Some(delta) = delta else { return Ok(false) };
    delta.validate()?;
    Ok(delta.repository_lineage == generation.repository_lineage
        && delta.repository_context == generation.repository_context
        && delta.from_generation == from_generation
        && delta.to_generation == generation.generation)
}

fn decode_prior(
    base: &crate::ShadowPartitionedActionHeadBase,
) -> Result<
    (TestTargetInventory, TestTargetInventoryValidationCertificate),
    ShadowCargoTestTargetHostError,
> {
    let inventory_json = serde_json::to_vec(&base.publication.artifact().payload)?;
    let inventory = TestTargetInventory::decode_json(&inventory_json)?;
    let validation: TestTargetInventoryValidationCertificate =
        serde_json::from_slice(&base.source_validation_json)?;
    validation.validate()?;
    if inventory.content_digest != base.head.content_digest
        || validation.inventory != inventory.content_digest
        || validation.certificate_digest != base.head.source_validation_certificate_digest
        || inventory.repository_lineage != base.head.key.repository_lineage
        || inventory.source_selector != base.head.key.source_selector
        || inventory.scope.digest() != base.head.key.scope_digest
    {
        return Err(ShadowCargoTestTargetHostError::PriorBinding);
    }
    Ok((inventory, validation))
}

#[derive(Debug, Error)]
pub enum ShadowCargoTestTargetHostError {
    #[error("the built-in test-target inventory action is missing")]
    ActionMissing,
    #[error("the provider context is invalid: {0}")]
    ProviderContext(&'static str),
    #[error("the action request is invalid: {0}")]
    Request(String),
    #[error("the refresh economic policy does not bind the action operational policy")]
    PolicyBinding,
    #[error("the persisted partitioned head does not bind the canonical host request and world")]
    HeadBinding,
    #[error("the persisted prior inventory does not bind the partitioned head")]
    PriorBinding,
    #[error("the persisted head generation {head} is newer than observed generation {observed}")]
    GenerationRegression { head: u64, observed: u64 },
    #[error(transparent)]
    Generation(#[from] needle_core::RepositoryGenerationError),
    #[error(transparent)]
    Inventory(#[from] TestTargetInventoryRuntimeError),
    #[error(transparent)]
    InventoryRecord(#[from] needle_core::TestTargetInventoryError),
    #[error(transparent)]
    Manifest(#[from] ShadowPartitionManifestError),
    #[error(transparent)]
    Artifact(#[from] PartitionedActionArtifactError),
    #[error(transparent)]
    Execution(#[from] super::ShadowTestTargetRefreshExecutionError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
