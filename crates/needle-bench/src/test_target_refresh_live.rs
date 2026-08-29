use needle_core::{
    ActionRequest, ArtifactRequest, CanonicalHasher, CapabilityMode, DependencyLocator, Digest,
    MAX_REFRESH_ECONOMIC_COST_MICROUSD, NeedFragmentId, NeedId, NeedKey, RepositoryContextId,
    SemanticWorld, StateDelta, TestTargetInventory, TestTargetInventoryScope,
};
use needle_runtime::{
    CargoTestTargetInventoryInput, CargoTestTargetRefreshAcquisition, CargoTestTargetRefreshInput,
    ShadowManifestContext, TestTargetInventoryRefreshDecision, TestTargetInventoryRefreshInput,
    TestTargetInventoryValidationCertificate, acquire_cargo_test_target_refresh_candidate,
    active_definition_set, built_in_action_contracts, cargo_test_target_partition_opaque_key,
    certify_test_target_inventory_shadow_manifest, enumerate_cargo_test_targets,
    evaluate_test_target_inventory_refresh, validate_cargo_test_target_inventory,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::path::Path;
use std::time::Instant;
use thiserror::Error;

mod acceptance;
mod capability_decision;

pub use acceptance::*;
pub use capability_decision::*;

pub const LIVE_TEST_TARGET_REFRESH_FORMAT_REVISION: u16 = 1;
pub const LIVE_TEST_TARGET_REFRESH_REPORT_SCHEMA: &str =
    "needle.test-target-refresh-live-calibration/1";
pub const MAX_LIVE_TEST_TARGET_REFRESH_REPORT_BYTES: usize = 128 * 1024;
pub const MAX_LIVE_TEST_TARGET_REFRESH_SAMPLES: usize = 100;
pub const MIN_LIVE_TEST_TARGET_REFRESH_SAMPLES: usize = 5;
pub const MAX_LIVE_TEST_TARGET_REFRESH_CHANGED_PATHS: usize = 256;
pub const MAX_LIVE_TEST_TARGET_REFRESH_SOURCE_BYTES: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveRefreshCostProvenanceInput {
    pub observed_fresh_microusd: u64,
    pub observed_refresh_microusd: u64,
    pub pricing_revision: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveRefreshCostProvenance {
    pub observed_fresh_microusd: u64,
    pub observed_refresh_microusd: u64,
    pub pricing_revision: Digest,
    pub evidence_digest: Digest,
    pub positive_monetary_value: bool,
}

impl LiveRefreshCostProvenance {
    fn new(input: LiveRefreshCostProvenanceInput) -> Result<Self, LiveRefreshCalibrationError> {
        let value = Self {
            observed_fresh_microusd: input.observed_fresh_microusd,
            observed_refresh_microusd: input.observed_refresh_microusd,
            pricing_revision: input.pricing_revision,
            evidence_digest: input.evidence_digest,
            positive_monetary_value: input.observed_refresh_microusd
                < input.observed_fresh_microusd,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), LiveRefreshCalibrationError> {
        if self.pricing_revision == Digest([0; 32])
            || self.evidence_digest == Digest([0; 32])
            || self.observed_fresh_microusd > MAX_REFRESH_ECONOMIC_COST_MICROUSD
            || self.observed_refresh_microusd > MAX_REFRESH_ECONOMIC_COST_MICROUSD
            || self.positive_monetary_value
                != (self.observed_refresh_microusd < self.observed_fresh_microusd)
        {
            return Err(LiveRefreshCalibrationError::CostProvenance);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct LiveTestTargetRefreshCalibrationInput<'a> {
    pub prior_repository_root: &'a Path,
    pub current_repository_root: &'a Path,
    pub source_repository: &'a str,
    pub source_sha: &'a str,
    pub changed_paths: Vec<String>,
    pub samples: usize,
    pub p95_budget_micros: u64,
    pub provider_timeout_seconds: u64,
    pub platform: &'a str,
    pub cost_provenance: Option<LiveRefreshCostProvenanceInput>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveRefreshMutationObservation {
    pub definition_digest: Digest,
    pub prior_content_digest: Digest,
    pub current_content_digest: Digest,
}

impl LiveRefreshMutationObservation {
    fn validate(self) -> Result<(), LiveRefreshCalibrationError> {
        if self.definition_digest == Digest([0; 32])
            || self.prior_content_digest == Digest([0; 32])
            || self.current_content_digest == Digest([0; 32])
            || self.prior_content_digest == self.current_content_digest
        {
            return Err(LiveRefreshCalibrationError::Mutation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveCargoSnapshot {
    pub metadata_json: Vec<u8>,
    pub cargo_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveTestTargetRefreshCalibrationReport {
    pub format_revision: u16,
    pub schema: String,
    pub authority: CapabilityMode,
    pub source_repository: String,
    pub source_sha: String,
    pub repository_identity_digest: Digest,
    pub cargo_version: String,
    pub platform: String,
    pub changed_paths: Vec<String>,
    pub mutation_definition_digest: Digest,
    pub prior_source_digest: Digest,
    pub current_source_digest: Digest,
    pub provider_timeout_seconds: u64,
    pub provider_process_transport_included: bool,
    pub full_current_oracle_outside_refresh_timing: bool,
    pub arm_order_alternated: bool,
    pub fresh_samples_micros: Vec<u64>,
    pub refresh_samples_micros: Vec<u64>,
    pub fresh_p95_micros: u64,
    pub refresh_p95_micros: u64,
    pub p95_budget_micros: u64,
    pub positive_latency_value: bool,
    pub bounded_refresh_p95: bool,
    pub exact_oracle_agreement: bool,
    pub stale_retained_partitions: usize,
    pub acquisition_retained_partitions: usize,
    pub retained_partitions: usize,
    pub recomputed_partitions: usize,
    pub refreshed_partitions: usize,
    pub added_partitions: usize,
    pub removed_partitions: usize,
    pub cost_provenance: Option<LiveRefreshCostProvenance>,
    pub gate_a4_observation_eligible: bool,
    pub gate_a4_closed: bool,
    pub report_digest: Digest,
}

impl LiveTestTargetRefreshCalibrationReport {
    pub fn decode_json(bytes: &[u8]) -> Result<Self, LiveRefreshCalibrationError> {
        if bytes.len() > MAX_LIVE_TEST_TARGET_REFRESH_REPORT_BYTES {
            return Err(LiveRefreshCalibrationError::ReportBound {
                actual: bytes.len(),
                maximum: MAX_LIVE_TEST_TARGET_REFRESH_REPORT_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| LiveRefreshCalibrationError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), LiveRefreshCalibrationError> {
        self.validate_shape()?;
        if self.report_digest != self.compute_digest() {
            return Err(LiveRefreshCalibrationError::ReportDigest);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), LiveRefreshCalibrationError> {
        if self.format_revision != LIVE_TEST_TARGET_REFRESH_FORMAT_REVISION
            || self.schema != LIVE_TEST_TARGET_REFRESH_REPORT_SCHEMA
            || self.authority != CapabilityMode::Shadow
            || self.source_repository.is_empty()
            || self.source_repository.len() > MAX_LIVE_TEST_TARGET_REFRESH_SOURCE_BYTES
            || self.source_repository.chars().any(char::is_control)
            || !valid_git_sha(&self.source_sha)
            || self.cargo_version.is_empty()
            || self.cargo_version.len() > needle_runtime::MAX_CARGO_VERSION_BYTES
            || self.cargo_version.chars().any(char::is_control)
            || self.platform.is_empty()
            || self.platform.len() > 64
            || self.platform.chars().any(char::is_control)
            || self.changed_paths.is_empty()
            || self.changed_paths.len() > MAX_LIVE_TEST_TARGET_REFRESH_CHANGED_PATHS
            || !strictly_sorted(&self.changed_paths)
            || self
                .changed_paths
                .iter()
                .any(|path| DependencyLocator::repository_path(path).is_err())
            || self.mutation_definition_digest == Digest([0; 32])
            || self.prior_source_digest == Digest([0; 32])
            || self.current_source_digest == Digest([0; 32])
            || self.prior_source_digest == self.current_source_digest
            || !(MIN_LIVE_TEST_TARGET_REFRESH_SAMPLES..=MAX_LIVE_TEST_TARGET_REFRESH_SAMPLES)
                .contains(&self.fresh_samples_micros.len())
            || self.fresh_samples_micros.len() != self.refresh_samples_micros.len()
            || self.fresh_samples_micros.contains(&0)
            || self.refresh_samples_micros.contains(&0)
            || self.p95_budget_micros == 0
            || self.provider_timeout_seconds == 0
            || !self.provider_process_transport_included
            || !self.full_current_oracle_outside_refresh_timing
            || !self.arm_order_alternated
            || !self.exact_oracle_agreement
            || self.stale_retained_partitions != 0
            || self.retained_partitions == 0
            || self.fresh_p95_micros != percentile(&self.fresh_samples_micros, 95)
            || self.refresh_p95_micros != percentile(&self.refresh_samples_micros, 95)
            || self.positive_latency_value != (self.refresh_p95_micros < self.fresh_p95_micros)
            || self.bounded_refresh_p95 != (self.refresh_p95_micros <= self.p95_budget_micros)
            || self.gate_a4_closed
        {
            return Err(LiveRefreshCalibrationError::ReportShape);
        }
        if self.repository_identity_digest
            != repository_identity_digest(&self.source_repository, &self.source_sha)
        {
            return Err(LiveRefreshCalibrationError::RepositoryIdentity);
        }
        if let Some(cost) = &self.cost_provenance {
            cost.validate()?;
        }
        let eligible = self.positive_latency_value
            && self.bounded_refresh_p95
            && self.exact_oracle_agreement
            && self.stale_retained_partitions == 0
            && self.cost_provenance.as_ref().is_none_or(|cost| cost.positive_monetary_value);
        if self.gate_a4_observation_eligible != eligible {
            return Err(LiveRefreshCalibrationError::Eligibility);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"test-target-refresh-live-calibration-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_u8(0);
        hasher.field_str(&self.source_repository);
        hasher.field_str(&self.source_sha);
        hasher.field_digest(self.repository_identity_digest);
        hasher.field_str(&self.cargo_version);
        hasher.field_str(&self.platform);
        hash_strings(&mut hasher, &self.changed_paths);
        hasher.field_digest(self.mutation_definition_digest);
        hasher.field_digest(self.prior_source_digest);
        hasher.field_digest(self.current_source_digest);
        hash_u64(&mut hasher, self.provider_timeout_seconds);
        hash_bool(&mut hasher, self.provider_process_transport_included);
        hash_bool(&mut hasher, self.full_current_oracle_outside_refresh_timing);
        hash_bool(&mut hasher, self.arm_order_alternated);
        hash_u64s(&mut hasher, &self.fresh_samples_micros);
        hash_u64s(&mut hasher, &self.refresh_samples_micros);
        hash_u64(&mut hasher, self.fresh_p95_micros);
        hash_u64(&mut hasher, self.refresh_p95_micros);
        hash_u64(&mut hasher, self.p95_budget_micros);
        hash_bool(&mut hasher, self.positive_latency_value);
        hash_bool(&mut hasher, self.bounded_refresh_p95);
        hash_bool(&mut hasher, self.exact_oracle_agreement);
        hash_usize(&mut hasher, self.stale_retained_partitions);
        hash_usize(&mut hasher, self.acquisition_retained_partitions);
        hash_usize(&mut hasher, self.retained_partitions);
        hash_usize(&mut hasher, self.recomputed_partitions);
        hash_usize(&mut hasher, self.refreshed_partitions);
        hash_usize(&mut hasher, self.added_partitions);
        hash_usize(&mut hasher, self.removed_partitions);
        match &self.cost_provenance {
            Some(cost) => {
                hasher.field_u8(1);
                hash_u64(&mut hasher, cost.observed_fresh_microusd);
                hash_u64(&mut hasher, cost.observed_refresh_microusd);
                hasher.field_digest(cost.pricing_revision);
                hasher.field_digest(cost.evidence_digest);
                hash_bool(&mut hasher, cost.positive_monetary_value);
            }
            None => hasher.field_u8(0),
        }
        hash_bool(&mut hasher, self.gate_a4_observation_eligible);
        hash_bool(&mut hasher, self.gate_a4_closed);
        hasher.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RefreshShape {
    acquisition_retained_partitions: usize,
    retained_partitions: usize,
    recomputed_partitions: usize,
    refreshed_partitions: usize,
    added_partitions: usize,
    removed_partitions: usize,
    stale_retained_partitions: usize,
}

pub fn evaluate_live_test_target_refresh_calibration<F, E, A, AE>(
    mut input: LiveTestTargetRefreshCalibrationInput<'_>,
    mut acquire_snapshot: F,
    activate_current: A,
) -> Result<LiveTestTargetRefreshCalibrationReport, LiveRefreshCalibrationError>
where
    F: FnMut(&Path) -> Result<LiveCargoSnapshot, E>,
    E: std::fmt::Display,
    A: FnOnce() -> Result<LiveRefreshMutationObservation, AE>,
    AE: std::fmt::Display,
{
    validate_input(&input)?;
    input.changed_paths.sort_unstable();
    if !strictly_sorted(&input.changed_paths) {
        return Err(LiveRefreshCalibrationError::ChangedPaths);
    }
    let repository = repository_identity_digest(input.source_repository, input.source_sha);
    let source = "paired-live-shadow";
    let scope = TestTargetInventoryScope::all();
    let prior_snapshot = acquire_snapshot(input.prior_repository_root)
        .map_err(|error| LiveRefreshCalibrationError::Provider(error.to_string()))?;
    let prior_input = cargo_input(
        input.prior_repository_root,
        repository,
        source,
        scope.clone(),
        &prior_snapshot,
    );
    let prior = enumerate_cargo_test_targets(prior_input.clone()).map_err(runtime)?;
    let prior_validation =
        validate_cargo_test_target_inventory(prior_input, &prior).map_err(runtime)?;
    let request = action_request(repository, input.source_sha)?;
    let world = SemanticWorld {
        repository_lineage: repository,
        source_selector: source.to_owned(),
        platform: input.platform.to_owned(),
        features: "default".to_owned(),
        configuration: None,
        toolchain: Some(Digest::blake3(prior_snapshot.cargo_version.as_bytes())),
    };
    let context = ShadowManifestContext {
        request: &request,
        world: &world,
        definition_set_digest: active_definition_set().audit_digest,
    };
    let prior_publication =
        certify_test_target_inventory_shadow_manifest(context, &prior, &prior_validation, 1)
            .map_err(runtime)?;
    let changed_locators = input
        .changed_paths
        .iter()
        .map(|path| DependencyLocator::repository_path(path))
        .collect::<Result<Vec<_>, _>>()
        .map_err(runtime)?;
    let delta = StateDelta::new(
        repository,
        RepositoryContextId::new(Digest::blake3(b"paired-live-shadow-worktree")),
        1,
        2,
        changed_locators,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        true,
    )
    .map_err(runtime)?;

    let mutation = activate_current()
        .map_err(|error| LiveRefreshCalibrationError::MutationActivation(error.to_string()))?;
    mutation.validate()?;

    let oracle_snapshot = acquire_snapshot(input.current_repository_root)
        .map_err(|error| LiveRefreshCalibrationError::Provider(error.to_string()))?;
    ensure_toolchain(&prior_snapshot, &oracle_snapshot)?;
    let oracle_input = cargo_input(
        input.current_repository_root,
        repository,
        source,
        scope.clone(),
        &oracle_snapshot,
    );
    let oracle = enumerate_cargo_test_targets(oracle_input.clone()).map_err(runtime)?;
    let oracle_validation =
        validate_cargo_test_target_inventory(oracle_input, &oracle).map_err(runtime)?;
    let oracle_publication =
        certify_test_target_inventory_shadow_manifest(context, &oracle, &oracle_validation, 2)
            .map_err(runtime)?;

    let warmup_shape = refresh_once(
        input.current_repository_root,
        repository,
        source,
        scope.clone(),
        &oracle_snapshot,
        &prior,
        &prior_validation,
        &prior_publication,
        &oracle,
        &oracle_validation,
        &oracle_publication,
        context,
        &delta,
    )?;
    let mut fresh_samples = Vec::with_capacity(input.samples);
    let mut refresh_samples = Vec::with_capacity(input.samples);
    for sample in 0..input.samples {
        if sample % 2 == 0 {
            fresh_samples.push(measure_fresh(
                input.current_repository_root,
                repository,
                source,
                scope.clone(),
                &prior_snapshot,
                &oracle,
                &oracle_validation,
                &oracle_publication,
                context,
                &mut acquire_snapshot,
            )?);
            let (elapsed, shape) = measure_refresh(
                input.current_repository_root,
                repository,
                source,
                scope.clone(),
                &prior_snapshot,
                &prior,
                &prior_validation,
                &prior_publication,
                &oracle,
                &oracle_validation,
                &oracle_publication,
                context,
                &delta,
                &mut acquire_snapshot,
            )?;
            ensure_shape(warmup_shape, shape)?;
            refresh_samples.push(elapsed);
        } else {
            let (elapsed, shape) = measure_refresh(
                input.current_repository_root,
                repository,
                source,
                scope.clone(),
                &prior_snapshot,
                &prior,
                &prior_validation,
                &prior_publication,
                &oracle,
                &oracle_validation,
                &oracle_publication,
                context,
                &delta,
                &mut acquire_snapshot,
            )?;
            ensure_shape(warmup_shape, shape)?;
            refresh_samples.push(elapsed);
            fresh_samples.push(measure_fresh(
                input.current_repository_root,
                repository,
                source,
                scope.clone(),
                &prior_snapshot,
                &oracle,
                &oracle_validation,
                &oracle_publication,
                context,
                &mut acquire_snapshot,
            )?);
        }
    }
    let fresh_p95 = percentile(&fresh_samples, 95);
    let refresh_p95 = percentile(&refresh_samples, 95);
    let cost_provenance = input.cost_provenance.map(LiveRefreshCostProvenance::new).transpose()?;
    let eligible = refresh_p95 < fresh_p95
        && refresh_p95 <= input.p95_budget_micros
        && warmup_shape.stale_retained_partitions == 0
        && cost_provenance.as_ref().is_none_or(|cost| cost.positive_monetary_value);
    let mut report = LiveTestTargetRefreshCalibrationReport {
        format_revision: LIVE_TEST_TARGET_REFRESH_FORMAT_REVISION,
        schema: LIVE_TEST_TARGET_REFRESH_REPORT_SCHEMA.to_owned(),
        authority: CapabilityMode::Shadow,
        source_repository: input.source_repository.to_owned(),
        source_sha: input.source_sha.to_owned(),
        repository_identity_digest: repository,
        cargo_version: prior_snapshot.cargo_version,
        platform: input.platform.to_owned(),
        changed_paths: input.changed_paths,
        mutation_definition_digest: mutation.definition_digest,
        prior_source_digest: mutation.prior_content_digest,
        current_source_digest: mutation.current_content_digest,
        provider_timeout_seconds: input.provider_timeout_seconds,
        provider_process_transport_included: true,
        full_current_oracle_outside_refresh_timing: true,
        arm_order_alternated: true,
        fresh_samples_micros: fresh_samples,
        refresh_samples_micros: refresh_samples,
        fresh_p95_micros: fresh_p95,
        refresh_p95_micros: refresh_p95,
        p95_budget_micros: input.p95_budget_micros,
        positive_latency_value: refresh_p95 < fresh_p95,
        bounded_refresh_p95: refresh_p95 <= input.p95_budget_micros,
        exact_oracle_agreement: true,
        stale_retained_partitions: warmup_shape.stale_retained_partitions,
        acquisition_retained_partitions: warmup_shape.acquisition_retained_partitions,
        retained_partitions: warmup_shape.retained_partitions,
        recomputed_partitions: warmup_shape.recomputed_partitions,
        refreshed_partitions: warmup_shape.refreshed_partitions,
        added_partitions: warmup_shape.added_partitions,
        removed_partitions: warmup_shape.removed_partitions,
        cost_provenance,
        gate_a4_observation_eligible: eligible,
        gate_a4_closed: false,
        report_digest: Digest([0; 32]),
    };
    report.validate_shape()?;
    report.report_digest = report.compute_digest();
    report.validate()?;
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn measure_fresh<F, E>(
    root: &Path,
    repository: Digest,
    source: &str,
    scope: TestTargetInventoryScope,
    expected_toolchain: &LiveCargoSnapshot,
    oracle: &TestTargetInventory,
    oracle_validation: &TestTargetInventoryValidationCertificate,
    oracle_publication: &needle_runtime::ShadowPartitionManifestPublication,
    context: ShadowManifestContext<'_>,
    acquire_snapshot: &mut F,
) -> Result<u64, LiveRefreshCalibrationError>
where
    F: FnMut(&Path) -> Result<LiveCargoSnapshot, E>,
    E: std::fmt::Display,
{
    let started = Instant::now();
    let snapshot = acquire_snapshot(root)
        .map_err(|error| LiveRefreshCalibrationError::Provider(error.to_string()))?;
    ensure_toolchain(expected_toolchain, &snapshot)?;
    let current = cargo_input(root, repository, source, scope, &snapshot);
    let inventory = enumerate_cargo_test_targets(current.clone()).map_err(runtime)?;
    let validation = validate_cargo_test_target_inventory(current, &inventory).map_err(runtime)?;
    let publication =
        certify_test_target_inventory_shadow_manifest(context, &inventory, &validation, 2)
            .map_err(runtime)?;
    if &inventory != oracle
        || &validation != oracle_validation
        || &publication != oracle_publication
    {
        return Err(LiveRefreshCalibrationError::OracleAgreement);
    }
    black_box((inventory, validation, publication));
    elapsed_micros(started)
}

#[allow(clippy::too_many_arguments)]
fn measure_refresh<F, E>(
    root: &Path,
    repository: Digest,
    source: &str,
    scope: TestTargetInventoryScope,
    expected_toolchain: &LiveCargoSnapshot,
    prior: &TestTargetInventory,
    prior_validation: &TestTargetInventoryValidationCertificate,
    prior_publication: &needle_runtime::ShadowPartitionManifestPublication,
    oracle: &TestTargetInventory,
    oracle_validation: &TestTargetInventoryValidationCertificate,
    oracle_publication: &needle_runtime::ShadowPartitionManifestPublication,
    context: ShadowManifestContext<'_>,
    delta: &StateDelta,
    acquire_snapshot: &mut F,
) -> Result<(u64, RefreshShape), LiveRefreshCalibrationError>
where
    F: FnMut(&Path) -> Result<LiveCargoSnapshot, E>,
    E: std::fmt::Display,
{
    let started = Instant::now();
    let snapshot = acquire_snapshot(root)
        .map_err(|error| LiveRefreshCalibrationError::Provider(error.to_string()))?;
    ensure_toolchain(expected_toolchain, &snapshot)?;
    let shape = refresh_once(
        root,
        repository,
        source,
        scope,
        &snapshot,
        prior,
        prior_validation,
        prior_publication,
        oracle,
        oracle_validation,
        oracle_publication,
        context,
        delta,
    )?;
    Ok((elapsed_micros(started)?, shape))
}

#[allow(clippy::too_many_arguments)]
fn refresh_once(
    root: &Path,
    repository: Digest,
    source: &str,
    scope: TestTargetInventoryScope,
    snapshot: &LiveCargoSnapshot,
    prior: &TestTargetInventory,
    prior_validation: &TestTargetInventoryValidationCertificate,
    prior_publication: &needle_runtime::ShadowPartitionManifestPublication,
    oracle: &TestTargetInventory,
    oracle_validation: &TestTargetInventoryValidationCertificate,
    oracle_publication: &needle_runtime::ShadowPartitionManifestPublication,
    context: ShadowManifestContext<'_>,
    delta: &StateDelta,
) -> Result<RefreshShape, LiveRefreshCalibrationError> {
    let acquisition = acquire_cargo_test_target_refresh_candidate(CargoTestTargetRefreshInput {
        current: cargo_input(root, repository, source, scope, snapshot),
        prior_inventory: prior,
        prior_validation,
        state_delta: delta,
    })
    .map_err(runtime)?;
    let CargoTestTargetRefreshAcquisition::Candidate { result: candidate } = acquisition else {
        return Err(LiveRefreshCalibrationError::UnexpectedFullCompute);
    };
    if &candidate.inventory != oracle || &candidate.validation_certificate != oracle_validation {
        return Err(LiveRefreshCalibrationError::OracleAgreement);
    }
    let current_publication = certify_test_target_inventory_shadow_manifest(
        context,
        &candidate.inventory,
        &candidate.validation_certificate,
        2,
    )
    .map_err(runtime)?;
    if &current_publication != oracle_publication {
        return Err(LiveRefreshCalibrationError::OracleAgreement);
    }
    let decision = evaluate_test_target_inventory_refresh(TestTargetInventoryRefreshInput {
        prior_inventory: prior,
        prior_validation,
        prior_publication,
        current_inventory: &candidate.inventory,
        current_validation: &candidate.validation_certificate,
        current_publication: &current_publication,
        state_delta: delta,
    })
    .map_err(runtime)?;
    let TestTargetInventoryRefreshDecision::Refresh { result } = decision else {
        return Err(LiveRefreshCalibrationError::UnexpectedFullCompute);
    };
    if &result.reconstructed != oracle || &result.validation_certificate != oracle_validation {
        return Err(LiveRefreshCalibrationError::OracleAgreement);
    }
    let shape = RefreshShape {
        acquisition_retained_partitions: candidate.retained_partitions,
        retained_partitions: result.plan.retained.len(),
        recomputed_partitions: candidate.recomputed_partitions,
        refreshed_partitions: result.plan.refreshed.len(),
        added_partitions: result.plan.added.len(),
        removed_partitions: result.plan.removed.len(),
        stale_retained_partitions: stale_retained_count(prior, oracle, &result.plan.retained),
    };
    black_box((candidate, result));
    Ok(shape)
}

fn validate_input(
    input: &LiveTestTargetRefreshCalibrationInput<'_>,
) -> Result<(), LiveRefreshCalibrationError> {
    if input.source_repository.is_empty()
        || input.source_repository.len() > MAX_LIVE_TEST_TARGET_REFRESH_SOURCE_BYTES
        || input.source_repository.chars().any(char::is_control)
        || !valid_git_sha(input.source_sha)
        || input.changed_paths.is_empty()
        || input.changed_paths.len() > MAX_LIVE_TEST_TARGET_REFRESH_CHANGED_PATHS
        || !(MIN_LIVE_TEST_TARGET_REFRESH_SAMPLES..=MAX_LIVE_TEST_TARGET_REFRESH_SAMPLES)
            .contains(&input.samples)
        || input.p95_budget_micros == 0
        || input.provider_timeout_seconds == 0
        || input.platform.is_empty()
        || input.platform.len() > 64
    {
        return Err(LiveRefreshCalibrationError::Input);
    }
    for path in &input.changed_paths {
        DependencyLocator::repository_path(path).map_err(runtime)?;
    }
    Ok(())
}

fn cargo_input<'a>(
    root: &'a Path,
    repository: Digest,
    source: &'a str,
    scope: TestTargetInventoryScope,
    snapshot: &'a LiveCargoSnapshot,
) -> CargoTestTargetInventoryInput<'a> {
    CargoTestTargetInventoryInput {
        repository_root: root,
        repository_lineage: repository,
        source_selector: source,
        scope,
        metadata_json: &snapshot.metadata_json,
        cargo_version: &snapshot.cargo_version,
    }
}

fn action_request(
    repository: Digest,
    source_sha: &str,
) -> Result<ActionRequest, LiveRefreshCalibrationError> {
    let definition = built_in_action_contracts()
        .iter()
        .find(|definition| definition.contract.id.as_str() == "needle.tests.inventory")
        .ok_or(LiveRefreshCalibrationError::ActionMissing)?;
    let fragment = NeedFragmentId::new(Digest::blake3(b"gate-a4-live-refresh-fragment"));
    let route = NeedKey::new("needle.tests.inventory").map_err(runtime)?;
    ActionRequest::new(
        &definition.contract,
        ArtifactRequest {
            contract_id: definition.output_contract_id.to_owned(),
            contract_revision: definition.output_contract_revision,
            repository_id: repository,
            source_snapshot_digest: Digest::blake3(source_sha.as_bytes()),
            route_key: route.clone(),
            normalized_request: "enumerate Cargo test targets".to_owned(),
            semantic_fragment_id: Some(fragment),
            input_artifact_ids: Vec::new(),
        },
        definition.contract.default_dispatch_policy,
        route,
        NeedId::new(fragment.digest()),
    )
    .map_err(runtime)
}

fn ensure_toolchain(
    expected: &LiveCargoSnapshot,
    observed: &LiveCargoSnapshot,
) -> Result<(), LiveRefreshCalibrationError> {
    if observed.cargo_version != expected.cargo_version {
        return Err(LiveRefreshCalibrationError::ToolchainDrift);
    }
    Ok(())
}

fn ensure_shape(
    expected: RefreshShape,
    observed: RefreshShape,
) -> Result<(), LiveRefreshCalibrationError> {
    if expected != observed {
        return Err(LiveRefreshCalibrationError::ObservationDrift);
    }
    Ok(())
}

fn stale_retained_count(
    prior: &TestTargetInventory,
    current: &TestTargetInventory,
    retained: &[needle_core::PartitionKeyMapping],
) -> usize {
    let prior = prior
        .partitions
        .iter()
        .map(|partition| (cargo_test_target_partition_opaque_key(&partition.key), partition))
        .collect::<BTreeMap<_, _>>();
    let current = current
        .partitions
        .iter()
        .map(|partition| (cargo_test_target_partition_opaque_key(&partition.key), partition))
        .collect::<BTreeMap<_, _>>();
    retained
        .iter()
        .filter(|mapping| {
            prior.get(&mapping.prior.key_digest) != current.get(&mapping.current.key_digest)
        })
        .count()
}

fn elapsed_micros(started: Instant) -> Result<u64, LiveRefreshCalibrationError> {
    let value: u64 = started
        .elapsed()
        .as_micros()
        .try_into()
        .map_err(|_| LiveRefreshCalibrationError::Timing)?;
    Ok(value.max(1))
}

fn percentile(values: &[u64], percentile: usize) -> u64 {
    let mut values = values.to_vec();
    values.sort_unstable();
    let rank = (values.len() * percentile).div_ceil(100).saturating_sub(1);
    values[rank.min(values.len().saturating_sub(1))]
}

fn repository_identity_digest(source_repository: &str, source_sha: &str) -> Digest {
    let mut hasher = CanonicalHasher::new(b"live-refresh-repository-identity-v1");
    hasher.field_str(source_repository);
    hasher.field_str(source_sha);
    hasher.finish()
}

fn valid_git_sha(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn hash_strings(hasher: &mut CanonicalHasher, values: &[String]) {
    hasher.field_u32(values.len().try_into().unwrap_or(u32::MAX));
    for value in values {
        hasher.field_str(value);
    }
}

fn hash_u64s(hasher: &mut CanonicalHasher, values: &[u64]) {
    hasher.field_u32(values.len().try_into().unwrap_or(u32::MAX));
    for value in values {
        hash_u64(hasher, *value);
    }
}

fn hash_u64(hasher: &mut CanonicalHasher, value: u64) {
    hasher.field_bytes(&value.to_le_bytes());
}

fn hash_usize(hasher: &mut CanonicalHasher, value: usize) {
    hash_u64(hasher, value.try_into().unwrap_or(u64::MAX));
}

fn hash_bool(hasher: &mut CanonicalHasher, value: bool) {
    hasher.field_u8(u8::from(value));
}

fn runtime(error: impl std::fmt::Display) -> LiveRefreshCalibrationError {
    LiveRefreshCalibrationError::Runtime(error.to_string())
}

#[derive(Debug, Error)]
pub enum LiveRefreshCalibrationError {
    #[error("live refresh calibration input is invalid or outside its bounds")]
    Input,
    #[error("changed repository paths must be canonical, ordered, and unique")]
    ChangedPaths,
    #[error("the built-in test-target inventory action is missing")]
    ActionMissing,
    #[error("Cargo provider acquisition failed: {0}")]
    Provider(String),
    #[error("the Cargo toolchain changed during paired observation")]
    ToolchainDrift,
    #[error("the paired source changed during observation")]
    ObservationDrift,
    #[error("the declared live mutation is invalid")]
    Mutation,
    #[error("the declared live mutation could not be activated: {0}")]
    MutationActivation(String),
    #[error("the refresh path unexpectedly selected full compute")]
    UnexpectedFullCompute,
    #[error("the refresh candidate differs from the deterministic fresh oracle")]
    OracleAgreement,
    #[error("cost provenance is incomplete, unbound, or inconsistent")]
    CostProvenance,
    #[error("live refresh timing overflowed")]
    Timing,
    #[error("live refresh report has an invalid shape")]
    ReportShape,
    #[error("live refresh report repository identity is invalid")]
    RepositoryIdentity,
    #[error("live refresh report eligibility is inconsistent")]
    Eligibility,
    #[error("live refresh report digest is invalid")]
    ReportDigest,
    #[error("live refresh report contains {actual} bytes; the maximum is {maximum}")]
    ReportBound { actual: usize, maximum: usize },
    #[error("live refresh report JSON is invalid: {0}")]
    Json(String),
    #[error("live refresh runtime validation failed: {0}")]
    Runtime(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn report() -> LiveTestTargetRefreshCalibrationReport {
        let mut value = LiveTestTargetRefreshCalibrationReport {
            format_revision: LIVE_TEST_TARGET_REFRESH_FORMAT_REVISION,
            schema: LIVE_TEST_TARGET_REFRESH_REPORT_SCHEMA.to_owned(),
            authority: CapabilityMode::Shadow,
            source_repository: "https://github.com/dtolnay/thiserror".to_owned(),
            source_sha: "485c2b7eed2702c4a109be3cf42bb4be27fe16bd".to_owned(),
            repository_identity_digest: repository_identity_digest(
                "https://github.com/dtolnay/thiserror",
                "485c2b7eed2702c4a109be3cf42bb4be27fe16bd",
            ),
            cargo_version: "cargo 1.97.0".to_owned(),
            platform: "windows".to_owned(),
            changed_paths: vec!["impl/Cargo.toml".to_owned()],
            mutation_definition_digest: Digest::blake3(b"append-comment-v1"),
            prior_source_digest: Digest::blake3(b"prior"),
            current_source_digest: Digest::blake3(b"current"),
            provider_timeout_seconds: 30,
            provider_process_transport_included: true,
            full_current_oracle_outside_refresh_timing: true,
            arm_order_alternated: true,
            fresh_samples_micros: vec![100, 101, 102, 103, 104],
            refresh_samples_micros: vec![40, 41, 42, 43, 44],
            fresh_p95_micros: 104,
            refresh_p95_micros: 44,
            p95_budget_micros: 1_000,
            positive_latency_value: true,
            bounded_refresh_p95: true,
            exact_oracle_agreement: true,
            stale_retained_partitions: 0,
            acquisition_retained_partitions: 2,
            retained_partitions: 2,
            recomputed_partitions: 1,
            refreshed_partitions: 1,
            added_partitions: 0,
            removed_partitions: 0,
            cost_provenance: None,
            gate_a4_observation_eligible: true,
            gate_a4_closed: false,
            report_digest: Digest([0; 32]),
        };
        value.report_digest = value.compute_digest();
        value
    }

    #[test]
    fn report_round_trip_is_digest_bound_and_shadow_only() {
        let value = report();
        value.validate().unwrap();
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(LiveTestTargetRefreshCalibrationReport::decode_json(&bytes).unwrap(), value);
        let mut tampered = value.clone();
        tampered.refresh_samples_micros[0] = 39;
        assert!(tampered.validate().is_err());
        let mut promoted = value;
        promoted.authority = CapabilityMode::Authoritative;
        assert!(promoted.validate().is_err());
    }

    #[test]
    fn report_rejects_noncanonical_paths_and_inconsistent_optional_cost() {
        let mut value = report();
        value.changed_paths = vec!["impl/Cargo.toml".to_owned(), "impl/Cargo.toml".to_owned()];
        value.report_digest = value.compute_digest();
        assert!(value.validate().is_err());

        let mut value = report();
        value.cost_provenance = Some(LiveRefreshCostProvenance {
            observed_fresh_microusd: 5,
            observed_refresh_microusd: 10,
            pricing_revision: Digest::blake3(b"pricing"),
            evidence_digest: Digest::blake3(b"evidence"),
            positive_monetary_value: true,
        });
        value.report_digest = value.compute_digest();
        assert!(value.validate().is_err());
    }
}
