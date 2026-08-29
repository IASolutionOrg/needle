use needle_core::{
    ActionRequest, ArtifactRequest, CanonicalHasher, DependencyLocator, Digest, NeedFragmentId,
    NeedId, NeedKey, RepositoryContextId, SemanticWorld, StateDelta, TestTargetInventory,
    TestTargetInventoryScope,
};
use needle_runtime::{
    CargoTestTargetInventoryInput, CargoTestTargetRefreshAcquisition,
    CargoTestTargetRefreshFallback, CargoTestTargetRefreshInput, ShadowManifestContext,
    TestTargetInventoryRefreshDecision, TestTargetInventoryRefreshInput,
    TestTargetInventoryValidationCertificate, acquire_cargo_test_target_refresh_candidate,
    built_in_action_contracts, cargo_test_target_adapter_definition,
    cargo_test_target_partition_opaque_key, cargo_test_target_refresh_acquisition_definition,
    certify_test_target_inventory_shadow_manifest, enumerate_cargo_test_targets,
    evaluate_test_target_inventory_refresh, test_target_inventory_partition_policy_definition,
    test_target_inventory_refresh_definition, test_target_inventory_validator_definition,
    validate_cargo_test_target_inventory,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::hint::black_box;
use std::path::{Component, Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const TEST_TARGET_REFRESH_GATE_MANIFEST_SCHEMA: &str =
    "needle.test-target-refresh-gate-a4-manifest/1";
pub const TEST_TARGET_REFRESH_GATE_REPORT_SCHEMA: &str =
    "needle.test-target-refresh-gate-a4-report/1";
pub const TEST_TARGET_REFRESH_GATE_FORMAT_REVISION: u16 = 1;
pub const MAX_TEST_TARGET_REFRESH_GATE_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_TEST_TARGET_REFRESH_GATE_TASKS: usize = 16;
pub const MAX_TEST_TARGET_REFRESH_GATE_IDENTIFIER_BYTES: usize = 128;
pub const MAX_TEST_TARGET_REFRESH_GATE_FAILURES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestTargetRefreshMutation {
    ManifestContentChange,
    ExplicitTargetAddition,
    ExplicitTargetRemoval,
    TargetMetadataChange,
    ConventionalTargetAddition,
    WorkspaceManifestChange,
    UnmappedRepositoryChange,
    IncompleteDelta,
}

impl TestTargetRefreshMutation {
    pub const ALL: [Self; 8] = [
        Self::ManifestContentChange,
        Self::ExplicitTargetAddition,
        Self::ExplicitTargetRemoval,
        Self::TargetMetadataChange,
        Self::ConventionalTargetAddition,
        Self::WorkspaceManifestChange,
        Self::UnmappedRepositoryChange,
        Self::IncompleteDelta,
    ];

    pub fn definition_digest(self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"test-target-refresh-mutation-v1");
        hasher.field_u8(mutation_tag(self));
        match self {
            Self::ManifestContentChange => {
                hasher.field_str("append-package-manifest-comment");
                hasher.field_str("delta:package-manifest");
            }
            Self::ExplicitTargetAddition => {
                hasher.field_str("append-explicit-test-and-metadata-target");
                hasher.field_str("delta:package-manifest,target-source");
            }
            Self::ExplicitTargetRemoval => {
                hasher.field_str("remove-explicit-test-and-metadata-target");
                hasher.field_str("delta:package-manifest,target-source");
            }
            Self::TargetMetadataChange => {
                hasher.field_str("change-package-and-target-edition");
                hasher.field_str("delta:package-manifest");
            }
            Self::ConventionalTargetAddition => {
                hasher.field_str("add-conventional-test-and-metadata-target");
                hasher.field_str("delta:target-source");
            }
            Self::WorkspaceManifestChange => {
                hasher.field_str("append-workspace-manifest-comment");
                hasher.field_str("fallback:workspace-change");
            }
            Self::UnmappedRepositoryChange => {
                hasher.field_str("add-unmapped-readme");
                hasher.field_str("fallback:unmapped-repository-change");
            }
            Self::IncompleteDelta => {
                hasher.field_str("append-package-manifest-comment");
                hasher.field_str("fallback:incomplete-delta");
            }
        }
        hasher.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestTargetRefreshGateFallback {
    IncompleteDelta,
    WorkspaceChange,
    UnmappedRepositoryChange,
}

impl TestTargetRefreshGateFallback {
    fn matches_runtime(self, actual: CargoTestTargetRefreshFallback) -> bool {
        matches!(
            (self, actual),
            (Self::IncompleteDelta, CargoTestTargetRefreshFallback::IncompleteDelta)
                | (Self::WorkspaceChange, CargoTestTargetRefreshFallback::WorkspaceChange)
                | (
                    Self::UnmappedRepositoryChange,
                    CargoTestTargetRefreshFallback::UnmappedRepositoryChange
                )
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
pub enum TestTargetRefreshGateExpected {
    Refresh {
        acquisition_retained_partitions: usize,
        retained_partitions: usize,
        recomputed_partitions: usize,
        refreshed_partitions: usize,
        added_partitions: usize,
        removed_partitions: usize,
    },
    FullCompute {
        reason: TestTargetRefreshGateFallback,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestTargetRefreshGateTask {
    pub id: String,
    pub mutation: TestTargetRefreshMutation,
    pub mutation_definition_digest: Digest,
    pub expected: TestTargetRefreshGateExpected,
}

impl TestTargetRefreshGateTask {
    fn validate(&self, package_count: usize) -> Result<(), TestTargetRefreshGateError> {
        validate_identifier("task.id", &self.id)?;
        if self.mutation_definition_digest != self.mutation.definition_digest() {
            return Err(TestTargetRefreshGateError::DefinitionDrift(self.id.clone()));
        }
        let expected = expected_for(self.mutation, package_count);
        if self.expected != expected {
            return Err(TestTargetRefreshGateError::Expectation(self.id.clone()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestTargetRefreshGateManifest {
    pub format_revision: u16,
    pub schema: String,
    pub package_count: usize,
    pub samples_per_refresh_case: usize,
    pub p95_budget_micros: u64,
    pub fixture_definition_digest: Digest,
    pub adapter_definition_digest: Digest,
    pub acquisition_definition_digest: Digest,
    pub refresh_definition_digest: Digest,
    pub validator_definition_digest: Digest,
    pub partition_policy_definition_digest: Digest,
    pub tasks: Vec<TestTargetRefreshGateTask>,
    pub manifest_digest: Digest,
}

impl TestTargetRefreshGateManifest {
    pub fn new(
        package_count: usize,
        samples_per_refresh_case: usize,
        p95_budget_micros: u64,
        mut tasks: Vec<TestTargetRefreshGateTask>,
    ) -> Result<Self, TestTargetRefreshGateError> {
        tasks.sort_by(|left, right| left.id.cmp(&right.id));
        let mut value = Self {
            format_revision: TEST_TARGET_REFRESH_GATE_FORMAT_REVISION,
            schema: TEST_TARGET_REFRESH_GATE_MANIFEST_SCHEMA.to_owned(),
            package_count,
            samples_per_refresh_case,
            p95_budget_micros,
            fixture_definition_digest: fixture_definition_digest(package_count),
            adapter_definition_digest: cargo_test_target_adapter_definition(),
            acquisition_definition_digest: cargo_test_target_refresh_acquisition_definition(),
            refresh_definition_digest: test_target_inventory_refresh_definition(),
            validator_definition_digest: test_target_inventory_validator_definition(),
            partition_policy_definition_digest: test_target_inventory_partition_policy_definition(),
            tasks,
            manifest_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.manifest_digest = value.compute_digest();
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, TestTargetRefreshGateError> {
        if bytes.len() > MAX_TEST_TARGET_REFRESH_GATE_MANIFEST_BYTES {
            return Err(TestTargetRefreshGateError::Bound("manifest.bytes"));
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| TestTargetRefreshGateError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), TestTargetRefreshGateError> {
        self.validate_shape()?;
        if self.manifest_digest != self.compute_digest() {
            return Err(TestTargetRefreshGateError::Digest("manifest.manifest_digest"));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), TestTargetRefreshGateError> {
        if self.format_revision != TEST_TARGET_REFRESH_GATE_FORMAT_REVISION {
            return Err(TestTargetRefreshGateError::FormatRevision(self.format_revision));
        }
        if self.schema != TEST_TARGET_REFRESH_GATE_MANIFEST_SCHEMA {
            return Err(TestTargetRefreshGateError::Schema);
        }
        if !(8..=needle_core::MAX_TEST_TARGET_PACKAGES).contains(&self.package_count)
            || !(1..=100).contains(&self.samples_per_refresh_case)
            || self.p95_budget_micros == 0
            || self.p95_budget_micros > 1_000_000
            || self.tasks.is_empty()
            || self.tasks.len() > MAX_TEST_TARGET_REFRESH_GATE_TASKS
            || !self.tasks.windows(2).all(|pair| pair[0].id < pair[1].id)
        {
            return Err(TestTargetRefreshGateError::Bound("manifest.shape"));
        }
        if self.fixture_definition_digest != fixture_definition_digest(self.package_count)
            || self.adapter_definition_digest != cargo_test_target_adapter_definition()
            || self.acquisition_definition_digest
                != cargo_test_target_refresh_acquisition_definition()
            || self.refresh_definition_digest != test_target_inventory_refresh_definition()
            || self.validator_definition_digest != test_target_inventory_validator_definition()
            || self.partition_policy_definition_digest
                != test_target_inventory_partition_policy_definition()
        {
            return Err(TestTargetRefreshGateError::DefinitionDrift("manifest".to_owned()));
        }
        let mut coverage = BTreeSet::new();
        for task in &self.tasks {
            task.validate(self.package_count)?;
            coverage.insert(task.mutation);
        }
        if coverage != TestTargetRefreshMutation::ALL.into_iter().collect() {
            return Err(TestTargetRefreshGateError::Coverage);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"test-target-refresh-gate-a4-manifest-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_u32(self.package_count.try_into().unwrap_or(u32::MAX));
        hasher.field_u32(self.samples_per_refresh_case.try_into().unwrap_or(u32::MAX));
        hasher.field_bytes(&self.p95_budget_micros.to_le_bytes());
        hasher.field_digest(self.fixture_definition_digest);
        hasher.field_digest(self.adapter_definition_digest);
        hasher.field_digest(self.acquisition_definition_digest);
        hasher.field_digest(self.refresh_definition_digest);
        hasher.field_digest(self.validator_definition_digest);
        hasher.field_digest(self.partition_policy_definition_digest);
        hasher.field_u16(self.tasks.len().try_into().unwrap_or(u16::MAX));
        for task in &self.tasks {
            hasher.field_str(&task.id);
            hasher.field_u8(mutation_tag(task.mutation));
            hasher.field_digest(task.mutation_definition_digest);
            hash_expected(&mut hasher, &task.expected);
        }
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestTargetRefreshGateCaseReport {
    pub id: String,
    pub mutation: TestTargetRefreshMutation,
    pub observed_decision: String,
    pub expectation_matched: bool,
    pub oracle_agreement: bool,
    pub stale_retained_partitions: usize,
    pub acquisition_retained_partitions: usize,
    pub retained_partitions: usize,
    pub recomputed_partitions: usize,
    pub refreshed_partitions: usize,
    pub added_partitions: usize,
    pub removed_partitions: usize,
    pub fresh_compute_p95_nanos: Option<u64>,
    pub refresh_end_to_end_p95_nanos: Option<u64>,
    pub positive_net_refresh_value: Option<bool>,
    pub bounded_p95: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestTargetRefreshGateReport {
    pub format_revision: u16,
    pub schema: String,
    pub manifest_digest: Digest,
    pub authority: String,
    pub provider_process_transport_included: bool,
    pub full_current_oracle_outside_refresh_timing: bool,
    pub cases: Vec<TestTargetRefreshGateCaseReport>,
    pub expectations_matched: bool,
    pub exact_oracle_agreement: bool,
    pub zero_stale_retained_partitions: bool,
    pub refresh_cases_positive: bool,
    pub refresh_cases_bounded: bool,
    pub gate_a4_corpus_eligible: bool,
    pub gate_a4_closed: bool,
    pub failures: Vec<String>,
}

pub fn frozen_test_target_refresh_gate_manifest() -> TestTargetRefreshGateManifest {
    let package_count = 64;
    let tasks = TestTargetRefreshMutation::ALL
        .into_iter()
        .map(|mutation| TestTargetRefreshGateTask {
            id: mutation_id(mutation).to_owned(),
            mutation,
            mutation_definition_digest: mutation.definition_digest(),
            expected: expected_for(mutation, package_count),
        })
        .collect();
    TestTargetRefreshGateManifest::new(package_count, 12, 250_000, tasks)
        .expect("static Gate A4 corpus manifest")
}

pub fn evaluate_test_target_refresh_gate(
    manifest: &TestTargetRefreshGateManifest,
) -> Result<TestTargetRefreshGateReport, TestTargetRefreshGateError> {
    manifest.validate()?;
    let mut cases = Vec::with_capacity(manifest.tasks.len());
    let mut failures = Vec::new();
    for task in &manifest.tasks {
        let report = evaluate_case(manifest, task)?;
        if !report.expectation_matched {
            failures.push(format!("{}: observed decision differs from the manifest", task.id));
        }
        if !report.oracle_agreement {
            failures.push(format!("{}: targeted result differs from the fresh oracle", task.id));
        }
        if report.stale_retained_partitions != 0 {
            failures.push(format!("{}: stale retained partitions detected", task.id));
        }
        if report.positive_net_refresh_value == Some(false) {
            failures.push(format!("{}: refresh has no positive net value", task.id));
        }
        if report.bounded_p95 == Some(false) {
            failures.push(format!("{}: refresh exceeds the p95 budget", task.id));
        }
        cases.push(report);
    }
    if failures.len() > MAX_TEST_TARGET_REFRESH_GATE_FAILURES {
        failures.truncate(MAX_TEST_TARGET_REFRESH_GATE_FAILURES);
    }
    let expectations_matched = cases.iter().all(|case| case.expectation_matched);
    let exact_oracle_agreement = cases.iter().all(|case| case.oracle_agreement);
    let zero_stale_retained_partitions =
        cases.iter().all(|case| case.stale_retained_partitions == 0);
    let refresh_cases_positive =
        cases.iter().filter_map(|case| case.positive_net_refresh_value).all(|value| value)
            && cases.iter().any(|case| case.positive_net_refresh_value.is_some());
    let refresh_cases_bounded = cases.iter().filter_map(|case| case.bounded_p95).all(|value| value)
        && cases.iter().any(|case| case.bounded_p95.is_some());
    let gate_a4_corpus_eligible = expectations_matched
        && exact_oracle_agreement
        && zero_stale_retained_partitions
        && refresh_cases_positive
        && refresh_cases_bounded
        && failures.is_empty();
    Ok(TestTargetRefreshGateReport {
        format_revision: TEST_TARGET_REFRESH_GATE_FORMAT_REVISION,
        schema: TEST_TARGET_REFRESH_GATE_REPORT_SCHEMA.to_owned(),
        manifest_digest: manifest.manifest_digest,
        authority: "shadow".to_owned(),
        provider_process_transport_included: false,
        full_current_oracle_outside_refresh_timing: true,
        cases,
        expectations_matched,
        exact_oracle_agreement,
        zero_stale_retained_partitions,
        refresh_cases_positive,
        refresh_cases_bounded,
        gate_a4_corpus_eligible,
        gate_a4_closed: false,
        failures,
    })
}

fn evaluate_case(
    manifest: &TestTargetRefreshGateManifest,
    task: &TestTargetRefreshGateTask,
) -> Result<TestTargetRefreshGateCaseReport, TestTargetRefreshGateError> {
    let mut fixture = RefreshFixture::new(manifest.package_count, &task.id)?;
    let repository = Digest::blake3(format!("gate-a4-repository:{}", task.id));
    let source = "frozen-shadow-worktree";
    let request = action_request(repository, source)?;
    let world = semantic_world(repository, source);
    let definition_set = Digest::blake3(b"gate-a4-frozen-definition-set");
    let prior_metadata = fixture.metadata_bytes()?;
    let prior = enumerate(&fixture, &prior_metadata, repository, source)?;
    let prior_validation = validate(&fixture, &prior_metadata, repository, source, &prior)?;
    let prior_publication = certify_test_target_inventory_shadow_manifest(
        ShadowManifestContext {
            request: &request,
            world: &world,
            definition_set_digest: definition_set,
        },
        &prior,
        &prior_validation,
        1,
    )?;
    let mutation = fixture.apply(task.mutation)?;
    let current_metadata = fixture.metadata_bytes()?;
    let delta = StateDelta::new(
        repository,
        RepositoryContextId::new(Digest::blake3(format!("gate-a4-worktree:{}", task.id))),
        1,
        2,
        mutation
            .changed_paths
            .iter()
            .map(|path| DependencyLocator::repository_path(path))
            .collect::<Result<Vec<_>, _>>()?,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        mutation.complete,
    )?;
    let oracle = enumerate(&fixture, &current_metadata, repository, source)?;
    let oracle_validation = validate(&fixture, &current_metadata, repository, source, &oracle)?;
    let acquisition = acquire_cargo_test_target_refresh_candidate(CargoTestTargetRefreshInput {
        current: fixture.input(&current_metadata, repository, source),
        prior_inventory: &prior,
        prior_validation: &prior_validation,
        state_delta: &delta,
    })?;

    match (&task.expected, acquisition) {
        (
            TestTargetRefreshGateExpected::Refresh {
                acquisition_retained_partitions,
                retained_partitions,
                recomputed_partitions,
                refreshed_partitions,
                added_partitions,
                removed_partitions,
            },
            CargoTestTargetRefreshAcquisition::Candidate { result: candidate },
        ) => {
            let oracle_agreement = candidate.inventory == oracle
                && candidate.validation_certificate == oracle_validation;
            let current_publication = certify_test_target_inventory_shadow_manifest(
                ShadowManifestContext {
                    request: &request,
                    world: &world,
                    definition_set_digest: definition_set,
                },
                &candidate.inventory,
                &candidate.validation_certificate,
                2,
            )?;
            let decision =
                evaluate_test_target_inventory_refresh(TestTargetInventoryRefreshInput {
                    prior_inventory: &prior,
                    prior_validation: &prior_validation,
                    prior_publication: &prior_publication,
                    current_inventory: &candidate.inventory,
                    current_validation: &candidate.validation_certificate,
                    current_publication: &current_publication,
                    state_delta: &delta,
                })?;
            let TestTargetInventoryRefreshDecision::Refresh { result } = decision else {
                return Ok(failed_case(task, "full_compute"));
            };
            let stale = stale_retained_count(&prior, &oracle, &result.plan.retained);
            let expectation_matched = candidate.retained_partitions
                == *acquisition_retained_partitions
                && candidate.recomputed_partitions == *recomputed_partitions
                && result.plan.retained.len() == *retained_partitions
                && result.plan.refreshed.len() == *refreshed_partitions
                && result.plan.added.len() == *added_partitions
                && result.plan.removed.len() == *removed_partitions;
            let (fresh_p95, refresh_p95) = measure_case(
                manifest,
                &fixture,
                &current_metadata,
                repository,
                source,
                &request,
                &world,
                definition_set,
                &prior,
                &prior_validation,
                &prior_publication,
                &delta,
            )?;
            Ok(TestTargetRefreshGateCaseReport {
                id: task.id.clone(),
                mutation: task.mutation,
                observed_decision: "refresh".to_owned(),
                expectation_matched,
                oracle_agreement: oracle_agreement
                    && result.reconstructed == oracle
                    && result.validation_certificate == oracle_validation,
                stale_retained_partitions: stale,
                acquisition_retained_partitions: candidate.retained_partitions,
                retained_partitions: result.plan.retained.len(),
                recomputed_partitions: candidate.recomputed_partitions,
                refreshed_partitions: result.plan.refreshed.len(),
                added_partitions: result.plan.added.len(),
                removed_partitions: result.plan.removed.len(),
                fresh_compute_p95_nanos: Some(fresh_p95),
                refresh_end_to_end_p95_nanos: Some(refresh_p95),
                positive_net_refresh_value: Some(refresh_p95 < fresh_p95),
                bounded_p95: Some(refresh_p95 <= manifest.p95_budget_micros * 1_000),
            })
        }
        (
            TestTargetRefreshGateExpected::FullCompute { reason: expected },
            CargoTestTargetRefreshAcquisition::FullCompute { reason: actual },
        ) => Ok(TestTargetRefreshGateCaseReport {
            id: task.id.clone(),
            mutation: task.mutation,
            observed_decision: format!("full_compute:{actual:?}").to_ascii_lowercase(),
            expectation_matched: expected.matches_runtime(actual),
            oracle_agreement: true,
            stale_retained_partitions: 0,
            acquisition_retained_partitions: 0,
            retained_partitions: 0,
            recomputed_partitions: oracle.partitions.len(),
            refreshed_partitions: 0,
            added_partitions: 0,
            removed_partitions: 0,
            fresh_compute_p95_nanos: None,
            refresh_end_to_end_p95_nanos: None,
            positive_net_refresh_value: None,
            bounded_p95: None,
        }),
        (_, CargoTestTargetRefreshAcquisition::Candidate { .. }) => {
            Ok(failed_case(task, "refresh"))
        }
        (_, CargoTestTargetRefreshAcquisition::FullCompute { .. }) => {
            Ok(failed_case(task, "full_compute"))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn measure_case(
    manifest: &TestTargetRefreshGateManifest,
    fixture: &RefreshFixture,
    metadata: &[u8],
    repository: Digest,
    source: &str,
    request: &ActionRequest,
    world: &SemanticWorld,
    definition_set: Digest,
    prior: &TestTargetInventory,
    prior_validation: &TestTargetInventoryValidationCertificate,
    prior_publication: &needle_runtime::ShadowPartitionManifestPublication,
    delta: &StateDelta,
) -> Result<(u64, u64), TestTargetRefreshGateError> {
    let measure_fresh = || -> Result<u64, TestTargetRefreshGateError> {
        let started = Instant::now();
        let inventory = enumerate(fixture, metadata, repository, source)?;
        let certificate = validate(fixture, metadata, repository, source, &inventory)?;
        black_box((inventory, certificate));
        Ok(elapsed_nanos(started))
    };
    let measure_refresh = || -> Result<u64, TestTargetRefreshGateError> {
        let started = Instant::now();
        let acquisition =
            acquire_cargo_test_target_refresh_candidate(CargoTestTargetRefreshInput {
                current: fixture.input(metadata, repository, source),
                prior_inventory: prior,
                prior_validation,
                state_delta: delta,
            })?;
        let CargoTestTargetRefreshAcquisition::Candidate { result: candidate } = acquisition else {
            return Err(TestTargetRefreshGateError::Decision);
        };
        let publication = certify_test_target_inventory_shadow_manifest(
            ShadowManifestContext { request, world, definition_set_digest: definition_set },
            &candidate.inventory,
            &candidate.validation_certificate,
            2,
        )?;
        let decision = evaluate_test_target_inventory_refresh(TestTargetInventoryRefreshInput {
            prior_inventory: prior,
            prior_validation,
            prior_publication,
            current_inventory: &candidate.inventory,
            current_validation: &candidate.validation_certificate,
            current_publication: &publication,
            state_delta: delta,
        })?;
        if !matches!(decision, TestTargetInventoryRefreshDecision::Refresh { .. }) {
            return Err(TestTargetRefreshGateError::Decision);
        }
        black_box(decision);
        Ok(elapsed_nanos(started))
    };
    let mut fresh = Vec::with_capacity(manifest.samples_per_refresh_case);
    let mut refresh = Vec::with_capacity(manifest.samples_per_refresh_case);
    for sample in 0..manifest.samples_per_refresh_case {
        if sample % 2 == 0 {
            fresh.push(measure_fresh()?);
            refresh.push(measure_refresh()?);
        } else {
            refresh.push(measure_refresh()?);
            fresh.push(measure_fresh()?);
        }
    }
    Ok((percentile(&mut fresh, 95), percentile(&mut refresh, 95)))
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

fn failed_case(
    task: &TestTargetRefreshGateTask,
    observed: &str,
) -> TestTargetRefreshGateCaseReport {
    TestTargetRefreshGateCaseReport {
        id: task.id.clone(),
        mutation: task.mutation,
        observed_decision: observed.to_owned(),
        expectation_matched: false,
        oracle_agreement: false,
        stale_retained_partitions: 0,
        acquisition_retained_partitions: 0,
        retained_partitions: 0,
        recomputed_partitions: 0,
        refreshed_partitions: 0,
        added_partitions: 0,
        removed_partitions: 0,
        fresh_compute_p95_nanos: None,
        refresh_end_to_end_p95_nanos: None,
        positive_net_refresh_value: None,
        bounded_p95: None,
    }
}

struct AppliedMutation {
    changed_paths: Vec<String>,
    complete: bool,
}

struct RefreshFixture {
    root: PathBuf,
    metadata: serde_json::Value,
}

impl RefreshFixture {
    fn new(packages: usize, case_id: &str) -> Result<Self, TestTargetRefreshGateError> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "needle-gate-a4-{}-{}-{nonce}",
            std::process::id(),
            case_id
        ));
        fs::create_dir_all(root.join("crates"))?;
        fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = [\"crates/*\"]\n")?;
        let mut package_values = Vec::with_capacity(packages);
        let mut member_ids = Vec::with_capacity(packages);
        for index in 0..packages {
            let name = format!("pkg{index:03}");
            let package_root = root.join("crates").join(&name);
            fs::create_dir_all(package_root.join("src"))?;
            let mut manifest = format!(
                "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\npath = \"src/lib.rs\"\n"
            );
            let mut targets = vec![target_json(&package_root, &name, "lib", "src/lib.rs", true)];
            if index == 0 {
                fs::create_dir_all(package_root.join("tests"))?;
                fs::write(package_root.join("tests/removable.rs"), "#[test] fn removable() {}\n")?;
                manifest
                    .push_str("\n[[test]]\nname = \"removable\"\npath = \"tests/removable.rs\"\n");
                targets.push(target_json(
                    &package_root,
                    "removable",
                    "test",
                    "tests/removable.rs",
                    false,
                ));
            }
            fs::write(package_root.join("Cargo.toml"), manifest)?;
            fs::write(package_root.join("src/lib.rs"), "pub fn target() {}\n")?;
            let id = format!("path+file:///gate-a4/{name}#0.1.0");
            member_ids.push(id.clone());
            package_values.push(json!({
                "id": id,
                "name": name,
                "manifest_path": package_root.join("Cargo.toml"),
                "targets": targets,
            }));
        }
        Ok(Self {
            root: root.clone(),
            metadata: json!({
                "packages": package_values,
                "workspace_members": member_ids,
                "workspace_root": root,
            }),
        })
    }

    fn metadata_bytes(&self) -> Result<Vec<u8>, TestTargetRefreshGateError> {
        Ok(serde_json::to_vec(&self.metadata)?)
    }

    fn input<'a>(
        &'a self,
        metadata: &'a [u8],
        repository: Digest,
        source: &'a str,
    ) -> CargoTestTargetInventoryInput<'a> {
        CargoTestTargetInventoryInput {
            repository_root: &self.root,
            repository_lineage: repository,
            source_selector: source,
            scope: TestTargetInventoryScope::all(),
            metadata_json: metadata,
            cargo_version: "cargo 1.90.0",
        }
    }

    fn apply(
        &mut self,
        mutation: TestTargetRefreshMutation,
    ) -> Result<AppliedMutation, TestTargetRefreshGateError> {
        let package_root = self.root.join("crates/pkg000");
        let package_manifest = package_root.join("Cargo.toml");
        let package_manifest_relative = "crates/pkg000/Cargo.toml".to_owned();
        match mutation {
            TestTargetRefreshMutation::ManifestContentChange => {
                append(&package_manifest, "\n# manifest-content-change\n")?;
                Ok(AppliedMutation {
                    changed_paths: vec![package_manifest_relative],
                    complete: true,
                })
            }
            TestTargetRefreshMutation::ExplicitTargetAddition => {
                append(
                    &package_manifest,
                    "\n[[test]]\nname = \"added\"\npath = \"tests/added.rs\"\n",
                )?;
                fs::write(package_root.join("tests/added.rs"), "#[test] fn added() {}\n")?;
                self.package_targets_mut(0)?.push(target_json(
                    &package_root,
                    "added",
                    "test",
                    "tests/added.rs",
                    false,
                ));
                Ok(AppliedMutation {
                    changed_paths: vec![
                        package_manifest_relative,
                        "crates/pkg000/tests/added.rs".to_owned(),
                    ],
                    complete: true,
                })
            }
            TestTargetRefreshMutation::ExplicitTargetRemoval => {
                let current = fs::read_to_string(&package_manifest)?;
                let removed = "\n[[test]]\nname = \"removable\"\npath = \"tests/removable.rs\"\n";
                if !current.contains(removed) {
                    return Err(TestTargetRefreshGateError::Fixture("removable target".to_owned()));
                }
                fs::write(&package_manifest, current.replace(removed, ""))?;
                fs::remove_file(package_root.join("tests/removable.rs"))?;
                self.package_targets_mut(0)?.retain(|target| target["name"] != json!("removable"));
                Ok(AppliedMutation {
                    changed_paths: vec![
                        package_manifest_relative,
                        "crates/pkg000/tests/removable.rs".to_owned(),
                    ],
                    complete: true,
                })
            }
            TestTargetRefreshMutation::TargetMetadataChange => {
                let current = fs::read_to_string(&package_manifest)?;
                fs::write(
                    &package_manifest,
                    current.replace("edition = \"2024\"", "edition = \"2021\""),
                )?;
                for target in self.package_targets_mut(0)? {
                    target["edition"] = json!("2021");
                }
                Ok(AppliedMutation {
                    changed_paths: vec![package_manifest_relative],
                    complete: true,
                })
            }
            TestTargetRefreshMutation::ConventionalTargetAddition => {
                fs::write(
                    package_root.join("tests/conventional.rs"),
                    "#[test] fn conventional() {}\n",
                )?;
                self.package_targets_mut(0)?.push(target_json(
                    &package_root,
                    "conventional",
                    "test",
                    "tests/conventional.rs",
                    false,
                ));
                Ok(AppliedMutation {
                    changed_paths: vec!["crates/pkg000/tests/conventional.rs".to_owned()],
                    complete: true,
                })
            }
            TestTargetRefreshMutation::WorkspaceManifestChange => {
                append(&self.root.join("Cargo.toml"), "\n# workspace-wide-change\n")?;
                Ok(AppliedMutation { changed_paths: vec!["Cargo.toml".to_owned()], complete: true })
            }
            TestTargetRefreshMutation::UnmappedRepositoryChange => {
                fs::write(self.root.join("README.md"), "unmapped change\n")?;
                Ok(AppliedMutation { changed_paths: vec!["README.md".to_owned()], complete: true })
            }
            TestTargetRefreshMutation::IncompleteDelta => {
                append(&package_manifest, "\n# incomplete-delta\n")?;
                Ok(AppliedMutation {
                    changed_paths: vec![package_manifest_relative],
                    complete: false,
                })
            }
        }
    }

    fn package_targets_mut(
        &mut self,
        index: usize,
    ) -> Result<&mut Vec<serde_json::Value>, TestTargetRefreshGateError> {
        self.metadata["packages"][index]["targets"]
            .as_array_mut()
            .ok_or_else(|| TestTargetRefreshGateError::Fixture("metadata targets".to_owned()))
    }
}

impl Drop for RefreshFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn target_json(
    package_root: &Path,
    name: &str,
    kind: &str,
    relative: &str,
    doctest: bool,
) -> serde_json::Value {
    json!({
        "name": name,
        "kind": [kind],
        "crate_types": [if kind == "lib" { "lib" } else { "bin" }],
        "required-features": [],
        "src_path": package_root.join(relative),
        "edition": "2024",
        "test": true,
        "doctest": doctest,
    })
}

fn enumerate(
    fixture: &RefreshFixture,
    metadata: &[u8],
    repository: Digest,
    source: &str,
) -> Result<TestTargetInventory, TestTargetRefreshGateError> {
    Ok(enumerate_cargo_test_targets(fixture.input(metadata, repository, source))?)
}

fn validate(
    fixture: &RefreshFixture,
    metadata: &[u8],
    repository: Digest,
    source: &str,
    inventory: &TestTargetInventory,
) -> Result<TestTargetInventoryValidationCertificate, TestTargetRefreshGateError> {
    Ok(validate_cargo_test_target_inventory(
        fixture.input(metadata, repository, source),
        inventory,
    )?)
}

fn action_request(
    repository: Digest,
    source: &str,
) -> Result<ActionRequest, TestTargetRefreshGateError> {
    let definition = built_in_action_contracts()
        .iter()
        .find(|definition| definition.contract.id.as_str() == "needle.tests.inventory")
        .ok_or_else(|| TestTargetRefreshGateError::Fixture("action contract".to_owned()))?;
    let fragment = NeedFragmentId::new(Digest::blake3(b"gate-a4-refresh-fragment"));
    let route = NeedKey::new("needle.tests.inventory")?;
    Ok(ActionRequest::new(
        &definition.contract,
        ArtifactRequest {
            contract_id: definition.output_contract_id.to_owned(),
            contract_revision: definition.output_contract_revision,
            repository_id: repository,
            source_snapshot_digest: Digest::blake3(source.as_bytes()),
            route_key: route.clone(),
            normalized_request: "enumerate Cargo test targets".to_owned(),
            semantic_fragment_id: Some(fragment),
            input_artifact_ids: Vec::new(),
        },
        definition.contract.default_dispatch_policy,
        route,
        NeedId::new(fragment.digest()),
    )?)
}

fn semantic_world(repository: Digest, source: &str) -> SemanticWorld {
    SemanticWorld {
        repository_lineage: repository,
        source_selector: source.to_owned(),
        platform: "any".to_owned(),
        features: "default".to_owned(),
        configuration: None,
        toolchain: None,
    }
}

fn append(path: &Path, suffix: &str) -> Result<(), TestTargetRefreshGateError> {
    let current = fs::read_to_string(path)?;
    fs::write(path, format!("{current}{suffix}"))?;
    Ok(())
}

fn expected_for(
    mutation: TestTargetRefreshMutation,
    packages: usize,
) -> TestTargetRefreshGateExpected {
    let retained = packages.saturating_sub(1);
    match mutation {
        TestTargetRefreshMutation::ManifestContentChange
        | TestTargetRefreshMutation::TargetMetadataChange => {
            TestTargetRefreshGateExpected::Refresh {
                acquisition_retained_partitions: retained,
                retained_partitions: retained,
                recomputed_partitions: 2,
                refreshed_partitions: 2,
                added_partitions: 0,
                removed_partitions: 0,
            }
        }
        TestTargetRefreshMutation::ExplicitTargetAddition => {
            TestTargetRefreshGateExpected::Refresh {
                acquisition_retained_partitions: retained,
                retained_partitions: retained,
                recomputed_partitions: 3,
                refreshed_partitions: 2,
                added_partitions: 1,
                removed_partitions: 0,
            }
        }
        TestTargetRefreshMutation::ConventionalTargetAddition => {
            TestTargetRefreshGateExpected::Refresh {
                acquisition_retained_partitions: retained,
                retained_partitions: packages.saturating_add(1),
                recomputed_partitions: 3,
                refreshed_partitions: 0,
                added_partitions: 1,
                removed_partitions: 0,
            }
        }
        TestTargetRefreshMutation::ExplicitTargetRemoval => {
            TestTargetRefreshGateExpected::Refresh {
                acquisition_retained_partitions: retained,
                retained_partitions: retained,
                recomputed_partitions: 1,
                refreshed_partitions: 1,
                added_partitions: 0,
                removed_partitions: 1,
            }
        }
        TestTargetRefreshMutation::WorkspaceManifestChange => {
            TestTargetRefreshGateExpected::FullCompute {
                reason: TestTargetRefreshGateFallback::WorkspaceChange,
            }
        }
        TestTargetRefreshMutation::UnmappedRepositoryChange => {
            TestTargetRefreshGateExpected::FullCompute {
                reason: TestTargetRefreshGateFallback::UnmappedRepositoryChange,
            }
        }
        TestTargetRefreshMutation::IncompleteDelta => TestTargetRefreshGateExpected::FullCompute {
            reason: TestTargetRefreshGateFallback::IncompleteDelta,
        },
    }
}

fn fixture_definition_digest(package_count: usize) -> Digest {
    let mut hasher = CanonicalHasher::new(b"test-target-refresh-gate-fixture-v1");
    hasher.field_u32(package_count.try_into().unwrap_or(u32::MAX));
    hasher.field_str("workspace-members:crates-star");
    hasher.field_str("explicit-lib-per-package");
    hasher.field_str("pkg000-explicit-removable-test");
    hasher.field_str("cargo-metadata-format-1-in-memory");
    hasher.field_str("cargo-1.90.0");
    hasher.finish()
}

fn mutation_id(mutation: TestTargetRefreshMutation) -> &'static str {
    match mutation {
        TestTargetRefreshMutation::ManifestContentChange => "manifest-content-change",
        TestTargetRefreshMutation::ExplicitTargetAddition => "explicit-target-addition",
        TestTargetRefreshMutation::ExplicitTargetRemoval => "explicit-target-removal",
        TestTargetRefreshMutation::TargetMetadataChange => "target-metadata-change",
        TestTargetRefreshMutation::ConventionalTargetAddition => "conventional-target-addition",
        TestTargetRefreshMutation::WorkspaceManifestChange => "workspace-manifest-change",
        TestTargetRefreshMutation::UnmappedRepositoryChange => "unmapped-repository-change",
        TestTargetRefreshMutation::IncompleteDelta => "incomplete-delta",
    }
}

fn mutation_tag(mutation: TestTargetRefreshMutation) -> u8 {
    match mutation {
        TestTargetRefreshMutation::ManifestContentChange => 0,
        TestTargetRefreshMutation::ExplicitTargetAddition => 1,
        TestTargetRefreshMutation::ExplicitTargetRemoval => 2,
        TestTargetRefreshMutation::TargetMetadataChange => 3,
        TestTargetRefreshMutation::ConventionalTargetAddition => 4,
        TestTargetRefreshMutation::WorkspaceManifestChange => 5,
        TestTargetRefreshMutation::UnmappedRepositoryChange => 6,
        TestTargetRefreshMutation::IncompleteDelta => 7,
    }
}

fn hash_expected(hasher: &mut CanonicalHasher, expected: &TestTargetRefreshGateExpected) {
    match expected {
        TestTargetRefreshGateExpected::Refresh {
            acquisition_retained_partitions,
            retained_partitions,
            recomputed_partitions,
            refreshed_partitions,
            added_partitions,
            removed_partitions,
        } => {
            hasher.field_u8(0);
            for value in [
                acquisition_retained_partitions,
                retained_partitions,
                recomputed_partitions,
                refreshed_partitions,
                added_partitions,
                removed_partitions,
            ] {
                hasher.field_u32((*value).try_into().unwrap_or(u32::MAX));
            }
        }
        TestTargetRefreshGateExpected::FullCompute { reason } => {
            hasher.field_u8(1);
            hasher.field_u8(match reason {
                TestTargetRefreshGateFallback::IncompleteDelta => 0,
                TestTargetRefreshGateFallback::WorkspaceChange => 1,
                TestTargetRefreshGateFallback::UnmappedRepositoryChange => 2,
            });
        }
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), TestTargetRefreshGateError> {
    if value.is_empty()
        || value.len() > MAX_TEST_TARGET_REFRESH_GATE_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
        || Path::new(value)
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(TestTargetRefreshGateError::Identifier(field));
    }
    Ok(())
}

fn elapsed_nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().try_into().unwrap_or(u64::MAX)
}

fn percentile(values: &mut [u64], percentile: usize) -> u64 {
    values.sort_unstable();
    let index = (values.len() - 1) * percentile / 100;
    values[index]
}

#[derive(Debug, Error)]
pub enum TestTargetRefreshGateError {
    #[error("Gate A4 corpus field `{0}` exceeds its bound")]
    Bound(&'static str),
    #[error("Gate A4 corpus format revision {0} is unsupported")]
    FormatRevision(u16),
    #[error("Gate A4 corpus schema is unsupported")]
    Schema,
    #[error("Gate A4 corpus JSON is invalid: {0}")]
    Json(String),
    #[error("Gate A4 corpus digest `{0}` is inconsistent")]
    Digest(&'static str),
    #[error("Gate A4 corpus definition drifted for `{0}`")]
    DefinitionDrift(String),
    #[error("Gate A4 corpus expectation is inconsistent for `{0}`")]
    Expectation(String),
    #[error("Gate A4 corpus does not cover every required mutation")]
    Coverage,
    #[error("Gate A4 corpus identifier `{0}` is invalid")]
    Identifier(&'static str),
    #[error("Gate A4 fixture is invalid: {0}")]
    Fixture(String),
    #[error("Gate A4 refresh decision is inconsistent")]
    Decision,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    JsonCodec(#[from] serde_json::Error),
    #[error(transparent)]
    Time(#[from] std::time::SystemTimeError),
    #[error(transparent)]
    Runtime(#[from] needle_runtime::TestTargetInventoryRuntimeError),
    #[error(transparent)]
    Manifest(#[from] needle_runtime::ShadowPartitionManifestError),
    #[error(transparent)]
    Refresh(#[from] needle_runtime::TestTargetInventoryRefreshError),
    #[error(transparent)]
    Repository(#[from] needle_core::RepositoryGenerationError),
    #[error(transparent)]
    NeedKey(#[from] needle_core::NeedKeyError),
    #[error(transparent)]
    ActionRequest(#[from] needle_core::ActionValidationError),
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &[u8] =
        include_bytes!("../../../benchmarks/corpus/test-target-refresh/gate-a4-manifest.json");

    #[test]
    fn checked_in_manifest_matches_current_frozen_definition() {
        let checked = TestTargetRefreshGateManifest::decode_json(MANIFEST).unwrap();
        assert_eq!(checked, frozen_test_target_refresh_gate_manifest());
    }

    #[test]
    fn manifest_rejects_digest_and_definition_tamper() {
        let manifest = frozen_test_target_refresh_gate_manifest();
        let mut digest = serde_json::to_value(&manifest).unwrap();
        digest["manifest_digest"] = json!(Digest::blake3(b"tampered"));
        assert!(
            TestTargetRefreshGateManifest::decode_json(&serde_json::to_vec(&digest).unwrap())
                .is_err()
        );
        let mut definition = serde_json::to_value(&manifest).unwrap();
        definition["tasks"][0]["mutation_definition_digest"] =
            json!(Digest::blake3(b"tampered-definition"));
        assert!(
            TestTargetRefreshGateManifest::decode_json(&serde_json::to_vec(&definition).unwrap())
                .is_err()
        );
    }
}
