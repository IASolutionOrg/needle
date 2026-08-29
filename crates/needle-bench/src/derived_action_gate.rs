mod acceptance;
mod evaluation;
mod runner;
mod study;
mod synthetic;
mod wire;

pub use acceptance::{DerivedActionGateAcceptance, DerivedActionGateAcceptanceDecision};
pub use evaluation::evaluate_derived_action_gate;
pub use runner::*;
pub use study::*;
pub use synthetic::synthetic_derived_action_gate_material;
pub use wire::{DerivedActionObservationParse, parse_derived_action_observations};

use needle_core::{CanonicalHasher, Digest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

pub const DERIVED_ACTION_GATE_MANIFEST_SCHEMA: &str = "needle.derived-action-gate-a3-manifest/1";
pub const DERIVED_ACTION_GATE_OBSERVATION_SCHEMA: &str =
    "needle.derived-action-gate-a3-observation/1";
pub const DERIVED_ACTION_GATE_REPORT_SCHEMA: &str = "needle.derived-action-gate-a3-report/1";
pub const DERIVED_ACTION_GATE_ACCEPTANCE_SCHEMA: &str =
    "needle.derived-action-gate-a3-acceptance/1";
pub const DERIVED_ACTION_GATE_FORMAT_REVISION: u16 = 1;
pub const MAX_DERIVED_ACTION_GATE_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_DERIVED_ACTION_GATE_ACCEPTANCE_BYTES: usize = 1024 * 1024;
pub const MAX_DERIVED_ACTION_GATE_REVIEW_MATERIAL_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DERIVED_ACTION_GATE_OBSERVATIONS_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DERIVED_ACTION_GATE_OBSERVATION_LINE_BYTES: usize = 64 * 1024;
pub const MAX_DERIVED_ACTION_GATE_TASKS: usize = 64;
pub const MAX_DERIVED_ACTION_GATE_PAIR_SEEDS: usize = 16;
pub const MAX_DERIVED_ACTION_GATE_OBSERVATIONS: usize =
    MAX_DERIVED_ACTION_GATE_TASKS * MAX_DERIVED_ACTION_GATE_PAIR_SEEDS * 2;
pub const MAX_DERIVED_ACTION_GATE_IDENTIFIER_BYTES: usize = 256;
pub const MAX_DERIVED_ACTION_GATE_FAILURE_BYTES: usize = 4 * 1024;
pub const MAX_DERIVED_ACTION_GATE_FAILURES: usize = 128;
pub const MAX_DERIVED_ACTION_GATE_LIMITATIONS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedActionKind {
    ArchitectureBrief,
    ChangeImpact,
}

impl DerivedActionKind {
    pub const ALL: [Self; 2] = [Self::ArchitectureBrief, Self::ChangeImpact];

    pub const fn action_id(self) -> &'static str {
        match self {
            Self::ArchitectureBrief => "needle.architecture.describe",
            Self::ChangeImpact => "needle.change.impact",
        }
    }

    pub fn current_definitions(self) -> (Digest, Digest, Digest) {
        match self {
            Self::ArchitectureBrief => (
                needle_runtime::architecture_brief_analysis_definition(),
                needle_runtime::architecture_brief_validator_definition(),
                needle_runtime::architecture_brief_partition_policy_definition(),
            ),
            Self::ChangeImpact => (
                needle_runtime::change_impact_analysis_definition(),
                needle_runtime::change_impact_validator_definition(),
                needle_runtime::change_impact_partition_policy_definition(),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedActionReuseScenario {
    Exact,
    Project,
    Assemble,
}

impl DerivedActionReuseScenario {
    pub const ALL: [Self; 3] = [Self::Exact, Self::Project, Self::Assemble];
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedActionEvaluationArm {
    Fresh,
    Reuse,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedActionEvidenceClass {
    Synthetic,
    AcceptedShadow,
    ProviderBacked,
}

impl DerivedActionEvidenceClass {
    pub const fn evidence_claim(self, acceptance_valid: bool) -> &'static str {
        match self {
            Self::Synthetic => "protocol_only_synthetic",
            Self::AcceptedShadow if acceptance_valid => "bounded_accepted_shadow_calibration",
            Self::AcceptedShadow => "accepted_shadow_unaccepted",
            Self::ProviderBacked => "bounded_provider_backed_calibration",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionGateTask {
    pub id: String,
    pub action: DerivedActionKind,
    pub scenario: DerivedActionReuseScenario,
    pub semantic_request_digest: Digest,
    pub fixture_digest: Digest,
    pub oracle_commitment: Digest,
    pub execution_profile_digest: Digest,
    pub action_definition_digest: Digest,
    pub validator_definition_digest: Digest,
    pub partition_policy_digest: Digest,
    pub pair_seeds: Vec<u64>,
}

impl DerivedActionGateTask {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        action: DerivedActionKind,
        scenario: DerivedActionReuseScenario,
        semantic_request_digest: Digest,
        fixture_digest: Digest,
        oracle_commitment: Digest,
        execution_profile_digest: Digest,
        mut pair_seeds: Vec<u64>,
    ) -> Result<Self, DerivedActionGateError> {
        pair_seeds.sort_unstable();
        let (action_definition_digest, validator_definition_digest, partition_policy_digest) =
            action.current_definitions();
        let value = Self {
            id: id.into(),
            action,
            scenario,
            semantic_request_digest,
            fixture_digest,
            oracle_commitment,
            execution_profile_digest,
            action_definition_digest,
            validator_definition_digest,
            partition_policy_digest,
            pair_seeds,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DerivedActionGateError> {
        validate_identifier("task.id", &self.id)?;
        validate_nonzero_digest("task.semantic_request_digest", self.semantic_request_digest)?;
        validate_nonzero_digest("task.fixture_digest", self.fixture_digest)?;
        validate_nonzero_digest("task.oracle_commitment", self.oracle_commitment)?;
        validate_nonzero_digest("task.execution_profile_digest", self.execution_profile_digest)?;
        let (action, validator, partition) = self.action.current_definitions();
        if self.action_definition_digest != action
            || self.validator_definition_digest != validator
            || self.partition_policy_digest != partition
        {
            return Err(DerivedActionGateError::DefinitionDrift(self.id.clone()));
        }
        validate_sorted_unique(
            "task.pair_seeds",
            &self.pair_seeds,
            1,
            MAX_DERIVED_ACTION_GATE_PAIR_SEEDS,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionGateManifest {
    pub format_revision: u16,
    pub schema: String,
    pub evidence_class: DerivedActionEvidenceClass,
    pub repository_sha: String,
    pub tasks: Vec<DerivedActionGateTask>,
    pub manifest_digest: Digest,
}

impl DerivedActionGateManifest {
    pub fn new(
        evidence_class: DerivedActionEvidenceClass,
        repository_sha: impl Into<String>,
        mut tasks: Vec<DerivedActionGateTask>,
    ) -> Result<Self, DerivedActionGateError> {
        tasks.sort_by(|left, right| left.id.cmp(&right.id));
        let mut value = Self {
            format_revision: DERIVED_ACTION_GATE_FORMAT_REVISION,
            schema: DERIVED_ACTION_GATE_MANIFEST_SCHEMA.to_owned(),
            evidence_class,
            repository_sha: repository_sha.into(),
            tasks,
            manifest_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.manifest_digest = value.compute_digest();
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, DerivedActionGateError> {
        if bytes.len() > MAX_DERIVED_ACTION_GATE_MANIFEST_BYTES {
            return Err(DerivedActionGateError::Bound {
                field: "manifest.bytes",
                actual: bytes.len(),
                maximum: MAX_DERIVED_ACTION_GATE_MANIFEST_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| DerivedActionGateError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DerivedActionGateError> {
        self.validate_shape()?;
        if self.manifest_digest != self.compute_digest() {
            return Err(DerivedActionGateError::Digest("manifest.manifest_digest"));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), DerivedActionGateError> {
        if self.format_revision != DERIVED_ACTION_GATE_FORMAT_REVISION {
            return Err(DerivedActionGateError::FormatRevision(self.format_revision));
        }
        if self.schema != DERIVED_ACTION_GATE_MANIFEST_SCHEMA {
            return Err(DerivedActionGateError::Schema("manifest.schema"));
        }
        validate_repository_sha(&self.repository_sha)?;
        if self.tasks.len() > MAX_DERIVED_ACTION_GATE_TASKS {
            return Err(DerivedActionGateError::Bound {
                field: "manifest.tasks",
                actual: self.tasks.len(),
                maximum: MAX_DERIVED_ACTION_GATE_TASKS,
            });
        }
        if self.tasks.is_empty() || self.tasks.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err(DerivedActionGateError::Canonical("manifest.tasks"));
        }
        let mut coverage = BTreeSet::new();
        for task in &self.tasks {
            task.validate()?;
            coverage.insert((task.action, task.scenario));
        }
        let expected = DerivedActionKind::ALL
            .into_iter()
            .flat_map(|action| {
                DerivedActionReuseScenario::ALL.into_iter().map(move |scenario| (action, scenario))
            })
            .collect::<BTreeSet<_>>();
        if coverage != expected {
            return Err(DerivedActionGateError::ScenarioCoverage);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"derived-action-gate-a3-manifest-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_u8(evidence_class_tag(self.evidence_class));
        hasher.field_str(&self.repository_sha);
        hasher.field_u16(self.tasks.len().try_into().unwrap_or(u16::MAX));
        for task in &self.tasks {
            hasher.field_str(&task.id);
            hasher.field_u8(action_tag(task.action));
            hasher.field_u8(scenario_tag(task.scenario));
            hasher.field_digest(task.semantic_request_digest);
            hasher.field_digest(task.fixture_digest);
            hasher.field_digest(task.oracle_commitment);
            hasher.field_digest(task.execution_profile_digest);
            hasher.field_digest(task.action_definition_digest);
            hasher.field_digest(task.validator_definition_digest);
            hasher.field_digest(task.partition_policy_digest);
            hasher.field_u16(task.pair_seeds.len().try_into().unwrap_or(u16::MAX));
            for seed in &task.pair_seeds {
                hash_u64(&mut hasher, *seed);
            }
        }
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionGateObservation {
    pub format_revision: u16,
    pub schema: String,
    pub manifest_digest: Digest,
    pub task_id: String,
    pub action: DerivedActionKind,
    pub scenario: DerivedActionReuseScenario,
    pub arm: DerivedActionEvaluationArm,
    pub pair_seed: u64,
    pub evidence_class: DerivedActionEvidenceClass,
    pub execution_profile_digest: Digest,
    pub model_id: Option<String>,
    pub pricing_snapshot_digest: Digest,
    pub oracle_commitment: Digest,
    pub quality_judgment_digest: Digest,
    pub output_digest: Digest,
    pub validation_certificate_digest: Digest,
    pub structural_validation_passed: bool,
    pub quality_passed: bool,
    pub semantic_equivalence_passed: Option<bool>,
    pub total_cost_microcredits: u64,
    pub latency_micros: u64,
    pub worker_started: bool,
    pub provider_calls: u16,
    pub provider_observation_digest: Option<Digest>,
    pub infrastructure_failure: Option<String>,
}

impl DerivedActionGateObservation {
    pub fn validate(&self) -> Result<(), DerivedActionGateError> {
        if self.format_revision != DERIVED_ACTION_GATE_FORMAT_REVISION {
            return Err(DerivedActionGateError::FormatRevision(self.format_revision));
        }
        if self.schema != DERIVED_ACTION_GATE_OBSERVATION_SCHEMA {
            return Err(DerivedActionGateError::Schema("observation.schema"));
        }
        validate_identifier("observation.task_id", &self.task_id)?;
        if let Some(model) = &self.model_id {
            validate_label("observation.model_id", model)?;
        }
        if let Some(failure) = &self.infrastructure_failure
            && (failure.trim().is_empty() || failure.len() > MAX_DERIVED_ACTION_GATE_FAILURE_BYTES)
        {
            return Err(DerivedActionGateError::Text("observation.infrastructure_failure"));
        }
        for (field, digest) in [
            ("observation.manifest_digest", self.manifest_digest),
            ("observation.execution_profile_digest", self.execution_profile_digest),
            ("observation.pricing_snapshot_digest", self.pricing_snapshot_digest),
            ("observation.oracle_commitment", self.oracle_commitment),
            ("observation.quality_judgment_digest", self.quality_judgment_digest),
            ("observation.output_digest", self.output_digest),
            ("observation.validation_certificate_digest", self.validation_certificate_digest),
        ] {
            validate_nonzero_digest(field, digest)?;
        }
        if self.latency_micros == 0 {
            return Err(DerivedActionGateError::Metric("observation.latency_micros"));
        }
        match self.arm {
            DerivedActionEvaluationArm::Fresh => {
                if self.model_id.is_none()
                    || self.semantic_equivalence_passed.is_some()
                    || !self.worker_started
                {
                    return Err(DerivedActionGateError::ArmShape(self.task_id.clone()));
                }
            }
            DerivedActionEvaluationArm::Reuse => {
                if self.model_id.is_some()
                    || self.semantic_equivalence_passed.is_none()
                    || self.worker_started
                    || self.provider_calls != 0
                    || self.provider_observation_digest.is_some()
                {
                    return Err(DerivedActionGateError::ArmShape(self.task_id.clone()));
                }
            }
        }
        match self.evidence_class {
            DerivedActionEvidenceClass::Synthetic | DerivedActionEvidenceClass::AcceptedShadow
                if self.provider_calls != 0 || self.provider_observation_digest.is_some() =>
            {
                return Err(DerivedActionGateError::ProviderBinding(self.task_id.clone()));
            }
            DerivedActionEvidenceClass::ProviderBacked
                if self.arm == DerivedActionEvaluationArm::Fresh
                    && (self.provider_calls != 1 || self.provider_observation_digest.is_none()) =>
            {
                return Err(DerivedActionGateError::ProviderBinding(self.task_id.clone()));
            }
            _ if self.provider_calls == 0 && self.provider_observation_digest.is_some() => {
                return Err(DerivedActionGateError::ProviderBinding(self.task_id.clone()));
            }
            _ if self.provider_calls > 0 && self.provider_observation_digest.is_none() => {
                return Err(DerivedActionGateError::ProviderBinding(self.task_id.clone()));
            }
            _ => {}
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"derived-action-gate-a3-observation-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_digest(self.manifest_digest);
        hasher.field_str(&self.task_id);
        hasher.field_u8(action_tag(self.action));
        hasher.field_u8(scenario_tag(self.scenario));
        hasher.field_u8(match self.arm {
            DerivedActionEvaluationArm::Fresh => 0,
            DerivedActionEvaluationArm::Reuse => 1,
        });
        hash_u64(&mut hasher, self.pair_seed);
        hasher.field_u8(evidence_class_tag(self.evidence_class));
        hasher.field_digest(self.execution_profile_digest);
        hash_optional_str(&mut hasher, self.model_id.as_deref());
        hasher.field_digest(self.pricing_snapshot_digest);
        hasher.field_digest(self.oracle_commitment);
        hasher.field_digest(self.quality_judgment_digest);
        hasher.field_digest(self.output_digest);
        hasher.field_digest(self.validation_certificate_digest);
        hasher.field_u8(u8::from(self.structural_validation_passed));
        hasher.field_u8(u8::from(self.quality_passed));
        hash_optional_bool(&mut hasher, self.semantic_equivalence_passed);
        hash_u64(&mut hasher, self.total_cost_microcredits);
        hash_u64(&mut hasher, self.latency_micros);
        hasher.field_u8(u8::from(self.worker_started));
        hasher.field_u16(self.provider_calls);
        hash_optional_digest(&mut hasher, self.provider_observation_digest);
        hash_optional_str(&mut hasher, self.infrastructure_failure.as_deref());
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionGateTaskReport {
    pub task_id: String,
    pub action: DerivedActionKind,
    pub scenario: DerivedActionReuseScenario,
    pub expected_pairs: u16,
    pub observed_pairs: u16,
    pub structural_validation_passed: bool,
    pub quality_passed: bool,
    pub semantic_equivalence_passed: bool,
    pub positive_net_value: bool,
    pub fresh_cost_microcredits: Option<u64>,
    pub reuse_cost_microcredits: Option<u64>,
    pub savings_basis_points: Option<i64>,
    pub passed: bool,
    pub failures: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionGateActionReport {
    pub action: DerivedActionKind,
    pub exact_passed: bool,
    pub project_passed: bool,
    pub assemble_passed: bool,
    pub quality_passed: bool,
    pub positive_net_value: bool,
    pub gate_a3_passed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionGateReport {
    pub format_revision: u16,
    pub schema: String,
    pub manifest_digest: Digest,
    pub observation_set_digest: Digest,
    pub evidence_class: DerivedActionEvidenceClass,
    pub evidence_claim: String,
    pub acceptance_artifact_digest: Option<Digest>,
    pub acceptance_valid: bool,
    pub provider_execution_performed_by_harness: bool,
    pub provider_calls_observed: u32,
    pub protocol_valid: bool,
    pub structural_validation_passed: bool,
    pub quality_passed: bool,
    pub semantic_equivalence_passed: bool,
    pub positive_net_value: bool,
    pub gate_a3_eligible: bool,
    pub gate_a3_passed: bool,
    pub statistical_claim: bool,
    pub tasks: Vec<DerivedActionGateTaskReport>,
    pub actions: Vec<DerivedActionGateActionReport>,
    pub failures: Vec<String>,
    pub report_digest: Digest,
}

impl DerivedActionGateReport {
    pub fn validate(&self) -> Result<(), DerivedActionGateError> {
        if self.format_revision != DERIVED_ACTION_GATE_FORMAT_REVISION {
            return Err(DerivedActionGateError::FormatRevision(self.format_revision));
        }
        if self.schema != DERIVED_ACTION_GATE_REPORT_SCHEMA {
            return Err(DerivedActionGateError::Schema("report.schema"));
        }
        if self.provider_execution_performed_by_harness || self.statistical_claim {
            return Err(DerivedActionGateError::ReportAuthority);
        }
        for (field, digest) in [
            ("report.manifest_digest", self.manifest_digest),
            ("report.observation_set_digest", self.observation_set_digest),
        ] {
            validate_nonzero_digest(field, digest)?;
        }
        if self.evidence_claim != self.evidence_class.evidence_claim(self.acceptance_valid) {
            return Err(DerivedActionGateError::ReportConsistency("report.evidence_claim"));
        }
        match self.evidence_class {
            DerivedActionEvidenceClass::AcceptedShadow => {
                if self.acceptance_valid && self.acceptance_artifact_digest.is_none() {
                    return Err(DerivedActionGateError::ReportConsistency("report.acceptance"));
                }
            }
            _ if self.acceptance_valid || self.acceptance_artifact_digest.is_some() => {
                return Err(DerivedActionGateError::ReportConsistency("report.acceptance"));
            }
            _ => {}
        }
        if let Some(digest) = self.acceptance_artifact_digest {
            validate_nonzero_digest("report.acceptance_artifact_digest", digest)?;
        }
        if self.tasks.is_empty() || self.tasks.len() > MAX_DERIVED_ACTION_GATE_TASKS {
            return Err(DerivedActionGateError::Bound {
                field: "report.tasks",
                actual: self.tasks.len(),
                maximum: MAX_DERIVED_ACTION_GATE_TASKS,
            });
        }
        if self.tasks.windows(2).any(|pair| pair[0].task_id >= pair[1].task_id) {
            return Err(DerivedActionGateError::Canonical("report.tasks"));
        }
        let mut coverage = BTreeSet::new();
        for task in &self.tasks {
            validate_identifier("report.task.task_id", &task.task_id)?;
            if task.expected_pairs == 0
                || usize::from(task.expected_pairs) > MAX_DERIVED_ACTION_GATE_PAIR_SEEDS
                || task.observed_pairs > task.expected_pairs
            {
                return Err(DerivedActionGateError::Metric("report.task.pairs"));
            }
            validate_report_failures("report.task.failures", &task.failures)?;
            let expected_passed = task.observed_pairs == task.expected_pairs
                && task.structural_validation_passed
                && task.quality_passed
                && task.semantic_equivalence_passed
                && task.positive_net_value
                && task.failures.is_empty();
            if task.passed != expected_passed {
                return Err(DerivedActionGateError::ReportConsistency("report.task.passed"));
            }
            coverage.insert((task.action, task.scenario));
        }
        let expected_coverage = DerivedActionKind::ALL
            .into_iter()
            .flat_map(|action| {
                DerivedActionReuseScenario::ALL.into_iter().map(move |scenario| (action, scenario))
            })
            .collect::<BTreeSet<_>>();
        if coverage != expected_coverage {
            return Err(DerivedActionGateError::ScenarioCoverage);
        }
        let expected_actions = DerivedActionKind::ALL
            .into_iter()
            .map(|action| evaluation::action_report(action, &self.tasks, self.gate_a3_eligible))
            .collect::<Vec<_>>();
        if self.actions != expected_actions {
            return Err(DerivedActionGateError::ReportConsistency("report.actions"));
        }
        let expected_structural = self.tasks.iter().all(|task| task.structural_validation_passed);
        let expected_quality = self.tasks.iter().all(|task| task.quality_passed);
        let expected_equivalence = self.tasks.iter().all(|task| task.semantic_equivalence_passed);
        let expected_positive = self.tasks.iter().all(|task| task.positive_net_value);
        let expected_eligible = match self.evidence_class {
            DerivedActionEvidenceClass::Synthetic => false,
            DerivedActionEvidenceClass::AcceptedShadow => self.acceptance_valid,
            DerivedActionEvidenceClass::ProviderBacked => true,
        };
        let expected_gate_passed = expected_eligible
            && self.protocol_valid
            && self.actions.iter().all(|action| action.gate_a3_passed);
        let expected_provider_calls =
            self.tasks.iter().map(|task| u32::from(task.expected_pairs)).sum::<u32>();
        let provider_calls_consistent = match self.evidence_class {
            DerivedActionEvidenceClass::ProviderBacked if self.protocol_valid => {
                self.provider_calls_observed == expected_provider_calls
            }
            DerivedActionEvidenceClass::Synthetic | DerivedActionEvidenceClass::AcceptedShadow => {
                self.provider_calls_observed == 0
            }
            DerivedActionEvidenceClass::ProviderBacked => true,
        };
        if self.structural_validation_passed != expected_structural
            || self.quality_passed != expected_quality
            || self.semantic_equivalence_passed != expected_equivalence
            || self.positive_net_value != expected_positive
            || self.gate_a3_eligible != expected_eligible
            || self.gate_a3_passed != expected_gate_passed
            || !provider_calls_consistent
        {
            return Err(DerivedActionGateError::ReportConsistency("report.summary"));
        }
        validate_report_failures("report.failures", &self.failures)?;
        if self.report_digest != self.compute_digest() {
            return Err(DerivedActionGateError::Digest("report.report_digest"));
        }
        Ok(())
    }

    pub(crate) fn seal(&mut self) {
        self.report_digest = self.compute_digest();
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"derived-action-gate-a3-report-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_digest(self.manifest_digest);
        hasher.field_digest(self.observation_set_digest);
        hasher.field_u8(evidence_class_tag(self.evidence_class));
        hasher.field_str(&self.evidence_claim);
        hash_optional_digest(&mut hasher, self.acceptance_artifact_digest);
        for value in [
            self.acceptance_valid,
            self.provider_execution_performed_by_harness,
            self.protocol_valid,
            self.structural_validation_passed,
            self.quality_passed,
            self.semantic_equivalence_passed,
            self.positive_net_value,
            self.gate_a3_eligible,
            self.gate_a3_passed,
            self.statistical_claim,
        ] {
            hasher.field_u8(u8::from(value));
        }
        hasher.field_u32(self.provider_calls_observed);
        hasher.field_u16(self.tasks.len().try_into().unwrap_or(u16::MAX));
        for task in &self.tasks {
            hasher.field_str(&task.task_id);
            hasher.field_u8(action_tag(task.action));
            hasher.field_u8(scenario_tag(task.scenario));
            hasher.field_u16(task.expected_pairs);
            hasher.field_u16(task.observed_pairs);
            for value in [
                task.structural_validation_passed,
                task.quality_passed,
                task.semantic_equivalence_passed,
                task.positive_net_value,
                task.passed,
            ] {
                hasher.field_u8(u8::from(value));
            }
            hash_optional_u64(&mut hasher, task.fresh_cost_microcredits);
            hash_optional_u64(&mut hasher, task.reuse_cost_microcredits);
            hash_optional_i64(&mut hasher, task.savings_basis_points);
            hasher.field_u16(task.failures.len().try_into().unwrap_or(u16::MAX));
            for failure in &task.failures {
                hasher.field_str(failure);
            }
        }
        hasher.field_u16(self.actions.len().try_into().unwrap_or(u16::MAX));
        for action in &self.actions {
            hasher.field_u8(action_tag(action.action));
            for value in [
                action.exact_passed,
                action.project_passed,
                action.assemble_passed,
                action.quality_passed,
                action.positive_net_value,
                action.gate_a3_passed,
            ] {
                hasher.field_u8(u8::from(value));
            }
        }
        hasher.field_u16(self.failures.len().try_into().unwrap_or(u16::MAX));
        for failure in &self.failures {
            hasher.field_str(failure);
        }
        hasher.finish()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DerivedActionGateError {
    #[error("derived-action Gate A3 bound exceeded for {field}: {actual} > {maximum}")]
    Bound { field: &'static str, actual: usize, maximum: usize },
    #[error("derived-action Gate A3 JSON is invalid: {0}")]
    Json(String),
    #[error("unsupported format revision {0}")]
    FormatRevision(u16),
    #[error("unsupported schema in {0}")]
    Schema(&'static str),
    #[error("invalid identifier in {0}")]
    Identifier(&'static str),
    #[error("invalid text in {0}")]
    Text(&'static str),
    #[error("invalid digest in {0}")]
    Digest(&'static str),
    #[error("invalid metric in {0}")]
    Metric(&'static str),
    #[error("non-canonical collection {0}")]
    Canonical(&'static str),
    #[error("action definition drift for task {0}")]
    DefinitionDrift(String),
    #[error("manifest must cover Exact, Project, and Assemble for both derived actions")]
    ScenarioCoverage,
    #[error("derived-action accepted Shadow evidence binding is invalid")]
    AcceptanceBinding,
    #[error("derived-action accepted Shadow evidence was explicitly rejected")]
    AcceptanceRejected,
    #[error("invalid Fresh/Reuse observation shape for task {0}")]
    ArmShape(String),
    #[error("invalid provider evidence binding for task {0}")]
    ProviderBinding(String),
    #[error("report attempted to claim authority outside the offline harness boundary")]
    ReportAuthority,
    #[error("inconsistent derived-action Gate A3 report field {0}")]
    ReportConsistency(&'static str),
}

pub(crate) fn action_tag(action: DerivedActionKind) -> u8 {
    match action {
        DerivedActionKind::ArchitectureBrief => 0,
        DerivedActionKind::ChangeImpact => 1,
    }
}

pub(crate) fn scenario_tag(scenario: DerivedActionReuseScenario) -> u8 {
    match scenario {
        DerivedActionReuseScenario::Exact => 0,
        DerivedActionReuseScenario::Project => 1,
        DerivedActionReuseScenario::Assemble => 2,
    }
}

pub(crate) fn evidence_class_tag(class: DerivedActionEvidenceClass) -> u8 {
    match class {
        DerivedActionEvidenceClass::Synthetic => 0,
        DerivedActionEvidenceClass::AcceptedShadow => 1,
        DerivedActionEvidenceClass::ProviderBacked => 2,
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), DerivedActionGateError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_DERIVED_ACTION_GATE_IDENTIFIER_BYTES
        || !bytes[0].is_ascii_lowercase()
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'.' | b'_' | b'-')
        })
    {
        return Err(DerivedActionGateError::Identifier(field));
    }
    Ok(())
}

fn validate_label(field: &'static str, value: &str) -> Result<(), DerivedActionGateError> {
    if value.trim().is_empty()
        || value.len() > MAX_DERIVED_ACTION_GATE_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(DerivedActionGateError::Text(field));
    }
    Ok(())
}

fn validate_repository_sha(value: &str) -> Result<(), DerivedActionGateError> {
    if !matches!(value.len(), 40 | 64)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(DerivedActionGateError::Identifier("manifest.repository_sha"));
    }
    Ok(())
}

fn validate_nonzero_digest(
    field: &'static str,
    digest: Digest,
) -> Result<(), DerivedActionGateError> {
    if digest == Digest([0; 32]) {
        return Err(DerivedActionGateError::Digest(field));
    }
    Ok(())
}

fn validate_report_failures(
    field: &'static str,
    failures: &[String],
) -> Result<(), DerivedActionGateError> {
    if failures.len() > MAX_DERIVED_ACTION_GATE_FAILURES
        || failures.windows(2).any(|pair| pair[0] >= pair[1])
        || failures.iter().any(|failure| {
            failure.trim().is_empty() || failure.len() > MAX_DERIVED_ACTION_GATE_FAILURE_BYTES
        })
    {
        return Err(DerivedActionGateError::Text(field));
    }
    Ok(())
}

fn validate_sorted_unique<T: Ord>(
    field: &'static str,
    values: &[T],
    minimum: usize,
    maximum: usize,
) -> Result<(), DerivedActionGateError> {
    if values.len() < minimum || values.len() > maximum {
        return Err(DerivedActionGateError::Bound { field, actual: values.len(), maximum });
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DerivedActionGateError::Canonical(field));
    }
    Ok(())
}

pub(crate) fn hash_u64(hasher: &mut CanonicalHasher, value: u64) {
    hasher.field_bytes(&value.to_le_bytes());
}

pub(crate) fn hash_optional_digest(hasher: &mut CanonicalHasher, value: Option<Digest>) {
    match value {
        Some(value) => {
            hasher.field_u8(1);
            hasher.field_digest(value);
        }
        None => hasher.field_u8(0),
    }
}

fn hash_optional_str(hasher: &mut CanonicalHasher, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.field_u8(1);
            hasher.field_str(value);
        }
        None => hasher.field_u8(0),
    }
}

fn hash_optional_bool(hasher: &mut CanonicalHasher, value: Option<bool>) {
    match value {
        Some(value) => {
            hasher.field_u8(1);
            hasher.field_u8(u8::from(value));
        }
        None => hasher.field_u8(0),
    }
}

fn hash_optional_u64(hasher: &mut CanonicalHasher, value: Option<u64>) {
    match value {
        Some(value) => {
            hasher.field_u8(1);
            hash_u64(hasher, value);
        }
        None => hasher.field_u8(0),
    }
}

fn hash_optional_i64(hasher: &mut CanonicalHasher, value: Option<i64>) {
    match value {
        Some(value) => {
            hasher.field_u8(1);
            hasher.field_bytes(&value.to_le_bytes());
        }
        None => hasher.field_u8(0),
    }
}

#[cfg(test)]
mod tests;
