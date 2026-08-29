use super::{
    DerivedActionEvidenceClass, DerivedActionGateError, DerivedActionGateManifest,
    DerivedActionGateTask, DerivedActionKind, DerivedActionReuseScenario,
    MAX_DERIVED_ACTION_GATE_PAIR_SEEDS, action_tag, scenario_tag, validate_identifier,
    validate_repository_sha,
};
use needle_core::{
    ActionRequest, ArtifactKind, ArtifactRequest, CanonicalHasher, Digest, NeedFragmentId, NeedId,
    NeedKey, TestTargetPackageKey,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const DERIVED_ACTION_STUDY_SCHEMA: &str = "needle.derived-action-study/1";
pub const DERIVED_ACTION_STUDY_ORACLES_SCHEMA: &str = "needle.derived-action-study-oracles/1";
pub const DERIVED_ACTION_STUDY_FORMAT_REVISION: u16 = 1;
pub const MAX_DERIVED_ACTION_STUDY_BYTES: usize = 1024 * 1024;
pub const MAX_DERIVED_ACTION_STUDY_TEXT_BYTES: usize = 4 * 1024;
pub const MAX_DERIVED_ACTION_STUDY_PATH_BYTES: usize = 512;
pub const MAX_DERIVED_ACTION_STUDY_ITEMS: usize = 64;
pub const MAX_DERIVED_ACTION_STUDY_PARTITIONS: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionStudySource {
    pub repository_url: String,
    pub base_sha: String,
    pub change_target_sha: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedActionStudyFreshExecution {
    ExternalModel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedActionStudyReuseExecution {
    OfflineValidatedReuse,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionStudyExecutionProfile {
    pub id: String,
    pub fresh_execution: DerivedActionStudyFreshExecution,
    pub reuse_execution: DerivedActionStudyReuseExecution,
    pub pair_seeds: Vec<u64>,
}

impl DerivedActionStudyExecutionProfile {
    pub fn digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"derived-action-study-execution-profile-v1");
        hasher.field_str(&self.id);
        hasher.field_u8(match self.fresh_execution {
            DerivedActionStudyFreshExecution::ExternalModel => 0,
        });
        hasher.field_u8(match self.reuse_execution {
            DerivedActionStudyReuseExecution::OfflineValidatedReuse => 0,
        });
        hasher.field_u16(self.pair_seeds.len().try_into().unwrap_or(u16::MAX));
        for seed in &self.pair_seeds {
            hash_u64(&mut hasher, *seed);
        }
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureStudyFixture {
    pub workspace_manifest: String,
    pub package_universe: Vec<TestTargetPackageKey>,
    pub requested_packages: Vec<String>,
    pub reuse_source_packages: Vec<Vec<String>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeStudySubjectKind {
    Implementation,
    Test,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeStudyRequirement {
    pub id: String,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeStudySubject {
    pub id: String,
    pub kind: ChangeStudySubjectKind,
    pub canonical_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeStudyComponent {
    pub id: String,
    pub requirement_id: String,
    pub subject_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpactStudyFixture {
    pub requirements: Vec<ChangeStudyRequirement>,
    pub subjects: Vec<ChangeStudySubject>,
    pub components: Vec<ChangeStudyComponent>,
    pub changed_paths: Vec<String>,
    pub focused_test_command: Vec<String>,
    pub requested_components: Vec<String>,
    pub reuse_source_components: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DerivedActionStudyFixture {
    ArchitectureBrief(ArchitectureStudyFixture),
    ChangeImpact(ChangeImpactStudyFixture),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionStudyTask {
    pub id: String,
    pub action: DerivedActionKind,
    pub scenario: DerivedActionReuseScenario,
    pub prompt: String,
    pub fixture: DerivedActionStudyFixture,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionStudy {
    pub format_revision: u16,
    pub schema: String,
    pub source: DerivedActionStudySource,
    pub execution_profile: DerivedActionStudyExecutionProfile,
    pub tasks: Vec<DerivedActionStudyTask>,
}

impl DerivedActionStudy {
    pub fn decode_json(bytes: &[u8]) -> Result<Self, DerivedActionStudyError> {
        validate_wire_bound("study.bytes", bytes)?;
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| DerivedActionStudyError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DerivedActionStudyError> {
        if self.format_revision != DERIVED_ACTION_STUDY_FORMAT_REVISION {
            return Err(DerivedActionStudyError::FormatRevision(self.format_revision));
        }
        if self.schema != DERIVED_ACTION_STUDY_SCHEMA {
            return Err(DerivedActionStudyError::Schema("study.schema"));
        }
        validate_source(&self.source)?;
        validate_identifier("study.execution_profile.id", &self.execution_profile.id)?;
        validate_sorted_unique_seeds(&self.execution_profile.pair_seeds)?;
        validate_task_coverage(&self.tasks)?;
        for task in &self.tasks {
            validate_task(task)?;
        }
        Ok(())
    }

    pub fn gate_manifest(
        &self,
        evidence_class: DerivedActionEvidenceClass,
        oracles: &DerivedActionStudyOracleBundle,
    ) -> Result<DerivedActionGateManifest, DerivedActionStudyError> {
        self.validate()?;
        oracles.validate_for(self)?;
        let oracle_by_task = oracles
            .tasks
            .iter()
            .map(|oracle| (oracle.task_id.as_str(), oracle))
            .collect::<BTreeMap<_, _>>();
        let mut tasks = Vec::with_capacity(self.tasks.len());
        for task in &self.tasks {
            let oracle = oracle_by_task
                .get(task.id.as_str())
                .ok_or_else(|| DerivedActionStudyError::OracleBinding(task.id.clone()))?;
            tasks.push(DerivedActionGateTask::new(
                task.id.as_str(),
                task.action,
                task.scenario,
                self.semantic_request_digest(task)?,
                self.fixture_digest(task),
                oracle.commitment(),
                self.execution_profile.digest(),
                self.execution_profile.pair_seeds.clone(),
            )?);
        }
        Ok(DerivedActionGateManifest::new(evidence_class, self.source.base_sha.clone(), tasks)?)
    }

    pub fn fixture_digest(&self, task: &DerivedActionStudyTask) -> Digest {
        let mut hasher = CanonicalHasher::new(b"derived-action-study-fixture-v1");
        hash_task_source(&mut hasher, &self.source, task.action);
        hasher.field_str(&task.id);
        hasher.field_u8(action_tag(task.action));
        hasher.field_u8(scenario_tag(task.scenario));
        hasher.field_normalized_lines(&task.prompt);
        hash_fixture(&mut hasher, &task.fixture, true);
        hasher.finish()
    }

    pub fn semantic_fragment_digest(&self, task: &DerivedActionStudyTask) -> Digest {
        let mut hasher = CanonicalHasher::new(b"derived-action-study-semantic-fragment-v1");
        hash_task_source(&mut hasher, &self.source, task.action);
        hasher.field_u8(action_tag(task.action));
        hash_fixture(&mut hasher, &task.fixture, false);
        hasher.finish()
    }

    pub fn semantic_request_digest(
        &self,
        task: &DerivedActionStudyTask,
    ) -> Result<Digest, DerivedActionStudyError> {
        let kind = match task.action {
            DerivedActionKind::ArchitectureBrief => ArtifactKind::architecture_brief(),
            DerivedActionKind::ChangeImpact => ArtifactKind::change_impact(),
        };
        let definition = needle_runtime::built_in_action_for_artifact_kind(&kind)
            .ok_or(DerivedActionStudyError::ActionDefinition)?;
        let fragment = self.semantic_fragment_digest(task);
        let route = NeedKey::new(definition.contract.id.as_str())
            .map_err(|_| DerivedActionStudyError::ActionDefinition)?;
        let request = ActionRequest::new(
            &definition.contract,
            ArtifactRequest {
                contract_id: definition.output_contract_id.to_owned(),
                contract_revision: definition.output_contract_revision,
                repository_id: Digest::blake3(self.source.repository_url.as_bytes()),
                source_snapshot_digest: Digest::blake3(self.source.base_sha.as_bytes()),
                route_key: route.clone(),
                normalized_request: task.prompt.clone(),
                semantic_fragment_id: Some(NeedFragmentId::new(fragment)),
                input_artifact_ids: Vec::new(),
            },
            definition.contract.default_dispatch_policy,
            route,
            NeedId::new(fragment),
        )?;
        Ok(request.semantic_id().digest())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionStudyOracle {
    pub task_id: String,
    pub required_findings: Vec<String>,
    pub required_evidence_paths: Vec<String>,
    pub forbidden_claims: Vec<String>,
    pub reviewer_checks: Vec<String>,
}

impl DerivedActionStudyOracle {
    pub fn commitment(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"derived-action-study-oracle-v1");
        hasher.field_str(&self.task_id);
        hash_strings(&mut hasher, &self.required_findings, true);
        hash_strings(&mut hasher, &self.required_evidence_paths, false);
        hash_strings(&mut hasher, &self.forbidden_claims, true);
        hash_strings(&mut hasher, &self.reviewer_checks, true);
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionStudyOracleBundle {
    pub format_revision: u16,
    pub schema: String,
    pub tasks: Vec<DerivedActionStudyOracle>,
}

impl DerivedActionStudyOracleBundle {
    pub fn decode_json(bytes: &[u8]) -> Result<Self, DerivedActionStudyError> {
        validate_wire_bound("oracles.bytes", bytes)?;
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| DerivedActionStudyError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DerivedActionStudyError> {
        if self.format_revision != DERIVED_ACTION_STUDY_FORMAT_REVISION {
            return Err(DerivedActionStudyError::FormatRevision(self.format_revision));
        }
        if self.schema != DERIVED_ACTION_STUDY_ORACLES_SCHEMA {
            return Err(DerivedActionStudyError::Schema("oracles.schema"));
        }
        validate_collection("oracles.tasks", self.tasks.len(), 6, MAX_DERIVED_ACTION_STUDY_ITEMS)?;
        if self.tasks.windows(2).any(|pair| pair[0].task_id >= pair[1].task_id) {
            return Err(DerivedActionStudyError::Canonical("oracles.tasks"));
        }
        for oracle in &self.tasks {
            validate_identifier("oracle.task_id", &oracle.task_id)?;
            validate_text_set("oracle.required_findings", &oracle.required_findings)?;
            validate_path_set("oracle.required_evidence_paths", &oracle.required_evidence_paths)?;
            validate_text_set("oracle.forbidden_claims", &oracle.forbidden_claims)?;
            validate_text_set("oracle.reviewer_checks", &oracle.reviewer_checks)?;
        }
        Ok(())
    }

    pub fn validate_for(&self, study: &DerivedActionStudy) -> Result<(), DerivedActionStudyError> {
        self.validate()?;
        let study_ids = study.tasks.iter().map(|task| &task.id).collect::<Vec<_>>();
        let oracle_ids = self.tasks.iter().map(|task| &task.task_id).collect::<Vec<_>>();
        if study_ids != oracle_ids {
            return Err(DerivedActionStudyError::OracleCoverage);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum DerivedActionStudyError {
    #[error("derived-action study bound exceeded for {field}: {actual} > {maximum}")]
    Bound { field: &'static str, actual: usize, maximum: usize },
    #[error("derived-action study JSON is invalid: {0}")]
    Json(String),
    #[error("unsupported derived-action study format revision {0}")]
    FormatRevision(u16),
    #[error("unsupported schema in {0}")]
    Schema(&'static str),
    #[error("invalid derived-action study text in {0}")]
    Text(&'static str),
    #[error("invalid derived-action study source")]
    Source,
    #[error("invalid derived-action study path in {0}")]
    Path(&'static str),
    #[error("non-canonical derived-action study collection {0}")]
    Canonical(&'static str),
    #[error("derived-action study must cover all six action/scenario tasks")]
    ScenarioCoverage,
    #[error("invalid {0:?} scenario shape for task {1}")]
    ScenarioShape(DerivedActionReuseScenario, String),
    #[error("derived-action study fixture does not match action for task {0}")]
    ActionFixture(String),
    #[error("derived-action study oracle coverage does not match task coverage")]
    OracleCoverage,
    #[error("derived-action study oracle missing for task {0}")]
    OracleBinding(String),
    #[error("built-in action definition is unavailable")]
    ActionDefinition,
    #[error(transparent)]
    Gate(#[from] DerivedActionGateError),
    #[error(transparent)]
    Action(#[from] needle_core::ActionValidationError),
}

fn validate_wire_bound(field: &'static str, bytes: &[u8]) -> Result<(), DerivedActionStudyError> {
    if bytes.len() > MAX_DERIVED_ACTION_STUDY_BYTES {
        return Err(DerivedActionStudyError::Bound {
            field,
            actual: bytes.len(),
            maximum: MAX_DERIVED_ACTION_STUDY_BYTES,
        });
    }
    Ok(())
}

fn validate_source(source: &DerivedActionStudySource) -> Result<(), DerivedActionStudyError> {
    let url = source.repository_url.as_bytes();
    if url.is_empty()
        || url.len() > MAX_DERIVED_ACTION_STUDY_TEXT_BYTES
        || !source.repository_url.starts_with("https://")
        || source.repository_url.chars().any(char::is_control)
        || source.base_sha == source.change_target_sha
        || validate_repository_sha(&source.base_sha).is_err()
        || validate_repository_sha(&source.change_target_sha).is_err()
    {
        return Err(DerivedActionStudyError::Source);
    }
    Ok(())
}

fn validate_sorted_unique_seeds(seeds: &[u64]) -> Result<(), DerivedActionStudyError> {
    validate_collection(
        "study.execution_profile.pair_seeds",
        seeds.len(),
        1,
        MAX_DERIVED_ACTION_GATE_PAIR_SEEDS,
    )?;
    if seeds.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DerivedActionStudyError::Canonical("study.execution_profile.pair_seeds"));
    }
    Ok(())
}

fn validate_task_coverage(tasks: &[DerivedActionStudyTask]) -> Result<(), DerivedActionStudyError> {
    validate_collection("study.tasks", tasks.len(), 6, MAX_DERIVED_ACTION_STUDY_ITEMS)?;
    if tasks.windows(2).any(|pair| pair[0].id >= pair[1].id) {
        return Err(DerivedActionStudyError::Canonical("study.tasks"));
    }
    let actual = tasks.iter().map(|task| (task.action, task.scenario)).collect::<BTreeSet<_>>();
    let expected = DerivedActionKind::ALL
        .into_iter()
        .flat_map(|action| {
            DerivedActionReuseScenario::ALL.into_iter().map(move |scenario| (action, scenario))
        })
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(DerivedActionStudyError::ScenarioCoverage);
    }
    Ok(())
}

fn validate_task(task: &DerivedActionStudyTask) -> Result<(), DerivedActionStudyError> {
    validate_identifier("study.task.id", &task.id)?;
    validate_text("study.task.prompt", &task.prompt)?;
    match (task.action, &task.fixture) {
        (
            DerivedActionKind::ArchitectureBrief,
            DerivedActionStudyFixture::ArchitectureBrief(value),
        ) => validate_architecture_fixture(task, value),
        (DerivedActionKind::ChangeImpact, DerivedActionStudyFixture::ChangeImpact(value)) => {
            validate_change_fixture(task, value)
        }
        _ => Err(DerivedActionStudyError::ActionFixture(task.id.clone())),
    }
}

fn validate_architecture_fixture(
    task: &DerivedActionStudyTask,
    fixture: &ArchitectureStudyFixture,
) -> Result<(), DerivedActionStudyError> {
    validate_path("architecture.workspace_manifest", &fixture.workspace_manifest)?;
    validate_collection(
        "architecture.package_universe",
        fixture.package_universe.len(),
        1,
        MAX_DERIVED_ACTION_STUDY_ITEMS,
    )?;
    if fixture.package_universe.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DerivedActionStudyError::Canonical("architecture.package_universe"));
    }
    for package in &fixture.package_universe {
        package
            .validate()
            .map_err(|_| DerivedActionStudyError::Canonical("architecture.package_universe"))?;
    }
    let universe = fixture
        .package_universe
        .iter()
        .map(|package| package.name.clone())
        .collect::<BTreeSet<_>>();
    let requested = validate_scope_set(
        "architecture.requested_packages",
        &fixture.requested_packages,
        &universe,
    )?;
    let sources = validate_partition_sets(
        "architecture.reuse_source_packages",
        &fixture.reuse_source_packages,
        &universe,
    )?;
    validate_scenario_shape(task, &requested, &sources, universe.len())
}

fn validate_change_fixture(
    task: &DerivedActionStudyTask,
    fixture: &ChangeImpactStudyFixture,
) -> Result<(), DerivedActionStudyError> {
    validate_collection(
        "change.requirements",
        fixture.requirements.len(),
        1,
        MAX_DERIVED_ACTION_STUDY_ITEMS,
    )?;
    validate_collection(
        "change.subjects",
        fixture.subjects.len(),
        1,
        MAX_DERIVED_ACTION_STUDY_ITEMS,
    )?;
    validate_collection(
        "change.components",
        fixture.components.len(),
        1,
        MAX_DERIVED_ACTION_STUDY_ITEMS,
    )?;
    if fixture.requirements.windows(2).any(|pair| pair[0].id >= pair[1].id)
        || fixture.subjects.windows(2).any(|pair| pair[0].id >= pair[1].id)
        || fixture.components.windows(2).any(|pair| pair[0].id >= pair[1].id)
    {
        return Err(DerivedActionStudyError::Canonical("change.definitions"));
    }
    let requirement_ids =
        fixture.requirements.iter().map(|item| item.id.as_str()).collect::<BTreeSet<_>>();
    let subject_ids = fixture.subjects.iter().map(|item| item.id.as_str()).collect::<BTreeSet<_>>();
    for requirement in &fixture.requirements {
        validate_identifier("change.requirement.id", &requirement.id)?;
        validate_text("change.requirement.text", &requirement.text)?;
    }
    for subject in &fixture.subjects {
        validate_identifier("change.subject.id", &subject.id)?;
        validate_text("change.subject.canonical_name", &subject.canonical_name)?;
    }
    for component in &fixture.components {
        validate_identifier("change.component.id", &component.id)?;
        if !requirement_ids.contains(component.requirement_id.as_str())
            || !subject_ids.contains(component.subject_id.as_str())
        {
            return Err(DerivedActionStudyError::Canonical("change.components"));
        }
    }
    validate_path_set("change.changed_paths", &fixture.changed_paths)?;
    validate_text_sequence("change.focused_test_command", &fixture.focused_test_command)?;
    let universe = fixture.components.iter().map(|item| item.id.clone()).collect::<BTreeSet<_>>();
    let requested = validate_scope_set(
        "change.requested_components",
        &fixture.requested_components,
        &universe,
    )?;
    let sources = validate_partition_sets(
        "change.reuse_source_components",
        &fixture.reuse_source_components,
        &universe,
    )?;
    validate_scenario_shape(task, &requested, &sources, universe.len())
}

fn validate_scope_set(
    field: &'static str,
    values: &[String],
    universe: &BTreeSet<String>,
) -> Result<BTreeSet<String>, DerivedActionStudyError> {
    validate_canonical_strings(field, values, true)?;
    if values.iter().any(|value| !universe.contains(value)) {
        return Err(DerivedActionStudyError::Canonical(field));
    }
    Ok(if values.is_empty() { universe.clone() } else { values.iter().cloned().collect() })
}

fn validate_partition_sets(
    field: &'static str,
    values: &[Vec<String>],
    universe: &BTreeSet<String>,
) -> Result<Vec<BTreeSet<String>>, DerivedActionStudyError> {
    validate_collection(field, values.len(), 1, MAX_DERIVED_ACTION_STUDY_PARTITIONS)?;
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DerivedActionStudyError::Canonical(field));
    }
    values.iter().map(|value| validate_scope_set(field, value, universe)).collect()
}

fn validate_scenario_shape(
    task: &DerivedActionStudyTask,
    requested: &BTreeSet<String>,
    sources: &[BTreeSet<String>],
    universe_len: usize,
) -> Result<(), DerivedActionStudyError> {
    let valid = match task.scenario {
        DerivedActionReuseScenario::Exact => sources.len() == 1 && sources[0] == *requested,
        DerivedActionReuseScenario::Project => {
            sources.len() == 1
                && requested.len() < universe_len
                && requested.is_subset(&sources[0])
                && requested != &sources[0]
        }
        DerivedActionReuseScenario::Assemble => {
            if sources.len() < 2 || sources.iter().any(BTreeSet::is_empty) {
                false
            } else {
                let mut union = BTreeSet::new();
                sources.iter().all(|source| source.iter().all(|item| union.insert(item.clone())))
                    && union == *requested
            }
        }
    };
    if valid {
        Ok(())
    } else {
        Err(DerivedActionStudyError::ScenarioShape(task.scenario, task.id.clone()))
    }
}

fn validate_collection(
    field: &'static str,
    actual: usize,
    minimum: usize,
    maximum: usize,
) -> Result<(), DerivedActionStudyError> {
    if actual < minimum {
        return Err(DerivedActionStudyError::Canonical(field));
    }
    if actual > maximum {
        return Err(DerivedActionStudyError::Bound { field, actual, maximum });
    }
    Ok(())
}

fn validate_text(field: &'static str, value: &str) -> Result<(), DerivedActionStudyError> {
    if value.trim().is_empty()
        || value.len() > MAX_DERIVED_ACTION_STUDY_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(DerivedActionStudyError::Text(field));
    }
    Ok(())
}

fn validate_path(field: &'static str, value: &str) -> Result<(), DerivedActionStudyError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_DERIVED_ACTION_STUDY_PATH_BYTES
        || value.starts_with('/')
        || value.contains('\\')
        || value.split('/').any(|component| component.is_empty() || matches!(component, "." | ".."))
        || value.chars().any(char::is_control)
    {
        return Err(DerivedActionStudyError::Path(field));
    }
    Ok(())
}

fn validate_path_set(
    field: &'static str,
    values: &[String],
) -> Result<(), DerivedActionStudyError> {
    validate_collection(field, values.len(), 1, MAX_DERIVED_ACTION_STUDY_ITEMS)?;
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DerivedActionStudyError::Canonical(field));
    }
    for value in values {
        validate_path(field, value)?;
    }
    Ok(())
}

fn validate_text_set(
    field: &'static str,
    values: &[String],
) -> Result<(), DerivedActionStudyError> {
    validate_collection(field, values.len(), 1, MAX_DERIVED_ACTION_STUDY_ITEMS)?;
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DerivedActionStudyError::Canonical(field));
    }
    for value in values {
        validate_text(field, value)?;
    }
    Ok(())
}

fn validate_text_sequence(
    field: &'static str,
    values: &[String],
) -> Result<(), DerivedActionStudyError> {
    validate_collection(field, values.len(), 1, MAX_DERIVED_ACTION_STUDY_ITEMS)?;
    for value in values {
        validate_text(field, value)?;
    }
    Ok(())
}

fn validate_canonical_strings(
    field: &'static str,
    values: &[String],
    allow_empty: bool,
) -> Result<(), DerivedActionStudyError> {
    if (!allow_empty && values.is_empty()) || values.len() > MAX_DERIVED_ACTION_STUDY_ITEMS {
        return Err(DerivedActionStudyError::Bound {
            field,
            actual: values.len(),
            maximum: MAX_DERIVED_ACTION_STUDY_ITEMS,
        });
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DerivedActionStudyError::Canonical(field));
    }
    for value in values {
        validate_identifier(field, value)?;
    }
    Ok(())
}

fn hash_task_source(
    hasher: &mut CanonicalHasher,
    source: &DerivedActionStudySource,
    action: DerivedActionKind,
) {
    hasher.field_str(&source.repository_url);
    hasher.field_str(&source.base_sha);
    if action == DerivedActionKind::ChangeImpact {
        hasher.field_str(&source.change_target_sha);
    }
}

fn hash_fixture(
    hasher: &mut CanonicalHasher,
    fixture: &DerivedActionStudyFixture,
    include_reuse_shape: bool,
) {
    match fixture {
        DerivedActionStudyFixture::ArchitectureBrief(value) => {
            hasher.field_u8(0);
            hasher.field_str(&value.workspace_manifest);
            hasher.field_u16(value.package_universe.len().try_into().unwrap_or(u16::MAX));
            for package in &value.package_universe {
                hasher.field_str(&package.name);
                hasher.field_str(&package.manifest_path);
            }
            hash_strings(hasher, &value.requested_packages, false);
            if include_reuse_shape {
                hash_partitions(hasher, &value.reuse_source_packages);
            }
        }
        DerivedActionStudyFixture::ChangeImpact(value) => {
            hasher.field_u8(1);
            hasher.field_u16(value.requirements.len().try_into().unwrap_or(u16::MAX));
            for requirement in &value.requirements {
                hasher.field_str(&requirement.id);
                hasher.field_normalized_lines(&requirement.text);
            }
            hasher.field_u16(value.subjects.len().try_into().unwrap_or(u16::MAX));
            for subject in &value.subjects {
                hasher.field_str(&subject.id);
                hasher.field_u8(match subject.kind {
                    ChangeStudySubjectKind::Implementation => 0,
                    ChangeStudySubjectKind::Test => 1,
                });
                hasher.field_str(&subject.canonical_name);
            }
            hasher.field_u16(value.components.len().try_into().unwrap_or(u16::MAX));
            for component in &value.components {
                hasher.field_str(&component.id);
                hasher.field_str(&component.requirement_id);
                hasher.field_str(&component.subject_id);
            }
            hash_strings(hasher, &value.changed_paths, false);
            hash_strings(hasher, &value.requested_components, false);
            if include_reuse_shape {
                hash_strings(hasher, &value.focused_test_command, true);
                hash_partitions(hasher, &value.reuse_source_components);
            }
        }
    }
}

fn hash_partitions(hasher: &mut CanonicalHasher, values: &[Vec<String>]) {
    hasher.field_u16(values.len().try_into().unwrap_or(u16::MAX));
    for value in values {
        hash_strings(hasher, value, false);
    }
}

fn hash_strings(hasher: &mut CanonicalHasher, values: &[String], normalize: bool) {
    hasher.field_u16(values.len().try_into().unwrap_or(u16::MAX));
    for value in values {
        if normalize {
            hasher.field_normalized_lines(value);
        } else {
            hasher.field_str(value);
        }
    }
}

fn hash_u64(hasher: &mut CanonicalHasher, value: u64) {
    hasher.field_u32((value >> 32) as u32);
    hasher.field_u32(value as u32);
}

#[cfg(test)]
mod tests {
    use super::*;

    const STUDY: &[u8] =
        include_bytes!("../../../../benchmarks/corpus/derived-actions/thiserror/study.json");
    const ORACLES: &[u8] = include_bytes!(
        "../../../../benchmarks/corpus/derived-actions/thiserror/sealed-oracles.json"
    );
    const MANIFEST: &[u8] = include_bytes!(
        "../../../../benchmarks/corpus/derived-actions/thiserror/gate-a3-manifest.json"
    );

    #[test]
    fn checked_in_thiserror_study_is_complete_and_commitment_bound() {
        let study = DerivedActionStudy::decode_json(STUDY).unwrap();
        let oracles = DerivedActionStudyOracleBundle::decode_json(ORACLES).unwrap();
        let generated =
            study.gate_manifest(DerivedActionEvidenceClass::AcceptedShadow, &oracles).unwrap();
        let checked = DerivedActionGateManifest::decode_json(MANIFEST).unwrap();
        assert_eq!(checked, generated);
        assert_eq!(checked.repository_sha, study.source.base_sha);
        assert_eq!(checked.tasks.len(), 6);

        let architecture_exact =
            checked.tasks.iter().find(|task| task.id == "architecture-exact").unwrap();
        let architecture_assemble =
            checked.tasks.iter().find(|task| task.id == "architecture-assemble").unwrap();
        let change_exact =
            checked.tasks.iter().find(|task| task.id == "change-impact-exact").unwrap();
        let change_assemble =
            checked.tasks.iter().find(|task| task.id == "change-impact-assemble").unwrap();
        assert_eq!(
            architecture_exact.semantic_request_digest,
            architecture_assemble.semantic_request_digest
        );
        assert_eq!(change_exact.semantic_request_digest, change_assemble.semantic_request_digest);
        assert_ne!(architecture_exact.fixture_digest, architecture_assemble.fixture_digest);
        assert_ne!(change_exact.fixture_digest, change_assemble.fixture_digest);
    }

    #[test]
    fn study_wire_and_scenario_shapes_fail_closed() {
        let study = DerivedActionStudy::decode_json(STUDY).unwrap();
        let mut unknown = serde_json::to_value(&study).unwrap();
        unknown.as_object_mut().unwrap().insert("unknown".to_owned(), serde_json::json!(true));
        assert!(DerivedActionStudy::decode_json(&serde_json::to_vec(&unknown).unwrap()).is_err());
        assert!(matches!(
            DerivedActionStudy::decode_json(&vec![b'x'; MAX_DERIVED_ACTION_STUDY_BYTES + 1]),
            Err(DerivedActionStudyError::Bound { field: "study.bytes", .. })
        ));

        let mut invalid = study;
        let task =
            invalid.tasks.iter_mut().find(|task| task.id == "architecture-assemble").unwrap();
        let DerivedActionStudyFixture::ArchitectureBrief(fixture) = &mut task.fixture else {
            unreachable!();
        };
        fixture.reuse_source_packages.pop();
        assert!(matches!(
            invalid.validate(),
            Err(DerivedActionStudyError::ScenarioShape(DerivedActionReuseScenario::Assemble, _))
        ));
    }
}
