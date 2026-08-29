mod architecture;
mod change;

use super::{
    ArchitectureStudyFixture, ChangeImpactStudyFixture, DerivedActionEvidenceClass,
    DerivedActionGateManifest, DerivedActionKind, DerivedActionReuseScenario, DerivedActionStudy,
    DerivedActionStudyError, DerivedActionStudyFixture, DerivedActionStudyTask,
    MAX_DERIVED_ACTION_GATE_REVIEW_MATERIAL_BYTES, MAX_DERIVED_ACTION_STUDY_ITEMS,
};
use architecture::{architecture_scope, build_architecture_output, validate_architecture_output};
use change::{build_change_output, change_scope, validate_change_output};
use needle_core::{
    ArchitectureAssertionKind, ArchitectureBrief, ChangeImpact, ChangeImpactDisposition,
    ChangeImpactEvidenceRole, ChangeImpactEvidenceState, ChangeImpactKind, Digest,
};
use needle_runtime::{
    ArchitectureBriefValidationCertificate, ChangeImpactValidationCertificate,
    assemble_architecture_briefs, assemble_change_impacts, project_architecture_brief,
    project_change_impact,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;
use thiserror::Error;

pub const DERIVED_ACTION_PUBLIC_RUN_SCHEMA: &str = "needle.derived-action-public-run/1";
pub const DERIVED_ACTION_EXTERNAL_RESULTS_SCHEMA: &str = "needle.derived-action-external-results/1";
pub const DERIVED_ACTION_REVIEW_MATERIAL_SCHEMA: &str = "needle.derived-action-review-material/1";
pub const DERIVED_ACTION_RUNNER_FORMAT_REVISION: u16 = 1;
pub const MAX_DERIVED_ACTION_EXTERNAL_RESULTS_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionPublicRun {
    pub format_revision: u16,
    pub schema: String,
    pub manifest_digest: Digest,
    pub repository_url: String,
    pub base_sha: String,
    pub change_target_sha: String,
    pub execution_profile_id: String,
    pub execution_profile_digest: Digest,
    pub tasks: Vec<DerivedActionPublicTask>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionPublicTask {
    pub id: String,
    pub action: DerivedActionKind,
    pub scenario: DerivedActionReuseScenario,
    pub semantic_request_digest: Digest,
    pub fixture_digest: Digest,
    pub prompt: String,
    pub fixture: DerivedActionStudyFixture,
    pub response_template: DerivedActionExternalDraft,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionExternalResults {
    pub format_revision: u16,
    pub schema: String,
    pub manifest_digest: Digest,
    pub tasks: Vec<DerivedActionExternalTaskResult>,
}

impl DerivedActionExternalResults {
    pub fn decode_json(bytes: &[u8]) -> Result<Self, DerivedActionRunnerError> {
        validate_wire_bound(
            "external_results.bytes",
            bytes,
            MAX_DERIVED_ACTION_EXTERNAL_RESULTS_BYTES,
        )?;
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| DerivedActionRunnerError::Json(error.to_string()))?;
        value.validate_shape()?;
        Ok(value)
    }

    fn validate_shape(&self) -> Result<(), DerivedActionRunnerError> {
        if self.format_revision != DERIVED_ACTION_RUNNER_FORMAT_REVISION {
            return Err(DerivedActionRunnerError::FormatRevision(self.format_revision));
        }
        if self.schema != DERIVED_ACTION_EXTERNAL_RESULTS_SCHEMA {
            return Err(DerivedActionRunnerError::Schema("external_results.schema"));
        }
        if self.tasks.len() > MAX_DERIVED_ACTION_STUDY_ITEMS
            || self.tasks.windows(2).any(|pair| pair[0].task_id >= pair[1].task_id)
        {
            return Err(DerivedActionRunnerError::Canonical("external_results.tasks"));
        }
        for task in &self.tasks {
            validate_label("external_results.task_id", &task.task_id)?;
            validate_label("external_results.model_id", &task.model_id)?;
            if task.latency_micros == 0 {
                return Err(DerivedActionRunnerError::Metric(task.task_id.clone()));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionExternalTaskResult {
    pub task_id: String,
    pub model_id: String,
    pub latency_micros: u64,
    pub total_cost_microcredits: u64,
    pub output: DerivedActionExternalDraft,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DerivedActionExternalDraft {
    ArchitectureBrief(ArchitectureBriefDraft),
    ChangeImpact(ChangeImpactDraft),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureBriefDraft {
    pub packages: Vec<ArchitecturePackageDraft>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitecturePackageDraft {
    pub package: String,
    pub summary: String,
    pub summary_evidence_paths: Vec<String>,
    pub assertions: Vec<ArchitectureAssertionDraft>,
    pub gaps: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureAssertionDraft {
    pub kind: ArchitectureAssertionKind,
    pub text: String,
    pub evidence_paths: Vec<String>,
    pub related_packages: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpactDraft {
    pub assessments: Vec<ChangeImpactAssessmentDraft>,
    pub gaps: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpactAssessmentDraft {
    pub component: String,
    pub disposition: ChangeImpactDisposition,
    pub impact_kinds: Vec<ChangeImpactKind>,
    pub rationale: String,
    pub evidence: Vec<ChangeImpactEvidenceDraft>,
    pub affected_paths: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpactEvidenceDraft {
    pub path: String,
    pub state: ChangeImpactEvidenceState,
    pub roles: Vec<ChangeImpactEvidenceRole>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedActionChangedFile {
    pub path: String,
    pub before: Option<Vec<u8>>,
    pub after: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedActionSourceMaterial {
    pub repository_root: PathBuf,
    pub changes: Vec<DerivedActionChangedFile>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionReviewMaterial {
    pub format_revision: u16,
    pub schema: String,
    pub manifest_digest: Digest,
    pub repository_url: String,
    pub base_sha: String,
    pub change_target_sha: String,
    pub tasks: Vec<DerivedActionTaskReview>,
}

impl DerivedActionReviewMaterial {
    pub fn decode_json(bytes: &[u8]) -> Result<Self, DerivedActionRunnerError> {
        validate_wire_bound(
            "review_material.bytes",
            bytes,
            MAX_DERIVED_ACTION_GATE_REVIEW_MATERIAL_BYTES,
        )?;
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| DerivedActionRunnerError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DerivedActionRunnerError> {
        if self.format_revision != DERIVED_ACTION_RUNNER_FORMAT_REVISION {
            return Err(DerivedActionRunnerError::FormatRevision(self.format_revision));
        }
        if self.schema != DERIVED_ACTION_REVIEW_MATERIAL_SCHEMA {
            return Err(DerivedActionRunnerError::Schema("review_material.schema"));
        }
        if self.tasks.is_empty()
            || self.tasks.len() > MAX_DERIVED_ACTION_STUDY_ITEMS
            || self.tasks.windows(2).any(|pair| pair[0].task_id >= pair[1].task_id)
        {
            return Err(DerivedActionRunnerError::Canonical("review_material.tasks"));
        }
        for task in &self.tasks {
            task.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionTaskReview {
    pub task_id: String,
    pub action: DerivedActionKind,
    pub scenario: DerivedActionReuseScenario,
    pub model_id: String,
    pub fresh_latency_micros: u64,
    pub fresh_total_cost_microcredits: u64,
    pub reuse_latency_micros: u64,
    pub canonical_output_equal: bool,
    pub fresh: DerivedActionValidatedOutput,
    pub reuse: DerivedActionValidatedOutput,
}

impl DerivedActionTaskReview {
    fn validate(&self) -> Result<(), DerivedActionRunnerError> {
        validate_label("review.task_id", &self.task_id)?;
        validate_label("review.model_id", &self.model_id)?;
        if self.fresh_latency_micros == 0 || self.reuse_latency_micros == 0 {
            return Err(DerivedActionRunnerError::Metric(self.task_id.clone()));
        }
        if self.fresh.action() != self.action || self.reuse.action() != self.action {
            return Err(DerivedActionRunnerError::Binding(self.task_id.clone()));
        }
        self.fresh.validate()?;
        self.reuse.validate()?;
        if self.canonical_output_equal != (self.fresh.output_digest() == self.reuse.output_digest())
        {
            return Err(DerivedActionRunnerError::Binding(self.task_id.clone()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DerivedActionValidatedOutput {
    ArchitectureBrief {
        artifact: Box<ArchitectureBrief>,
        certificate: ArchitectureBriefValidationCertificate,
    },
    ChangeImpact {
        artifact: Box<ChangeImpact>,
        certificate: ChangeImpactValidationCertificate,
    },
}

impl DerivedActionValidatedOutput {
    pub fn action(&self) -> DerivedActionKind {
        match self {
            Self::ArchitectureBrief { .. } => DerivedActionKind::ArchitectureBrief,
            Self::ChangeImpact { .. } => DerivedActionKind::ChangeImpact,
        }
    }

    pub fn output_digest(&self) -> Digest {
        match self {
            Self::ArchitectureBrief { artifact, .. } => artifact.content_digest,
            Self::ChangeImpact { artifact, .. } => artifact.content_digest,
        }
    }

    pub fn certificate_digest(&self) -> Digest {
        match self {
            Self::ArchitectureBrief { certificate, .. } => certificate.id,
            Self::ChangeImpact { certificate, .. } => certificate.id,
        }
    }

    fn validate(&self) -> Result<(), DerivedActionRunnerError> {
        match self {
            Self::ArchitectureBrief { artifact, certificate } => {
                artifact.validate().map_err(artifact_error)?;
                certificate.validate().map_err(artifact_error)?;
                if certificate.brief != artifact.content_digest {
                    return Err(DerivedActionRunnerError::Binding(
                        "architecture certificate".to_owned(),
                    ));
                }
            }
            Self::ChangeImpact { artifact, certificate } => {
                artifact.validate().map_err(artifact_error)?;
                certificate.validate().map_err(artifact_error)?;
                if certificate.impact != artifact.content_digest {
                    return Err(DerivedActionRunnerError::Binding(
                        "change-impact certificate".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

pub fn derived_action_public_run(
    study: &DerivedActionStudy,
    manifest: &DerivedActionGateManifest,
) -> Result<DerivedActionPublicRun, DerivedActionRunnerError> {
    validate_manifest_binding(study, manifest)?;
    let gate_tasks =
        manifest.tasks.iter().map(|task| (task.id.as_str(), task)).collect::<BTreeMap<_, _>>();
    let tasks = study
        .tasks
        .iter()
        .map(|task| {
            let gate = gate_tasks
                .get(task.id.as_str())
                .ok_or_else(|| DerivedActionRunnerError::Binding(task.id.clone()))?;
            Ok(DerivedActionPublicTask {
                id: task.id.clone(),
                action: task.action,
                scenario: task.scenario,
                semantic_request_digest: gate.semantic_request_digest,
                fixture_digest: gate.fixture_digest,
                prompt: task.prompt.clone(),
                fixture: task.fixture.clone(),
                response_template: response_template(task)?,
            })
        })
        .collect::<Result<Vec<_>, DerivedActionRunnerError>>()?;
    Ok(DerivedActionPublicRun {
        format_revision: DERIVED_ACTION_RUNNER_FORMAT_REVISION,
        schema: DERIVED_ACTION_PUBLIC_RUN_SCHEMA.to_owned(),
        manifest_digest: manifest.manifest_digest,
        repository_url: study.source.repository_url.clone(),
        base_sha: study.source.base_sha.clone(),
        change_target_sha: study.source.change_target_sha.clone(),
        execution_profile_id: study.execution_profile.id.clone(),
        execution_profile_digest: study.execution_profile.digest(),
        tasks,
    })
}

impl DerivedActionPublicRun {
    pub fn decode_json(bytes: &[u8]) -> Result<Self, DerivedActionRunnerError> {
        validate_wire_bound(
            "public_run.bytes",
            bytes,
            MAX_DERIVED_ACTION_GATE_REVIEW_MATERIAL_BYTES,
        )?;
        serde_json::from_slice(bytes)
            .map_err(|error| DerivedActionRunnerError::Json(error.to_string()))
    }
}

pub fn import_derived_action_results(
    study: &DerivedActionStudy,
    manifest: &DerivedActionGateManifest,
    public_run: &DerivedActionPublicRun,
    external: &DerivedActionExternalResults,
    source: &DerivedActionSourceMaterial,
) -> Result<DerivedActionReviewMaterial, DerivedActionRunnerError> {
    let expected_public = derived_action_public_run(study, manifest)?;
    if public_run != &expected_public {
        return Err(DerivedActionRunnerError::Binding("public run".to_owned()));
    }
    external.validate_shape()?;
    if external.manifest_digest != manifest.manifest_digest {
        return Err(DerivedActionRunnerError::Binding("external manifest".to_owned()));
    }
    validate_source_material(study, source)?;
    let external_by_task =
        external.tasks.iter().map(|task| (task.task_id.as_str(), task)).collect::<BTreeMap<_, _>>();
    if external_by_task.len() != study.tasks.len()
        || study.tasks.iter().any(|task| !external_by_task.contains_key(task.id.as_str()))
    {
        return Err(DerivedActionRunnerError::Binding("external task set".to_owned()));
    }

    let mut fresh = BTreeMap::<String, DerivedActionValidatedOutput>::new();
    for task in &study.tasks {
        let result = external_by_task
            .get(task.id.as_str())
            .ok_or_else(|| DerivedActionRunnerError::Binding(task.id.clone()))?;
        fresh.insert(task.id.clone(), build_fresh_output(study, task, &result.output, source)?);
    }
    let architecture_exact =
        exact_output(&study.tasks, &fresh, DerivedActionKind::ArchitectureBrief)?.clone();
    let change_exact = exact_output(&study.tasks, &fresh, DerivedActionKind::ChangeImpact)?.clone();

    let mut tasks = Vec::with_capacity(study.tasks.len());
    for task in &study.tasks {
        let result = external_by_task
            .get(task.id.as_str())
            .ok_or_else(|| DerivedActionRunnerError::Binding(task.id.clone()))?;
        let start = Instant::now();
        let reuse = match task.action {
            DerivedActionKind::ArchitectureBrief => {
                reuse_architecture(study, task, &architecture_exact, source)?
            }
            DerivedActionKind::ChangeImpact => reuse_change(study, task, &change_exact, source)?,
        };
        let reuse_latency_micros =
            start.elapsed().as_micros().max(1).try_into().unwrap_or(u64::MAX);
        let fresh_output = fresh
            .remove(&task.id)
            .ok_or_else(|| DerivedActionRunnerError::Binding(task.id.clone()))?;
        tasks.push(DerivedActionTaskReview {
            task_id: task.id.clone(),
            action: task.action,
            scenario: task.scenario,
            model_id: result.model_id.clone(),
            fresh_latency_micros: result.latency_micros,
            fresh_total_cost_microcredits: result.total_cost_microcredits,
            reuse_latency_micros,
            canonical_output_equal: fresh_output.output_digest() == reuse.output_digest(),
            fresh: fresh_output,
            reuse,
        });
    }
    let material = DerivedActionReviewMaterial {
        format_revision: DERIVED_ACTION_RUNNER_FORMAT_REVISION,
        schema: DERIVED_ACTION_REVIEW_MATERIAL_SCHEMA.to_owned(),
        manifest_digest: manifest.manifest_digest,
        repository_url: study.source.repository_url.clone(),
        base_sha: study.source.base_sha.clone(),
        change_target_sha: study.source.change_target_sha.clone(),
        tasks,
    };
    material.validate()?;
    let encoded = serde_json::to_vec(&material)
        .map_err(|error| DerivedActionRunnerError::Json(error.to_string()))?;
    validate_wire_bound(
        "review_material.bytes",
        &encoded,
        MAX_DERIVED_ACTION_GATE_REVIEW_MATERIAL_BYTES,
    )?;
    Ok(material)
}

fn build_fresh_output(
    study: &DerivedActionStudy,
    task: &DerivedActionStudyTask,
    draft: &DerivedActionExternalDraft,
    source: &DerivedActionSourceMaterial,
) -> Result<DerivedActionValidatedOutput, DerivedActionRunnerError> {
    match (&task.fixture, draft) {
        (
            DerivedActionStudyFixture::ArchitectureBrief(fixture),
            DerivedActionExternalDraft::ArchitectureBrief(draft),
        ) => build_architecture_output(study, fixture, draft, &source.repository_root),
        (
            DerivedActionStudyFixture::ChangeImpact(fixture),
            DerivedActionExternalDraft::ChangeImpact(draft),
        ) => build_change_output(study, fixture, draft, source),
        _ => Err(DerivedActionRunnerError::Binding(task.id.clone())),
    }
}

fn exact_output<'a>(
    tasks: &[DerivedActionStudyTask],
    outputs: &'a BTreeMap<String, DerivedActionValidatedOutput>,
    action: DerivedActionKind,
) -> Result<&'a DerivedActionValidatedOutput, DerivedActionRunnerError> {
    let task = tasks
        .iter()
        .find(|task| task.action == action && task.scenario == DerivedActionReuseScenario::Exact)
        .ok_or_else(|| DerivedActionRunnerError::Binding("exact task".to_owned()))?;
    outputs.get(&task.id).ok_or_else(|| DerivedActionRunnerError::Binding(task.id.clone()))
}

fn reuse_architecture(
    study: &DerivedActionStudy,
    task: &DerivedActionStudyTask,
    exact: &DerivedActionValidatedOutput,
    source: &DerivedActionSourceMaterial,
) -> Result<DerivedActionValidatedOutput, DerivedActionRunnerError> {
    let DerivedActionValidatedOutput::ArchitectureBrief { artifact, .. } = exact else {
        return Err(DerivedActionRunnerError::Binding(task.id.clone()));
    };
    let DerivedActionStudyFixture::ArchitectureBrief(fixture) = &task.fixture else {
        return Err(DerivedActionRunnerError::Binding(task.id.clone()));
    };
    let scope = architecture_scope(fixture)?;
    let output = match task.scenario {
        DerivedActionReuseScenario::Exact => artifact.as_ref().clone(),
        DerivedActionReuseScenario::Project => {
            project_architecture_brief(artifact, scope.clone()).map_err(artifact_error)?
        }
        DerivedActionReuseScenario::Assemble => {
            let slices = fixture
                .reuse_source_packages
                .iter()
                .map(|packages| {
                    let partition = architecture_scope_for_names(fixture, packages)?;
                    project_architecture_brief(artifact, partition).map_err(artifact_error)
                })
                .collect::<Result<Vec<_>, DerivedActionRunnerError>>()?;
            assemble_architecture_briefs(&slices, scope.clone()).map_err(artifact_error)?
        }
    };
    validate_architecture_output(study, fixture, output, &source.repository_root)
}

fn reuse_change(
    study: &DerivedActionStudy,
    task: &DerivedActionStudyTask,
    exact: &DerivedActionValidatedOutput,
    source: &DerivedActionSourceMaterial,
) -> Result<DerivedActionValidatedOutput, DerivedActionRunnerError> {
    let DerivedActionValidatedOutput::ChangeImpact { artifact, .. } = exact else {
        return Err(DerivedActionRunnerError::Binding(task.id.clone()));
    };
    let DerivedActionStudyFixture::ChangeImpact(fixture) = &task.fixture else {
        return Err(DerivedActionRunnerError::Binding(task.id.clone()));
    };
    let scope = change_scope(study, fixture)?;
    let output = match task.scenario {
        DerivedActionReuseScenario::Exact => artifact.as_ref().clone(),
        DerivedActionReuseScenario::Project => {
            project_change_impact(artifact, scope.clone()).map_err(artifact_error)?
        }
        DerivedActionReuseScenario::Assemble => {
            let slices = fixture
                .reuse_source_components
                .iter()
                .map(|components| {
                    let partition = change::change_scope_for_names(study, fixture, components)?;
                    project_change_impact(artifact, partition).map_err(artifact_error)
                })
                .collect::<Result<Vec<_>, DerivedActionRunnerError>>()?;
            assemble_change_impacts(&slices, scope.clone()).map_err(artifact_error)?
        }
    };
    validate_change_output(study, fixture, output, source)
}

fn architecture_scope_for_names(
    fixture: &ArchitectureStudyFixture,
    names: &[String],
) -> Result<needle_core::ArchitectureBriefScope, DerivedActionRunnerError> {
    architecture::architecture_scope_for_names(fixture, names)
}

fn validate_manifest_binding(
    study: &DerivedActionStudy,
    manifest: &DerivedActionGateManifest,
) -> Result<(), DerivedActionRunnerError> {
    study.validate()?;
    manifest.validate()?;
    if manifest.evidence_class != DerivedActionEvidenceClass::AcceptedShadow
        || manifest.repository_sha != study.source.base_sha
        || manifest.tasks.len() != study.tasks.len()
    {
        return Err(DerivedActionRunnerError::Binding("manifest".to_owned()));
    }
    let manifest_tasks =
        manifest.tasks.iter().map(|task| (task.id.as_str(), task)).collect::<BTreeMap<_, _>>();
    for task in &study.tasks {
        let bound = manifest_tasks
            .get(task.id.as_str())
            .ok_or_else(|| DerivedActionRunnerError::Binding(task.id.clone()))?;
        if bound.action != task.action
            || bound.scenario != task.scenario
            || bound.semantic_request_digest != study.semantic_request_digest(task)?
            || bound.fixture_digest != study.fixture_digest(task)
            || bound.execution_profile_digest != study.execution_profile.digest()
            || bound.pair_seeds != study.execution_profile.pair_seeds
        {
            return Err(DerivedActionRunnerError::Binding(task.id.clone()));
        }
    }
    Ok(())
}

fn validate_source_material(
    study: &DerivedActionStudy,
    source: &DerivedActionSourceMaterial,
) -> Result<(), DerivedActionRunnerError> {
    if !source.repository_root.is_dir() {
        return Err(DerivedActionRunnerError::Source("repository root".to_owned()));
    }
    if source.changes.windows(2).any(|pair| pair[0].path >= pair[1].path) {
        return Err(DerivedActionRunnerError::Canonical("source.changes"));
    }
    let expected = study
        .tasks
        .iter()
        .find_map(|task| match &task.fixture {
            DerivedActionStudyFixture::ChangeImpact(fixture) => Some(&fixture.changed_paths),
            _ => None,
        })
        .ok_or_else(|| DerivedActionRunnerError::Source("change fixture".to_owned()))?;
    if source.changes.iter().map(|file| &file.path).collect::<Vec<_>>()
        != expected.iter().collect::<Vec<_>>()
    {
        return Err(DerivedActionRunnerError::Source("changed paths".to_owned()));
    }
    for file in &source.changes {
        if file.before.is_none() && file.after.is_none() {
            return Err(DerivedActionRunnerError::Source(file.path.clone()));
        }
    }
    Ok(())
}

fn response_template(
    task: &DerivedActionStudyTask,
) -> Result<DerivedActionExternalDraft, DerivedActionRunnerError> {
    match &task.fixture {
        DerivedActionStudyFixture::ArchitectureBrief(fixture) => {
            let requested = requested_package_names(fixture);
            Ok(DerivedActionExternalDraft::ArchitectureBrief(ArchitectureBriefDraft {
                packages: requested
                    .into_iter()
                    .map(|package| ArchitecturePackageDraft {
                        package,
                        summary: "<model-authored package summary>".to_owned(),
                        summary_evidence_paths: vec!["<repository-relative path>".to_owned()],
                        assertions: vec![ArchitectureAssertionDraft {
                            kind: ArchitectureAssertionKind::Responsibility,
                            text: "<model-authored assertion>".to_owned(),
                            evidence_paths: vec!["<repository-relative path>".to_owned()],
                            related_packages: Vec::new(),
                        }],
                        gaps: vec!["<unsupported or incomplete area>".to_owned()],
                    })
                    .collect(),
            }))
        }
        DerivedActionStudyFixture::ChangeImpact(fixture) => {
            let requested = requested_component_names(fixture);
            Ok(DerivedActionExternalDraft::ChangeImpact(ChangeImpactDraft {
                assessments: requested
                    .into_iter()
                    .map(|component| ChangeImpactAssessmentDraft {
                        component,
                        disposition: ChangeImpactDisposition::Unknown,
                        impact_kinds: Vec::new(),
                        rationale: "<model-authored impact rationale>".to_owned(),
                        evidence: vec![ChangeImpactEvidenceDraft {
                            path: fixture.changed_paths[0].clone(),
                            state: ChangeImpactEvidenceState::After,
                            roles: vec![ChangeImpactEvidenceRole::Supporting],
                        }],
                        affected_paths: Vec::new(),
                    })
                    .collect(),
                gaps: vec!["<unsupported or incomplete area>".to_owned()],
            }))
        }
    }
}

fn requested_package_names(fixture: &ArchitectureStudyFixture) -> Vec<String> {
    if fixture.requested_packages.is_empty() {
        fixture.package_universe.iter().map(|package| package.name.clone()).collect()
    } else {
        fixture.requested_packages.clone()
    }
}

fn requested_component_names(fixture: &ChangeImpactStudyFixture) -> Vec<String> {
    if fixture.requested_components.is_empty() {
        fixture.components.iter().map(|component| component.id.clone()).collect()
    } else {
        fixture.requested_components.clone()
    }
}

fn validate_wire_bound(
    field: &'static str,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), DerivedActionRunnerError> {
    if bytes.len() > maximum {
        return Err(DerivedActionRunnerError::Bound { field, actual: bytes.len(), maximum });
    }
    Ok(())
}

fn validate_label(field: &'static str, value: &str) -> Result<(), DerivedActionRunnerError> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(DerivedActionRunnerError::Text(field));
    }
    Ok(())
}

fn artifact_error(error: impl std::fmt::Display) -> DerivedActionRunnerError {
    DerivedActionRunnerError::Artifact(error.to_string())
}

#[derive(Debug, Error)]
pub enum DerivedActionRunnerError {
    #[error("derived-action runner format revision {0} is unsupported")]
    FormatRevision(u16),
    #[error("{0} has an unsupported schema")]
    Schema(&'static str),
    #[error("{field} contains {actual} bytes; maximum is {maximum}")]
    Bound { field: &'static str, actual: usize, maximum: usize },
    #[error("{0} must be ordered, unique, and bounded")]
    Canonical(&'static str),
    #[error("{0} is empty or unbounded")]
    Text(&'static str),
    #[error("runner binding failed for {0}")]
    Binding(String),
    #[error("source material is invalid for {0}")]
    Source(String),
    #[error("external metric is invalid for {0}")]
    Metric(String),
    #[error("derived-action JSON is invalid: {0}")]
    Json(String),
    #[error("artifact construction or validation failed: {0}")]
    Artifact(String),
    #[error(transparent)]
    Study(#[from] DerivedActionStudyError),
    #[error(transparent)]
    Gate(#[from] super::DerivedActionGateError),
}

#[cfg(test)]
mod tests;
