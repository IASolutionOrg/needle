use super::{
    ChangeImpactDraft, ChangeImpactStudyFixture, DerivedActionChangedFile,
    DerivedActionRunnerError, DerivedActionSourceMaterial, DerivedActionStudy,
    DerivedActionValidatedOutput, artifact_error,
};
use crate::ChangeStudySubjectKind;
use needle_core::{
    CanonicalHasher, ChangeId, ChangeImpact, ChangeImpactAssessment, ChangeImpactComponentKey,
    ChangeImpactEvidence, ChangeImpactEvidenceRole, ChangeImpactEvidenceState,
    ChangeImpactRequirement, ChangeImpactScope, Digest, PatchArtifact, PatchFile, PatchOperation,
    Subject, SubjectId, SubjectKind,
};
use needle_runtime::{
    ChangeImpactValidationInput, MAX_CHANGE_IMPACT_BLOB_FILE_BYTES,
    MAX_CHANGE_IMPACT_BLOB_TOTAL_BYTES, PatchFileBlob, change_impact_analysis_definition,
    derive_change_impact_change_set, validate_change_impact,
};
use std::collections::{BTreeMap, BTreeSet};

struct ChangeContext {
    repository_lineage: Digest,
    requirements: Vec<ChangeImpactRequirement>,
    subjects: Vec<Subject>,
    components: BTreeMap<String, ChangeImpactComponentKey>,
    patch: PatchArtifact,
    blobs: Vec<PatchFileBlob>,
}

#[derive(Default)]
struct EvidenceDefinition {
    roles: BTreeSet<ChangeImpactEvidenceRole>,
    subjects: BTreeSet<SubjectId>,
}

pub(super) fn change_scope(
    study: &DerivedActionStudy,
    fixture: &ChangeImpactStudyFixture,
) -> Result<ChangeImpactScope, DerivedActionRunnerError> {
    change_scope_for_names(study, fixture, &fixture.requested_components)
}

pub(super) fn change_scope_for_names(
    study: &DerivedActionStudy,
    fixture: &ChangeImpactStudyFixture,
    names: &[String],
) -> Result<ChangeImpactScope, DerivedActionRunnerError> {
    if names.is_empty() {
        return Ok(ChangeImpactScope::all());
    }
    let context = change_identity_context(study, fixture)?;
    let components = names
        .iter()
        .map(|name| {
            context.components.get(name).copied().ok_or_else(|| {
                DerivedActionRunnerError::Binding(format!("change component {name}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    ChangeImpactScope::new(components).map_err(artifact_error)
}

pub(super) fn build_change_output(
    study: &DerivedActionStudy,
    fixture: &ChangeImpactStudyFixture,
    draft: &ChangeImpactDraft,
    source: &DerivedActionSourceMaterial,
) -> Result<DerivedActionValidatedOutput, DerivedActionRunnerError> {
    let context = build_change_context(study, fixture, source)?;
    let scope = scope_from_context(fixture, &context)?;
    let expected = if fixture.requested_components.is_empty() {
        fixture.components.iter().map(|component| component.id.as_str()).collect::<Vec<_>>()
    } else {
        fixture.requested_components.iter().map(String::as_str).collect::<Vec<_>>()
    };
    let actual = draft
        .assessments
        .iter()
        .map(|assessment| assessment.component.as_str())
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(DerivedActionRunnerError::Binding("change component scope".to_owned()));
    }

    let source_by_path =
        source.changes.iter().map(|file| (file.path.as_str(), file)).collect::<BTreeMap<_, _>>();
    let all_subjects = context.subjects.iter().map(|subject| subject.id).collect::<BTreeSet<_>>();
    let mut definitions =
        BTreeMap::<(String, ChangeImpactEvidenceState), EvidenceDefinition>::new();
    for file in &source.changes {
        let stable_roles = stable_evidence_roles(&file.path);
        if file.before.is_some() {
            let definition = definitions
                .entry((file.path.clone(), ChangeImpactEvidenceState::Before))
                .or_default();
            definition.roles.extend(stable_roles.iter().copied());
            definition.subjects.extend(all_subjects.iter().copied());
        }
        if file.after.is_some() {
            let definition = definitions
                .entry((file.path.clone(), ChangeImpactEvidenceState::After))
                .or_default();
            definition.roles.extend(stable_roles.iter().copied());
            definition.subjects.extend(all_subjects.iter().copied());
        }
    }
    for assessment in &draft.assessments {
        let key = context
            .components
            .get(&assessment.component)
            .ok_or_else(|| DerivedActionRunnerError::Binding(assessment.component.clone()))?;
        for reference in &assessment.evidence {
            if !source_by_path.contains_key(reference.path.as_str()) {
                return Err(DerivedActionRunnerError::Binding(format!(
                    "change evidence {}",
                    reference.path
                )));
            }
            let definition = definitions
                .get_mut(&(reference.path.clone(), reference.state))
                .ok_or_else(|| {
                    DerivedActionRunnerError::Binding(format!(
                        "change evidence state {}",
                        reference.path
                    ))
                })?;
            if reference.roles.iter().any(|role| !definition.roles.contains(role)) {
                return Err(DerivedActionRunnerError::Binding(format!(
                    "change evidence role {}",
                    reference.path
                )));
            }
            definition.subjects.insert(key.subject);
        }
    }

    let mut evidence = Vec::with_capacity(definitions.len());
    let mut evidence_by_key = BTreeMap::new();
    for ((path, state), definition) in definitions {
        let file = source_by_path
            .get(path.as_str())
            .ok_or_else(|| DerivedActionRunnerError::Binding(path.clone()))?;
        let bytes = match state {
            ChangeImpactEvidenceState::Before => file.before.as_deref(),
            ChangeImpactEvidenceState::After => file.after.as_deref(),
        }
        .ok_or_else(|| DerivedActionRunnerError::Binding(path.clone()))?;
        let item = ChangeImpactEvidence::new(
            path.clone(),
            state,
            Digest::blake3(bytes),
            None,
            None,
            definition.roles.into_iter().collect(),
            definition.subjects.into_iter().collect(),
        )
        .map_err(artifact_error)?;
        evidence_by_key.insert((path, state), item.id);
        evidence.push(item);
    }
    let assessments = draft
        .assessments
        .iter()
        .map(|assessment| {
            let key =
                context.components.get(&assessment.component).copied().ok_or_else(|| {
                    DerivedActionRunnerError::Binding(assessment.component.clone())
                })?;
            if assessment
                .affected_paths
                .iter()
                .any(|path| !source_by_path.contains_key(path.as_str()))
            {
                return Err(DerivedActionRunnerError::Binding(format!(
                    "affected paths for {}",
                    assessment.component
                )));
            }
            let evidence_ids = assessment
                .evidence
                .iter()
                .map(|reference| {
                    evidence_by_key
                        .get(&(reference.path.clone(), reference.state))
                        .copied()
                        .ok_or_else(|| DerivedActionRunnerError::Binding(reference.path.clone()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            ChangeImpactAssessment::new(
                key,
                assessment.disposition,
                assessment.impact_kinds.clone(),
                assessment.rationale.clone(),
                evidence_ids,
                Vec::new(),
                assessment.affected_paths.clone(),
                Vec::new(),
            )
            .map_err(artifact_error)
        })
        .collect::<Result<Vec<_>, DerivedActionRunnerError>>()?;
    let artifact = ChangeImpact::new(
        context.repository_lineage,
        study.source.base_sha.clone(),
        derive_change_impact_change_set(&context.patch, &context.blobs).map_err(artifact_error)?,
        scope,
        change_impact_analysis_definition(),
        context.requirements.clone(),
        Vec::new(),
        context.subjects.clone(),
        Vec::new(),
        None,
        None,
        evidence,
        assessments,
        draft.gaps.clone(),
    )
    .map_err(artifact_error)?;
    validate_with_context(study, fixture, artifact, source, &context)
}

pub(super) fn validate_change_output(
    study: &DerivedActionStudy,
    fixture: &ChangeImpactStudyFixture,
    artifact: ChangeImpact,
    source: &DerivedActionSourceMaterial,
) -> Result<DerivedActionValidatedOutput, DerivedActionRunnerError> {
    let context = build_change_context(study, fixture, source)?;
    validate_with_context(study, fixture, artifact, source, &context)
}

fn validate_with_context(
    study: &DerivedActionStudy,
    fixture: &ChangeImpactStudyFixture,
    artifact: ChangeImpact,
    source: &DerivedActionSourceMaterial,
    context: &ChangeContext,
) -> Result<DerivedActionValidatedOutput, DerivedActionRunnerError> {
    let scope = scope_from_context(fixture, context)?;
    let certificate = validate_change_impact(
        ChangeImpactValidationInput {
            repository_root: &source.repository_root,
            repository_lineage: context.repository_lineage,
            source_selector: &study.source.base_sha,
            patch: &context.patch,
            patch_blobs: &context.blobs,
            scope: &scope,
            requirements: &context.requirements,
            constraints: &[],
            subjects: &context.subjects,
            accepted_inputs: &[],
            test_inventory: None,
            test_inventory_certificate: None,
        },
        &artifact,
    )
    .map_err(artifact_error)?;
    Ok(DerivedActionValidatedOutput::ChangeImpact { artifact: Box::new(artifact), certificate })
}

fn change_identity_context(
    study: &DerivedActionStudy,
    fixture: &ChangeImpactStudyFixture,
) -> Result<ChangeContext, DerivedActionRunnerError> {
    let repository_lineage = Digest::blake3(study.source.repository_url.as_bytes());
    let requirements = fixture
        .requirements
        .iter()
        .map(|requirement| {
            ChangeImpactRequirement::new(requirement.text.clone()).map_err(artifact_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let requirement_by_study_id = fixture
        .requirements
        .iter()
        .zip(&requirements)
        .map(|(source, requirement)| (source.id.as_str(), requirement.id))
        .collect::<BTreeMap<_, _>>();
    let mut subjects = fixture
        .subjects
        .iter()
        .map(|subject| {
            let kind = match subject.kind {
                ChangeStudySubjectKind::Implementation => SubjectKind::Module,
                ChangeStudySubjectKind::Test => SubjectKind::Test,
            };
            (subject.id.as_str(), Subject::exact(repository_lineage, kind, &subject.canonical_name))
        })
        .collect::<Vec<_>>();
    subjects.sort_by_key(|(_, subject)| subject.id);
    let subject_by_study_id =
        subjects.iter().map(|(id, subject)| (*id, subject.id)).collect::<BTreeMap<_, _>>();
    let components = fixture
        .components
        .iter()
        .map(|component| {
            let requirement = requirement_by_study_id
                .get(component.requirement_id.as_str())
                .copied()
                .ok_or_else(|| DerivedActionRunnerError::Binding(component.id.clone()))?;
            let subject = subject_by_study_id
                .get(component.subject_id.as_str())
                .copied()
                .ok_or_else(|| DerivedActionRunnerError::Binding(component.id.clone()))?;
            Ok((component.id.clone(), ChangeImpactComponentKey { requirement, subject }))
        })
        .collect::<Result<BTreeMap<_, _>, DerivedActionRunnerError>>()?;
    let ordered_subjects = subjects.into_iter().map(|(_, subject)| subject).collect::<Vec<_>>();
    let core_universe = requirements
        .iter()
        .flat_map(|requirement| {
            ordered_subjects.iter().map(move |subject| ChangeImpactComponentKey {
                requirement: requirement.id,
                subject: subject.id,
            })
        })
        .collect::<BTreeSet<_>>();
    if components.values().copied().collect::<BTreeSet<_>>() != core_universe {
        return Err(DerivedActionRunnerError::Binding(
            "change component universe is not Cartesian".to_owned(),
        ));
    }
    Ok(ChangeContext {
        repository_lineage,
        requirements,
        subjects: ordered_subjects,
        components,
        patch: empty_patch(study),
        blobs: Vec::new(),
    })
}

fn build_change_context(
    study: &DerivedActionStudy,
    fixture: &ChangeImpactStudyFixture,
    source: &DerivedActionSourceMaterial,
) -> Result<ChangeContext, DerivedActionRunnerError> {
    let mut context = change_identity_context(study, fixture)?;
    let mut files = Vec::with_capacity(source.changes.len());
    let mut blobs = Vec::with_capacity(source.changes.len());
    let mut total_bytes = 0usize;
    for file in &source.changes {
        validate_changed_file(file, &mut total_bytes)?;
        let operation = match (file.before.is_some(), file.after.is_some()) {
            (false, true) => PatchOperation::Create,
            (true, true) => PatchOperation::Update,
            (true, false) => PatchOperation::Delete,
            (false, false) => return Err(DerivedActionRunnerError::Source(file.path.clone())),
        };
        files.push(PatchFile {
            path: file.path.clone(),
            operation,
            before_digest: file.before.as_deref().map(Digest::blake3),
            after_digest: file.after.as_deref().map(Digest::blake3),
            before_bytes: file.before.as_ref().map_or(0, Vec::len) as u64,
            after_bytes: file.after.as_ref().map_or(0, Vec::len) as u64,
        });
        blobs.push(PatchFileBlob {
            path: file.path.clone(),
            before: file.before.clone(),
            after: file.after.clone(),
        });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    blobs.sort_by(|left, right| left.path.cmp(&right.path));
    let source_snapshot = Digest::blake3(study.source.base_sha.as_bytes());
    let mut output_hasher = CanonicalHasher::new(b"derived-action-change-target-v1");
    output_hasher.field_str(&study.source.change_target_sha);
    for file in &files {
        output_hasher.field_str(&file.path);
        if let Some(digest) = file.after_digest {
            output_hasher.field_digest(digest);
        }
    }
    context.patch = PatchArtifact {
        id: PatchArtifact::compute_id(source_snapshot, &files),
        change_id: ChangeId::from_digest(Digest::blake3(
            format!("{}:{}", study.source.base_sha, study.source.change_target_sha).as_bytes(),
        )),
        revision: 1,
        source_snapshot,
        files,
        summary: "Pinned derived-action study change.".to_owned(),
        acceptance_coverage: Vec::new(),
        residual_risks: Vec::new(),
        declared_output_digest: output_hasher.finish(),
        discrepancies: Vec::new(),
    };
    context.blobs = blobs;
    Ok(context)
}

fn scope_from_context(
    fixture: &ChangeImpactStudyFixture,
    context: &ChangeContext,
) -> Result<ChangeImpactScope, DerivedActionRunnerError> {
    if fixture.requested_components.is_empty() {
        return Ok(ChangeImpactScope::all());
    }
    let components = fixture
        .requested_components
        .iter()
        .map(|name| {
            context
                .components
                .get(name)
                .copied()
                .ok_or_else(|| DerivedActionRunnerError::Binding(name.clone()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ChangeImpactScope::new(components).map_err(artifact_error)
}

fn validate_changed_file(
    file: &DerivedActionChangedFile,
    total_bytes: &mut usize,
) -> Result<(), DerivedActionRunnerError> {
    for bytes in [&file.before, &file.after].into_iter().flatten() {
        if bytes.len() > MAX_CHANGE_IMPACT_BLOB_FILE_BYTES {
            return Err(DerivedActionRunnerError::Source(format!(
                "{} exceeds per-file bound",
                file.path
            )));
        }
        *total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| DerivedActionRunnerError::Source("change byte total".to_owned()))?;
        if *total_bytes > MAX_CHANGE_IMPACT_BLOB_TOTAL_BYTES {
            return Err(DerivedActionRunnerError::Source("change byte total".to_owned()));
        }
    }
    if file.before.as_deref() == file.after.as_deref() {
        return Err(DerivedActionRunnerError::Source(format!(
            "{} has identical states",
            file.path
        )));
    }
    Ok(())
}

fn stable_evidence_roles(path: &str) -> BTreeSet<ChangeImpactEvidenceRole> {
    let mut roles = BTreeSet::from([
        ChangeImpactEvidenceRole::ChangedSurface,
        ChangeImpactEvidenceRole::Supporting,
    ]);
    if path.starts_with("tests/") || path.contains("/tests/") {
        roles.insert(ChangeImpactEvidenceRole::Test);
    } else {
        roles.insert(ChangeImpactEvidenceRole::Implementation);
    }
    roles
}

fn empty_patch(study: &DerivedActionStudy) -> PatchArtifact {
    let source_snapshot = Digest::blake3(study.source.base_sha.as_bytes());
    PatchArtifact {
        id: PatchArtifact::compute_id(source_snapshot, &[]),
        change_id: ChangeId::from_digest(Digest::blake3(b"uninitialized-derived-action-patch")),
        revision: 1,
        source_snapshot,
        files: Vec::new(),
        summary: String::new(),
        acceptance_coverage: Vec::new(),
        residual_risks: Vec::new(),
        declared_output_digest: Digest::blake3(b"uninitialized-derived-action-patch"),
        discrepancies: Vec::new(),
    }
}
