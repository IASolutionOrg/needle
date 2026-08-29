use super::{
    ArchitectureBriefDraft, ArchitectureStudyFixture, DerivedActionRunnerError, DerivedActionStudy,
    DerivedActionValidatedOutput, artifact_error,
};
use needle_core::{
    ArchitectureAssertion, ArchitectureAssertionKind, ArchitectureBrief, ArchitectureBriefScope,
    ArchitectureEvidence, ArchitectureEvidenceRole, ArchitecturePackageBrief, Digest,
    TestTargetPackageKey,
};
use needle_runtime::{
    ArchitectureBriefValidationInput, MAX_ARCHITECTURE_EVIDENCE_FILE_BYTES,
    architecture_brief_analysis_definition, validate_architecture_brief,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

type EvidenceKey = (String, Vec<TestTargetPackageKey>);

#[derive(Default)]
struct EvidenceDefinition {
    roles: BTreeSet<ArchitectureEvidenceRole>,
}

pub(super) fn architecture_scope(
    fixture: &ArchitectureStudyFixture,
) -> Result<ArchitectureBriefScope, DerivedActionRunnerError> {
    architecture_scope_for_names(fixture, &fixture.requested_packages)
}

pub(super) fn architecture_scope_for_names(
    fixture: &ArchitectureStudyFixture,
    names: &[String],
) -> Result<ArchitectureBriefScope, DerivedActionRunnerError> {
    if names.is_empty() {
        return Ok(ArchitectureBriefScope::all());
    }
    let packages = names
        .iter()
        .map(|name| package_by_name(fixture, name).cloned())
        .collect::<Result<Vec<_>, _>>()?;
    ArchitectureBriefScope::new(packages).map_err(artifact_error)
}

pub(super) fn build_architecture_output(
    study: &DerivedActionStudy,
    fixture: &ArchitectureStudyFixture,
    draft: &ArchitectureBriefDraft,
    root: &Path,
) -> Result<DerivedActionValidatedOutput, DerivedActionRunnerError> {
    let scope = architecture_scope(fixture)?;
    let expected = if fixture.requested_packages.is_empty() {
        fixture.package_universe.iter().map(|package| package.name.as_str()).collect::<Vec<_>>()
    } else {
        fixture.requested_packages.iter().map(String::as_str).collect::<Vec<_>>()
    };
    let actual = draft.packages.iter().map(|package| package.package.as_str()).collect::<Vec<_>>();
    if actual != expected {
        return Err(DerivedActionRunnerError::Binding("architecture package scope".to_owned()));
    }

    let mut definitions = BTreeMap::<EvidenceKey, EvidenceDefinition>::new();
    add_evidence_role(
        &mut definitions,
        (fixture.workspace_manifest.clone(), Vec::new()),
        ArchitectureEvidenceRole::Manifest,
    );
    for package in &draft.packages {
        let key = package_by_name(fixture, &package.package)?.clone();
        let package_key = vec![key.clone()];
        for role in [
            ArchitectureEvidenceRole::Manifest,
            ArchitectureEvidenceRole::DependencyDeclaration,
            ArchitectureEvidenceRole::Supporting,
        ] {
            add_evidence_role(
                &mut definitions,
                (key.manifest_path.clone(), package_key.clone()),
                role,
            );
        }
        for path in &package.summary_evidence_paths {
            add_evidence_role(
                &mut definitions,
                (path.clone(), package_key.clone()),
                ArchitectureEvidenceRole::Supporting,
            );
        }
        for assertion in &package.assertions {
            let role = assertion_role(assertion.kind);
            for path in &assertion.evidence_paths {
                add_evidence_role(&mut definitions, (path.clone(), package_key.clone()), role);
            }
        }
    }

    let mut evidence = Vec::with_capacity(definitions.len());
    let mut evidence_by_key = BTreeMap::<EvidenceKey, Digest>::new();
    for ((path, packages), definition) in definitions {
        let item = ArchitectureEvidence::new(
            path.clone(),
            bounded_file_digest(root, &path)?,
            None,
            None,
            definition.roles.into_iter().collect(),
            packages.clone(),
        )
        .map_err(artifact_error)?;
        evidence_by_key.insert((path, packages), item.id);
        evidence.push(item);
    }

    let workspace_evidence = evidence_by_key
        .get(&(fixture.workspace_manifest.clone(), Vec::new()))
        .copied()
        .ok_or_else(|| DerivedActionRunnerError::Binding("workspace evidence".to_owned()))?;
    let mut packages = Vec::with_capacity(draft.packages.len());
    for package in &draft.packages {
        let package_key = package_by_name(fixture, &package.package)?.clone();
        let evidence_package_key = vec![package_key.clone()];
        let mut summary_evidence = BTreeSet::from([workspace_evidence]);
        summary_evidence.insert(evidence_id(
            &evidence_by_key,
            &package_key.manifest_path,
            &evidence_package_key,
        )?);
        for path in &package.summary_evidence_paths {
            summary_evidence.insert(evidence_id(&evidence_by_key, path, &evidence_package_key)?);
        }
        let assertions = package
            .assertions
            .iter()
            .map(|assertion| {
                if assertion.evidence_paths.is_empty() {
                    return Err(DerivedActionRunnerError::Binding(
                        "architecture assertion evidence".to_owned(),
                    ));
                }
                let ids = assertion
                    .evidence_paths
                    .iter()
                    .map(|path| evidence_id(&evidence_by_key, path, &evidence_package_key))
                    .collect::<Result<Vec<_>, _>>()?;
                let related = assertion
                    .related_packages
                    .iter()
                    .map(|name| package_by_name(fixture, name).cloned())
                    .collect::<Result<Vec<_>, _>>()?;
                ArchitectureAssertion::new(assertion.kind, assertion.text.clone(), ids, related)
                    .map_err(artifact_error)
            })
            .collect::<Result<Vec<_>, DerivedActionRunnerError>>()?;
        packages.push(
            ArchitecturePackageBrief::new(
                package_key,
                package.summary.clone(),
                summary_evidence.into_iter().collect(),
                assertions,
                package.gaps.clone(),
            )
            .map_err(artifact_error)?,
        );
    }
    let artifact = ArchitectureBrief::new(
        Digest::blake3(study.source.repository_url.as_bytes()),
        study.source.base_sha.clone(),
        fixture.workspace_manifest.clone(),
        scope,
        architecture_brief_analysis_definition(),
        fixture.package_universe.clone(),
        evidence,
        packages,
    )
    .map_err(artifact_error)?;
    validate_architecture_output(study, fixture, artifact, root)
}

pub(super) fn validate_architecture_output(
    study: &DerivedActionStudy,
    fixture: &ArchitectureStudyFixture,
    artifact: ArchitectureBrief,
    root: &Path,
) -> Result<DerivedActionValidatedOutput, DerivedActionRunnerError> {
    let scope = architecture_scope(fixture)?;
    let certificate = validate_architecture_brief(
        ArchitectureBriefValidationInput {
            repository_root: root,
            repository_lineage: Digest::blake3(study.source.repository_url.as_bytes()),
            source_selector: &study.source.base_sha,
            workspace_manifest: &fixture.workspace_manifest,
            scope: &scope,
            package_universe: &fixture.package_universe,
        },
        &artifact,
    )
    .map_err(artifact_error)?;
    Ok(DerivedActionValidatedOutput::ArchitectureBrief {
        artifact: Box::new(artifact),
        certificate,
    })
}

fn package_by_name<'a>(
    fixture: &'a ArchitectureStudyFixture,
    name: &str,
) -> Result<&'a TestTargetPackageKey, DerivedActionRunnerError> {
    fixture
        .package_universe
        .iter()
        .find(|package| package.name == name)
        .ok_or_else(|| DerivedActionRunnerError::Binding(format!("architecture package {name}")))
}

fn add_evidence_role(
    definitions: &mut BTreeMap<EvidenceKey, EvidenceDefinition>,
    key: EvidenceKey,
    role: ArchitectureEvidenceRole,
) {
    definitions.entry(key).or_default().roles.insert(role);
}

fn evidence_id(
    evidence: &BTreeMap<EvidenceKey, Digest>,
    path: &str,
    packages: &[TestTargetPackageKey],
) -> Result<Digest, DerivedActionRunnerError> {
    evidence
        .get(&(path.to_owned(), packages.to_vec()))
        .copied()
        .ok_or_else(|| DerivedActionRunnerError::Binding(format!("architecture evidence {path}")))
}

fn assertion_role(kind: ArchitectureAssertionKind) -> ArchitectureEvidenceRole {
    match kind {
        ArchitectureAssertionKind::Responsibility | ArchitectureAssertionKind::DesignConstraint => {
            ArchitectureEvidenceRole::Supporting
        }
        ArchitectureAssertionKind::EntryPoint => ArchitectureEvidenceRole::EntryPoint,
        ArchitectureAssertionKind::PublicBoundary => ArchitectureEvidenceRole::PublicBoundary,
        ArchitectureAssertionKind::Dependency => ArchitectureEvidenceRole::DependencyDeclaration,
    }
}

fn bounded_file_digest(root: &Path, relative: &str) -> Result<Digest, DerivedActionRunnerError> {
    let path = root.join(relative);
    let mut bytes = Vec::new();
    File::open(&path)
        .map_err(|error| DerivedActionRunnerError::Source(format!("{}: {error}", path.display())))?
        .take((MAX_ARCHITECTURE_EVIDENCE_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            DerivedActionRunnerError::Source(format!("{}: {error}", path.display()))
        })?;
    if bytes.len() > MAX_ARCHITECTURE_EVIDENCE_FILE_BYTES {
        return Err(DerivedActionRunnerError::Source(format!(
            "architecture evidence {} exceeds {} bytes",
            relative, MAX_ARCHITECTURE_EVIDENCE_FILE_BYTES
        )));
    }
    Ok(Digest::blake3(bytes))
}
