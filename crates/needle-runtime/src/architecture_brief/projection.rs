use super::{ArchitectureBriefRuntimeError, architecture_brief_analysis_definition};
use needle_core::{
    ArchitectureBrief, ArchitectureBriefScope, ArchitectureEvidence, ArchitecturePackageBrief,
    Digest, MAX_ARCHITECTURE_PACKAGES, TestTargetPackageKey,
};
use std::collections::{BTreeMap, BTreeSet};

pub fn project_architecture_brief(
    source: &ArchitectureBrief,
    scope: ArchitectureBriefScope,
) -> Result<ArchitectureBrief, ArchitectureBriefRuntimeError> {
    source.validate()?;
    scope.validate()?;
    if source.analysis_definition_digest != architecture_brief_analysis_definition()
        || !scope.is_projection_of(&source.scope)
        || scope
            .packages
            .iter()
            .any(|package| source.package_universe.binary_search(package).is_err())
    {
        return Err(ArchitectureBriefRuntimeError::ProjectionScope);
    }
    let packages = source
        .packages
        .iter()
        .filter(|package| scope.includes(&package.package))
        .cloned()
        .collect::<Vec<_>>();
    let evidence = referenced_evidence(&packages, &source.evidence)?;
    ArchitectureBrief::new(
        source.repository_lineage,
        source.source_selector.clone(),
        source.workspace_manifest.clone(),
        scope,
        source.analysis_definition_digest,
        source.package_universe.clone(),
        evidence,
        packages,
    )
    .map_err(Into::into)
}

pub fn assemble_architecture_briefs(
    inputs: &[ArchitectureBrief],
    scope: ArchitectureBriefScope,
) -> Result<ArchitectureBrief, ArchitectureBriefRuntimeError> {
    if inputs.len() < 2 || inputs.len() > MAX_ARCHITECTURE_PACKAGES {
        return Err(ArchitectureBriefRuntimeError::Assembly);
    }
    scope.validate()?;
    let first = &inputs[0];
    first.validate()?;
    if first.analysis_definition_digest != architecture_brief_analysis_definition() {
        return Err(ArchitectureBriefRuntimeError::Assembly);
    }

    let mut selected_packages = BTreeSet::<TestTargetPackageKey>::new();
    let mut package_briefs = Vec::<ArchitecturePackageBrief>::new();
    let mut evidence = BTreeMap::<Digest, ArchitectureEvidence>::new();
    for input in inputs {
        input.validate()?;
        if input.repository_lineage != first.repository_lineage
            || input.source_selector != first.source_selector
            || input.workspace_manifest != first.workspace_manifest
            || input.analysis_definition_digest != first.analysis_definition_digest
            || input.package_universe != first.package_universe
            || input.scope.packages.is_empty()
        {
            return Err(ArchitectureBriefRuntimeError::Assembly);
        }
        for package in &input.scope.packages {
            if !selected_packages.insert(package.clone()) {
                return Err(ArchitectureBriefRuntimeError::Assembly);
            }
        }
        package_briefs.extend(input.packages.iter().cloned());
        for item in &input.evidence {
            match evidence.get(&item.id) {
                Some(existing) if existing != item => {
                    return Err(ArchitectureBriefRuntimeError::Assembly);
                }
                Some(_) => {}
                None => {
                    evidence.insert(item.id, item.clone());
                }
            }
        }
    }

    let assembled_packages = selected_packages.into_iter().collect::<Vec<_>>();
    let expected_packages =
        if scope.packages.is_empty() { &first.package_universe } else { &scope.packages };
    if &assembled_packages != expected_packages {
        return Err(ArchitectureBriefRuntimeError::Assembly);
    }
    package_briefs.sort_by(|left, right| left.package.cmp(&right.package));
    if !package_briefs.windows(2).all(|pair| pair[0].package < pair[1].package) {
        return Err(ArchitectureBriefRuntimeError::Assembly);
    }

    ArchitectureBrief::new(
        first.repository_lineage,
        first.source_selector.clone(),
        first.workspace_manifest.clone(),
        scope,
        first.analysis_definition_digest,
        first.package_universe.clone(),
        evidence.into_values().collect(),
        package_briefs,
    )
    .map_err(Into::into)
}

fn referenced_evidence(
    packages: &[ArchitecturePackageBrief],
    evidence: &[ArchitectureEvidence],
) -> Result<Vec<ArchitectureEvidence>, ArchitectureBriefRuntimeError> {
    let mut ids = BTreeSet::new();
    for package in packages {
        ids.extend(package.summary_evidence_ids.iter().copied());
        for assertion in &package.assertions {
            ids.extend(assertion.evidence_ids.iter().copied());
        }
    }
    let values = evidence.iter().filter(|item| ids.contains(&item.id)).cloned().collect::<Vec<_>>();
    if values.len() != ids.len() {
        return Err(ArchitectureBriefRuntimeError::ProjectionScope);
    }
    Ok(values)
}
