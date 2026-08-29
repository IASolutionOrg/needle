use super::{ChangeImpactRuntimeError, change_impact_analysis_definition};
use needle_core::{
    ChangeImpact, ChangeImpactAssessment, ChangeImpactEvidence, ChangeImpactEvidenceRole,
    ChangeImpactScope, Digest, MAX_CHANGE_IMPACT_COMPONENTS,
};
use std::collections::{BTreeMap, BTreeSet};

pub fn project_change_impact(
    source: &ChangeImpact,
    scope: ChangeImpactScope,
) -> Result<ChangeImpact, ChangeImpactRuntimeError> {
    source.validate()?;
    scope.validate()?;
    let universe = source.component_universe();
    if scope.components.is_empty()
        || source.analysis_definition_digest != change_impact_analysis_definition()
        || !scope.is_projection_of(&source.scope)
        || scope.components.iter().any(|key| universe.binary_search(key).is_err())
    {
        return Err(ChangeImpactRuntimeError::ProjectionScope);
    }
    let assessments = source
        .assessments
        .iter()
        .filter(|assessment| scope.includes(&assessment.key))
        .cloned()
        .collect::<Vec<_>>();
    let evidence = referenced_evidence(&assessments, &source.evidence)?;
    ChangeImpact::new(
        source.repository_lineage,
        source.source_selector.clone(),
        source.change_set.clone(),
        scope,
        source.analysis_definition_digest,
        source.requirement_universe.clone(),
        source.constraints.clone(),
        source.subject_universe.clone(),
        source.accepted_inputs.clone(),
        source.test_inventory_digest,
        source.test_inventory_validation_certificate,
        evidence,
        assessments,
        source.gaps.clone(),
    )
    .map_err(Into::into)
}

pub fn assemble_change_impacts(
    inputs: &[ChangeImpact],
    scope: ChangeImpactScope,
) -> Result<ChangeImpact, ChangeImpactRuntimeError> {
    if inputs.len() < 2 || inputs.len() > MAX_CHANGE_IMPACT_COMPONENTS {
        return Err(ChangeImpactRuntimeError::Assembly);
    }
    scope.validate()?;
    let first = &inputs[0];
    first.validate()?;
    if first.analysis_definition_digest != change_impact_analysis_definition() {
        return Err(ChangeImpactRuntimeError::Assembly);
    }

    let mut selected = BTreeSet::new();
    let mut assessments = Vec::<ChangeImpactAssessment>::new();
    let mut evidence = BTreeMap::<Digest, ChangeImpactEvidence>::new();
    for input in inputs {
        input.validate()?;
        if input.repository_lineage != first.repository_lineage
            || input.source_selector != first.source_selector
            || input.change_set != first.change_set
            || input.analysis_definition_digest != first.analysis_definition_digest
            || input.requirement_universe != first.requirement_universe
            || input.constraints != first.constraints
            || input.subject_universe != first.subject_universe
            || input.accepted_inputs != first.accepted_inputs
            || input.test_inventory_digest != first.test_inventory_digest
            || input.test_inventory_validation_certificate
                != first.test_inventory_validation_certificate
            || input.gaps != first.gaps
            || input.scope.components.is_empty()
        {
            return Err(ChangeImpactRuntimeError::Assembly);
        }
        for key in &input.scope.components {
            if !selected.insert(*key) {
                return Err(ChangeImpactRuntimeError::Assembly);
            }
        }
        assessments.extend(input.assessments.iter().cloned());
        for item in &input.evidence {
            match evidence.get(&item.id) {
                Some(existing) if existing != item => {
                    return Err(ChangeImpactRuntimeError::Assembly);
                }
                Some(_) => {}
                None => {
                    evidence.insert(item.id, item.clone());
                }
            }
        }
    }
    let selected = selected.into_iter().collect::<Vec<_>>();
    let universe = first.component_universe();
    let expected = if scope.components.is_empty() { &universe } else { &scope.components };
    if &selected != expected {
        return Err(ChangeImpactRuntimeError::Assembly);
    }
    assessments.sort_by_key(|assessment| assessment.key);
    ChangeImpact::new(
        first.repository_lineage,
        first.source_selector.clone(),
        first.change_set.clone(),
        scope,
        first.analysis_definition_digest,
        first.requirement_universe.clone(),
        first.constraints.clone(),
        first.subject_universe.clone(),
        first.accepted_inputs.clone(),
        first.test_inventory_digest,
        first.test_inventory_validation_certificate,
        evidence.into_values().collect(),
        assessments,
        first.gaps.clone(),
    )
    .map_err(Into::into)
}

fn referenced_evidence(
    assessments: &[ChangeImpactAssessment],
    evidence: &[ChangeImpactEvidence],
) -> Result<Vec<ChangeImpactEvidence>, ChangeImpactRuntimeError> {
    let mut ids = assessments
        .iter()
        .flat_map(|assessment| assessment.evidence_ids.iter().copied())
        .collect::<BTreeSet<_>>();
    ids.extend(
        evidence
            .iter()
            .filter(|item| {
                item.roles.binary_search(&ChangeImpactEvidenceRole::ChangedSurface).is_ok()
            })
            .map(|item| item.id),
    );
    let values = evidence.iter().filter(|item| ids.contains(&item.id)).cloned().collect::<Vec<_>>();
    if values.len() != ids.len() {
        return Err(ChangeImpactRuntimeError::ProjectionScope);
    }
    Ok(values)
}
