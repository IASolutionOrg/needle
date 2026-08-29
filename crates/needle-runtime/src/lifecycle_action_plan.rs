use crate::{
    built_in_action_contracts, built_in_action_for_predicate,
    semantic_action_request::build_semantic_action_request,
};
use needle_core::{
    Digest, LifecycleError, LifecycleExploreActionPlan, MAX_NEED_INPUTS, MAX_NEED_SUBJECTS,
    MAX_OBLIGATION_FACETS, MAX_PREFERRED_OBLIGATIONS, MAX_REQUIRED_OBLIGATIONS,
    MAX_SEMANTIC_CONSTRAINTS, NEED_IR_FORMAT_REVISION, Need, NeedFragment, NeedRequest,
};
use std::collections::BTreeSet;
use thiserror::Error;

pub fn compile_lifecycle_explore_action_plan(
    request: &NeedRequest,
    need: &Need,
    fragment: &NeedFragment,
    repository_id: Digest,
    source_snapshot_digest: Digest,
) -> Result<LifecycleExploreActionPlan, LifecycleExploreActionPlanError> {
    validate_complete_fragment(request, need, fragment, repository_id)?;
    if source_snapshot_digest == Digest([0; 32]) {
        return Err(LifecycleExploreActionPlanError::SourceBinding);
    }

    let predicates =
        fragment.obligations.iter().map(|obligation| obligation.predicate).collect::<BTreeSet<_>>();
    let actions = predicates
        .into_iter()
        .map(|predicate| {
            let definition = built_in_action_for_predicate(predicate);
            build_semantic_action_request(
                request,
                fragment,
                repository_id,
                source_snapshot_digest,
                definition,
            )
            .map_err(LifecycleExploreActionPlanError::Action)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let plan =
        LifecycleExploreActionPlan::new(fragment.clone(), actions, need.definition_digest())?;
    validate_lifecycle_explore_action_plan(&plan)?;
    Ok(plan)
}

pub fn validate_lifecycle_explore_action_plan(
    plan: &LifecycleExploreActionPlan,
) -> Result<(), LifecycleExploreActionPlanError> {
    plan.validate()?;
    let expected_contracts = plan
        .fragment
        .obligations
        .iter()
        .map(|obligation| built_in_action_for_predicate(obligation.predicate).contract.id.clone())
        .collect::<BTreeSet<_>>();
    if expected_contracts.len() != plan.actions.len()
        || plan.actions.iter().any(|request| !expected_contracts.contains(&request.contract))
    {
        return Err(LifecycleExploreActionPlanError::ActionDefinition);
    }
    for request in &plan.actions {
        let definition = built_in_action_contracts()
            .iter()
            .find(|candidate| candidate.contract.id == request.contract)
            .ok_or(LifecycleExploreActionPlanError::ActionDefinition)?;
        request
            .validate(&definition.contract)
            .map_err(|error| LifecycleExploreActionPlanError::Action(error.to_string()))?;
        if request.artifact_request.contract_id != definition.output_contract_id
            || request.artifact_request.contract_revision != definition.output_contract_revision
            || definition.predicate().is_none_or(|predicate| {
                !plan
                    .fragment
                    .obligations
                    .iter()
                    .any(|obligation| obligation.predicate == predicate)
            })
        {
            return Err(LifecycleExploreActionPlanError::ActionDefinition);
        }
    }
    Ok(())
}

pub(crate) fn validate_lifecycle_explore_action_plan_need(
    plan: &LifecycleExploreActionPlan,
    need: &Need,
) -> Result<NeedRequest, LifecycleExploreActionPlanError> {
    validate_lifecycle_explore_action_plan(plan)?;
    let action = plan.actions.first().ok_or(LifecycleExploreActionPlanError::ActionDefinition)?;
    let request = NeedRequest {
        key: action.route.clone(),
        body: action.artifact_request.normalized_request.clone(),
    };
    validate_complete_fragment(&request, need, &plan.fragment, plan.repository_id())?;
    if plan.need_definition_digest != need.definition_digest() {
        return Err(LifecycleExploreActionPlanError::NeedBinding);
    }
    Ok(request)
}

fn validate_complete_fragment(
    request: &NeedRequest,
    need: &Need,
    fragment: &NeedFragment,
    repository_id: Digest,
) -> Result<(), LifecycleExploreActionPlanError> {
    if need.format_revision != NEED_IR_FORMAT_REVISION
        || need.subjects.len() > MAX_NEED_SUBJECTS
        || need.required.len() > MAX_REQUIRED_OBLIGATIONS
        || need.preferred.len() > MAX_PREFERRED_OBLIGATIONS
        || need.semantic_constraints.len() > MAX_SEMANTIC_CONSTRAINTS
        || need.input_artifacts.len() > MAX_NEED_INPUTS
        || need
            .required
            .iter()
            .chain(&need.preferred)
            .any(|obligation| obligation.facets.len() > MAX_OBLIGATION_FACETS)
        || need.required.is_empty()
        || need.residual.is_some()
        || Digest::blake3(request.body.as_bytes()) != need.body_digest
        || fragment.root_need != need.id
        || fragment.subject_definitions != need.subjects
        || fragment.obligations != need.required
        || fragment.world != need.world
        || fragment.semantic_inputs != need.input_artifacts
        || fragment.world.repository_lineage != repository_id
        || !fragment.is_consistent()
    {
        return Err(LifecycleExploreActionPlanError::NeedBinding);
    }
    Ok(())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LifecycleExploreActionPlanError {
    #[error(transparent)]
    Lifecycle(#[from] LifecycleError),
    #[error("lifecycle Explore plan is not bound to a complete accepted Need fragment")]
    NeedBinding,
    #[error("lifecycle Explore plan source snapshot is invalid")]
    SourceBinding,
    #[error("lifecycle Explore plan references an incompatible action definition")]
    ActionDefinition,
    #[error("lifecycle Explore action request is invalid: {0}")]
    Action(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use needle_core::{
        Facet, NeedId, Obligation, PredicateKind, SemanticWorld, Subject, SubjectKind,
        need_fragment,
    };

    fn fixture() -> (NeedRequest, Need, NeedFragment, Digest, Digest) {
        let repository = Digest::blake3(b"lifecycle-plan-repository");
        let source = Digest::blake3(b"lifecycle-plan-source");
        let subject = Subject::exact(repository, SubjectKind::CliOption, "--flag");
        let mut required = vec![
            Obligation::new(
                PredicateKind::ImplementationLocation,
                subject.id,
                vec![Facet { key: "selection".to_owned(), value: "primary".to_owned() }],
            ),
            Obligation::new(
                PredicateKind::RuntimeFlow,
                subject.id,
                vec![Facet { key: "scenario".to_owned(), value: "default".to_owned() }],
            ),
        ];
        required.sort();
        let request = NeedRequest {
            key: needle_core::NeedKey::new("trace.state-flow").unwrap(),
            body: "Trace the flag through the current source.".to_owned(),
        };
        let need = Need {
            id: NeedId::new(Digest::blake3(b"lifecycle-plan-need")),
            subjects: vec![subject],
            required,
            preferred: Vec::new(),
            semantic_constraints: Vec::new(),
            world: SemanticWorld {
                repository_lineage: repository,
                source_selector: "worktree".to_owned(),
                platform: "windows".to_owned(),
                features: "default".to_owned(),
                configuration: None,
                toolchain: None,
            },
            input_artifacts: Vec::new(),
            residual: None,
            body_digest: Digest::blake3(request.body.as_bytes()),
            format_revision: NEED_IR_FORMAT_REVISION,
        };
        let fragment = need_fragment(&need, need.required.clone(), need.input_artifacts.clone());
        (request, need, fragment, repository, source)
    }

    #[test]
    fn compiler_emits_one_canonical_action_per_required_predicate() {
        let (request, need, fragment, repository, source) = fixture();
        let plan =
            compile_lifecycle_explore_action_plan(&request, &need, &fragment, repository, source)
                .unwrap();
        assert_eq!(plan.actions.len(), 2);
        assert_eq!(plan.need_definition_digest, need.definition_digest());
        assert_eq!(plan.source_snapshot(), Some(source));
        assert_eq!(plan.repository_id(), repository);
        assert!(plan.actions.windows(2).all(|pair| pair[0].contract < pair[1].contract));
        validate_lifecycle_explore_action_plan(&plan).unwrap();
    }

    #[test]
    fn compiler_rejects_partial_or_reworded_need_material() {
        let (mut request, mut need, fragment, repository, source) = fixture();
        need.residual = Some(needle_core::ResidualIntent {
            raw_digest: Digest::blake3(b"residual"),
            reason: needle_core::ResidualReason::LegacyFreeForm,
            mandatory: true,
        });
        assert_eq!(
            compile_lifecycle_explore_action_plan(&request, &need, &fragment, repository, source,),
            Err(LifecycleExploreActionPlanError::NeedBinding)
        );
        need.residual = None;
        request.body.push_str(" changed");
        assert_eq!(
            compile_lifecycle_explore_action_plan(&request, &need, &fragment, repository, source,),
            Err(LifecycleExploreActionPlanError::NeedBinding)
        );
    }

    #[test]
    fn validator_requires_one_action_for_every_distinct_predicate() {
        let (request, need, fragment, repository, source) = fixture();
        let complete =
            compile_lifecycle_explore_action_plan(&request, &need, &fragment, repository, source)
                .unwrap();
        let incomplete = LifecycleExploreActionPlan::new(
            complete.fragment.clone(),
            vec![complete.actions[0].clone()],
            complete.need_definition_digest,
        )
        .unwrap();

        assert_eq!(
            validate_lifecycle_explore_action_plan(&incomplete),
            Err(LifecycleExploreActionPlanError::ActionDefinition)
        );
    }

    #[test]
    fn validator_rejects_a_different_stored_need_definition() {
        let (request, need, fragment, repository, source) = fixture();
        let plan =
            compile_lifecycle_explore_action_plan(&request, &need, &fragment, repository, source)
                .unwrap();
        let mut different = need;
        different.preferred = vec![different.required[0].clone()];

        assert_eq!(
            validate_lifecycle_explore_action_plan_need(&plan, &different),
            Err(LifecycleExploreActionPlanError::NeedBinding)
        );
    }
}
