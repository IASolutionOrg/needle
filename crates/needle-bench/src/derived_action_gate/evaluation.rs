use super::{
    DERIVED_ACTION_GATE_FORMAT_REVISION, DERIVED_ACTION_GATE_REPORT_SCHEMA,
    DerivedActionEvaluationArm, DerivedActionEvidenceClass, DerivedActionGateAcceptance,
    DerivedActionGateActionReport, DerivedActionGateError, DerivedActionGateManifest,
    DerivedActionGateObservation, DerivedActionGateReport, DerivedActionGateTask,
    DerivedActionGateTaskReport, DerivedActionKind, DerivedActionObservationParse,
    DerivedActionReuseScenario, MAX_DERIVED_ACTION_GATE_FAILURE_BYTES,
    MAX_DERIVED_ACTION_GATE_FAILURES, MAX_DERIVED_ACTION_GATE_OBSERVATIONS,
};
use needle_core::{CanonicalHasher, Digest};
use std::collections::BTreeMap;

type ObservationKey = (String, u64, DerivedActionEvaluationArm);

struct EvaluatedTask {
    report: DerivedActionGateTaskReport,
    protocol_valid: bool,
}

pub fn evaluate_derived_action_gate(
    manifest: &DerivedActionGateManifest,
    parsed: &DerivedActionObservationParse,
    acceptance: Option<&DerivedActionGateAcceptance>,
) -> Result<DerivedActionGateReport, DerivedActionGateError> {
    manifest.validate()?;
    let parsed_items = parsed.observations.len().saturating_add(parsed.errors.len());
    if parsed_items > MAX_DERIVED_ACTION_GATE_OBSERVATIONS {
        return Err(DerivedActionGateError::Bound {
            field: "observations.items",
            actual: parsed_items,
            maximum: MAX_DERIVED_ACTION_GATE_OBSERVATIONS,
        });
    }
    let bounded_parse_errors =
        parsed.errors.iter().map(|error| bounded_failure(error)).collect::<Vec<_>>();
    let mut failures = Vec::new();
    for error in &bounded_parse_errors {
        push_failure(&mut failures, error.clone());
    }
    let mut protocol_valid = parsed.errors.is_empty();
    let mut observations = Vec::with_capacity(parsed.observations.len());
    for observation in &parsed.observations {
        match observation.validate() {
            Ok(()) => observations.push(observation),
            Err(error) => {
                protocol_valid = false;
                push_failure(
                    &mut failures,
                    format!("invalid observation for {}: {error}", observation.task_id),
                );
            }
        }
    }
    observations.sort_by_key(|observation| {
        (observation.task_id.as_str(), observation.pair_seed, observation.arm)
    });
    let observation_set_digest = observation_set_digest(&observations, &bounded_parse_errors);
    let (acceptance_artifact_digest, acceptance_valid) = match (manifest.evidence_class, acceptance)
    {
        (DerivedActionEvidenceClass::AcceptedShadow, Some(acceptance)) => {
            acceptance.validate()?;
            let valid =
                match acceptance.validate_for(manifest.manifest_digest, observation_set_digest) {
                    Ok(()) => true,
                    Err(error) => {
                        push_failure(&mut failures, error.to_string());
                        false
                    }
                };
            (Some(acceptance.acceptance_digest), valid)
        }
        (DerivedActionEvidenceClass::AcceptedShadow, None) => {
            push_failure(
                &mut failures,
                "accepted Shadow evidence requires an external acceptance artifact".to_owned(),
            );
            (None, false)
        }
        (_, Some(_)) => return Err(DerivedActionGateError::AcceptanceBinding),
        (_, None) => (None, false),
    };
    let provider_calls_observed = observations
        .iter()
        .map(|observation| u32::from(observation.provider_calls))
        .fold(0_u32, u32::saturating_add);

    let task_by_id =
        manifest.tasks.iter().map(|task| (task.id.as_str(), task)).collect::<BTreeMap<_, _>>();
    let mut by_key = BTreeMap::<ObservationKey, &DerivedActionGateObservation>::new();
    for observation in &observations {
        let key = (observation.task_id.clone(), observation.pair_seed, observation.arm);
        if by_key.insert(key, observation).is_some() {
            protocol_valid = false;
            push_failure(
                &mut failures,
                format!(
                    "duplicate observation for {} seed {} {:?}",
                    observation.task_id, observation.pair_seed, observation.arm
                ),
            );
        }
        let Some(task) = task_by_id.get(observation.task_id.as_str()) else {
            protocol_valid = false;
            push_failure(
                &mut failures,
                format!("observation references unknown task {}", observation.task_id),
            );
            continue;
        };
        if task.pair_seeds.binary_search(&observation.pair_seed).is_err() {
            protocol_valid = false;
            push_failure(
                &mut failures,
                format!("observation uses undeclared pair seed for {}", observation.task_id),
            );
        }
    }

    let evaluated = manifest
        .tasks
        .iter()
        .map(|task| evaluate_task(manifest, task, &by_key))
        .collect::<Vec<_>>();
    protocol_valid &= evaluated.iter().all(|task| task.protocol_valid);
    let tasks = evaluated.into_iter().map(|task| task.report).collect::<Vec<_>>();
    let gate_a3_eligible = match manifest.evidence_class {
        DerivedActionEvidenceClass::Synthetic => false,
        DerivedActionEvidenceClass::AcceptedShadow => acceptance_valid,
        DerivedActionEvidenceClass::ProviderBacked => true,
    };
    let actions = DerivedActionKind::ALL
        .into_iter()
        .map(|action| action_report(action, &tasks, gate_a3_eligible))
        .collect::<Vec<_>>();

    let structural_validation_passed = tasks.iter().all(|task| task.structural_validation_passed);
    let quality_passed = tasks.iter().all(|task| task.quality_passed);
    let semantic_equivalence_passed = tasks.iter().all(|task| task.semantic_equivalence_passed);
    let positive_net_value = tasks.iter().all(|task| task.positive_net_value);
    let gate_a3_passed =
        gate_a3_eligible && protocol_valid && actions.iter().all(|action| action.gate_a3_passed);

    for task in &tasks {
        for failure in &task.failures {
            push_failure(&mut failures, format!("{}: {failure}", task.task_id));
        }
    }
    if manifest.evidence_class == DerivedActionEvidenceClass::Synthetic {
        push_failure(
            &mut failures,
            "synthetic material is protocol-only and cannot close Gate A3".to_owned(),
        );
    }
    failures.sort();
    failures.dedup();

    let mut report = DerivedActionGateReport {
        format_revision: DERIVED_ACTION_GATE_FORMAT_REVISION,
        schema: DERIVED_ACTION_GATE_REPORT_SCHEMA.to_owned(),
        manifest_digest: manifest.manifest_digest,
        observation_set_digest,
        evidence_class: manifest.evidence_class,
        evidence_claim: manifest.evidence_class.evidence_claim(acceptance_valid).to_owned(),
        acceptance_artifact_digest,
        acceptance_valid,
        provider_execution_performed_by_harness: false,
        provider_calls_observed,
        protocol_valid,
        structural_validation_passed,
        quality_passed,
        semantic_equivalence_passed,
        positive_net_value,
        gate_a3_eligible,
        gate_a3_passed,
        statistical_claim: false,
        tasks,
        actions,
        failures,
        report_digest: Digest([0; 32]),
    };
    report.seal();
    report.validate()?;
    Ok(report)
}

fn evaluate_task(
    manifest: &DerivedActionGateManifest,
    task: &DerivedActionGateTask,
    observations: &BTreeMap<ObservationKey, &DerivedActionGateObservation>,
) -> EvaluatedTask {
    let mut failures = Vec::new();
    let mut protocol_valid = true;
    let mut observed_pairs = 0_u16;
    let mut structural_validation_passed = true;
    let mut quality_passed = true;
    let mut semantic_equivalence_passed = true;
    let mut positive_net_value = true;
    let mut fresh_cost = Some(0_u64);
    let mut reuse_cost = Some(0_u64);

    for seed in &task.pair_seeds {
        let fresh = observations.get(&(task.id.clone(), *seed, DerivedActionEvaluationArm::Fresh));
        let reuse = observations.get(&(task.id.clone(), *seed, DerivedActionEvaluationArm::Reuse));
        let (Some(fresh), Some(reuse)) = (fresh, reuse) else {
            protocol_valid = false;
            structural_validation_passed = false;
            quality_passed = false;
            semantic_equivalence_passed = false;
            positive_net_value = false;
            push_failure(&mut failures, format!("missing Fresh/Reuse pair for seed {seed}"));
            continue;
        };
        observed_pairs = observed_pairs.saturating_add(1);
        for observation in [*fresh, *reuse] {
            if observation.manifest_digest != manifest.manifest_digest
                || observation.task_id != task.id
                || observation.action != task.action
                || observation.scenario != task.scenario
                || observation.evidence_class != manifest.evidence_class
                || observation.execution_profile_digest != task.execution_profile_digest
                || observation.oracle_commitment != task.oracle_commitment
            {
                protocol_valid = false;
                push_failure(&mut failures, format!("binding mismatch for seed {seed}"));
            }
            if observation.infrastructure_failure.is_some() {
                protocol_valid = false;
                push_failure(&mut failures, format!("infrastructure failure for seed {seed}"));
            }
        }
        if fresh.pricing_snapshot_digest != reuse.pricing_snapshot_digest {
            protocol_valid = false;
            push_failure(&mut failures, format!("pricing mismatch for seed {seed}"));
        }
        if fresh.provider_calls > 1 {
            protocol_valid = false;
            push_failure(
                &mut failures,
                format!("automatic retry or multiple provider calls for seed {seed}"),
            );
        }
        let pair_structural =
            fresh.structural_validation_passed && reuse.structural_validation_passed;
        structural_validation_passed &= pair_structural;
        if !pair_structural {
            push_failure(&mut failures, format!("structural validation failed for seed {seed}"));
        }
        let pair_quality = fresh.quality_passed && reuse.quality_passed;
        quality_passed &= pair_quality;
        if !pair_quality {
            push_failure(&mut failures, format!("quality oracle failed for seed {seed}"));
        }
        let pair_equivalent = reuse.semantic_equivalence_passed == Some(true)
            && (task.scenario != DerivedActionReuseScenario::Exact
                || fresh.output_digest == reuse.output_digest);
        semantic_equivalence_passed &= pair_equivalent;
        if !pair_equivalent {
            push_failure(&mut failures, format!("semantic equivalence failed for seed {seed}"));
        }
        let pair_positive = fresh.total_cost_microcredits > reuse.total_cost_microcredits;
        positive_net_value &= pair_positive;
        if !pair_positive {
            push_failure(&mut failures, format!("reuse was not cheaper for seed {seed}"));
        }
        fresh_cost = fresh_cost.and_then(|total| total.checked_add(fresh.total_cost_microcredits));
        reuse_cost = reuse_cost.and_then(|total| total.checked_add(reuse.total_cost_microcredits));
        if fresh_cost.is_none() || reuse_cost.is_none() {
            protocol_valid = false;
            positive_net_value = false;
            push_failure(&mut failures, "cost total overflow".to_owned());
        }
    }

    failures.sort();
    failures.dedup();
    let passed = protocol_valid
        && structural_validation_passed
        && quality_passed
        && semantic_equivalence_passed
        && positive_net_value;
    EvaluatedTask {
        protocol_valid,
        report: DerivedActionGateTaskReport {
            task_id: task.id.clone(),
            action: task.action,
            scenario: task.scenario,
            expected_pairs: task.pair_seeds.len().try_into().unwrap_or(u16::MAX),
            observed_pairs,
            structural_validation_passed,
            quality_passed,
            semantic_equivalence_passed,
            positive_net_value,
            fresh_cost_microcredits: fresh_cost,
            reuse_cost_microcredits: reuse_cost,
            savings_basis_points: savings_basis_points(fresh_cost, reuse_cost),
            passed,
            failures,
        },
    }
}

pub(super) fn action_report(
    action: DerivedActionKind,
    tasks: &[DerivedActionGateTaskReport],
    gate_a3_eligible: bool,
) -> DerivedActionGateActionReport {
    let scenario_passed = |scenario| {
        let matching = tasks
            .iter()
            .filter(|task| task.action == action && task.scenario == scenario)
            .collect::<Vec<_>>();
        !matching.is_empty() && matching.iter().all(|task| task.passed)
    };
    let matching = tasks.iter().filter(|task| task.action == action).collect::<Vec<_>>();
    let exact_passed = scenario_passed(DerivedActionReuseScenario::Exact);
    let project_passed = scenario_passed(DerivedActionReuseScenario::Project);
    let assemble_passed = scenario_passed(DerivedActionReuseScenario::Assemble);
    let quality_passed = !matching.is_empty() && matching.iter().all(|task| task.quality_passed);
    let positive_net_value =
        !matching.is_empty() && matching.iter().all(|task| task.positive_net_value);
    let gate_a3_passed = gate_a3_eligible
        && exact_passed
        && project_passed
        && assemble_passed
        && quality_passed
        && positive_net_value;
    DerivedActionGateActionReport {
        action,
        exact_passed,
        project_passed,
        assemble_passed,
        quality_passed,
        positive_net_value,
        gate_a3_passed,
    }
}

fn observation_set_digest(
    observations: &[&DerivedActionGateObservation],
    parse_errors: &[String],
) -> Digest {
    let mut hasher = CanonicalHasher::new(b"derived-action-gate-a3-observation-set-v1");
    hasher.field_u16(observations.len().try_into().unwrap_or(u16::MAX));
    for observation in observations {
        hasher.field_digest(observation.canonical_digest());
    }
    hasher.field_u16(parse_errors.len().try_into().unwrap_or(u16::MAX));
    for error in parse_errors {
        hasher.field_str(error);
    }
    hasher.finish()
}

fn savings_basis_points(fresh: Option<u64>, reuse: Option<u64>) -> Option<i64> {
    let (fresh, reuse) = fresh.zip(reuse)?;
    if fresh == 0 {
        return None;
    }
    let difference = i128::from(fresh) - i128::from(reuse);
    let basis_points = difference.saturating_mul(10_000) / i128::from(fresh);
    Some(basis_points.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64)
}

fn push_failure(failures: &mut Vec<String>, failure: String) {
    if failures.len() < MAX_DERIVED_ACTION_GATE_FAILURES {
        failures.push(bounded_failure(&failure));
    }
}

fn bounded_failure(failure: &str) -> String {
    if failure.len() <= MAX_DERIVED_ACTION_GATE_FAILURE_BYTES {
        return failure.to_owned();
    }
    failure.chars().take(MAX_DERIVED_ACTION_GATE_FAILURE_BYTES / 4).collect()
}

#[cfg(test)]
pub(crate) fn expected_observation_keys(
    manifest: &DerivedActionGateManifest,
) -> std::collections::BTreeSet<(String, u64, DerivedActionEvaluationArm)> {
    manifest
        .tasks
        .iter()
        .flat_map(|task| {
            task.pair_seeds.iter().flat_map(move |seed| {
                [DerivedActionEvaluationArm::Fresh, DerivedActionEvaluationArm::Reuse]
                    .into_iter()
                    .map(move |arm| (task.id.clone(), *seed, arm))
            })
        })
        .collect()
}
