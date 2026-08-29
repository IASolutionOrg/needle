use super::evaluation::expected_observation_keys;
use super::*;
use serde_json::json;

fn manifest(class: DerivedActionEvidenceClass) -> DerivedActionGateManifest {
    let mut tasks = Vec::new();
    for action in DerivedActionKind::ALL {
        for scenario in DerivedActionReuseScenario::ALL {
            let action_name = match action {
                DerivedActionKind::ArchitectureBrief => "architecture",
                DerivedActionKind::ChangeImpact => "change-impact",
            };
            let scenario_name = match scenario {
                DerivedActionReuseScenario::Exact => "exact",
                DerivedActionReuseScenario::Project => "project",
                DerivedActionReuseScenario::Assemble => "assemble",
            };
            let id = format!("{action_name}-{scenario_name}");
            tasks.push(
                DerivedActionGateTask::new(
                    id.as_str(),
                    action,
                    scenario,
                    Digest::blake3(format!("request-{id}")),
                    Digest::blake3(format!("fixture-{id}")),
                    Digest::blake3(format!("oracle-{id}")),
                    Digest::blake3(b"execution-profile"),
                    vec![7],
                )
                .unwrap(),
            );
        }
    }
    DerivedActionGateManifest::new(class, "0123456789abcdef0123456789abcdef01234567", tasks)
        .unwrap()
}

fn observations(manifest: &DerivedActionGateManifest) -> Vec<DerivedActionGateObservation> {
    let mut observations = Vec::new();
    for task in &manifest.tasks {
        for arm in [DerivedActionEvaluationArm::Fresh, DerivedActionEvaluationArm::Reuse] {
            let fresh = arm == DerivedActionEvaluationArm::Fresh;
            let provider_calls = u16::from(
                fresh && manifest.evidence_class == DerivedActionEvidenceClass::ProviderBacked,
            );
            let output_digest = if fresh || task.scenario == DerivedActionReuseScenario::Exact {
                Digest::blake3(format!("fresh-output-{}", task.id))
            } else {
                Digest::blake3(format!("reuse-output-{}", task.id))
            };
            observations.push(DerivedActionGateObservation {
                format_revision: DERIVED_ACTION_GATE_FORMAT_REVISION,
                schema: DERIVED_ACTION_GATE_OBSERVATION_SCHEMA.to_owned(),
                manifest_digest: manifest.manifest_digest,
                task_id: task.id.clone(),
                action: task.action,
                scenario: task.scenario,
                arm,
                pair_seed: 7,
                evidence_class: manifest.evidence_class,
                execution_profile_digest: task.execution_profile_digest,
                model_id: fresh.then(|| "fixture-model".to_owned()),
                pricing_snapshot_digest: Digest::blake3(b"pricing"),
                oracle_commitment: task.oracle_commitment,
                quality_judgment_digest: Digest::blake3(format!("quality-{}-{arm:?}", task.id)),
                output_digest,
                validation_certificate_digest: Digest::blake3(format!(
                    "certificate-{}-{arm:?}",
                    task.id
                )),
                structural_validation_passed: true,
                quality_passed: true,
                semantic_equivalence_passed: (!fresh).then_some(true),
                total_cost_microcredits: if fresh { 1_000 } else { 200 },
                latency_micros: if fresh { 100_000 } else { 1_000 },
                worker_started: fresh,
                provider_calls,
                provider_observation_digest: (provider_calls > 0)
                    .then(|| Digest::blake3(format!("provider-{}", task.id))),
                infrastructure_failure: None,
            });
        }
    }
    observations
}

fn parsed(observations: Vec<DerivedActionGateObservation>) -> DerivedActionObservationParse {
    DerivedActionObservationParse { observations, errors: Vec::new() }
}

fn accepted_shadow_artifact(
    manifest: &DerivedActionGateManifest,
    observations: &[DerivedActionGateObservation],
) -> DerivedActionGateAcceptance {
    let preflight =
        evaluate_derived_action_gate(manifest, &parsed(observations.to_vec()), None).unwrap();
    let decisions = DerivedActionKind::ALL
        .into_iter()
        .flat_map(|action| {
            DerivedActionReuseScenario::ALL.into_iter().map(move |scenario| {
                DerivedActionGateAcceptanceDecision::accepted(action, scenario)
            })
        })
        .collect();
    DerivedActionGateAcceptance::new(
        manifest.manifest_digest,
        preflight.observation_set_digest,
        Digest::blake3(b"reviewed-output-material"),
        "human-reviewer",
        1_786_320_000_000,
        decisions,
        vec![
            "bounded single-seed Shadow calibration; no authority or statistical claim".to_owned(),
        ],
    )
    .unwrap()
}

#[test]
fn synthetic_protocol_is_complete_positive_and_permanently_gate_ineligible() {
    let manifest = manifest(DerivedActionEvidenceClass::Synthetic);
    let observations = observations(&manifest);
    assert_eq!(expected_observation_keys(&manifest).len(), observations.len());
    let report = evaluate_derived_action_gate(&manifest, &parsed(observations), None).unwrap();
    assert!(report.protocol_valid);
    assert!(report.structural_validation_passed);
    assert!(report.quality_passed);
    assert!(report.semantic_equivalence_passed);
    assert!(report.positive_net_value);
    assert!(!report.gate_a3_eligible);
    assert!(!report.gate_a3_passed);
    assert_eq!(report.provider_calls_observed, 0);
    assert_eq!(report.evidence_claim, "protocol_only_synthetic");
    assert!(!report.provider_execution_performed_by_harness);
    assert!(!report.statistical_claim);
    assert!(report.actions.iter().all(|action| !action.gate_a3_passed));
    assert!(report.validate().is_ok());
}

#[test]
fn imported_provider_or_accepted_shadow_evidence_can_close_only_the_bounded_gate() {
    let provider = manifest(DerivedActionEvidenceClass::ProviderBacked);
    let provider_report =
        evaluate_derived_action_gate(&provider, &parsed(observations(&provider)), None).unwrap();
    assert!(provider_report.protocol_valid);
    assert!(provider_report.gate_a3_eligible);
    assert!(provider_report.gate_a3_passed);
    assert_eq!(provider_report.provider_calls_observed, 6);

    let accepted = manifest(DerivedActionEvidenceClass::AcceptedShadow);
    let accepted_observations = observations(&accepted);
    let missing_acceptance =
        evaluate_derived_action_gate(&accepted, &parsed(accepted_observations.clone()), None)
            .unwrap();
    assert!(missing_acceptance.protocol_valid);
    assert!(!missing_acceptance.acceptance_valid);
    assert_eq!(missing_acceptance.evidence_claim, "accepted_shadow_unaccepted");
    assert!(!missing_acceptance.gate_a3_eligible);
    assert!(!missing_acceptance.gate_a3_passed);
    let acceptance = accepted_shadow_artifact(&accepted, &accepted_observations);
    let accepted_report =
        evaluate_derived_action_gate(&accepted, &parsed(accepted_observations), Some(&acceptance))
            .unwrap();
    assert!(accepted_report.acceptance_valid);
    assert_eq!(accepted_report.evidence_claim, "bounded_accepted_shadow_calibration");
    assert_eq!(accepted_report.acceptance_artifact_digest, Some(acceptance.acceptance_digest));
    assert!(accepted_report.gate_a3_eligible);
    assert!(accepted_report.gate_a3_passed);
    assert!(accepted_report.actions.iter().all(|action| action.gate_a3_passed));
    assert!(!accepted_report.statistical_claim);
    assert!(!accepted_report.provider_execution_performed_by_harness);
    assert_eq!(accepted_report.provider_calls_observed, 0);

    let mut provider_misclassified = observations(&accepted).remove(0);
    provider_misclassified.provider_calls = 1;
    provider_misclassified.provider_observation_digest = Some(Digest::blake3(b"provider"));
    assert!(matches!(
        provider_misclassified.validate(),
        Err(DerivedActionGateError::ProviderBinding(_))
    ));
}

#[test]
fn quality_economics_missing_pairs_and_duplicates_fail_closed_independently() {
    let manifest = manifest(DerivedActionEvidenceClass::AcceptedShadow);
    let mut quality = observations(&manifest);
    let reuse = quality
        .iter_mut()
        .find(|observation| observation.arm == DerivedActionEvaluationArm::Reuse)
        .unwrap();
    reuse.quality_passed = false;
    reuse.total_cost_microcredits = 1_100;
    let report = evaluate_derived_action_gate(&manifest, &parsed(quality), None).unwrap();
    assert!(report.protocol_valid);
    assert!(!report.quality_passed);
    assert!(!report.positive_net_value);
    assert!(!report.gate_a3_passed);

    let mut incomplete = observations(&manifest);
    incomplete.pop();
    let report = evaluate_derived_action_gate(&manifest, &parsed(incomplete), None).unwrap();
    assert!(!report.protocol_valid);
    assert!(!report.gate_a3_passed);

    let mut duplicate = observations(&manifest);
    duplicate.push(duplicate[0].clone());
    let report = evaluate_derived_action_gate(&manifest, &parsed(duplicate), None).unwrap();
    assert!(!report.protocol_valid);
    assert!(!report.gate_a3_passed);

    let direct_errors = DerivedActionObservationParse {
        observations: Vec::new(),
        errors: (0..129)
            .map(|index| {
                format!("{index}-{}", "x".repeat(MAX_DERIVED_ACTION_GATE_FAILURE_BYTES + 1))
            })
            .collect(),
    };
    let report = evaluate_derived_action_gate(&manifest, &direct_errors, None).unwrap();
    assert!(!report.protocol_valid);
    assert_eq!(report.failures.len(), MAX_DERIVED_ACTION_GATE_FAILURES);
    assert!(report.validate().is_ok());

    let mut bypassed_validation = observations(&manifest);
    bypassed_validation[0].model_id =
        Some("x".repeat(MAX_DERIVED_ACTION_GATE_IDENTIFIER_BYTES + 1));
    let report =
        evaluate_derived_action_gate(&manifest, &parsed(bypassed_validation), None).unwrap();
    assert!(!report.protocol_valid);
    assert!(!report.gate_a3_passed);
}

#[test]
fn manifest_definition_drift_scenario_gaps_and_digest_tamper_are_rejected() {
    let mut drifted = manifest(DerivedActionEvidenceClass::Synthetic);
    drifted.tasks[0].validator_definition_digest = Digest::blake3(b"drift");
    assert!(matches!(drifted.validate(), Err(DerivedActionGateError::DefinitionDrift(_))));

    let mut missing = manifest(DerivedActionEvidenceClass::Synthetic);
    missing.tasks.remove(0);
    assert_eq!(missing.validate(), Err(DerivedActionGateError::ScenarioCoverage));

    let mut tampered = manifest(DerivedActionEvidenceClass::Synthetic);
    tampered.manifest_digest = Digest::blake3(b"tampered");
    assert_eq!(
        tampered.validate(),
        Err(DerivedActionGateError::Digest("manifest.manifest_digest"))
    );
}

#[test]
fn accepted_shadow_artifact_is_bounded_external_and_fail_closed() {
    let accepted_manifest = manifest(DerivedActionEvidenceClass::AcceptedShadow);
    let accepted_observations = observations(&accepted_manifest);
    let acceptance = accepted_shadow_artifact(&accepted_manifest, &accepted_observations);
    let encoded = serde_json::to_vec(&acceptance).unwrap();
    assert_eq!(DerivedActionGateAcceptance::decode_json(&encoded).unwrap(), acceptance);
    let mut unknown = serde_json::to_value(&acceptance).unwrap();
    unknown.as_object_mut().unwrap().insert("unknown".to_owned(), json!(true));
    assert!(
        DerivedActionGateAcceptance::decode_json(&serde_json::to_vec(&unknown).unwrap()).is_err()
    );
    let mut digest_tamper = acceptance.clone();
    digest_tamper.acceptance_digest = Digest::blake3(b"tampered-acceptance");
    assert_eq!(
        digest_tamper.validate(),
        Err(DerivedActionGateError::Digest("acceptance.acceptance_digest"))
    );

    let wrong_binding = DerivedActionGateAcceptance::new(
        accepted_manifest.manifest_digest,
        Digest::blake3(b"different-observation-set"),
        Digest::blake3(b"reviewed-output-material"),
        "human-reviewer",
        1_786_320_000_000,
        DerivedActionKind::ALL
            .into_iter()
            .flat_map(|action| {
                DerivedActionReuseScenario::ALL.into_iter().map(move |scenario| {
                    DerivedActionGateAcceptanceDecision::accepted(action, scenario)
                })
            })
            .collect(),
        vec!["bounded calibration only".to_owned()],
    )
    .unwrap();
    let report = evaluate_derived_action_gate(
        &accepted_manifest,
        &parsed(accepted_observations.clone()),
        Some(&wrong_binding),
    )
    .unwrap();
    assert!(!report.acceptance_valid);
    assert!(!report.gate_a3_passed);

    let mut rejected_decisions = acceptance.decisions.clone();
    rejected_decisions[0].semantic_equivalence_accepted = false;
    let rejected = DerivedActionGateAcceptance::new(
        acceptance.manifest_digest,
        acceptance.observation_set_digest,
        acceptance.review_material_digest,
        acceptance.reviewer_id.clone(),
        acceptance.reviewed_unix_ms,
        rejected_decisions,
        acceptance.limitations.clone(),
    )
    .unwrap();
    let report = evaluate_derived_action_gate(
        &accepted_manifest,
        &parsed(accepted_observations),
        Some(&rejected),
    )
    .unwrap();
    assert!(!report.acceptance_valid);
    assert!(!report.gate_a3_eligible);
    assert!(!report.gate_a3_passed);

    let mut authority_tamper = acceptance.clone();
    authority_tamper.authority_promotion_approved = true;
    assert_eq!(authority_tamper.validate(), Err(DerivedActionGateError::ReportAuthority));
    let synthetic = manifest(DerivedActionEvidenceClass::Synthetic);
    assert_eq!(
        evaluate_derived_action_gate(
            &synthetic,
            &parsed(observations(&synthetic)),
            Some(&acceptance),
        ),
        Err(DerivedActionGateError::AcceptanceBinding)
    );
    assert!(matches!(
        DerivedActionGateAcceptance::decode_json(&vec![
            b'x';
            MAX_DERIVED_ACTION_GATE_ACCEPTANCE_BYTES + 1
        ]),
        Err(DerivedActionGateError::Bound { field: "acceptance.bytes", .. })
    ));
}

#[test]
fn bounded_wire_rejects_unknown_fields_oversized_lines_and_report_tamper() {
    let manifest = manifest(DerivedActionEvidenceClass::Synthetic);
    let encoded = serde_json::to_vec(&manifest).unwrap();
    assert_eq!(DerivedActionGateManifest::decode_json(&encoded).unwrap(), manifest);
    let mut unknown = serde_json::to_value(&manifest).unwrap();
    unknown.as_object_mut().unwrap().insert("unknown".to_owned(), json!(true));
    assert!(
        DerivedActionGateManifest::decode_json(&serde_json::to_vec(&unknown).unwrap()).is_err()
    );
    assert!(matches!(
        DerivedActionGateManifest::decode_json(&vec![
            b'x';
            MAX_DERIVED_ACTION_GATE_MANIFEST_BYTES + 1
        ]),
        Err(DerivedActionGateError::Bound { field: "manifest.bytes", .. })
    ));

    let observation = observations(&manifest).remove(0);
    let line = serde_json::to_string(&observation).unwrap();
    let one_parsed = parse_derived_action_observations(line.as_bytes()).unwrap();
    assert_eq!(one_parsed.observations, vec![observation]);
    let oversized = format!(
        "{{\"padding\":\"{}\"}}",
        "x".repeat(MAX_DERIVED_ACTION_GATE_OBSERVATION_LINE_BYTES)
    );
    let oversized_parsed = parse_derived_action_observations(oversized.as_bytes()).unwrap();
    assert!(oversized_parsed.observations.is_empty());
    assert_eq!(oversized_parsed.errors.len(), 1);

    let mut report =
        evaluate_derived_action_gate(&manifest, &parsed(observations(&manifest)), None).unwrap();
    report.positive_net_value = false;
    assert_eq!(report.validate(), Err(DerivedActionGateError::ReportConsistency("report.summary")));

    let mut inconsistent =
        evaluate_derived_action_gate(&manifest, &parsed(observations(&manifest)), None).unwrap();
    inconsistent.evidence_claim = "provider_backed".to_owned();
    inconsistent.seal();
    assert_eq!(
        inconsistent.validate(),
        Err(DerivedActionGateError::ReportConsistency("report.evidence_claim"))
    );
}

#[test]
fn checked_in_synthetic_material_matches_the_generator_and_remains_gate_ineligible() {
    let checked_manifest = DerivedActionGateManifest::decode_json(include_bytes!(
        "../../../../benchmarks/corpus/derived-actions/gate-a3-manifest.json"
    ))
    .unwrap();
    let checked_observations = parse_derived_action_observations(include_bytes!(
        "../../../../benchmarks/corpus/derived-actions/synthetic-observations.jsonl"
    ))
    .unwrap();
    let (generated_manifest, generated_observations) = synthetic_derived_action_gate_material();
    assert_eq!(checked_manifest, generated_manifest);
    assert_eq!(checked_observations.errors, Vec::<String>::new());
    assert_eq!(checked_observations.observations, generated_observations);

    let report =
        evaluate_derived_action_gate(&checked_manifest, &checked_observations, None).unwrap();
    assert!(report.protocol_valid);
    assert!(report.quality_passed);
    assert!(report.positive_net_value);
    assert!(!report.gate_a3_eligible);
    assert!(!report.gate_a3_passed);
}
