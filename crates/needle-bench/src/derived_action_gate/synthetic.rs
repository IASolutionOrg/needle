use super::{
    DERIVED_ACTION_GATE_FORMAT_REVISION, DERIVED_ACTION_GATE_OBSERVATION_SCHEMA,
    DerivedActionEvaluationArm, DerivedActionEvidenceClass, DerivedActionGateManifest,
    DerivedActionGateObservation, DerivedActionGateTask, DerivedActionKind,
    DerivedActionReuseScenario,
};
use needle_core::Digest;

/// Build deterministic protocol-only material. It is permanently classified
/// as Synthetic and therefore cannot close Gate A3.
pub fn synthetic_derived_action_gate_material()
-> (DerivedActionGateManifest, Vec<DerivedActionGateObservation>) {
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
                    Digest::blake3(format!("synthetic-request-{id}")),
                    Digest::blake3(format!("synthetic-fixture-{id}")),
                    Digest::blake3(format!("synthetic-oracle-{id}")),
                    Digest::blake3(b"synthetic-execution-profile"),
                    vec![7],
                )
                .expect("static synthetic task is valid"),
            );
        }
    }
    let manifest = DerivedActionGateManifest::new(
        DerivedActionEvidenceClass::Synthetic,
        "0123456789abcdef0123456789abcdef01234567",
        tasks,
    )
    .expect("static synthetic manifest is valid");
    let mut observations = Vec::with_capacity(manifest.tasks.len() * 2);
    for task in &manifest.tasks {
        for arm in [DerivedActionEvaluationArm::Fresh, DerivedActionEvaluationArm::Reuse] {
            let fresh = arm == DerivedActionEvaluationArm::Fresh;
            observations.push(DerivedActionGateObservation {
                format_revision: DERIVED_ACTION_GATE_FORMAT_REVISION,
                schema: DERIVED_ACTION_GATE_OBSERVATION_SCHEMA.to_owned(),
                manifest_digest: manifest.manifest_digest,
                task_id: task.id.clone(),
                action: task.action,
                scenario: task.scenario,
                arm,
                pair_seed: 7,
                evidence_class: DerivedActionEvidenceClass::Synthetic,
                execution_profile_digest: task.execution_profile_digest,
                model_id: fresh.then(|| "synthetic-model".to_owned()),
                pricing_snapshot_digest: Digest::blake3(b"synthetic-pricing"),
                oracle_commitment: task.oracle_commitment,
                quality_judgment_digest: Digest::blake3(format!(
                    "synthetic-quality-{}-{arm:?}",
                    task.id
                )),
                output_digest: if fresh || task.scenario == DerivedActionReuseScenario::Exact {
                    Digest::blake3(format!("synthetic-fresh-output-{}", task.id))
                } else {
                    Digest::blake3(format!("synthetic-reuse-output-{}", task.id))
                },
                validation_certificate_digest: Digest::blake3(format!(
                    "synthetic-certificate-{}-{arm:?}",
                    task.id
                )),
                structural_validation_passed: true,
                quality_passed: true,
                semantic_equivalence_passed: (!fresh).then_some(true),
                total_cost_microcredits: if fresh { 1_000 } else { 200 },
                latency_micros: if fresh { 100_000 } else { 1_000 },
                worker_started: fresh,
                provider_calls: 0,
                provider_observation_digest: None,
                infrastructure_failure: None,
            });
        }
    }
    (manifest, observations)
}
