use super::*;
use crate::{
    LifecycleExploreActionResolver, LifecycleExploreActionResolverOutcome,
    LifecycleExploreShadowObservation, SemanticLifecycleExploreActionResolver,
    implementation_location_exact_capability,
};
use needle_core::{
    ActionAssuranceEvidenceInput, ActionCapabilityDecisionInput, ArtifactId, ArtifactRequestId,
    ArtifactValidationCertificateId, ChangeId, ChangeRequest, DevelopmentLifecycle, LifecyclePhase,
    LifecycleTransition, LifecycleUsage,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn digest(label: &str) -> Digest {
    Digest::blake3(label.as_bytes())
}

fn temporary_store() -> (PathBuf, RuntimeStore) {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let path = std::env::temp_dir()
        .join(format!("needle-action-assurance-{}-{nanos}.sqlite3", std::process::id()));
    (path.clone(), RuntimeStore::new(path))
}

fn cleanup(path: &Path) {
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        let _ = fs::remove_file(candidate);
    }
}

fn evidence() -> ActionAssuranceEvidence {
    let capability = implementation_location_exact_capability();
    ActionAssuranceEvidence::new(ActionAssuranceEvidenceInput {
        capability_class: capability.id,
        capability_definition_digest: capability.definition_digest,
        action_request: ArtifactRequestId::new(digest("request")),
        artifact: ArtifactId::new(digest("artifact")),
        validation_certificate: ArtifactValidationCertificateId::new(digest("certificate")),
        repository: digest("repository"),
        source_snapshot: digest("source"),
        lifecycle: needle_core::LifecycleId(digest("lifecycle")),
        adapter_invocation: digest("adapter-invocation"),
        evidence_kind: ActionAssuranceEvidenceKind::ProviderBackedFresh,
        execution_evidence_digest: digest("live-report"),
        observed_unix_ms: 10,
    })
    .unwrap()
}

fn decision(
    evidence: &ActionAssuranceEvidence,
    previous_decision: Option<ActionCapabilityDecisionId>,
    selected_mode: CapabilityMode,
    decided_unix_ms: u64,
) -> ActionCapabilityDecision {
    decision_with_lifecycle(evidence, previous_decision, selected_mode, decided_unix_ms, false)
}

fn decision_with_lifecycle(
    evidence: &ActionAssuranceEvidence,
    previous_decision: Option<ActionCapabilityDecisionId>,
    selected_mode: CapabilityMode,
    decided_unix_ms: u64,
    lifecycle_consumption: bool,
) -> ActionCapabilityDecision {
    let capability = implementation_location_exact_capability();
    let authoritative = selected_mode == CapabilityMode::Authoritative;
    ActionCapabilityDecision::new(ActionCapabilityDecisionInput {
        capability_class: capability.id,
        capability_definition_digest: capability.definition_digest,
        evidence: evidence.id,
        evidence_definition_digest: evidence.definition_digest,
        previous_decision,
        selected_mode,
        automatic_resolver_consumption_approved: authoritative,
        automatic_lifecycle_consumption_approved: authoritative && lifecycle_consumption,
        decider_id: "local-operator".to_owned(),
        decided_unix_ms,
    })
    .unwrap()
}

#[test]
fn exact_reuse_requires_lifecycle_decision_and_commits_atomically_without_worker_usage() {
    let fixture = crate::store::lifecycles::tests::provider_backed_action_assurance_fixture();
    let resolver_only = decision(
        &fixture.evidence,
        None,
        CapabilityMode::Authoritative,
        fixture.evidence.observed_unix_ms.saturating_add(1),
    );
    fixture.store.accept_action_capability_decision(&fixture.evidence, &resolver_only).unwrap();

    let connection = Connection::open(&fixture.path).unwrap();
    let lifecycle_json: String = connection
        .query_row(
            "SELECT state_json FROM change_lifecycles WHERE lifecycle_id=?1",
            [fixture.evidence.lifecycle.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    let assured_lifecycle: DevelopmentLifecycle = serde_json::from_str(&lifecycle_json).unwrap();
    let plan = assured_lifecycle.spec.explore_action_plan.clone().unwrap();
    let change_id = ChangeId::from_digest(digest("reuse-target-change"));
    let change_request = ChangeRequest {
        task: "Reuse the exact assured implementation location.".to_owned(),
        acceptance_criteria: Vec::new(),
        allowed_paths: Vec::new(),
        artifact_ids: Vec::new(),
        claim_ids: Vec::new(),
        constraints: Vec::new(),
    };
    let initial = fixture
        .store
        .create_lifecycle_with_request(
            &change_id,
            fixture.evidence.repository,
            fixture.evidence.source_snapshot,
            &change_request,
            assured_lifecycle.spec,
        )
        .unwrap()
        .projection;
    let change = crate::LifecycleChangeContext {
        request_digest: change_request.digest(fixture.evidence.source_snapshot),
        request: change_request,
        repository_id: fixture.evidence.repository,
        source_snapshot: fixture.evidence.source_snapshot,
    };
    let resolution =
        SemanticLifecycleExploreActionResolver::new(fixture.store.clone()).resolve(&plan, &change);
    let LifecycleExploreActionResolverOutcome::Resolved(summaries) = resolution else {
        panic!("assured exact artifact must remain a current resolver candidate");
    };
    assert_eq!(summaries.len(), 1);
    assert!(matches!(
        fixture
            .store
            .try_complete_lifecycle_explore_from_reuse(
                &change_id,
                initial.state_digest,
                &summaries[0],
            )
            .unwrap(),
        crate::store::LifecycleExploreReuseCommit::Ineligible
    ));
    assert_eq!(fixture.store.replay_lifecycle(&change_id).unwrap(), initial);
    let observation = LifecycleExploreShadowObservation::from_resolver_outcome(
        initial.lifecycle.id,
        initial.state_digest,
        &plan,
        LifecycleExploreActionResolverOutcome::Resolved(summaries.clone()),
    );
    fixture.store.record_lifecycle_explore_action_observation(&observation).unwrap();

    let resolver_attempt = fixture
        .store
        .try_complete_lifecycle_explore_from_reuse(&change_id, initial.state_digest, &summaries[0])
        .unwrap();
    assert!(matches!(
        resolver_attempt,
        crate::store::LifecycleExploreReuseCommit::ResolverAuthorized(ref authority)
            if authority.decision == resolver_only.id
    ));
    let unchanged = fixture.store.replay_lifecycle(&change_id).unwrap();
    assert_eq!(unchanged, initial);

    let lifecycle_authority = decision_with_lifecycle(
        &fixture.evidence,
        Some(resolver_only.id),
        CapabilityMode::Authoritative,
        resolver_only.decided_unix_ms.saturating_add(1),
        true,
    );
    fixture
        .store
        .record_action_capability_decision(&lifecycle_authority, &fixture.evidence)
        .unwrap();
    let committed = fixture
        .store
        .try_complete_lifecycle_explore_from_reuse(&change_id, initial.state_digest, &summaries[0])
        .unwrap();
    let crate::store::LifecycleExploreReuseCommit::Committed { projection, completion } = committed
    else {
        panic!("lifecycle-approved exact authority must commit reuse");
    };
    assert_eq!(projection.lifecycle.phase, LifecyclePhase::Implement);
    assert_eq!(projection.lifecycle.usage, LifecycleUsage::default());
    assert_eq!(completion.authority.decision, lifecycle_authority.id);
    assert_eq!(projection.lifecycle.explore_reuse, Some(completion.as_ref().clone()));
    assert!(matches!(
        fixture.store.parent_transition_lifecycle(
            &change_id,
            projection.state_digest,
            LifecycleTransition::CompleteExploreFromReuse {
                reuse: completion.as_ref().clone(),
                artifacts: projection.lifecycle.exploration_artifacts.clone(),
            },
        ),
        Err(StoreError::LifecycleConflict(_))
    ));
    let events = fixture.store.replay_lifecycle_events(&change_id).unwrap();
    assert!(matches!(
        events.last().unwrap().kind,
        needle_core::LifecycleEventKind::Transitioned { ref transition }
            if matches!(transition.as_ref(), LifecycleTransition::CompleteExploreFromReuse { reuse, .. }
                if reuse == completion.as_ref())
    ));

    drop(fixture.store);
    cleanup(&fixture.path);
}

#[test]
fn evidence_and_linear_decisions_round_trip_idempotently() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let capability = implementation_location_exact_capability();
    let evidence = evidence();
    store.record_validated_action_assurance_evidence(&evidence, capability).unwrap();
    store.record_validated_action_assurance_evidence(&evidence, capability).unwrap();
    let loaded = store.action_assurance_evidence(evidence.id).unwrap().unwrap();
    assert_eq!(loaded.evidence, evidence);

    let authoritative = decision(&evidence, None, CapabilityMode::Authoritative, 20);
    store.record_action_capability_decision(&authoritative, &evidence).unwrap();
    store.record_action_capability_decision(&authoritative, &evidence).unwrap();
    let current = store.effective_action_capability_decision(capability.id).unwrap().unwrap();
    assert_eq!(current.decision, authoritative);
    assert_eq!(current.evidence, evidence);

    let demotion = decision(&evidence, Some(authoritative.id), CapabilityMode::Shadow, 21);
    store.record_action_capability_decision(&demotion, &evidence).unwrap();
    let current = store.effective_action_capability_decision(capability.id).unwrap().unwrap();
    assert_eq!(current.decision, demotion);
    drop(store);

    let reopened = RuntimeStore::new(&path);
    reopened.initialize().unwrap();
    let current = reopened.effective_action_capability_decision(capability.id).unwrap().unwrap();
    assert_eq!(current.decision, demotion);
    cleanup(&path);
}

#[test]
fn provider_backed_fresh_material_is_verified_before_evidence_is_persisted() {
    let fixture = crate::store::lifecycles::tests::provider_backed_action_assurance_fixture();
    fixture.store.record_action_assurance_evidence(&fixture.evidence).unwrap();
    let loaded = fixture.store.action_assurance_evidence(fixture.evidence.id).unwrap().unwrap();
    assert_eq!(loaded.evidence, fixture.evidence);
    drop(fixture.store);
    cleanup(&fixture.path);
}

#[test]
fn atomic_acceptance_rolls_back_partial_evidence_and_is_idempotent() {
    let fixture = crate::store::lifecycles::tests::provider_backed_action_assurance_fixture();
    let rejected = decision(
        &fixture.evidence,
        Some(ActionCapabilityDecisionId::new(digest("nonexistent-head"))),
        CapabilityMode::Authoritative,
        fixture.evidence.observed_unix_ms.saturating_add(1),
    );
    assert!(matches!(
        fixture.store.accept_action_capability_decision(&fixture.evidence, &rejected),
        Err(StoreError::ActionAssuranceConflict(_))
    ));
    assert!(fixture.store.action_assurance_evidence(fixture.evidence.id).unwrap().is_none());

    let accepted = decision(
        &fixture.evidence,
        None,
        CapabilityMode::Authoritative,
        fixture.evidence.observed_unix_ms.saturating_add(1),
    );
    let first =
        fixture.store.accept_action_capability_decision(&fixture.evidence, &accepted).unwrap();
    let second =
        fixture.store.accept_action_capability_decision(&fixture.evidence, &accepted).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.decision, accepted);
    assert_eq!(first.evidence, fixture.evidence);
    drop(fixture.store);
    cleanup(&fixture.path);
}

#[test]
fn read_only_preflight_reconstructs_exact_evidence_without_persisting_it() {
    let fixture = crate::store::lifecycles::tests::provider_backed_action_assurance_fixture();
    let path = fixture.path.clone();
    let expected = fixture.evidence.clone();
    drop(fixture.store);
    let store = RuntimeStore::new(&path);
    let shm_path = sqlite_sidecar_path(&path, "-shm");
    let shm_modified_before = fs::metadata(&shm_path).and_then(|value| value.modified()).ok();
    let input = ProviderBackedActionAssuranceInput {
        repository: expected.repository,
        source_snapshot: expected.source_snapshot,
        lifecycle: expected.lifecycle,
        adapter_invocation: expected.adapter_invocation,
        artifact: expected.artifact,
        execution_evidence_digest: expected.execution_evidence_digest,
    };
    let preflight = store.preflight_provider_backed_action_assurance(input.clone()).unwrap();
    assert_eq!(preflight.source_schema_version, 37);
    assert_eq!(preflight.evidence.capability_class, expected.capability_class);
    assert_eq!(preflight.evidence.action_request, expected.action_request);
    assert_eq!(preflight.evidence.artifact, expected.artifact);
    assert_eq!(preflight.evidence.validation_certificate, expected.validation_certificate);
    assert_eq!(preflight.evidence.execution_evidence_digest, expected.execution_evidence_digest);
    assert!(preflight.effective_decision.is_none());
    let connection = store.action_assurance_read_only_connection().unwrap();
    let evidence_rows: u64 = connection
        .query_row("SELECT COUNT(*) FROM action_assurance_records", [], |row| row.get(0))
        .unwrap();
    let decision_rows: u64 = connection
        .query_row("SELECT COUNT(*) FROM action_capability_decisions", [], |row| row.get(0))
        .unwrap();
    assert_eq!((evidence_rows, decision_rows), (0, 0));
    drop(connection);
    let shm_modified_after = fs::metadata(&shm_path).and_then(|value| value.modified()).ok();
    assert_eq!(shm_modified_after, shm_modified_before);

    let mut tampered = input.clone();
    tampered.repository = digest("other-repository");
    assert!(matches!(
        store.preflight_provider_backed_action_assurance(tampered),
        Err(StoreError::ActionAssuranceValidation(_))
    ));
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE schema_migrations SET checksum=?1 WHERE version=1",
            [digest("tampered-migration").to_string()],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        store.preflight_provider_backed_action_assurance(input),
        Err(StoreError::MigrationChecksum)
    ));
    drop(store);
    cleanup(&path);
}

#[test]
fn read_only_preflight_does_not_create_a_missing_database() {
    let (path, store) = temporary_store();
    assert!(
        store
            .preflight_provider_backed_action_assurance(ProviderBackedActionAssuranceInput {
                repository: digest("repository"),
                source_snapshot: digest("source"),
                lifecycle: needle_core::LifecycleId(digest("lifecycle")),
                adapter_invocation: digest("invocation"),
                artifact: ArtifactId::new(digest("artifact")),
                execution_evidence_digest: digest("report"),
            })
            .is_err()
    );
    assert!(!path.exists());
    cleanup(&path);
}

#[test]
fn decision_requires_recorded_evidence_and_exact_head() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let evidence = evidence();
    assert!(matches!(
        store.record_action_assurance_evidence(&evidence),
        Err(StoreError::ActionAssuranceValidation(_))
    ));
    let authoritative = decision(&evidence, None, CapabilityMode::Authoritative, 20);
    assert!(matches!(
        store.record_action_capability_decision(&authoritative, &evidence),
        Err(StoreError::ActionAssuranceConflict(_))
    ));

    store
        .record_validated_action_assurance_evidence(
            &evidence,
            implementation_location_exact_capability(),
        )
        .unwrap();
    store.record_action_capability_decision(&authoritative, &evidence).unwrap();
    let fork = decision(&evidence, None, CapabilityMode::Shadow, 21);
    assert!(matches!(
        store.record_action_capability_decision(&fork, &evidence),
        Err(StoreError::ActionAssuranceConflict(_))
    ));
    let stale_time = decision(&evidence, Some(authoritative.id), CapabilityMode::Shadow, 20);
    assert!(matches!(
        store.record_action_capability_decision(&stale_time, &evidence),
        Err(StoreError::ActionAssuranceConflict(_))
    ));
    cleanup(&path);
}

#[test]
fn tamper_and_unregistered_capabilities_fail_closed_and_tables_are_immutable() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let evidence = evidence();
    store
        .record_validated_action_assurance_evidence(
            &evidence,
            implementation_location_exact_capability(),
        )
        .unwrap();
    let authoritative = decision(&evidence, None, CapabilityMode::Authoritative, 20);
    store.record_action_capability_decision(&authoritative, &evidence).unwrap();

    let connection = Connection::open(&path).unwrap();
    assert!(
        connection
            .execute(
                "UPDATE action_assurance_records SET source_snapshot=?1 WHERE evidence_id=?2",
                params![digest("tampered").to_string(), evidence.id.to_string()],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "DELETE FROM action_capability_decisions WHERE decision_id=?1",
                [authoritative.id.to_string()],
            )
            .is_err()
    );
    drop(connection);

    assert!(matches!(
        store.effective_action_capability_decision(needle_core::ActionCapabilityClassId::new(
            digest("unregistered-capability")
        )),
        Err(StoreError::ActionAssuranceValidation(_))
    ));
    let unregistered = ActionAssuranceEvidence::new(ActionAssuranceEvidenceInput {
        capability_class: needle_core::ActionCapabilityClassId::new(digest("unregistered")),
        capability_definition_digest: digest("unregistered-definition"),
        action_request: evidence.action_request,
        artifact: evidence.artifact,
        validation_certificate: evidence.validation_certificate,
        repository: evidence.repository,
        source_snapshot: evidence.source_snapshot,
        lifecycle: evidence.lifecycle,
        adapter_invocation: evidence.adapter_invocation,
        evidence_kind: evidence.evidence_kind,
        execution_evidence_digest: evidence.execution_evidence_digest,
        observed_unix_ms: evidence.observed_unix_ms,
    })
    .unwrap();
    assert!(matches!(
        store.record_action_assurance_evidence(&unregistered),
        Err(StoreError::ActionAssuranceValidation(_))
    ));
    cleanup(&path);
}
