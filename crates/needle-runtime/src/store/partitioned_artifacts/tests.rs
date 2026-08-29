use super::*;
use crate::partitioned_action_artifact::tests::refresh_publication_fixture;
use needle_core::{
    ArtifactKind, RefreshCostEvidence, RefreshCostEvidenceBasis, RefreshCostEvidenceInput,
    RefreshEconomicAssessment, RefreshEconomicAssessmentInput, RefreshEconomicPolicy,
    RefreshEconomicPolicyInput,
};
use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn temporary_store() -> (PathBuf, RuntimeStore) {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let path = std::env::temp_dir().join(format!(
        "needle-partitioned-action-publication-{}-{}.sqlite3",
        std::process::id(),
        nanos
    ));
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

fn persist_refresh_prerequisites(
    store: &RuntimeStore,
    fixture: &crate::partitioned_action_artifact::tests::RefreshPublicationFixture,
) {
    store.publish_shadow_partition_manifest(&fixture.prior_manifest).unwrap();
    store.publish_shadow_partition_manifest(&fixture.current_manifest).unwrap();
    store.record_shadow_manifest_transition(&fixture.transition).unwrap();
    store
        .publish_shadow_partitioned_action_artifact(
            &fixture.request,
            &fixture.prior_manifest,
            &fixture.prior,
        )
        .unwrap();
}

fn economic_assessment(
    fixture: &crate::partitioned_action_artifact::tests::RefreshPublicationFixture,
) -> RefreshEconomicAssessment {
    let action =
        crate::built_in_action_for_artifact_kind(&ArtifactKind::test_target_inventory()).unwrap();
    let candidate_definition_digest = needle_core::Digest::blake3(b"refresh-plan");
    let policy = RefreshEconomicPolicy::new(RefreshEconomicPolicyInput {
        action_operational_policy_digest: action.contract.operational_policy_digest,
        refresh_policy_definition_digest: fixture.attempt.refresh_policy_definition_digest,
        minimum_expected_net_microusd: 1,
        maximum_refresh_latency_micros: Some(1_000),
    })
    .unwrap();
    let evidence = RefreshCostEvidence::new(RefreshCostEvidenceInput {
        request: fixture.attempt.request,
        action_contract: fixture.attempt.action_contract.clone(),
        candidate_definition_digest,
        operator_definition_digest: fixture.attempt.operator_definition_digest,
        execution_scope_digest: fixture.attempt.execution_scope_digest,
        basis: RefreshCostEvidenceBasis::BenchmarkDerived,
        evidence_digest: needle_core::Digest::blake3(b"economic-evidence"),
        pricing_revision: None,
        estimated_fresh_total_microusd: 100,
        estimated_refresh_total_microusd: 10,
        estimated_refresh_latency_micros: Some(100),
    })
    .unwrap();
    RefreshEconomicAssessment::new(RefreshEconomicAssessmentInput {
        request: fixture.attempt.request,
        action_contract: fixture.attempt.action_contract.clone(),
        candidate_definition_digest,
        operator_definition_digest: fixture.attempt.operator_definition_digest,
        execution_scope_digest: fixture.attempt.execution_scope_digest,
        policy,
        evidence: Some(evidence),
    })
    .unwrap()
}

#[test]
fn migrations_v25_v28_are_complete_and_partitioned_records_are_append_only() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let fixture = refresh_publication_fixture();
    persist_refresh_prerequisites(&store, &fixture);
    store
        .publish_shadow_refreshed_action_artifact(ShadowRefreshedActionArtifactPublication {
            request: &fixture.request,
            manifest: &fixture.current_manifest,
            result: &fixture.current,
            attempt: &fixture.attempt,
        })
        .unwrap();
    drop(store);

    let connection = Connection::open(&path).unwrap();
    let versions = connection
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| row.get::<_, u32>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(versions, (1..=37).collect::<Vec<_>>());
    for table in [
        "action_artifact_validation_certificates",
        "reuse_descriptors",
        "refresh_economic_selections",
    ] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get::<_, u32>(0),
                )
                .unwrap(),
            1
        );
    }
    assert!(
        connection
            .execute(
                "UPDATE reuse_descriptors SET created_unix_ms=0 WHERE descriptor_digest=?1",
                [fixture.current.descriptor.definition_digest.to_string()],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "DELETE FROM action_artifact_validation_certificates WHERE certificate_id=?1",
                [fixture.current.certificate.id.to_string()],
            )
            .is_err()
    );
    drop(connection);
    cleanup(&path);
}

#[test]
fn economic_refresh_publication_is_atomic_idempotent_and_attempt_bound() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let fixture = refresh_publication_fixture();
    let assessment = economic_assessment(&fixture);
    persist_refresh_prerequisites(&store, &fixture);
    for _ in 0..2 {
        store
            .publish_shadow_economically_selected_refreshed_action_artifact(
                ShadowEconomicallySelectedRefreshedActionArtifactPublication {
                    refresh: ShadowRefreshedActionArtifactPublication {
                        request: &fixture.request,
                        manifest: &fixture.current_manifest,
                        result: &fixture.current,
                        attempt: &fixture.attempt,
                    },
                    assessment: &assessment,
                },
            )
            .unwrap();
    }
    let stored = store.refresh_economic_assessment(assessment.definition_digest).unwrap().unwrap();
    assert_eq!(stored.assessment, assessment);
    assert_eq!(stored.selected_refresh_attempt, Some(fixture.attempt.id));
    assert_eq!(store.refresh_attempt(fixture.attempt.id).unwrap(), Some(fixture.attempt.clone()));
    drop(store);
    cleanup(&path);
}

#[test]
fn selection_insert_failure_rolls_back_result_attempt_and_assessment() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let fixture = refresh_publication_fixture();
    let assessment = economic_assessment(&fixture);
    persist_refresh_prerequisites(&store, &fixture);
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(&format!(
                "CREATE TRIGGER reject_test_refresh_selection
                 BEFORE INSERT ON refresh_economic_selections
                 WHEN NEW.assessment_digest = '{}'
                 BEGIN SELECT RAISE(ABORT, 'injected economic selection failure'); END;",
                assessment.definition_digest
            ))
            .unwrap();
    }
    assert!(
        store
            .publish_shadow_economically_selected_refreshed_action_artifact(
                ShadowEconomicallySelectedRefreshedActionArtifactPublication {
                    refresh: ShadowRefreshedActionArtifactPublication {
                        request: &fixture.request,
                        manifest: &fixture.current_manifest,
                        result: &fixture.current,
                        attempt: &fixture.attempt,
                    },
                    assessment: &assessment,
                },
            )
            .is_err()
    );
    assert_eq!(store.semantic_artifact(&fixture.current.artifact.id.to_string()).unwrap(), None);
    assert_eq!(store.refresh_attempt(fixture.attempt.id).unwrap(), None);
    assert_eq!(store.refresh_economic_assessment(assessment.definition_digest).unwrap(), None);
    drop(store);
    cleanup(&path);
}

#[test]
fn refreshed_publication_round_trips_idempotently_as_one_shadow_bundle() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let fixture = refresh_publication_fixture();
    persist_refresh_prerequisites(&store, &fixture);
    for _ in 0..2 {
        store
            .publish_shadow_refreshed_action_artifact(ShadowRefreshedActionArtifactPublication {
                request: &fixture.request,
                manifest: &fixture.current_manifest,
                result: &fixture.current,
                attempt: &fixture.attempt,
            })
            .unwrap();
    }
    assert_eq!(
        store.semantic_artifact(&fixture.current.artifact.id.to_string()).unwrap(),
        Some(fixture.current.artifact.clone())
    );
    assert_eq!(
        store.action_artifact_validation_certificate(fixture.current.certificate.id).unwrap(),
        Some(fixture.current.certificate.clone())
    );
    assert_eq!(
        store.stored_reuse_descriptor(fixture.current.descriptor.definition_digest).unwrap(),
        Some(fixture.current.descriptor.clone())
    );
    assert_eq!(store.refresh_attempt(fixture.attempt.id).unwrap(), Some(fixture.attempt.clone()));

    let connection = Connection::open(&path).unwrap();
    for (table, expected) in [
        ("artifacts", 2_u32),
        ("action_artifact_validation_certificates", 2),
        ("reuse_descriptors", 2),
        ("refresh_attempts", 1),
    ] {
        assert_eq!(
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, u32>(0)
                })
                .unwrap(),
            expected,
            "unexpected row count for {table}"
        );
    }
    drop(connection);
    drop(store);
    cleanup(&path);
}

#[test]
fn descriptor_insert_failure_rolls_back_artifact_certificate_and_attempt() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let fixture = refresh_publication_fixture();
    persist_refresh_prerequisites(&store, &fixture);
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(&format!(
                "CREATE TRIGGER reject_test_refresh_descriptor
                 BEFORE INSERT ON reuse_descriptors
                 WHEN NEW.descriptor_digest = '{}'
                 BEGIN SELECT RAISE(ABORT, 'injected descriptor failure'); END;",
                fixture.current.descriptor.definition_digest
            ))
            .unwrap();
    }
    assert!(
        store
            .publish_shadow_refreshed_action_artifact(ShadowRefreshedActionArtifactPublication {
                request: &fixture.request,
                manifest: &fixture.current_manifest,
                result: &fixture.current,
                attempt: &fixture.attempt,
            })
            .is_err()
    );
    assert_eq!(store.semantic_artifact(&fixture.current.artifact.id.to_string()).unwrap(), None);
    assert_eq!(
        store.action_artifact_validation_certificate(fixture.current.certificate.id).unwrap(),
        None
    );
    assert_eq!(
        store.stored_reuse_descriptor(fixture.current.descriptor.definition_digest).unwrap(),
        None
    );
    assert_eq!(store.refresh_attempt(fixture.attempt.id).unwrap(), None);
    drop(store);
    cleanup(&path);
}
