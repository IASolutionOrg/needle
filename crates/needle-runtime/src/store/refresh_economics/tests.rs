use super::*;
use needle_core::{
    ActionContractId, ArtifactRequestId, RefreshCostEvidence, RefreshCostEvidenceBasis,
    RefreshCostEvidenceInput, RefreshEconomicAssessmentInput, RefreshEconomicPolicy,
    RefreshEconomicPolicyInput,
};
use rusqlite::{Connection, params};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn digest(label: &str) -> Digest {
    Digest::blake3(label.as_bytes())
}

fn temporary_store() -> (PathBuf, RuntimeStore) {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let path = std::env::temp_dir().join(format!(
        "needle-refresh-economics-{}-{}.sqlite3",
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

fn assessment(label: &str, evidence: bool) -> RefreshEconomicAssessment {
    let request = ArtifactRequestId::new(digest(&format!("request-{label}")));
    let action_contract = ActionContractId::new("needle.tests.inventory").unwrap();
    let candidate_definition_digest = digest(&format!("candidate-{label}"));
    let operator_definition_digest = digest("operator");
    let execution_scope_digest = digest("scope");
    let policy = RefreshEconomicPolicy::new(RefreshEconomicPolicyInput {
        action_operational_policy_digest: digest("action-operational"),
        refresh_policy_definition_digest: digest("refresh-policy"),
        minimum_expected_net_microusd: 100,
        maximum_refresh_latency_micros: Some(500),
    })
    .unwrap();
    let evidence = evidence.then(|| {
        RefreshCostEvidence::new(RefreshCostEvidenceInput {
            request,
            action_contract: action_contract.clone(),
            candidate_definition_digest,
            operator_definition_digest,
            execution_scope_digest,
            basis: RefreshCostEvidenceBasis::BenchmarkDerived,
            evidence_digest: digest("evidence"),
            pricing_revision: None,
            estimated_fresh_total_microusd: 1_000,
            estimated_refresh_total_microusd: 400,
            estimated_refresh_latency_micros: Some(250),
        })
        .unwrap()
    });
    RefreshEconomicAssessment::new(RefreshEconomicAssessmentInput {
        request,
        action_contract,
        candidate_definition_digest,
        operator_definition_digest,
        execution_scope_digest,
        policy,
        evidence,
    })
    .unwrap()
}

#[test]
fn migration_v26_is_complete_and_assessments_are_append_only() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let value = assessment("immutable", true);
    store.persist_refresh_economic_assessment(&value).unwrap();
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
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='table' AND name='refresh_economic_assessments'",
                [],
                |row| row.get::<_, u32>(0),
            )
            .unwrap(),
        1
    );
    assert!(
        connection
            .execute(
                "UPDATE refresh_economic_assessments SET recorded_unix_ms=0
                 WHERE assessment_digest=?1",
                [value.definition_digest.to_string()],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "DELETE FROM refresh_economic_assessments WHERE assessment_digest=?1",
                [value.definition_digest.to_string()],
            )
            .is_err()
    );
    drop(connection);
    cleanup(&path);
}

#[test]
fn assessments_round_trip_idempotently_and_list_with_hard_bounds() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let refresh = assessment("refresh", true);
    let fallback = assessment("fallback", false);
    for value in [&refresh, &refresh, &fallback] {
        store.persist_refresh_economic_assessment(value).unwrap();
    }

    let stored = store.refresh_economic_assessment(refresh.definition_digest).unwrap().unwrap();
    assert_eq!(stored.assessment, refresh);
    assert!(stored.recorded_unix_ms > 0);
    let listed = store.refresh_economic_assessments(2).unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().any(|record| record.assessment == refresh));
    assert!(listed.iter().any(|record| record.assessment == fallback));
    assert!(store.refresh_economic_assessments(0).is_err());
    assert!(
        store.refresh_economic_assessments(MAX_REFRESH_ECONOMIC_ASSESSMENT_LIST_LIMIT + 1).is_err()
    );
    drop(store);
    cleanup(&path);
}

#[test]
fn indexed_column_corruption_is_detected_before_exposure() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let value = assessment("corrupt", true);
    let json = serde_json::to_string(&value).unwrap();
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "INSERT INTO refresh_economic_assessments(
                    assessment_digest, request_id, action_contract_id,
                    candidate_definition_digest, operator_definition_digest,
                    execution_scope_digest, policy_definition_digest,
                    evidence_definition_digest, expected_net_microusd,
                    decision, fallback_reason, authority, assessment_json, recorded_unix_ms
                 ) VALUES(
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                    'refresh', NULL, 'shadow', ?10, 1
                 )",
                params![
                    value.definition_digest.to_string(),
                    digest("wrong-request").to_string(),
                    value.action_contract.as_str(),
                    value.candidate_definition_digest.to_string(),
                    value.operator_definition_digest.to_string(),
                    value.execution_scope_digest.to_string(),
                    value.policy.definition_digest.to_string(),
                    value.evidence.as_ref().map(|evidence| evidence.definition_digest.to_string()),
                    value.expected_net_microusd,
                    json,
                ],
            )
            .unwrap();
    }
    assert!(matches!(
        store.refresh_economic_assessment(value.definition_digest),
        Err(StoreError::RefreshEconomicCorruption(_))
    ));
    drop(store);
    cleanup(&path);
}
