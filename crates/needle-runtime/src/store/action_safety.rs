use super::*;
use needle_core::{
    PATCH_APPLY_ACTION_CONTRACT, PATCH_VERIFY_ACTION_CONTRACT, TESTS_EXECUTE_ACTION_CONTRACT,
};
use serde::{Deserialize, Serialize};

/// Store-derived safety counters for action-native execution. These are
/// integrity observations, not estimates: any non-zero value blocks Gate A7.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSafetyMetrics {
    pub stale_artifact_served: u64,
    pub independent_evidence_bypassed: u64,
    pub external_effect_replayed: u64,
}

impl ActionSafetyMetrics {
    pub const fn is_clean(self) -> bool {
        self.stale_artifact_served == 0
            && self.independent_evidence_bypassed == 0
            && self.external_effect_replayed == 0
    }
}

impl RuntimeStore {
    /// Audit completed action operations using only immutable store records.
    /// The query does not infer language or repository structure.
    pub fn action_safety_metrics(&self) -> Result<ActionSafetyMetrics, StoreError> {
        self.initialize()?;
        let connection = self.connection()?;
        let stale_artifact_served = connection.query_row(
            "SELECT COUNT(*)
             FROM action_execution_operations operation
             JOIN artifacts artifact ON artifact.artifact_id=operation.artifact_id
             WHERE operation.state='completed'
               AND artifact.request_id!=operation.action_request_id",
            [],
            |row| row.get(0),
        )?;
        let independent_evidence_bypassed = connection.query_row(
            "SELECT COUNT(DISTINCT operation.operation_id)
             FROM action_execution_operations operation
             JOIN artifacts artifact ON artifact.artifact_id=operation.artifact_id
             JOIN opaque_action_validation_certificates certificate
               ON certificate.artifact_id=artifact.artifact_id
             WHERE operation.state='completed'
               AND (
                 (certificate.action_contract_id=?1
                   AND json_extract(artifact.artifact_json, '$.payload.status') IN ('passed', 'failed')
                   AND NOT EXISTS (
                     SELECT 1 FROM command_evidence evidence
                     WHERE evidence.evidence_id=json_extract(
                       artifact.artifact_json, '$.payload.command_evidence_id'
                     )
                   ))
                 OR
                 (certificate.action_contract_id=?2
                   AND (
                     COALESCE(json_type(
                       artifact.artifact_json,
                       '$.payload.input_test_evidence_artifacts'
                     ), 'missing')!='array'
                     OR json_array_length(json_extract(
                       artifact.artifact_json,
                       '$.payload.input_test_evidence_artifacts'
                     ))=0
                     OR EXISTS (
                       SELECT 1
                       FROM json_each(
                         artifact.artifact_json,
                         '$.payload.input_test_evidence_artifacts'
                       ) input
                       WHERE NOT EXISTS (
                         SELECT 1
                         FROM opaque_action_validation_certificates evidence_certificate
                         WHERE evidence_certificate.artifact_id=input.value
                           AND evidence_certificate.action_contract_id=?1
                       )
                     )
                   ))
               )",
            params![TESTS_EXECUTE_ACTION_CONTRACT, PATCH_VERIFY_ACTION_CONTRACT],
            |row| row.get(0),
        )?;
        let external_effect_replayed = connection.query_row(
            "SELECT COALESCE(SUM(replayed), 0)
             FROM (
               SELECT COUNT(DISTINCT operation.operation_id)-1 AS replayed
               FROM action_execution_operations operation
               JOIN artifacts artifact ON artifact.artifact_id=operation.artifact_id
               JOIN opaque_action_validation_certificates certificate
                 ON certificate.artifact_id=artifact.artifact_id
               WHERE operation.state='completed'
                 AND certificate.action_contract_id=?1
               GROUP BY
                 json_extract(artifact.artifact_json, '$.payload.change_id'),
                 json_extract(artifact.artifact_json, '$.payload.patch_id')
               HAVING COUNT(DISTINCT operation.operation_id)>1
             )",
            params![PATCH_APPLY_ACTION_CONTRACT],
            |row| row.get(0),
        )?;
        Ok(ActionSafetyMetrics {
            stale_artifact_served,
            independent_evidence_bypassed,
            external_effect_replayed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_store_has_clean_action_safety_metrics() {
        let path = std::env::temp_dir().join(format!(
            "needle-action-safety-{}-{}.sqlite3",
            std::process::id(),
            super::super::now_ms()
        ));
        let store = RuntimeStore::new(&path);
        assert_eq!(store.action_safety_metrics().unwrap(), ActionSafetyMetrics::default());
        drop(store);
        let _ = std::fs::remove_file(path);
    }
}
