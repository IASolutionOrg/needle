use super::{RuntimeStore, StoreError, now_ms};
use needle_core::{
    FailedRefreshMemo, FailedRefreshMemoId, FailedRefreshMemoKey,
    MAX_FAILED_REFRESH_MEMO_WIRE_BYTES, MAX_REFRESH_ATTEMPT_WIRE_BYTES, RefreshAttempt,
    RefreshAttemptId, RefreshFailureClass, RefreshOutcome,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::collections::{BTreeMap, BTreeSet};

struct AttemptRow {
    attempt_id: String,
    request_id: String,
    action_contract_id: String,
    prior_artifact_id: String,
    state_delta: String,
    prior_manifest_id: String,
    current_manifest_id: String,
    transition_id: String,
    refresh_policy_definition_digest: String,
    operator_definition_digest: String,
    execution_scope_digest: String,
    retained_partition_count: i64,
    refreshed_partition_count: i64,
    added_partition_count: i64,
    removed_partition_count: i64,
    execution_attempt_count: i64,
    outcome: String,
    failure_class: Option<String>,
    started_unix_ms: i64,
    completed_unix_ms: i64,
    cost_microusd: Option<i64>,
    authority: String,
    attempt_json: String,
}

struct MemoRow {
    memo_id: String,
    attempt_id: String,
    request_id: String,
    action_contract_id: String,
    prior_artifact_id: String,
    state_delta: String,
    refresh_policy_definition_digest: String,
    operator_definition_digest: String,
    execution_scope_digest: String,
    failure_class: String,
    failure_evidence_digest: String,
    expires_unix_ms: Option<i64>,
    memo_json: String,
}

impl RuntimeStore {
    /// Atomically persist one immutable Shadow refresh attempt and, for a
    /// failed attempt, its optional narrow memo. This is audit persistence
    /// only; no resolver path consumes either record.
    pub fn persist_refresh_attempt(
        &self,
        attempt: &RefreshAttempt,
        failed_memo: Option<&FailedRefreshMemo>,
    ) -> Result<(), StoreError> {
        attempt.validate()?;
        let attempt_json = serde_json::to_string(attempt)?;
        ensure_wire_bound("refresh attempt", attempt_json.len(), MAX_REFRESH_ATTEMPT_WIRE_BYTES)?;
        let memo_json = failed_memo
            .map(|memo| {
                memo.validate()?;
                validate_memo_binding(attempt, memo)?;
                let json = serde_json::to_string(memo)?;
                ensure_wire_bound(
                    "failed refresh memo",
                    json.len(),
                    MAX_FAILED_REFRESH_MEMO_WIRE_BYTES,
                )?;
                Ok::<String, StoreError>(json)
            })
            .transpose()?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_refresh_attempt(&transaction, attempt, &attempt_json)?;

        if let (Some(memo), Some(memo_json)) = (failed_memo, memo_json) {
            if let Some(existing) =
                read_failed_refresh_memo_for_attempt(&transaction, memo.attempt)?
            {
                if existing != *memo {
                    return Err(conflict(format!(
                        "attempt {} already has a different immutable failed-refresh memo",
                        memo.attempt
                    )));
                }
            } else if let Some(existing) = read_failed_refresh_memo(&transaction, memo.id)? {
                return Err(conflict(format!(
                    "memo {} is already bound to attempt {}",
                    existing.id, existing.attempt
                )));
            } else {
                transaction.execute(
                    "INSERT INTO failed_refresh_memos(
                        memo_id, attempt_id, request_id, action_contract_id,
                        prior_artifact_id, state_delta,
                        refresh_policy_definition_digest, operator_definition_digest,
                        execution_scope_digest, failure_class, failure_evidence_digest,
                        expires_unix_ms, memo_json, created_unix_ms
                     ) VALUES(
                        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14
                     )",
                    params![
                        memo.id.to_string(),
                        memo.attempt.to_string(),
                        memo.request.to_string(),
                        memo.action_contract.as_str(),
                        memo.prior_artifact.to_string(),
                        memo.state_delta.to_string(),
                        memo.refresh_policy_definition_digest.to_string(),
                        memo.operator_definition_digest.to_string(),
                        memo.execution_scope_digest.to_string(),
                        failure_class_name(memo.failure_class),
                        memo.failure_evidence_digest.to_string(),
                        memo.expires_unix_ms.map(refresh_u64_to_sql).transpose()?,
                        memo_json,
                        refresh_u64_to_sql(now_ms())?,
                    ],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn refresh_attempt(
        &self,
        id: RefreshAttemptId,
    ) -> Result<Option<RefreshAttempt>, StoreError> {
        let connection = self.connection()?;
        read_refresh_attempt(&connection, id)
    }

    pub fn failed_refresh_memo(
        &self,
        id: FailedRefreshMemoId,
    ) -> Result<Option<FailedRefreshMemo>, StoreError> {
        let connection = self.connection()?;
        read_failed_refresh_memo(&connection, id)
    }

    /// Return one active memo only when every failure-relevant identity is an
    /// exact match. Expired immutable records remain available by id for audit.
    pub fn active_failed_refresh_memo(
        &self,
        key: &FailedRefreshMemoKey,
        at_unix_ms: u64,
    ) -> Result<Option<FailedRefreshMemo>, StoreError> {
        let connection = self.connection()?;
        let memo_id = connection
            .query_row(
                "SELECT memo_id FROM failed_refresh_memos
                 WHERE request_id=?1 AND action_contract_id=?2
                   AND prior_artifact_id=?3 AND state_delta=?4
                   AND refresh_policy_definition_digest=?5
                   AND operator_definition_digest=?6 AND execution_scope_digest=?7
                   AND (expires_unix_ms IS NULL OR expires_unix_ms > ?8)
                 ORDER BY expires_unix_ms IS NULL DESC, expires_unix_ms DESC, memo_id ASC
                 LIMIT 1",
                params![
                    key.request.to_string(),
                    key.action_contract.as_str(),
                    key.prior_artifact.to_string(),
                    key.state_delta.to_string(),
                    key.refresh_policy_definition_digest.to_string(),
                    key.operator_definition_digest.to_string(),
                    key.execution_scope_digest.to_string(),
                    refresh_u64_to_sql(at_unix_ms)?,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(memo_id) = memo_id else {
            return Ok(None);
        };
        let id = parse_memo_id(&memo_id)?;
        let memo = read_failed_refresh_memo(&connection, id)?
            .ok_or_else(|| corruption("active failed-refresh memo disappeared during lookup"))?;
        if !memo.matches_key(key) || !memo.is_active_at(at_unix_ms) {
            return Err(corruption(
                "active failed-refresh memo lookup returned a mismatched record",
            ));
        }
        Ok(Some(memo))
    }
}

fn validate_memo_binding(
    attempt: &RefreshAttempt,
    memo: &FailedRefreshMemo,
) -> Result<(), StoreError> {
    let Some((failure_class, failure_evidence_digest)) = attempt.failure() else {
        return Err(binding("successful attempts cannot have failed-refresh memos"));
    };
    if memo.attempt != attempt.id
        || memo.request != attempt.request
        || memo.action_contract != attempt.action_contract
        || memo.prior_artifact != attempt.prior_artifact
        || memo.state_delta != attempt.state_delta
        || memo.refresh_policy_definition_digest != attempt.refresh_policy_definition_digest
        || memo.operator_definition_digest != attempt.operator_definition_digest
        || memo.execution_scope_digest != attempt.execution_scope_digest
        || memo.failure_class != failure_class
        || memo.failure_evidence_digest != failure_evidence_digest
        || memo.expires_unix_ms.is_some_and(|expires| expires <= attempt.completed_unix_ms)
    {
        return Err(binding("failed-refresh memo does not bind exactly to its failed attempt"));
    }
    Ok(())
}

pub(super) fn insert_refresh_attempt(
    connection: &Connection,
    attempt: &RefreshAttempt,
    attempt_json: &str,
) -> Result<(), StoreError> {
    validate_storage_bindings(connection, attempt)?;
    if let Some(existing) = read_refresh_attempt(connection, attempt.id)? {
        if existing != *attempt {
            return Err(conflict(format!(
                "attempt {} already has different immutable content",
                attempt.id
            )));
        }
        return Ok(());
    }
    let (outcome, failure_class) = outcome_columns(attempt.outcome);
    connection.execute(
        "INSERT INTO refresh_attempts(
            attempt_id, request_id, action_contract_id, prior_artifact_id,
            state_delta, prior_manifest_id, current_manifest_id, transition_id,
            refresh_policy_definition_digest, operator_definition_digest,
            execution_scope_digest, retained_partition_count,
            refreshed_partition_count, added_partition_count,
            removed_partition_count, execution_attempt_count, outcome,
            failure_class, started_unix_ms, completed_unix_ms, cost_microusd,
            authority, attempt_json, created_unix_ms
         ) VALUES(
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
            ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, 'shadow', ?22, ?23
         )",
        params![
            attempt.id.to_string(),
            attempt.request.to_string(),
            attempt.action_contract.as_str(),
            attempt.prior_artifact.to_string(),
            attempt.state_delta.to_string(),
            attempt.prior_manifest.to_string(),
            attempt.current_manifest.to_string(),
            attempt.manifest_transition.to_string(),
            attempt.refresh_policy_definition_digest.to_string(),
            attempt.operator_definition_digest.to_string(),
            attempt.execution_scope_digest.to_string(),
            refresh_usize_to_sql(attempt.retained_partitions.len())?,
            refresh_usize_to_sql(attempt.refreshed_partitions.len())?,
            refresh_usize_to_sql(attempt.added_partitions.len())?,
            refresh_usize_to_sql(attempt.removed_partitions.len())?,
            refresh_usize_to_sql(attempt.execution_attempts.len())?,
            outcome,
            failure_class,
            refresh_u64_to_sql(attempt.started_unix_ms)?,
            refresh_u64_to_sql(attempt.completed_unix_ms)?,
            attempt.cost_microusd.map(refresh_u64_to_sql).transpose()?,
            attempt_json,
            refresh_u64_to_sql(now_ms())?,
        ],
    )?;
    Ok(())
}

pub(super) fn validate_storage_bindings(
    connection: &Connection,
    attempt: &RefreshAttempt,
) -> Result<(), StoreError> {
    let binding_row = connection
        .query_row(
            "SELECT t.prior_manifest_id, t.current_manifest_id, t.state_delta,
                    p.action_request_id, p.action_contract_id,
                    c.action_request_id, c.action_contract_id
             FROM manifest_transitions t
             JOIN partition_manifests p ON p.manifest_id=t.prior_manifest_id
             JOIN partition_manifests c ON c.manifest_id=t.current_manifest_id
             WHERE t.transition_id=?1",
            [attempt.manifest_transition.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| binding("refresh transition is not persisted"))?;
    if binding_row.0 != attempt.prior_manifest.to_string()
        || binding_row.1 != attempt.current_manifest.to_string()
        || binding_row.2 != attempt.state_delta.to_string()
        || binding_row.3 != attempt.request.to_string()
        || binding_row.4 != attempt.action_contract.as_str()
        || binding_row.5 != attempt.request.to_string()
        || binding_row.6 != attempt.action_contract.as_str()
    {
        return Err(binding(
            "refresh attempt does not match its persisted manifests and transition",
        ));
    }

    let mut statement = connection.prepare(
        "SELECT prior_key_digest, current_key_digest
         FROM manifest_transition_mappings WHERE transition_id=?1",
    )?;
    let transition_pairs = statement
        .query_map([attempt.manifest_transition.to_string()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<BTreeSet<_>, _>>()?;
    let transition_current_to_prior = transition_pairs
        .iter()
        .map(|(prior, current)| (current.clone(), prior.clone()))
        .collect::<BTreeMap<_, _>>();
    let transition_prior =
        transition_pairs.iter().map(|(prior, _)| prior.clone()).collect::<BTreeSet<_>>();
    let transition_current =
        transition_pairs.iter().map(|(_, current)| current.clone()).collect::<BTreeSet<_>>();
    let prior_entries = manifest_entry_keys(connection, &attempt.prior_manifest.to_string())?;
    let current_entries = manifest_entry_keys(connection, &attempt.current_manifest.to_string())?;

    if attempt.retained_partitions.iter().any(|mapping| {
        !transition_pairs.contains(&(
            mapping.prior.key_digest.to_string(),
            mapping.current.key_digest.to_string(),
        ))
    }) || attempt
        .refreshed_partitions
        .iter()
        .any(|partition| !transition_current.contains(&partition.key_digest.to_string()))
        || attempt.added_partitions.iter().any(|partition| {
            !current_entries.contains(&partition.key_digest.to_string())
                || transition_current.contains(&partition.key_digest.to_string())
        })
        || attempt.removed_partitions.iter().any(|partition| {
            !prior_entries.contains(&partition.key_digest.to_string())
                || transition_prior.contains(&partition.key_digest.to_string())
        })
    {
        return Err(binding("refresh partition classes do not match the persisted transition"));
    }

    let attempt_current = attempt
        .retained_partitions
        .iter()
        .map(|mapping| mapping.current.key_digest.to_string())
        .chain(
            attempt
                .refreshed_partitions
                .iter()
                .chain(&attempt.added_partitions)
                .map(|partition| partition.key_digest.to_string()),
        )
        .collect::<BTreeSet<_>>();
    let mut attempt_prior = attempt
        .retained_partitions
        .iter()
        .map(|mapping| mapping.prior.key_digest.to_string())
        .chain(attempt.removed_partitions.iter().map(|partition| partition.key_digest.to_string()))
        .collect::<BTreeSet<_>>();
    for refreshed in &attempt.refreshed_partitions {
        let current = refreshed.key_digest.to_string();
        let prior = transition_current_to_prior
            .get(&current)
            .ok_or_else(|| binding("refreshed partition has no persisted prior mapping"))?;
        attempt_prior.insert(prior.clone());
    }
    if attempt_current != current_entries || attempt_prior != prior_entries {
        return Err(binding(
            "refresh partition classes do not cover both persisted manifests exactly",
        ));
    }
    Ok(())
}

fn manifest_entry_keys(
    connection: &Connection,
    manifest_id: &str,
) -> Result<BTreeSet<String>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT key_digest FROM partition_manifest_entries
         WHERE manifest_id=?1 ORDER BY key_digest",
    )?;
    statement
        .query_map([manifest_id], |row| row.get::<_, String>(0))?
        .collect::<Result<_, _>>()
        .map_err(StoreError::from)
}

fn read_refresh_attempt(
    connection: &Connection,
    id: RefreshAttemptId,
) -> Result<Option<RefreshAttempt>, StoreError> {
    let row = connection
        .query_row(
            "SELECT attempt_id, request_id, action_contract_id, prior_artifact_id,
                    state_delta, prior_manifest_id, current_manifest_id, transition_id,
                    refresh_policy_definition_digest, operator_definition_digest,
                    execution_scope_digest, retained_partition_count,
                    refreshed_partition_count, added_partition_count,
                    removed_partition_count, execution_attempt_count, outcome,
                    failure_class, started_unix_ms, completed_unix_ms, cost_microusd,
                    authority, attempt_json
             FROM refresh_attempts WHERE attempt_id=?1",
            [id.to_string()],
            attempt_row,
        )
        .optional()?;
    row.map(decode_attempt_row).transpose()
}

fn attempt_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AttemptRow> {
    Ok(AttemptRow {
        attempt_id: row.get(0)?,
        request_id: row.get(1)?,
        action_contract_id: row.get(2)?,
        prior_artifact_id: row.get(3)?,
        state_delta: row.get(4)?,
        prior_manifest_id: row.get(5)?,
        current_manifest_id: row.get(6)?,
        transition_id: row.get(7)?,
        refresh_policy_definition_digest: row.get(8)?,
        operator_definition_digest: row.get(9)?,
        execution_scope_digest: row.get(10)?,
        retained_partition_count: row.get(11)?,
        refreshed_partition_count: row.get(12)?,
        added_partition_count: row.get(13)?,
        removed_partition_count: row.get(14)?,
        execution_attempt_count: row.get(15)?,
        outcome: row.get(16)?,
        failure_class: row.get(17)?,
        started_unix_ms: row.get(18)?,
        completed_unix_ms: row.get(19)?,
        cost_microusd: row.get(20)?,
        authority: row.get(21)?,
        attempt_json: row.get(22)?,
    })
}

fn decode_attempt_row(row: AttemptRow) -> Result<RefreshAttempt, StoreError> {
    let attempt = RefreshAttempt::decode_json(row.attempt_json.as_bytes())?;
    let (outcome, failure_class) = outcome_columns(attempt.outcome);
    if row.attempt_id != attempt.id.to_string()
        || row.request_id != attempt.request.to_string()
        || row.action_contract_id != attempt.action_contract.as_str()
        || row.prior_artifact_id != attempt.prior_artifact.to_string()
        || row.state_delta != attempt.state_delta.to_string()
        || row.prior_manifest_id != attempt.prior_manifest.to_string()
        || row.current_manifest_id != attempt.current_manifest.to_string()
        || row.transition_id != attempt.manifest_transition.to_string()
        || row.refresh_policy_definition_digest
            != attempt.refresh_policy_definition_digest.to_string()
        || row.operator_definition_digest != attempt.operator_definition_digest.to_string()
        || row.execution_scope_digest != attempt.execution_scope_digest.to_string()
        || refresh_i64_to_usize(row.retained_partition_count)? != attempt.retained_partitions.len()
        || refresh_i64_to_usize(row.refreshed_partition_count)?
            != attempt.refreshed_partitions.len()
        || refresh_i64_to_usize(row.added_partition_count)? != attempt.added_partitions.len()
        || refresh_i64_to_usize(row.removed_partition_count)? != attempt.removed_partitions.len()
        || refresh_i64_to_usize(row.execution_attempt_count)? != attempt.execution_attempts.len()
        || row.outcome != outcome
        || row.failure_class.as_deref() != failure_class
        || refresh_i64_to_u64(row.started_unix_ms)? != attempt.started_unix_ms
        || refresh_i64_to_u64(row.completed_unix_ms)? != attempt.completed_unix_ms
        || row.cost_microusd.map(refresh_i64_to_u64).transpose()? != attempt.cost_microusd
        || row.authority != "shadow"
    {
        return Err(corruption("stored refresh-attempt columns do not match the canonical record"));
    }
    Ok(attempt)
}

fn read_failed_refresh_memo(
    connection: &Connection,
    id: FailedRefreshMemoId,
) -> Result<Option<FailedRefreshMemo>, StoreError> {
    let row = connection
        .query_row(
            "SELECT memo_id, attempt_id, request_id, action_contract_id,
                    prior_artifact_id, state_delta,
                    refresh_policy_definition_digest, operator_definition_digest,
                    execution_scope_digest, failure_class, failure_evidence_digest,
                    expires_unix_ms, memo_json
             FROM failed_refresh_memos WHERE memo_id=?1",
            [id.to_string()],
            memo_row,
        )
        .optional()?;
    row.map(decode_memo_row).transpose()
}

fn read_failed_refresh_memo_for_attempt(
    connection: &Connection,
    attempt: RefreshAttemptId,
) -> Result<Option<FailedRefreshMemo>, StoreError> {
    let memo_id = connection
        .query_row(
            "SELECT memo_id FROM failed_refresh_memos WHERE attempt_id=?1",
            [attempt.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    memo_id
        .map(|value| parse_memo_id(&value))
        .transpose()?
        .map(|id| read_failed_refresh_memo(connection, id))
        .transpose()
        .map(Option::flatten)
}

fn memo_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoRow> {
    Ok(MemoRow {
        memo_id: row.get(0)?,
        attempt_id: row.get(1)?,
        request_id: row.get(2)?,
        action_contract_id: row.get(3)?,
        prior_artifact_id: row.get(4)?,
        state_delta: row.get(5)?,
        refresh_policy_definition_digest: row.get(6)?,
        operator_definition_digest: row.get(7)?,
        execution_scope_digest: row.get(8)?,
        failure_class: row.get(9)?,
        failure_evidence_digest: row.get(10)?,
        expires_unix_ms: row.get(11)?,
        memo_json: row.get(12)?,
    })
}

fn decode_memo_row(row: MemoRow) -> Result<FailedRefreshMemo, StoreError> {
    let memo = FailedRefreshMemo::decode_json(row.memo_json.as_bytes())?;
    if row.memo_id != memo.id.to_string()
        || row.attempt_id != memo.attempt.to_string()
        || row.request_id != memo.request.to_string()
        || row.action_contract_id != memo.action_contract.as_str()
        || row.prior_artifact_id != memo.prior_artifact.to_string()
        || row.state_delta != memo.state_delta.to_string()
        || row.refresh_policy_definition_digest != memo.refresh_policy_definition_digest.to_string()
        || row.operator_definition_digest != memo.operator_definition_digest.to_string()
        || row.execution_scope_digest != memo.execution_scope_digest.to_string()
        || row.failure_class != failure_class_name(memo.failure_class)
        || row.failure_evidence_digest != memo.failure_evidence_digest.to_string()
        || row.expires_unix_ms.map(refresh_i64_to_u64).transpose()? != memo.expires_unix_ms
    {
        return Err(corruption(
            "stored failed-refresh memo columns do not match the canonical record",
        ));
    }
    Ok(memo)
}

fn outcome_columns(outcome: RefreshOutcome) -> (&'static str, Option<&'static str>) {
    match outcome {
        RefreshOutcome::Succeeded { .. } => ("succeeded", None),
        RefreshOutcome::Failed { failure_class, .. } => {
            ("failed", Some(failure_class_name(failure_class)))
        }
    }
}

fn failure_class_name(value: RefreshFailureClass) -> &'static str {
    match value {
        RefreshFailureClass::Acquisition => "acquisition",
        RefreshFailureClass::Operator => "operator",
        RefreshFailureClass::Reconstruction => "reconstruction",
        RefreshFailureClass::Validation => "validation",
        RefreshFailureClass::Timeout => "timeout",
        RefreshFailureClass::BudgetExceeded => "budget_exceeded",
        RefreshFailureClass::RuntimeUnavailable => "runtime_unavailable",
        RefreshFailureClass::Storage => "storage",
    }
}

fn parse_memo_id(value: &str) -> Result<FailedRefreshMemoId, StoreError> {
    needle_core::Digest::parse(value)
        .map(FailedRefreshMemoId::new)
        .map_err(|_| corruption(format!("stored failed-refresh memo id `{value}` is invalid")))
}

fn ensure_wire_bound(
    record: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), StoreError> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(conflict(format!("{record} contains {actual} bytes; the maximum is {maximum}")))
    }
}

fn refresh_u64_to_sql(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| conflict("refresh value exceeds the SQLite integer range"))
}

fn refresh_usize_to_sql(value: usize) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| conflict("refresh count exceeds the SQLite integer range"))
}

fn refresh_i64_to_u64(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| corruption("stored refresh value is negative"))
}

fn refresh_i64_to_usize(value: i64) -> Result<usize, StoreError> {
    usize::try_from(value).map_err(|_| corruption("stored refresh count is negative"))
}

fn binding(message: impl Into<String>) -> StoreError {
    StoreError::RefreshPersistenceBinding(message.into())
}

fn conflict(message: impl Into<String>) -> StoreError {
    StoreError::RefreshPersistenceConflict(message.into())
}

fn corruption(message: impl Into<String>) -> StoreError {
    StoreError::RefreshPersistenceCorruption(message.into())
}

#[cfg(test)]
#[path = "refreshes/tests.rs"]
mod tests;
