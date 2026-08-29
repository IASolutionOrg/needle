use super::{RuntimeStore, StoreError, now_ms};
use needle_core::{
    CapabilityMode, Digest, MAX_REFRESH_ECONOMIC_WIRE_BYTES, RefreshAttemptId,
    RefreshEconomicAssessment, RefreshEconomicDecision, RefreshEconomicFallback,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

pub const MAX_REFRESH_ECONOMIC_ASSESSMENT_LIST_LIMIT: usize = 500;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshEconomicAssessmentRecord {
    pub assessment: RefreshEconomicAssessment,
    pub selected_refresh_attempt: Option<RefreshAttemptId>,
    pub recorded_unix_ms: u64,
}

struct AssessmentRow {
    assessment_digest: String,
    request_id: String,
    action_contract_id: String,
    candidate_definition_digest: String,
    operator_definition_digest: String,
    execution_scope_digest: String,
    policy_definition_digest: String,
    evidence_definition_digest: Option<String>,
    expected_net_microusd: Option<i64>,
    decision: String,
    fallback_reason: Option<String>,
    authority: String,
    assessment_json: String,
    recorded_unix_ms: i64,
    selection_attempt_id: Option<String>,
    selection_candidate_definition_digest: Option<String>,
    selection_authority: Option<String>,
}

impl RuntimeStore {
    /// Persist one immutable, canonical Shadow economic assessment.
    ///
    /// This is audit-only storage. It does not authorize refresh, change a
    /// capability mode, or make the assessment a resolver input.
    pub fn persist_refresh_economic_assessment(
        &self,
        assessment: &RefreshEconomicAssessment,
    ) -> Result<(), StoreError> {
        assessment.validate()?;
        let assessment_json = serde_json::to_string(assessment)?;
        if assessment_json.len() > MAX_REFRESH_ECONOMIC_WIRE_BYTES {
            return Err(corruption(format!(
                "serialized assessment contains {} bytes; the maximum is {}",
                assessment_json.len(),
                MAX_REFRESH_ECONOMIC_WIRE_BYTES
            )));
        }

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_refresh_economic_assessment(&transaction, assessment, &assessment_json, now_ms())?;
        transaction.commit()?;
        Ok(())
    }

    pub fn refresh_economic_assessment(
        &self,
        definition_digest: Digest,
    ) -> Result<Option<RefreshEconomicAssessmentRecord>, StoreError> {
        let connection = self.connection()?;
        read_assessment(&connection, definition_digest)
    }

    pub fn refresh_economic_assessments(
        &self,
        limit: usize,
    ) -> Result<Vec<RefreshEconomicAssessmentRecord>, StoreError> {
        if limit == 0 || limit > MAX_REFRESH_ECONOMIC_ASSESSMENT_LIST_LIMIT {
            return Err(StoreError::RefreshEconomicQuery(format!(
                "limit must be between 1 and {MAX_REFRESH_ECONOMIC_ASSESSMENT_LIST_LIMIT}"
            )));
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare_cached(
            "SELECT a.assessment_digest, a.request_id, a.action_contract_id,
                    a.candidate_definition_digest, a.operator_definition_digest,
                    a.execution_scope_digest, a.policy_definition_digest,
                    a.evidence_definition_digest, a.expected_net_microusd,
                    a.decision, a.fallback_reason, a.authority, a.assessment_json,
                    a.recorded_unix_ms,
                    s.attempt_id, s.candidate_definition_digest, s.authority
             FROM refresh_economic_assessments a
             LEFT JOIN refresh_economic_selections s
               ON s.assessment_digest=a.assessment_digest
             ORDER BY a.recorded_unix_ms DESC, a.assessment_digest ASC
             LIMIT ?1",
        )?;
        let rows = statement.query_map([usize_to_sql(limit)?], map_row)?;
        rows.map(|row| row.map_err(StoreError::from).and_then(validate_row)).collect()
    }
}

fn read_assessment(
    connection: &rusqlite::Connection,
    definition_digest: Digest,
) -> Result<Option<RefreshEconomicAssessmentRecord>, StoreError> {
    let row = connection
        .query_row(
            "SELECT a.assessment_digest, a.request_id, a.action_contract_id,
                    a.candidate_definition_digest, a.operator_definition_digest,
                    a.execution_scope_digest, a.policy_definition_digest,
                    a.evidence_definition_digest, a.expected_net_microusd,
                    a.decision, a.fallback_reason, a.authority, a.assessment_json,
                    a.recorded_unix_ms,
                    s.attempt_id, s.candidate_definition_digest, s.authority
             FROM refresh_economic_assessments a
             LEFT JOIN refresh_economic_selections s
               ON s.assessment_digest=a.assessment_digest
             WHERE a.assessment_digest=?1",
            [definition_digest.to_string()],
            map_row,
        )
        .optional()?;
    row.map(validate_row).transpose()
}

fn map_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AssessmentRow> {
    Ok(AssessmentRow {
        assessment_digest: row.get(0)?,
        request_id: row.get(1)?,
        action_contract_id: row.get(2)?,
        candidate_definition_digest: row.get(3)?,
        operator_definition_digest: row.get(4)?,
        execution_scope_digest: row.get(5)?,
        policy_definition_digest: row.get(6)?,
        evidence_definition_digest: row.get(7)?,
        expected_net_microusd: row.get(8)?,
        decision: row.get(9)?,
        fallback_reason: row.get(10)?,
        authority: row.get(11)?,
        assessment_json: row.get(12)?,
        recorded_unix_ms: row.get(13)?,
        selection_attempt_id: row.get(14)?,
        selection_candidate_definition_digest: row.get(15)?,
        selection_authority: row.get(16)?,
    })
}

fn validate_row(row: AssessmentRow) -> Result<RefreshEconomicAssessmentRecord, StoreError> {
    if row.assessment_json.len() > MAX_REFRESH_ECONOMIC_WIRE_BYTES {
        return Err(corruption("stored assessment exceeds its wire bound"));
    }
    let assessment = RefreshEconomicAssessment::decode_json(row.assessment_json.as_bytes())
        .map_err(|error| corruption(error.to_string()))?;
    let (decision, fallback_reason) = decision_columns(assessment.decision);
    let expected = [
        ("assessment_digest", assessment.definition_digest.to_string(), row.assessment_digest),
        ("request_id", assessment.request.to_string(), row.request_id),
        (
            "action_contract_id",
            assessment.action_contract.as_str().to_owned(),
            row.action_contract_id,
        ),
        (
            "candidate_definition_digest",
            assessment.candidate_definition_digest.to_string(),
            row.candidate_definition_digest,
        ),
        (
            "operator_definition_digest",
            assessment.operator_definition_digest.to_string(),
            row.operator_definition_digest,
        ),
        (
            "execution_scope_digest",
            assessment.execution_scope_digest.to_string(),
            row.execution_scope_digest,
        ),
        (
            "policy_definition_digest",
            assessment.policy.definition_digest.to_string(),
            row.policy_definition_digest,
        ),
        ("decision", decision.to_owned(), row.decision),
        ("authority", authority_name(assessment.authority).to_owned(), row.authority),
    ];
    if let Some((field, _, _)) = expected.iter().find(|(_, expected, actual)| expected != actual) {
        return Err(corruption(format!("indexed {field} does not match assessment JSON")));
    }
    let evidence_definition_digest =
        assessment.evidence.as_ref().map(|value| value.definition_digest.to_string());
    if row.evidence_definition_digest != evidence_definition_digest
        || row.expected_net_microusd != assessment.expected_net_microusd
        || row.fallback_reason.as_deref() != fallback_reason
    {
        return Err(corruption("indexed economic fields do not match assessment JSON"));
    }
    let selected_refresh_attempt = match (
        row.selection_attempt_id,
        row.selection_candidate_definition_digest,
        row.selection_authority,
    ) {
        (None, None, None) => None,
        (Some(attempt), Some(candidate), Some(authority))
            if candidate == assessment.candidate_definition_digest.to_string()
                && authority == "shadow" =>
        {
            Some(RefreshAttemptId::new(
                Digest::parse(&attempt)
                    .map_err(|_| corruption("selected refresh attempt id is invalid"))?,
            ))
        }
        _ => return Err(corruption("economic selection does not bind its assessment")),
    };
    Ok(RefreshEconomicAssessmentRecord {
        assessment,
        selected_refresh_attempt,
        recorded_unix_ms: sql_to_u64(row.recorded_unix_ms)?,
    })
}

pub(super) fn insert_refresh_economic_assessment(
    connection: &rusqlite::Connection,
    assessment: &RefreshEconomicAssessment,
    assessment_json: &str,
    recorded_unix_ms: u64,
) -> Result<(), StoreError> {
    assessment.validate()?;
    if assessment_json.len() > MAX_REFRESH_ECONOMIC_WIRE_BYTES {
        return Err(corruption("serialized assessment exceeds its wire bound"));
    }
    if let Some(existing) = read_assessment(connection, assessment.definition_digest)? {
        if existing.assessment != *assessment {
            return Err(conflict(format!(
                "assessment {} already has different immutable content",
                assessment.definition_digest
            )));
        }
        return Ok(());
    }
    let (decision, fallback_reason) = decision_columns(assessment.decision);
    connection.execute(
        "INSERT INTO refresh_economic_assessments(
            assessment_digest, request_id, action_contract_id,
            candidate_definition_digest, operator_definition_digest,
            execution_scope_digest, policy_definition_digest,
            evidence_definition_digest, expected_net_microusd,
            decision, fallback_reason, authority, assessment_json, recorded_unix_ms
         ) VALUES(
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'shadow', ?12, ?13
         )",
        params![
            assessment.definition_digest.to_string(),
            assessment.request.to_string(),
            assessment.action_contract.as_str(),
            assessment.candidate_definition_digest.to_string(),
            assessment.operator_definition_digest.to_string(),
            assessment.execution_scope_digest.to_string(),
            assessment.policy.definition_digest.to_string(),
            assessment.evidence.as_ref().map(|value| value.definition_digest.to_string()),
            assessment.expected_net_microusd,
            decision,
            fallback_reason,
            assessment_json,
            u64_to_sql(recorded_unix_ms)?,
        ],
    )?;
    Ok(())
}

pub(super) fn insert_refresh_economic_selection(
    connection: &rusqlite::Connection,
    assessment: &RefreshEconomicAssessment,
    attempt: RefreshAttemptId,
    recorded_unix_ms: u64,
) -> Result<(), StoreError> {
    let existing = connection
        .query_row(
            "SELECT attempt_id, candidate_definition_digest
             FROM refresh_economic_selections WHERE assessment_digest=?1",
            [assessment.definition_digest.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((existing_attempt, existing_candidate)) = existing {
        if existing_attempt != attempt.to_string()
            || existing_candidate != assessment.candidate_definition_digest.to_string()
        {
            return Err(conflict(format!(
                "assessment {} already selects a different refresh attempt",
                assessment.definition_digest
            )));
        }
        return Ok(());
    }
    let conflicting_assessment = connection
        .query_row(
            "SELECT assessment_digest FROM refresh_economic_selections WHERE attempt_id=?1",
            [attempt.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(existing) = conflicting_assessment {
        return Err(conflict(format!(
            "refresh attempt {attempt} is already selected by assessment {existing}"
        )));
    }
    connection.execute(
        "INSERT INTO refresh_economic_selections(
            assessment_digest, attempt_id, candidate_definition_digest,
            authority, recorded_unix_ms
         ) VALUES(?1, ?2, ?3, 'shadow', ?4)",
        params![
            assessment.definition_digest.to_string(),
            attempt.to_string(),
            assessment.candidate_definition_digest.to_string(),
            u64_to_sql(recorded_unix_ms)?,
        ],
    )?;
    Ok(())
}

fn decision_columns(decision: RefreshEconomicDecision) -> (&'static str, Option<&'static str>) {
    match decision {
        RefreshEconomicDecision::Refresh => ("refresh", None),
        RefreshEconomicDecision::FullCompute { reason } => {
            ("full_compute", Some(fallback_reason_name(reason)))
        }
    }
}

fn fallback_reason_name(reason: RefreshEconomicFallback) -> &'static str {
    match reason {
        RefreshEconomicFallback::MissingCostEvidence => "missing_cost_evidence",
        RefreshEconomicFallback::BelowMinimumNetValue => "below_minimum_net_value",
        RefreshEconomicFallback::MissingLatencyEvidence => "missing_latency_evidence",
        RefreshEconomicFallback::RefreshLatencyBudgetExceeded => "refresh_latency_budget_exceeded",
    }
}

fn authority_name(authority: CapabilityMode) -> &'static str {
    match authority {
        CapabilityMode::Disabled => "disabled",
        CapabilityMode::Shadow => "shadow",
        CapabilityMode::Advisory => "advisory",
        CapabilityMode::Authoritative => "authoritative",
    }
}

fn usize_to_sql(value: usize) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::RefreshEconomicQuery("limit overflow".to_owned()))
}

fn u64_to_sql(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| corruption("record timestamp exceeds SQLite range"))
}

fn sql_to_u64(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| corruption("stored record timestamp is negative"))
}

fn conflict(message: impl Into<String>) -> StoreError {
    StoreError::RefreshEconomicConflict(message.into())
}

fn corruption(message: impl Into<String>) -> StoreError {
    StoreError::RefreshEconomicCorruption(message.into())
}

#[cfg(test)]
#[path = "refresh_economics/tests.rs"]
mod tests;
