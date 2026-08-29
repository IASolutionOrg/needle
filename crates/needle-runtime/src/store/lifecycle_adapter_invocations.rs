use super::*;
use crate::lifecycle_executor::{
    validate_lifecycle_phase_adapter_outcome, validate_lifecycle_phase_adapter_request,
};
use crate::{
    LifecyclePhaseAdapterOutcome, LifecyclePhaseAdapterRequest,
    MAX_LIFECYCLE_ADAPTER_OUTCOME_BYTES, MAX_LIFECYCLE_ADAPTER_REQUEST_BYTES,
};
use needle_core::{
    CanonicalHasher, ChangeId, LifecycleId, LifecyclePhase, LifecycleReason, LifecycleStatus,
    LifecycleTransition,
};
use rusqlite::TransactionBehavior;

const ADAPTER_ABORT_REASON_CODE: &str = "adapter_invocation_aborted";
const ADAPTER_ABORT_REASON_DETAIL: &[u8] =
    b"operator confirmed the abandoned adapter invocation was stopped";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleAdapterRecoverySource {
    WebUser,
}

impl LifecycleAdapterRecoverySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WebUser => "web_user",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::WebUser => 1,
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "web_user" => Ok(Self::WebUser),
            _ => Err(StoreError::LifecycleAdapterInvocationCorruption(format!(
                "unknown recovery source `{value}`"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleAdapterRecoveryRecord {
    pub recovery_digest: Digest,
    pub invocation_id: Digest,
    pub lifecycle_id: LifecycleId,
    pub expected_state_digest: Digest,
    pub request_digest: Digest,
    pub adapter_definition_digest: Digest,
    pub source: LifecycleAdapterRecoverySource,
    pub recovered_unix_ms: u64,
}

impl LifecycleAdapterRecoveryRecord {
    fn new(
        invocation_id: Digest,
        lifecycle_id: LifecycleId,
        expected_state_digest: Digest,
        request_digest: Digest,
        adapter_definition_digest: Digest,
        source: LifecycleAdapterRecoverySource,
        recovered_unix_ms: u64,
    ) -> Self {
        let mut value = Self {
            recovery_digest: Digest([0; 32]),
            invocation_id,
            lifecycle_id,
            expected_state_digest,
            request_digest,
            adapter_definition_digest,
            source,
            recovered_unix_ms,
        };
        value.recovery_digest = value.compute_digest();
        value
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"needle-lifecycle-adapter-recovery-v1");
        hasher.field_digest(self.invocation_id);
        hasher.field_digest(self.lifecycle_id.0);
        hasher.field_digest(self.expected_state_digest);
        hasher.field_digest(self.request_digest);
        hasher.field_digest(self.adapter_definition_digest);
        hasher.field_u8(self.source.tag());
        hasher.field_bytes(&self.recovered_unix_ms.to_le_bytes());
        hasher.finish()
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.recovery_digest != self.compute_digest() {
            return Err(StoreError::LifecycleAdapterInvocationCorruption(format!(
                "{}: recovery digest mismatch",
                self.invocation_id
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleAdapterInvocationRecord {
    pub invocation_id: Digest,
    pub lifecycle_id: LifecycleId,
    pub expected_state_digest: Digest,
    pub phase: LifecyclePhase,
    pub state: LifecycleAdapterInvocationState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleAdapterRecoveryResult {
    pub projection: crate::LifecycleProjection,
    pub recovery: LifecycleAdapterRecoveryRecord,
    pub created: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleAdapterInvocationState {
    InProgress {
        request_digest: Digest,
        adapter_definition_digest: Digest,
        started_unix_ms: u64,
    },
    Completed {
        request_digest: Digest,
        adapter_definition_digest: Digest,
        outcome: Box<LifecyclePhaseAdapterOutcome>,
        started_unix_ms: u64,
        completed_unix_ms: u64,
    },
    Aborted {
        request_digest: Digest,
        adapter_definition_digest: Digest,
        recovery: Box<LifecycleAdapterRecoveryRecord>,
        started_unix_ms: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleAdapterInvocationClaim {
    Claimed,
    Existing(LifecycleAdapterInvocationState),
}

pub(super) struct InvocationRow {
    invocation_id: String,
    lifecycle_id: String,
    expected_state_digest: String,
    phase: String,
    request_digest: String,
    adapter_definition_digest: String,
    request_json: String,
    started_unix_ms: u64,
    outcome_digest: Option<String>,
    outcome_json: Option<String>,
    completed_unix_ms: Option<u64>,
    recovery_digest: Option<String>,
    recovery_lifecycle_id: Option<String>,
    recovery_expected_state_digest: Option<String>,
    recovery_request_digest: Option<String>,
    recovery_adapter_definition_digest: Option<String>,
    recovery_source: Option<String>,
    recovered_unix_ms: Option<u64>,
}

impl RuntimeStore {
    /// Acquire the immutable invocation identity before an external adapter is
    /// allowed to run. An existing in-progress record is never reclaimed
    /// automatically: after a crash the host fails closed instead of risking a
    /// duplicate provider call.
    pub fn claim_lifecycle_adapter_invocation(
        &self,
        request: &LifecyclePhaseAdapterRequest,
        adapter_definition_digest: Digest,
    ) -> Result<LifecycleAdapterInvocationClaim, StoreError> {
        let (request_digest, request_json) = encode_request(request)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(row) = invocation_row(&transaction, request.invocation_id)? {
            let (stored_request, state) = decode_invocation_row(row)?;
            if stored_request != *request {
                return Err(StoreError::LifecycleAdapterInvocationConflict(format!(
                    "{}: invocation identity is bound to a different request",
                    request.invocation_id
                )));
            }
            let stored_adapter_definition_digest = match &state {
                LifecycleAdapterInvocationState::InProgress {
                    adapter_definition_digest, ..
                }
                | LifecycleAdapterInvocationState::Completed {
                    adapter_definition_digest, ..
                }
                | LifecycleAdapterInvocationState::Aborted { adapter_definition_digest, .. } => {
                    *adapter_definition_digest
                }
            };
            if stored_adapter_definition_digest != adapter_definition_digest {
                return Err(StoreError::LifecycleAdapterInvocationConflict(format!(
                    "{}: invocation is bound to a different adapter definition",
                    request.invocation_id
                )));
            }
            transaction.commit()?;
            return Ok(LifecycleAdapterInvocationClaim::Existing(state));
        }

        let current: Option<(String, String, String, String, String, String, String)> = transaction
            .query_row(
                "SELECT l.lifecycle_id, l.state_digest, l.state_json,
                        c.request_digest, c.repository_id, c.source_snapshot_digest, c.request_json
                 FROM change_lifecycles l
                 JOIN change_requests c ON c.change_id=l.change_id
                 WHERE l.change_id=?1",
                [request.lifecycle.change_id.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            lifecycle_id,
            state_digest,
            state_json,
            change_request_digest,
            repository_id,
            source_snapshot,
            change_request_json,
        )) = current
        else {
            return Err(StoreError::LifecycleNotFound(format!(
                "{}: lifecycle adapter invocation",
                request.lifecycle.change_id
            )));
        };
        let stored_lifecycle: needle_core::DevelopmentLifecycle = serde_json::from_str(&state_json)
            .map_err(|error| StoreError::LifecycleCorruption(error.to_string()))?;
        stored_lifecycle.validate()?;
        let stored_source = Digest::parse(&source_snapshot)
            .map_err(|error| StoreError::LifecycleCorruption(error.to_string()))?;
        let stored_request_digest = Digest::parse(&change_request_digest)
            .map_err(|error| StoreError::LifecycleCorruption(error.to_string()))?;
        let stored_repository = Digest::parse(&repository_id)
            .map_err(|error| StoreError::LifecycleCorruption(error.to_string()))?;
        let stored_request: needle_core::ChangeRequest = serde_json::from_str(&change_request_json)
            .map_err(|error| StoreError::LifecycleCorruption(error.to_string()))?;
        if stored_request.digest(stored_source) != stored_request_digest {
            return Err(StoreError::LifecycleCorruption(format!(
                "{}: immutable change request digest",
                request.lifecycle.change_id
            )));
        }
        let stored_change = crate::LifecycleChangeContext {
            request: stored_request,
            request_digest: stored_request_digest,
            repository_id: stored_repository,
            source_snapshot: stored_source,
        };
        if stored_lifecycle != request.lifecycle
            || stored_change != request.change
            || lifecycle_id != request.lifecycle.id.to_string()
            || state_digest != request.expected_state_digest.to_string()
            || stored_lifecycle.state_digest() != request.expected_state_digest
        {
            return Err(StoreError::LifecycleAdapterInvocationConflict(format!(
                "{}: lifecycle state changed before invocation",
                request.invocation_id
            )));
        }

        let started_unix_ms = now_ms();
        transaction.execute(
            "INSERT INTO lifecycle_adapter_invocations(
                invocation_id, lifecycle_id, expected_state_digest, phase,
                request_digest, adapter_definition_digest, request_json, started_unix_ms
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                request.invocation_id.to_string(),
                request.lifecycle.id.to_string(),
                request.expected_state_digest.to_string(),
                request.phase.as_str(),
                request_digest.to_string(),
                adapter_definition_digest.to_string(),
                request_json,
                started_unix_ms,
            ],
        )?;
        transaction.commit()?;
        Ok(LifecycleAdapterInvocationClaim::Claimed)
    }

    pub fn complete_lifecycle_adapter_invocation(
        &self,
        request: &LifecyclePhaseAdapterRequest,
        adapter_definition_digest: Digest,
        outcome: &LifecyclePhaseAdapterOutcome,
    ) -> Result<(), StoreError> {
        let (request_digest, _) = encode_request(request)?;
        let (outcome_digest, outcome_json) = encode_outcome(request, outcome)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = invocation_row(&transaction, request.invocation_id)?.ok_or_else(|| {
            StoreError::LifecycleAdapterInvocationConflict(format!(
                "{}: invocation was not acquired",
                request.invocation_id
            ))
        })?;
        let (stored_request, state) = decode_invocation_row(row)?;
        if stored_request != *request {
            return Err(StoreError::LifecycleAdapterInvocationConflict(format!(
                "{}: completion request differs from the acquired invocation",
                request.invocation_id
            )));
        }
        let (stored_request_digest, stored_adapter_definition_digest, started_unix_ms) =
            match &state {
                LifecycleAdapterInvocationState::InProgress {
                    request_digest,
                    adapter_definition_digest,
                    started_unix_ms,
                }
                | LifecycleAdapterInvocationState::Completed {
                    request_digest,
                    adapter_definition_digest,
                    started_unix_ms,
                    ..
                }
                | LifecycleAdapterInvocationState::Aborted {
                    request_digest,
                    adapter_definition_digest,
                    started_unix_ms,
                    ..
                } => (*request_digest, *adapter_definition_digest, *started_unix_ms),
            };
        if stored_request_digest != request_digest
            || stored_adapter_definition_digest != adapter_definition_digest
        {
            return Err(StoreError::LifecycleAdapterInvocationConflict(format!(
                "{}: adapter definition differs from the acquired invocation",
                request.invocation_id
            )));
        }
        if let LifecycleAdapterInvocationState::Completed { outcome: stored, .. } = &state {
            if stored.as_ref() == outcome {
                transaction.commit()?;
                return Ok(());
            }
            return Err(StoreError::LifecycleAdapterInvocationConflict(format!(
                "{}: invocation already has a different outcome",
                request.invocation_id
            )));
        }
        if matches!(state, LifecycleAdapterInvocationState::Aborted { .. }) {
            return Err(StoreError::LifecycleAdapterInvocationConflict(format!(
                "{}: invocation was explicitly aborted",
                request.invocation_id
            )));
        }
        let completed_unix_ms = now_ms().max(started_unix_ms);
        transaction.execute(
            "INSERT INTO lifecycle_adapter_outcomes(
                invocation_id, outcome_digest, outcome_json, completed_unix_ms
             ) VALUES(?1, ?2, ?3, ?4)",
            params![
                request.invocation_id.to_string(),
                outcome_digest.to_string(),
                outcome_json,
                completed_unix_ms,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn lifecycle_adapter_invocation_state(
        &self,
        invocation_id: Digest,
    ) -> Result<Option<LifecycleAdapterInvocationState>, StoreError> {
        let connection = self.connection()?;
        invocation_row(&connection, invocation_id)?
            .map(decode_invocation_row)
            .transpose()
            .map(|row| row.map(|(_, state)| state))
    }

    pub fn latest_lifecycle_adapter_invocation(
        &self,
        lifecycle_id: LifecycleId,
    ) -> Result<Option<LifecycleAdapterInvocationRecord>, StoreError> {
        let connection = self.connection()?;
        let invocation_id: Option<String> = connection
            .query_row(
                "SELECT invocation_id FROM lifecycle_adapter_invocations
                 WHERE lifecycle_id=?1
                 ORDER BY started_unix_ms DESC, invocation_id DESC
                 LIMIT 1",
                [lifecycle_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(invocation_id) = invocation_id else {
            return Ok(None);
        };
        let invocation_id = Digest::parse(&invocation_id)
            .map_err(|error| StoreError::LifecycleAdapterInvocationCorruption(error.to_string()))?;
        invocation_row(&connection, invocation_id)?.map(decode_invocation_record).transpose()
    }

    /// Explicitly abort one abandoned provider invocation and terminalize the
    /// exact lifecycle projection in the same transaction. This operation does
    /// not reclaim the invocation and never authorizes another provider call.
    pub fn abort_lifecycle_adapter_invocation(
        &self,
        change_id: &ChangeId,
        expected_state_digest: Digest,
        invocation_id: Digest,
        source: LifecycleAdapterRecoverySource,
    ) -> Result<LifecycleAdapterRecoveryResult, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = invocation_row(&transaction, invocation_id)?.ok_or_else(|| {
            StoreError::LifecycleAdapterInvocationConflict(format!(
                "{invocation_id}: invocation was not acquired"
            ))
        })?;
        let (request, state) = decode_invocation_row(row)?;
        if request.lifecycle.change_id != *change_id
            || request.expected_state_digest != expected_state_digest
            || request.invocation_id != invocation_id
        {
            return Err(StoreError::LifecycleAdapterInvocationConflict(format!(
                "{invocation_id}: recovery identity differs from the acquired invocation"
            )));
        }

        if let LifecycleAdapterInvocationState::Aborted { recovery, .. } = &state {
            if recovery.source != source {
                return Err(StoreError::LifecycleAdapterInvocationConflict(format!(
                    "{invocation_id}: recovery source differs from the immutable record"
                )));
            }
            let projection =
                super::lifecycles::lifecycle_projection_in_transaction(&transaction, change_id)?
                    .ok_or_else(|| StoreError::LifecycleNotFound(change_id.to_string()))?;
            let (expected, _) = request.lifecycle.transition(
                LifecycleTransition::Fail { reason: adapter_abort_reason()? },
                recovery.recovered_unix_ms,
            )?;
            if projection.lifecycle.status != LifecycleStatus::Failed
                || projection.lifecycle != expected
            {
                return Err(StoreError::LifecycleAdapterInvocationCorruption(format!(
                    "{invocation_id}: aborted invocation has no matching terminal lifecycle"
                )));
            }
            let result = LifecycleAdapterRecoveryResult {
                projection,
                recovery: recovery.as_ref().clone(),
                created: false,
            };
            transaction.commit()?;
            return Ok(result);
        }
        let LifecycleAdapterInvocationState::InProgress {
            request_digest,
            adapter_definition_digest,
            started_unix_ms,
        } = state
        else {
            return Err(StoreError::LifecycleAdapterInvocationConflict(format!(
                "{invocation_id}: only an in-progress invocation can be aborted"
            )));
        };

        let projection =
            super::lifecycles::lifecycle_projection_in_transaction(&transaction, change_id)?
                .ok_or_else(|| StoreError::LifecycleNotFound(change_id.to_string()))?;
        if projection.state_digest != expected_state_digest
            || projection.lifecycle != request.lifecycle
            || projection.lifecycle.id != request.lifecycle.id
            || projection.lifecycle.phase != request.phase
            || projection.lifecycle.status != LifecycleStatus::Active
        {
            return Err(StoreError::LifecycleAdapterInvocationConflict(format!(
                "{invocation_id}: lifecycle state changed before recovery"
            )));
        }

        let recovered_unix_ms = now_ms().max(started_unix_ms);
        let recovery = LifecycleAdapterRecoveryRecord::new(
            invocation_id,
            request.lifecycle.id,
            expected_state_digest,
            request_digest,
            adapter_definition_digest,
            source,
            recovered_unix_ms,
        );
        transaction.execute(
            "INSERT INTO lifecycle_adapter_recoveries(
                recovery_digest, invocation_id, lifecycle_id, expected_state_digest,
                request_digest, adapter_definition_digest, source, recovered_unix_ms
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                recovery.recovery_digest.to_string(),
                recovery.invocation_id.to_string(),
                recovery.lifecycle_id.to_string(),
                recovery.expected_state_digest.to_string(),
                recovery.request_digest.to_string(),
                recovery.adapter_definition_digest.to_string(),
                recovery.source.as_str(),
                recovery.recovered_unix_ms,
            ],
        )?;
        let projection = super::lifecycles::persist_transition(
            &transaction,
            &projection,
            expected_state_digest,
            LifecycleTransition::Fail { reason: adapter_abort_reason()? },
            recovered_unix_ms,
        )?;
        let result = LifecycleAdapterRecoveryResult { projection, recovery, created: true };
        transaction.commit()?;
        Ok(result)
    }
}

fn adapter_abort_reason() -> Result<LifecycleReason, StoreError> {
    LifecycleReason::new(ADAPTER_ABORT_REASON_CODE, ADAPTER_ABORT_REASON_DETAIL)
        .map_err(StoreError::from)
}

fn decode_invocation_record(
    row: InvocationRow,
) -> Result<LifecycleAdapterInvocationRecord, StoreError> {
    let (request, state) = decode_invocation_row(row)?;
    Ok(LifecycleAdapterInvocationRecord {
        invocation_id: request.invocation_id,
        lifecycle_id: request.lifecycle.id,
        expected_state_digest: request.expected_state_digest,
        phase: request.phase,
        state,
    })
}

fn encode_request(request: &LifecyclePhaseAdapterRequest) -> Result<(Digest, String), StoreError> {
    if !validate_lifecycle_phase_adapter_request(request) {
        return Err(StoreError::LifecycleAdapterInvocationValidation(
            "request is not canonical or execution-bound".to_owned(),
        ));
    }
    let encoded = serde_json::to_vec(request)?;
    if encoded.len() > MAX_LIFECYCLE_ADAPTER_REQUEST_BYTES {
        return Err(StoreError::LifecycleAdapterInvocationValidation(
            "request exceeds the byte bound".to_owned(),
        ));
    }
    let mut hasher = CanonicalHasher::new(b"needle-lifecycle-adapter-request-record");
    hasher.field_bytes(&encoded);
    let json = String::from_utf8(encoded).map_err(|_| {
        StoreError::LifecycleAdapterInvocationValidation("request JSON is not UTF-8".to_owned())
    })?;
    Ok((hasher.finish(), json))
}

fn encode_outcome(
    request: &LifecyclePhaseAdapterRequest,
    outcome: &LifecyclePhaseAdapterOutcome,
) -> Result<(Digest, String), StoreError> {
    if !validate_lifecycle_phase_adapter_outcome(request, outcome) {
        return Err(StoreError::LifecycleAdapterInvocationValidation(
            "outcome is not canonical or request-bound".to_owned(),
        ));
    }
    let encoded = serde_json::to_vec(outcome)?;
    if encoded.len() > MAX_LIFECYCLE_ADAPTER_OUTCOME_BYTES {
        return Err(StoreError::LifecycleAdapterInvocationValidation(
            "outcome exceeds the byte bound".to_owned(),
        ));
    }
    let mut hasher = CanonicalHasher::new(b"needle-lifecycle-adapter-outcome-record");
    hasher.field_bytes(&encoded);
    let json = String::from_utf8(encoded).map_err(|_| {
        StoreError::LifecycleAdapterInvocationValidation("outcome JSON is not UTF-8".to_owned())
    })?;
    Ok((hasher.finish(), json))
}

pub(super) fn invocation_row(
    connection: &Connection,
    invocation_id: Digest,
) -> Result<Option<InvocationRow>, StoreError> {
    connection
        .query_row(
            "SELECT i.invocation_id, i.lifecycle_id, i.expected_state_digest, i.phase,
                    i.request_digest, i.adapter_definition_digest, i.request_json,
                    i.started_unix_ms, o.outcome_digest, o.outcome_json, o.completed_unix_ms,
                    r.recovery_digest, r.lifecycle_id, r.expected_state_digest,
                    r.request_digest, r.adapter_definition_digest, r.source,
                    r.recovered_unix_ms
             FROM lifecycle_adapter_invocations i
             LEFT JOIN lifecycle_adapter_outcomes o ON o.invocation_id=i.invocation_id
             LEFT JOIN lifecycle_adapter_recoveries r ON r.invocation_id=i.invocation_id
             WHERE i.invocation_id=?1",
            [invocation_id.to_string()],
            |row| {
                Ok(InvocationRow {
                    invocation_id: row.get(0)?,
                    lifecycle_id: row.get(1)?,
                    expected_state_digest: row.get(2)?,
                    phase: row.get(3)?,
                    request_digest: row.get(4)?,
                    adapter_definition_digest: row.get(5)?,
                    request_json: row.get(6)?,
                    started_unix_ms: row.get(7)?,
                    outcome_digest: row.get(8)?,
                    outcome_json: row.get(9)?,
                    completed_unix_ms: row.get(10)?,
                    recovery_digest: row.get(11)?,
                    recovery_lifecycle_id: row.get(12)?,
                    recovery_expected_state_digest: row.get(13)?,
                    recovery_request_digest: row.get(14)?,
                    recovery_adapter_definition_digest: row.get(15)?,
                    recovery_source: row.get(16)?,
                    recovered_unix_ms: row.get(17)?,
                })
            },
        )
        .optional()
        .map_err(StoreError::from)
}

pub(super) fn decode_invocation_row(
    row: InvocationRow,
) -> Result<(LifecyclePhaseAdapterRequest, LifecycleAdapterInvocationState), StoreError> {
    let request: LifecyclePhaseAdapterRequest = serde_json::from_str(&row.request_json)
        .map_err(|error| StoreError::LifecycleAdapterInvocationCorruption(error.to_string()))?;
    let (canonical_request_digest, _) = encode_request(&request)
        .map_err(|error| StoreError::LifecycleAdapterInvocationCorruption(error.to_string()))?;
    let stored_adapter_definition_digest = Digest::parse(&row.adapter_definition_digest)
        .map_err(|error| StoreError::LifecycleAdapterInvocationCorruption(error.to_string()))?;
    if request.invocation_id.to_string() != row.invocation_id
        || request.lifecycle.id.to_string() != row.lifecycle_id
        || request.expected_state_digest.to_string() != row.expected_state_digest
        || request.phase.as_str() != row.phase
        || canonical_request_digest.to_string() != row.request_digest
    {
        return Err(StoreError::LifecycleAdapterInvocationCorruption(format!(
            "{}: columns differ from the canonical request",
            row.invocation_id
        )));
    }
    let request_digest = canonical_request_digest;
    match (
        row.outcome_digest,
        row.outcome_json,
        row.completed_unix_ms,
        row.recovery_digest,
        row.recovery_lifecycle_id,
        row.recovery_expected_state_digest,
        row.recovery_request_digest,
        row.recovery_adapter_definition_digest,
        row.recovery_source,
        row.recovered_unix_ms,
    ) {
        (None, None, None, None, None, None, None, None, None, None) => Ok((
            request,
            LifecycleAdapterInvocationState::InProgress {
                request_digest,
                adapter_definition_digest: stored_adapter_definition_digest,
                started_unix_ms: row.started_unix_ms,
            },
        )),
        (
            Some(outcome_digest),
            Some(outcome_json),
            Some(completed_unix_ms),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ) => {
            let outcome: LifecyclePhaseAdapterOutcome = serde_json::from_str(&outcome_json)
                .map_err(|error| {
                    StoreError::LifecycleAdapterInvocationCorruption(error.to_string())
                })?;
            let (canonical_outcome_digest, _) =
                encode_outcome(&request, &outcome).map_err(|error| {
                    StoreError::LifecycleAdapterInvocationCorruption(error.to_string())
                })?;
            if canonical_outcome_digest.to_string() != outcome_digest
                || completed_unix_ms < row.started_unix_ms
            {
                return Err(StoreError::LifecycleAdapterInvocationCorruption(format!(
                    "{}: outcome columns differ from the canonical record",
                    row.invocation_id
                )));
            }
            Ok((
                request,
                LifecycleAdapterInvocationState::Completed {
                    request_digest,
                    adapter_definition_digest: stored_adapter_definition_digest,
                    outcome: Box::new(outcome),
                    started_unix_ms: row.started_unix_ms,
                    completed_unix_ms,
                },
            ))
        }
        (
            None,
            None,
            None,
            Some(recovery_digest),
            Some(recovery_lifecycle_id),
            Some(recovery_expected_state_digest),
            Some(recovery_request_digest),
            Some(recovery_adapter_definition_digest),
            Some(recovery_source),
            Some(recovered_unix_ms),
        ) => {
            let recovery = LifecycleAdapterRecoveryRecord {
                recovery_digest: parse_recovery_digest(&recovery_digest, &row.invocation_id)?,
                invocation_id: request.invocation_id,
                lifecycle_id: LifecycleId(parse_recovery_digest(
                    &recovery_lifecycle_id,
                    &row.invocation_id,
                )?),
                expected_state_digest: parse_recovery_digest(
                    &recovery_expected_state_digest,
                    &row.invocation_id,
                )?,
                request_digest: parse_recovery_digest(
                    &recovery_request_digest,
                    &row.invocation_id,
                )?,
                adapter_definition_digest: parse_recovery_digest(
                    &recovery_adapter_definition_digest,
                    &row.invocation_id,
                )?,
                source: LifecycleAdapterRecoverySource::parse(&recovery_source)?,
                recovered_unix_ms,
            };
            recovery.validate()?;
            if recovery.lifecycle_id != request.lifecycle.id
                || recovery.expected_state_digest != request.expected_state_digest
                || recovery.request_digest != request_digest
                || recovery.adapter_definition_digest != stored_adapter_definition_digest
                || recovered_unix_ms < row.started_unix_ms
            {
                return Err(StoreError::LifecycleAdapterInvocationCorruption(format!(
                    "{}: recovery columns differ from the canonical record",
                    row.invocation_id
                )));
            }
            Ok((
                request,
                LifecycleAdapterInvocationState::Aborted {
                    request_digest,
                    adapter_definition_digest: stored_adapter_definition_digest,
                    recovery: Box::new(recovery),
                    started_unix_ms: row.started_unix_ms,
                },
            ))
        }
        _ => Err(StoreError::LifecycleAdapterInvocationCorruption(format!(
            "{}: partial or conflicting terminal record",
            row.invocation_id
        ))),
    }
}

fn parse_recovery_digest(value: &str, invocation_id: &str) -> Result<Digest, StoreError> {
    Digest::parse(value).map_err(|error| {
        StoreError::LifecycleAdapterInvocationCorruption(format!(
            "{invocation_id}: invalid recovery digest: {error}"
        ))
    })
}
