use super::{RuntimeStore, StoreError, now_ms};
use crate::action_capabilities::authority_capability_for_id;
use crate::{
    LifecycleAdapterInvocationState, LifecycleAdapterResult, built_in_action_for_artifact_kind,
};
use needle_core::{
    ActionAssuranceEvidence, ActionAssuranceEvidenceId, ActionAssuranceEvidenceInput,
    ActionAssuranceEvidenceKind, ActionCapabilityClass, ActionCapabilityDecision,
    ActionCapabilityDecisionId, ActionRequest, Artifact, ArtifactId, ArtifactRequestId,
    ArtifactValidationCertificate, ArtifactValidationCertificateId, CapabilityMode, Digest,
    LifecycleId, LifecyclePhase, LifecycleTransition,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderBackedActionAssuranceInput {
    pub repository: Digest,
    pub source_snapshot: Digest,
    pub lifecycle: LifecycleId,
    pub adapter_invocation: Digest,
    pub artifact: ArtifactId,
    pub execution_evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionAssurancePreflight {
    pub source_schema_version: u64,
    pub evidence: ActionAssuranceEvidence,
    pub effective_decision: Option<ActionCapabilityDecisionRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionAssuranceEvidenceRecord {
    pub evidence: ActionAssuranceEvidence,
    pub recorded_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionCapabilityDecisionRecord {
    pub decision: ActionCapabilityDecision,
    pub evidence: ActionAssuranceEvidence,
    pub recorded_unix_ms: u64,
}

struct EvidenceRow {
    evidence_id: String,
    capability_class_id: String,
    capability_definition_digest: String,
    evidence_definition_digest: String,
    action_request_id: String,
    artifact_id: String,
    validation_certificate_id: String,
    repository_lineage: String,
    source_snapshot: String,
    lifecycle_id: String,
    adapter_invocation_id: String,
    evidence_kind: String,
    execution_evidence_digest: String,
    observed_unix_ms: u64,
    evidence_json: String,
    recorded_unix_ms: u64,
}

struct DecisionRow {
    decision_id: String,
    capability_class_id: String,
    capability_definition_digest: String,
    evidence_id: String,
    evidence_definition_digest: String,
    previous_decision_id: Option<String>,
    selected_mode: String,
    automatic_resolver_consumption_approved: bool,
    automatic_lifecycle_consumption_approved: bool,
    decision_json: String,
    decided_unix_ms: u64,
    recorded_unix_ms: u64,
}

impl RuntimeStore {
    fn validate_provider_backed_action_assurance(
        connection: &Connection,
        evidence: &ActionAssuranceEvidence,
        current_capability: &ActionCapabilityClass,
    ) -> Result<(), StoreError> {
        let invocation_row = super::lifecycle_adapter_invocations::invocation_row(
            connection,
            evidence.adapter_invocation,
        )?
        .ok_or_else(|| {
            validation_message("provider-backed evidence has no durable adapter invocation")
        })?;
        let (invocation_request, invocation_state) =
            super::lifecycle_adapter_invocations::decode_invocation_row(invocation_row)?;
        let LifecycleAdapterInvocationState::Completed { outcome, completed_unix_ms, .. } =
            invocation_state
        else {
            return Err(validation_message("provider-backed evidence invocation is not completed"));
        };
        if invocation_request.lifecycle.id != evidence.lifecycle
            || invocation_request.phase != LifecyclePhase::Explore
            || invocation_request.change.repository_id != evidence.repository
            || invocation_request.change.source_snapshot != evidence.source_snapshot
            || completed_unix_ms > evidence.observed_unix_ms
        {
            return Err(validation_message(
                "provider-backed invocation does not bind the evidence lifecycle, source, repository, or time",
            ));
        }

        let lifecycle: Option<(String, String, String)> = connection
            .query_row(
                "SELECT l.source_snapshot_digest, c.repository_id, l.state_json
                 FROM change_lifecycles l
                 JOIN change_requests c ON c.change_id=l.change_id
                 WHERE l.lifecycle_id=?1",
                [evidence.lifecycle.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((source_snapshot, repository, lifecycle_json)) = lifecycle else {
            return Err(validation_message("provider-backed evidence has no durable lifecycle"));
        };
        if source_snapshot != evidence.source_snapshot.to_string()
            || repository != evidence.repository.to_string()
        {
            return Err(validation_message(
                "provider-backed lifecycle does not bind the evidence source or repository",
            ));
        }
        let lifecycle: needle_core::DevelopmentLifecycle = serde_json::from_str(&lifecycle_json)
            .map_err(|error| corruption(format!("stored assurance lifecycle: {error}")))?;
        lifecycle
            .validate()
            .map_err(|error| corruption(format!("stored assurance lifecycle: {error}")))?;
        let action_plan = lifecycle.spec.explore_action_plan.as_ref().ok_or_else(|| {
            validation_message("provider-backed assurance lifecycle has no Explore action plan")
        })?;
        if action_plan.actions.len() != 1
            || action_plan.actions[0].semantic_id() != evidence.action_request
        {
            return Err(validation_message(
                "provider-backed assurance is limited to one exact planned action",
            ));
        }

        let material: Option<(String, String, String, u16, u64, u64)> = connection
            .query_row(
                "SELECT r.request_json, a.artifact_json, c.certificate_json,
                        r.format_revision, a.created_unix_ms, c.issued_unix_ms
                 FROM artifact_requests r
                 JOIN artifacts a ON a.request_id=r.request_id
                 JOIN artifact_validation_certificates c ON c.artifact_id=a.artifact_id
                 WHERE r.request_id=?1 AND a.artifact_id=?2 AND c.certificate_id=?3",
                params![
                    evidence.action_request.to_string(),
                    evidence.artifact.to_string(),
                    evidence.validation_certificate.to_string(),
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((request_json, artifact_json, certificate_json, format_revision, created, issued)) =
            material
        else {
            return Err(validation_message(
                "action assurance material is not persisted as one certified action artifact",
            ));
        };
        if format_revision != super::ACTION_REQUEST_STORAGE_FORMAT_REVISION
            || created > evidence.observed_unix_ms
            || issued > evidence.observed_unix_ms
        {
            return Err(validation_message(
                "action assurance material has an invalid storage revision or observation time",
            ));
        }
        let request: ActionRequest = serde_json::from_str(&request_json)
            .map_err(|error| corruption(format!("stored assurance request: {error}")))?;
        let artifact: Artifact = serde_json::from_str(&artifact_json)
            .map_err(|error| corruption(format!("stored assurance artifact: {error}")))?;
        let certificate: ArtifactValidationCertificate = serde_json::from_str(&certificate_json)
            .map_err(|error| corruption(format!("stored assurance certificate: {error}")))?;
        let action =
            built_in_action_for_artifact_kind(&artifact.contract.kind).ok_or_else(|| {
                validation_message("assurance artifact kind has no built-in action definition")
            })?;
        request
            .validate(&action.contract)
            .map_err(|error| validation_message(error.to_string()))?;
        let descriptor =
            crate::reuse_descriptor::derive_shadow_reuse_descriptor_from_validated_pair(
                &artifact,
                &certificate,
            )
            .map_err(|error| validation_message(error.to_string()))?;
        if request.contract != current_capability.action_contract
            || action.contract.id != current_capability.action_contract
            || request.semantic_id() != evidence.action_request
            || descriptor.exact_request != evidence.action_request
            || descriptor.artifact != evidence.artifact
            || descriptor.validation_certificate != evidence.validation_certificate
            || request.artifact_request.repository_id != evidence.repository
            || request.artifact_request.source_snapshot_digest != evidence.source_snapshot
        {
            return Err(validation_message(
                "action assurance material does not bind the exact current action request",
            ));
        }

        let LifecycleAdapterResult::Completed { transition } = &outcome.result else {
            return Err(validation_message(
                "provider-backed evidence invocation did not complete Explore",
            ));
        };
        let LifecycleTransition::CompleteExplore { artifacts, .. } = transition.as_ref() else {
            return Err(validation_message(
                "provider-backed evidence invocation completed a different lifecycle phase",
            ));
        };
        if artifacts.len() != 1 || artifacts[0].id != evidence.artifact.digest() {
            return Err(validation_message(
                "provider-backed Explore completion is not the one assured artifact",
            ));
        }
        Ok(())
    }

    /// Reconstruct and validate the exact provider-backed evidence candidate
    /// without initializing, migrating, or mutating the source database.
    pub fn preflight_provider_backed_action_assurance(
        &self,
        input: ProviderBackedActionAssuranceInput,
    ) -> Result<ActionAssurancePreflight, StoreError> {
        let current_capability = crate::implementation_location_exact_capability();
        let connection = self.action_assurance_read_only_connection()?;
        let source_schema_version = validate_action_assurance_schema(&connection)?;

        let mut statement = connection.prepare(
            "SELECT a.request_id, c.certificate_id, a.created_unix_ms, c.issued_unix_ms
             FROM artifacts a
             JOIN artifact_validation_certificates c ON c.artifact_id=a.artifact_id
             WHERE a.artifact_id=?1
             ORDER BY c.certificate_id
             LIMIT 2",
        )?;
        let rows = statement.query_map([input.artifact.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u64>(2)?,
                row.get::<_, u64>(3)?,
            ))
        })?;
        let material = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if material.len() != 1 {
            return Err(validation_message(
                "authority preflight requires exactly one validation certificate for the assured artifact",
            ));
        }
        let (request_id, certificate_id, artifact_created_unix_ms, certificate_issued_unix_ms) =
            &material[0];
        let request_id = Digest::parse(request_id)
            .map(ArtifactRequestId::new)
            .map_err(|_| corruption("assurance artifact request id is invalid"))?;
        let certificate_id = Digest::parse(certificate_id)
            .map(ArtifactValidationCertificateId::new)
            .map_err(|_| corruption("assurance validation certificate id is invalid"))?;

        let invocation_row = super::lifecycle_adapter_invocations::invocation_row(
            &connection,
            input.adapter_invocation,
        )?
        .ok_or_else(|| validation_message("authority preflight invocation is unavailable"))?;
        let (_, invocation_state) =
            super::lifecycle_adapter_invocations::decode_invocation_row(invocation_row)?;
        let LifecycleAdapterInvocationState::Completed { completed_unix_ms, .. } = invocation_state
        else {
            return Err(validation_message("authority preflight invocation is not completed"));
        };
        let observed_unix_ms =
            completed_unix_ms.max(*artifact_created_unix_ms).max(*certificate_issued_unix_ms);
        let evidence = ActionAssuranceEvidence::new(ActionAssuranceEvidenceInput {
            capability_class: current_capability.id,
            capability_definition_digest: current_capability.definition_digest,
            action_request: request_id,
            artifact: input.artifact,
            validation_certificate: certificate_id,
            repository: input.repository,
            source_snapshot: input.source_snapshot,
            lifecycle: input.lifecycle,
            adapter_invocation: input.adapter_invocation,
            evidence_kind: ActionAssuranceEvidenceKind::ProviderBackedFresh,
            execution_evidence_digest: input.execution_evidence_digest,
            observed_unix_ms,
        })
        .map_err(validation)?;
        evidence.validate_for(current_capability).map_err(validation)?;
        Self::validate_provider_backed_action_assurance(
            &connection,
            &evidence,
            current_capability,
        )?;
        let effective_decision = if source_schema_version >= 32 {
            read_effective_decision(&connection, current_capability)?
        } else {
            None
        };
        Ok(ActionAssurancePreflight { source_schema_version, evidence, effective_decision })
    }

    fn action_assurance_read_only_connection(&self) -> Result<Connection, StoreError> {
        let wal_path = sqlite_sidecar_path(&self.path, "-wal");
        if fs::metadata(&wal_path).is_ok_and(|metadata| metadata.len() != 0) {
            return Err(validation_message(
                "authority preflight requires a quiescent database with no pending WAL content",
            ));
        }
        let immutable_uri = sqlite_immutable_uri(&self.path)?;
        let connection = Connection::open_with_flags(
            immutable_uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_URI,
        )?;
        connection.execute_batch(
            "PRAGMA query_only=ON;
             PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;
             PRAGMA busy_timeout=5000;",
        )?;
        Ok(connection)
    }

    pub fn record_action_assurance_evidence(
        &self,
        evidence: &ActionAssuranceEvidence,
    ) -> Result<(), StoreError> {
        let current_capability = registered_capability(evidence.capability_class)?;
        evidence.validate_for(current_capability).map_err(validation)?;
        let connection = self.connection()?;
        Self::validate_provider_backed_action_assurance(&connection, evidence, current_capability)?;
        drop(connection);
        self.record_validated_action_assurance_evidence(evidence, current_capability)
    }

    fn record_validated_action_assurance_evidence(
        &self,
        evidence: &ActionAssuranceEvidence,
        current_capability: &ActionCapabilityClass,
    ) -> Result<(), StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_evidence_recorded(&transaction, evidence, current_capability)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn action_assurance_evidence(
        &self,
        id: ActionAssuranceEvidenceId,
    ) -> Result<Option<ActionAssuranceEvidenceRecord>, StoreError> {
        let connection = self.connection()?;
        read_registered_evidence(&connection, id)
    }

    pub fn record_action_capability_decision(
        &self,
        decision: &ActionCapabilityDecision,
        evidence: &ActionAssuranceEvidence,
    ) -> Result<(), StoreError> {
        let current_capability = registered_capability(decision.capability_class)?;
        decision.validate_for(current_capability, evidence).map_err(validation)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored_evidence = read_evidence(&transaction, evidence.id, current_capability)?
            .ok_or_else(|| conflict("decision evidence has not been recorded"))?;
        if stored_evidence.evidence != *evidence {
            return Err(conflict("decision evidence differs from the stored record"));
        }
        ensure_decision_recorded(
            &transaction,
            decision,
            current_capability,
            &stored_evidence.evidence,
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically accept one already-rendered evidence/decision pair after
    /// revalidating the complete provider-backed material under the write lock.
    pub fn accept_action_capability_decision(
        &self,
        evidence: &ActionAssuranceEvidence,
        decision: &ActionCapabilityDecision,
    ) -> Result<ActionCapabilityDecisionRecord, StoreError> {
        let current_capability = registered_capability(decision.capability_class)?;
        decision.validate_for(current_capability, evidence).map_err(validation)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::validate_provider_backed_action_assurance(
            &transaction,
            evidence,
            current_capability,
        )?;
        let stored_evidence = ensure_evidence_recorded(&transaction, evidence, current_capability)?;
        let stored_decision = ensure_decision_recorded(
            &transaction,
            decision,
            current_capability,
            &stored_evidence.evidence,
        )?;
        let effective =
            read_effective_decision(&transaction, current_capability)?.ok_or_else(|| {
                corruption("accepted action capability decision has no effective head")
            })?;
        if effective.decision != stored_decision.decision {
            return Err(conflict(
                "accepted action capability decision is not the effective capability head",
            ));
        }
        transaction.commit()?;
        Ok(stored_decision)
    }

    pub fn effective_action_capability_decision(
        &self,
        capability: needle_core::ActionCapabilityClassId,
    ) -> Result<Option<ActionCapabilityDecisionRecord>, StoreError> {
        let current_capability = registered_capability(capability)?;
        let connection = self.connection()?;
        read_effective_decision(&connection, current_capability)
    }
}

fn ensure_evidence_recorded(
    transaction: &rusqlite::Transaction<'_>,
    evidence: &ActionAssuranceEvidence,
    current_capability: &ActionCapabilityClass,
) -> Result<ActionAssuranceEvidenceRecord, StoreError> {
    if let Some(existing) = read_evidence(transaction, evidence.id, current_capability)? {
        if existing.evidence == *evidence {
            return Ok(existing);
        }
        return Err(conflict("evidence id already binds different canonical content"));
    }
    let evidence_json = serde_json::to_string(evidence)?;
    let recorded_unix_ms = now_ms();
    transaction.execute(
        "INSERT INTO action_assurance_records(
            evidence_id, capability_class_id, capability_definition_digest,
            evidence_definition_digest,
            action_request_id, artifact_id, validation_certificate_id,
            repository_lineage, source_snapshot, lifecycle_id,
            adapter_invocation_id, evidence_kind,
            execution_evidence_digest, observed_unix_ms, evidence_json, recorded_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            evidence.id.to_string(),
            evidence.capability_class.to_string(),
            evidence.capability_definition_digest.to_string(),
            evidence.definition_digest.to_string(),
            evidence.action_request.to_string(),
            evidence.artifact.to_string(),
            evidence.validation_certificate.to_string(),
            evidence.repository.to_string(),
            evidence.source_snapshot.to_string(),
            evidence.lifecycle.to_string(),
            evidence.adapter_invocation.to_string(),
            evidence_kind_name(evidence.evidence_kind),
            evidence.execution_evidence_digest.to_string(),
            evidence.observed_unix_ms,
            evidence_json,
            recorded_unix_ms,
        ],
    )?;
    Ok(ActionAssuranceEvidenceRecord { evidence: evidence.clone(), recorded_unix_ms })
}

fn ensure_decision_recorded(
    transaction: &rusqlite::Transaction<'_>,
    decision: &ActionCapabilityDecision,
    current_capability: &ActionCapabilityClass,
    evidence: &ActionAssuranceEvidence,
) -> Result<ActionCapabilityDecisionRecord, StoreError> {
    if let Some(existing) = read_decision(transaction, decision.id, current_capability, evidence)? {
        if existing.decision == *decision {
            let latest = read_effective_decision(transaction, current_capability)?;
            if latest.as_ref().map(|record| record.decision.id) == Some(decision.id) {
                return Ok(existing);
            }
            return Err(conflict("existing decision is no longer the effective capability head"));
        }
        return Err(conflict("decision id already binds different canonical content"));
    }
    let latest = read_effective_decision(transaction, current_capability)?;
    if decision.previous_decision != latest.as_ref().map(|record| record.decision.id) {
        return Err(conflict("decision does not extend the current capability head"));
    }
    if latest
        .as_ref()
        .is_some_and(|record| decision.decided_unix_ms <= record.decision.decided_unix_ms)
    {
        return Err(conflict("decision time must advance monotonically"));
    }
    let decision_json = serde_json::to_string(decision)?;
    let recorded_unix_ms = now_ms();
    transaction.execute(
        "INSERT INTO action_capability_decisions(
            decision_id, capability_class_id, capability_definition_digest,
            evidence_id, evidence_definition_digest, previous_decision_id,
            selected_mode, automatic_resolver_consumption_approved,
            automatic_lifecycle_consumption_approved, decision_json,
            decided_unix_ms, recorded_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            decision.id.to_string(),
            decision.capability_class.to_string(),
            decision.capability_definition_digest.to_string(),
            decision.evidence.to_string(),
            decision.evidence_definition_digest.to_string(),
            decision.previous_decision.map(|id| id.to_string()),
            capability_mode_name(decision.selected_mode),
            decision.automatic_resolver_consumption_approved,
            decision.automatic_lifecycle_consumption_approved,
            decision_json,
            decision.decided_unix_ms,
            recorded_unix_ms,
        ],
    )?;
    Ok(ActionCapabilityDecisionRecord {
        decision: decision.clone(),
        evidence: evidence.clone(),
        recorded_unix_ms,
    })
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(suffix);
    PathBuf::from(value)
}

fn sqlite_immutable_uri(path: &Path) -> Result<String, StoreError> {
    let canonical = fs::canonicalize(path)?;
    let canonical = canonical
        .to_str()
        .ok_or_else(|| validation_message("authority preflight database path is not UTF-8"))?;
    #[cfg(windows)]
    let canonical = if let Some(value) = canonical.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{value}")
    } else {
        canonical.strip_prefix(r"\\?\").unwrap_or(canonical).to_owned()
    };
    #[cfg(not(windows))]
    let canonical = canonical.to_owned();
    let normalized = canonical.replace('\\', "/");
    let mut encoded = String::with_capacity(normalized.len().saturating_add(24));
    for byte in normalized.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/' | b':') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(&mut encoded, "%{byte:02X}")
                .map_err(|_| validation_message("authority preflight database URI is invalid"))?;
        }
    }
    let prefix = if encoded.starts_with('/') { "file:" } else { "file:/" };
    Ok(format!("{prefix}{encoded}?immutable=1"))
}

fn read_registered_evidence(
    connection: &Connection,
    id: ActionAssuranceEvidenceId,
) -> Result<Option<ActionAssuranceEvidenceRecord>, StoreError> {
    let row = read_evidence_row(connection, id)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let capability = registered_capability(parse_capability_id(&row.capability_class_id)?)?;
    decode_evidence_row(row, capability).map(Some)
}

fn read_evidence(
    connection: &Connection,
    id: ActionAssuranceEvidenceId,
    current_capability: &ActionCapabilityClass,
) -> Result<Option<ActionAssuranceEvidenceRecord>, StoreError> {
    read_evidence_row(connection, id)?
        .map(|row| decode_evidence_row(row, current_capability))
        .transpose()
}

fn read_evidence_row(
    connection: &Connection,
    id: ActionAssuranceEvidenceId,
) -> Result<Option<EvidenceRow>, StoreError> {
    connection
        .query_row(
            "SELECT evidence_id, capability_class_id, capability_definition_digest,
                    evidence_definition_digest,
                    action_request_id, artifact_id, validation_certificate_id,
                    repository_lineage, source_snapshot, lifecycle_id,
                    adapter_invocation_id, evidence_kind,
                    execution_evidence_digest, observed_unix_ms, evidence_json,
                    recorded_unix_ms
             FROM action_assurance_records WHERE evidence_id=?1",
            [id.to_string()],
            map_evidence_row,
        )
        .optional()
        .map_err(StoreError::from)
}

pub(super) fn read_effective_decision(
    connection: &Connection,
    current_capability: &ActionCapabilityClass,
) -> Result<Option<ActionCapabilityDecisionRecord>, StoreError> {
    let row = connection
        .query_row(
            "SELECT decision_id, capability_class_id, capability_definition_digest,
                    evidence_id, evidence_definition_digest, previous_decision_id,
                    selected_mode, automatic_resolver_consumption_approved,
                    automatic_lifecycle_consumption_approved, decision_json,
                    decided_unix_ms, recorded_unix_ms
             FROM action_capability_decisions
             WHERE capability_class_id=?1
             ORDER BY decided_unix_ms DESC, decision_id DESC
             LIMIT 1",
            [current_capability.id.to_string()],
            map_decision_row,
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let evidence_id = parse_evidence_id(&row.evidence_id)?;
    let evidence = read_evidence(connection, evidence_id, current_capability)?
        .ok_or_else(|| corruption("decision references missing evidence"))?;
    decode_decision_row(row, current_capability, evidence.evidence).map(Some)
}

fn read_decision(
    connection: &Connection,
    id: ActionCapabilityDecisionId,
    current_capability: &ActionCapabilityClass,
    evidence: &ActionAssuranceEvidence,
) -> Result<Option<ActionCapabilityDecisionRecord>, StoreError> {
    connection
        .query_row(
            "SELECT decision_id, capability_class_id, capability_definition_digest,
                    evidence_id, evidence_definition_digest, previous_decision_id,
                    selected_mode, automatic_resolver_consumption_approved,
                    automatic_lifecycle_consumption_approved, decision_json,
                    decided_unix_ms, recorded_unix_ms
             FROM action_capability_decisions WHERE decision_id=?1",
            [id.to_string()],
            map_decision_row,
        )
        .optional()?
        .map(|row| decode_decision_row(row, current_capability, evidence.clone()))
        .transpose()
}

fn map_evidence_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EvidenceRow> {
    Ok(EvidenceRow {
        evidence_id: row.get(0)?,
        capability_class_id: row.get(1)?,
        capability_definition_digest: row.get(2)?,
        evidence_definition_digest: row.get(3)?,
        action_request_id: row.get(4)?,
        artifact_id: row.get(5)?,
        validation_certificate_id: row.get(6)?,
        repository_lineage: row.get(7)?,
        source_snapshot: row.get(8)?,
        lifecycle_id: row.get(9)?,
        adapter_invocation_id: row.get(10)?,
        evidence_kind: row.get(11)?,
        execution_evidence_digest: row.get(12)?,
        observed_unix_ms: row.get(13)?,
        evidence_json: row.get(14)?,
        recorded_unix_ms: row.get(15)?,
    })
}

fn map_decision_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DecisionRow> {
    Ok(DecisionRow {
        decision_id: row.get(0)?,
        capability_class_id: row.get(1)?,
        capability_definition_digest: row.get(2)?,
        evidence_id: row.get(3)?,
        evidence_definition_digest: row.get(4)?,
        previous_decision_id: row.get(5)?,
        selected_mode: row.get(6)?,
        automatic_resolver_consumption_approved: row.get(7)?,
        automatic_lifecycle_consumption_approved: row.get(8)?,
        decision_json: row.get(9)?,
        decided_unix_ms: row.get(10)?,
        recorded_unix_ms: row.get(11)?,
    })
}

fn decode_evidence_row(
    row: EvidenceRow,
    current_capability: &ActionCapabilityClass,
) -> Result<ActionAssuranceEvidenceRecord, StoreError> {
    let evidence = ActionAssuranceEvidence::decode_json(row.evidence_json.as_bytes())
        .map_err(|error| corruption(error.to_string()))?;
    evidence.validate_for(current_capability).map_err(|error| corruption(error.to_string()))?;
    if evidence.id.to_string() != row.evidence_id
        || evidence.capability_class.to_string() != row.capability_class_id
        || evidence.capability_definition_digest.to_string() != row.capability_definition_digest
        || evidence.definition_digest.to_string() != row.evidence_definition_digest
        || evidence.action_request.to_string() != row.action_request_id
        || evidence.artifact.to_string() != row.artifact_id
        || evidence.validation_certificate.to_string() != row.validation_certificate_id
        || evidence.repository.to_string() != row.repository_lineage
        || evidence.source_snapshot.to_string() != row.source_snapshot
        || evidence.lifecycle.to_string() != row.lifecycle_id
        || evidence.adapter_invocation.to_string() != row.adapter_invocation_id
        || evidence_kind_name(evidence.evidence_kind) != row.evidence_kind
        || evidence.execution_evidence_digest.to_string() != row.execution_evidence_digest
        || evidence.observed_unix_ms != row.observed_unix_ms
    {
        return Err(corruption("action assurance columns differ from canonical evidence"));
    }
    Ok(ActionAssuranceEvidenceRecord { evidence, recorded_unix_ms: row.recorded_unix_ms })
}

fn decode_decision_row(
    row: DecisionRow,
    current_capability: &ActionCapabilityClass,
    evidence: ActionAssuranceEvidence,
) -> Result<ActionCapabilityDecisionRecord, StoreError> {
    let decision = ActionCapabilityDecision::decode_json(row.decision_json.as_bytes())
        .map_err(|error| corruption(error.to_string()))?;
    decision
        .validate_for(current_capability, &evidence)
        .map_err(|error| corruption(error.to_string()))?;
    if decision.id.to_string() != row.decision_id
        || decision.capability_class.to_string() != row.capability_class_id
        || decision.capability_definition_digest.to_string() != row.capability_definition_digest
        || decision.evidence.to_string() != row.evidence_id
        || decision.evidence_definition_digest.to_string() != row.evidence_definition_digest
        || decision.previous_decision.map(|id| id.to_string()) != row.previous_decision_id
        || capability_mode_name(decision.selected_mode) != row.selected_mode
        || decision.automatic_resolver_consumption_approved
            != row.automatic_resolver_consumption_approved
        || decision.automatic_lifecycle_consumption_approved
            != row.automatic_lifecycle_consumption_approved
        || decision.decided_unix_ms != row.decided_unix_ms
    {
        return Err(corruption("action capability columns differ from canonical decision"));
    }
    Ok(ActionCapabilityDecisionRecord {
        decision,
        evidence,
        recorded_unix_ms: row.recorded_unix_ms,
    })
}

fn parse_evidence_id(value: &str) -> Result<ActionAssuranceEvidenceId, StoreError> {
    Digest::parse(value)
        .map(ActionAssuranceEvidenceId::new)
        .map_err(|_| corruption("stored action assurance evidence id is invalid"))
}

fn parse_capability_id(value: &str) -> Result<needle_core::ActionCapabilityClassId, StoreError> {
    Digest::parse(value)
        .map(needle_core::ActionCapabilityClassId::new)
        .map_err(|_| corruption("stored action capability class id is invalid"))
}

fn validate_action_assurance_schema(connection: &Connection) -> Result<u64, StoreError> {
    let migrations = [
        super::MIGRATION_V1,
        super::MIGRATION_V2,
        super::MIGRATION_V3,
        super::MIGRATION_V4,
        super::MIGRATION_V5,
        super::MIGRATION_V6,
        super::MIGRATION_V7,
        super::MIGRATION_V8,
        super::MIGRATION_V9,
        super::MIGRATION_V10,
        super::MIGRATION_V11,
        super::MIGRATION_V12,
        super::MIGRATION_V13,
        super::MIGRATION_V14,
        super::MIGRATION_V15,
        super::MIGRATION_V16,
        super::MIGRATION_V17,
        super::MIGRATION_V18,
        super::MIGRATION_V19,
        super::MIGRATION_V20,
        super::MIGRATION_V21,
        super::MIGRATION_V22,
        super::MIGRATION_V23,
        super::MIGRATION_V24,
        super::MIGRATION_V25,
        super::MIGRATION_V26,
        super::MIGRATION_V27,
        super::MIGRATION_V28,
        super::MIGRATION_V29,
        super::MIGRATION_V30,
        super::MIGRATION_V31,
        super::MIGRATION_V32,
        super::MIGRATION_V33,
        super::MIGRATION_V34,
        super::MIGRATION_V35,
        super::MIGRATION_V36,
        super::MIGRATION_V37,
    ];
    let latest: Option<u64> =
        connection.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| row.get(0))?;
    let latest = latest
        .ok_or_else(|| validation_message("authority preflight database has no schema version"))?;
    if !(31..=37).contains(&latest) {
        return Err(validation_message(
            "authority preflight requires a checksummed schema version from 31 through 37",
        ));
    }
    let mut statement = connection
        .prepare("SELECT version, checksum FROM schema_migrations ORDER BY version ASC")?;
    let rows =
        statement.query_map([], |row| Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?)))?;
    let stored = rows.collect::<Result<Vec<_>, _>>()?;
    let expected_len = usize::try_from(latest)
        .map_err(|_| validation_message("authority preflight schema version is out of bounds"))?;
    if stored.len() != expected_len
        || stored.iter().zip(migrations.iter().take(expected_len)).enumerate().any(
            |(index, ((version, checksum), migration))| {
                *version != (index as u64).saturating_add(1)
                    || checksum != &Digest::blake3(*migration).to_string()
            },
        )
    {
        return Err(StoreError::MigrationChecksum);
    }
    Ok(latest)
}

fn registered_capability(
    id: needle_core::ActionCapabilityClassId,
) -> Result<&'static ActionCapabilityClass, StoreError> {
    authority_capability_for_id(id)
        .ok_or_else(|| validation_message("action capability is not registered for authority"))
}

const fn evidence_kind_name(value: ActionAssuranceEvidenceKind) -> &'static str {
    match value {
        ActionAssuranceEvidenceKind::ProviderBackedFresh => "provider_backed_fresh",
    }
}

const fn capability_mode_name(value: CapabilityMode) -> &'static str {
    match value {
        CapabilityMode::Disabled => "disabled",
        CapabilityMode::Shadow => "shadow",
        CapabilityMode::Advisory => "advisory",
        CapabilityMode::Authoritative => "authoritative",
    }
}

fn validation(error: needle_core::ActionAssuranceError) -> StoreError {
    StoreError::ActionAssuranceValidation(error.to_string())
}

fn validation_message(message: impl Into<String>) -> StoreError {
    StoreError::ActionAssuranceValidation(message.into())
}

fn conflict(message: impl Into<String>) -> StoreError {
    StoreError::ActionAssuranceConflict(message.into())
}

fn corruption(message: impl Into<String>) -> StoreError {
    StoreError::ActionAssuranceCorruption(message.into())
}

#[cfg(test)]
#[path = "action_assurance/tests.rs"]
mod tests;
