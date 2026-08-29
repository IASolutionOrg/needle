use super::{RuntimeStore, StoreError, now_ms, parse_digest};
use needle_core::{
    ArtifactId, ArtifactRequestId, ArtifactValidationCertificateId, Digest, LifecycleUsage,
    PartitionManifestId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ActionExecutionOperationClaim {
    Execute {
        resumed: bool,
    },
    Completed {
        artifact: ArtifactId,
        validation_certificate: ArtifactValidationCertificateId,
        partition_manifest: Option<PartitionManifestId>,
        usage: LifecycleUsage,
    },
}

impl RuntimeStore {
    pub(crate) fn claim_action_execution_operation(
        &self,
        operation_id: Digest,
        request: ArtifactRequestId,
    ) -> Result<ActionExecutionOperationClaim, StoreError> {
        self.initialize()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT action_request_id, state, artifact_id,
                        validation_certificate_id, partition_manifest_id, usage_json
                 FROM action_execution_operations WHERE operation_id=?1",
                [operation_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()?;
        let claim = match existing {
            None => {
                transaction.execute(
                    "INSERT INTO action_execution_operations(
                        operation_id, action_request_id, state, started_unix_ms
                     ) VALUES(?1, ?2, 'running', ?3)",
                    params![operation_id.to_string(), request.to_string(), sql_time(now_ms())?],
                )?;
                ActionExecutionOperationClaim::Execute { resumed: false }
            }
            Some((stored_request, state, artifact, certificate, manifest, usage)) => {
                if stored_request != request.to_string() {
                    return Err(conflict(
                        "operation id was already claimed by a different action request",
                    ));
                }
                if state == "running" {
                    ActionExecutionOperationClaim::Execute { resumed: true }
                } else if state == "completed" {
                    let artifact =
                        artifact.ok_or_else(|| conflict("completed operation has no artifact"))?;
                    let certificate = certificate
                        .ok_or_else(|| conflict("completed operation has no certificate"))?;
                    ActionExecutionOperationClaim::Completed {
                        artifact: ArtifactId::new(parse_digest(&artifact)?),
                        validation_certificate: ArtifactValidationCertificateId::new(parse_digest(
                            &certificate,
                        )?),
                        partition_manifest: manifest
                            .map(|value| parse_digest(&value).map(PartitionManifestId::new))
                            .transpose()?,
                        usage: usage
                            .map(|value| serde_json::from_str(&value))
                            .transpose()?
                            .unwrap_or_default(),
                    }
                } else {
                    return Err(conflict("operation has an unsupported state"));
                }
            }
        };
        transaction.commit()?;
        Ok(claim)
    }
}

pub(super) fn complete_action_execution_operation_in_transaction(
    connection: &Connection,
    operation_id: Digest,
    request: ArtifactRequestId,
    artifact: ArtifactId,
    validation_certificate: ArtifactValidationCertificateId,
    partition_manifest: Option<PartitionManifestId>,
    usage: &LifecycleUsage,
) -> Result<(), StoreError> {
    let existing = connection
        .query_row(
            "SELECT action_request_id, state, artifact_id,
                    validation_certificate_id, partition_manifest_id, usage_json
             FROM action_execution_operations WHERE operation_id=?1",
            [operation_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| conflict("operation was not claimed"))?;
    let expected = (
        request.to_string(),
        artifact.to_string(),
        validation_certificate.to_string(),
        partition_manifest.map(|value| value.to_string()),
        serde_json::to_string(usage)?,
    );
    if existing.0 != expected.0 {
        return Err(conflict("operation request binding changed"));
    }
    if existing.1 == "completed" {
        if existing.2.as_deref() == Some(expected.1.as_str())
            && existing.3.as_deref() == Some(expected.2.as_str())
            && existing.4 == expected.3
            && existing.5.as_deref() == Some(expected.4.as_str())
        {
            return Ok(());
        }
        return Err(conflict("operation completed with different immutable output"));
    }
    if existing.1 != "running" {
        return Err(conflict("operation is not running"));
    }
    let updated = connection.execute(
        "UPDATE action_execution_operations
         SET state='completed', artifact_id=?1, validation_certificate_id=?2,
             partition_manifest_id=?3, usage_json=?4, completed_unix_ms=?5
         WHERE operation_id=?6 AND action_request_id=?7 AND state='running'",
        params![
            expected.1,
            expected.2,
            expected.3,
            expected.4,
            sql_time(now_ms())?,
            operation_id.to_string(),
            expected.0,
        ],
    )?;
    if updated != 1 {
        return Err(conflict("operation completion CAS failed"));
    }
    Ok(())
}

fn sql_time(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| conflict("operation timestamp exceeds SQLite range"))
}

fn conflict(message: impl Into<String>) -> StoreError {
    StoreError::ActionExecutionConflict(message.into())
}
