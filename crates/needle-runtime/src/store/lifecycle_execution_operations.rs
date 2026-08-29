use super::{StoreError, now_ms};
use needle_core::{ChangeId, Digest};
use rusqlite::{Connection, OptionalExtension, params};

pub(super) fn bind_lifecycle_execution_operation_in_transaction(
    connection: &Connection,
    operation_id: Digest,
    request_digest: Digest,
    change_id: &ChangeId,
) -> Result<(), StoreError> {
    let existing = connection
        .query_row(
            "SELECT request_digest, change_id
             FROM lifecycle_execution_operations
             WHERE operation_id=?1",
            [operation_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((stored_request, stored_change)) = existing {
        if stored_request == request_digest.to_string() && stored_change == change_id.as_str() {
            return Ok(());
        }
        return Err(StoreError::LifecycleConflict(
            "operation id was already bound to a different lifecycle request".to_owned(),
        ));
    }
    connection.execute(
        "INSERT INTO lifecycle_execution_operations(
            operation_id, request_digest, change_id, created_unix_ms
         ) VALUES(?1, ?2, ?3, ?4)",
        params![
            operation_id.to_string(),
            request_digest.to_string(),
            change_id.as_str(),
            i64::try_from(now_ms()).map_err(|_| StoreError::LifecycleConflict(
                "lifecycle operation timestamp exceeds SQLite range".to_owned(),
            ))?,
        ],
    )?;
    Ok(())
}
