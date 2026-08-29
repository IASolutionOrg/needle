use super::{RuntimeStore, StoreError, now_ms, parse_digest};
use needle_core::{
    DefinitionSet, DefinitionSetGeneration, MAX_DEFINITION_SET_GENERATION_WIRE_BYTES,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

type DefinitionGenerationRow = (i64, String, String, String, String, String, String);

impl RuntimeStore {
    pub fn current_definition_set_generation(
        &self,
    ) -> Result<Option<DefinitionSetGeneration>, StoreError> {
        let connection = self.connection()?;
        let generation = connection
            .query_row("SELECT generation FROM definition_set_head WHERE singleton=1", [], |row| {
                row.get::<_, i64>(0)
            })
            .optional()?
            .map(definition_generation_from_sql)
            .transpose()?;
        let Some(generation) = generation else {
            return Ok(None);
        };
        read_definition_generation(&connection, generation)?.map(Some).ok_or_else(|| {
            StoreError::DefinitionGenerationCorruption(format!(
                "definition-set head points to missing generation {generation}"
            ))
        })
    }

    pub fn definition_set_generation(
        &self,
        generation: u64,
    ) -> Result<Option<DefinitionSetGeneration>, StoreError> {
        let connection = self.connection()?;
        read_definition_generation(&connection, generation)
    }

    pub(crate) fn reconcile_active_definition_set(
        &self,
    ) -> Result<DefinitionSetGeneration, StoreError> {
        self.reconcile_definition_set(crate::active_definition_set())
    }

    pub(super) fn reconcile_definition_set(
        &self,
        definition_set: &DefinitionSet,
    ) -> Result<DefinitionSetGeneration, StoreError> {
        definition_set.validate()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_number = transaction
            .query_row("SELECT generation FROM definition_set_head WHERE singleton=1", [], |row| {
                row.get::<_, i64>(0)
            })
            .optional()?
            .map(definition_generation_from_sql)
            .transpose()?;

        let Some(current_number) = current_number else {
            let existing: u64 = transaction.query_row(
                "SELECT COUNT(*) FROM definition_set_generations",
                [],
                |row| row.get(0),
            )?;
            if existing != 0 {
                return Err(StoreError::DefinitionGenerationCorruption(
                    "definition-set generations exist without a head".to_owned(),
                ));
            }
            let generation = DefinitionSetGeneration::new(0, definition_set.clone())?;
            insert_definition_generation(&transaction, &generation)?;
            transaction.execute(
                "INSERT INTO definition_set_head(singleton, generation, updated_unix_ms)
                 VALUES(1, 0, ?1)",
                [now_ms()],
            )?;
            transaction.commit()?;
            return Ok(generation);
        };

        let current =
            read_definition_generation(&transaction, current_number)?.ok_or_else(|| {
                StoreError::DefinitionGenerationCorruption(format!(
                    "definition-set head points to missing generation {current_number}"
                ))
            })?;
        if current.definition_set == *definition_set {
            transaction.commit()?;
            return Ok(current);
        }

        let next_number = current_number.checked_add(1).ok_or_else(|| {
            StoreError::DefinitionGenerationConflict(
                "definition-set generation counter overflowed".to_owned(),
            )
        })?;
        if read_definition_generation(&transaction, next_number)?.is_some() {
            return Err(StoreError::DefinitionGenerationCorruption(format!(
                "definition-set generation {next_number} exists beyond the active head"
            )));
        }
        let next = DefinitionSetGeneration::new(next_number, definition_set.clone())?;
        insert_definition_generation(&transaction, &next)?;
        let updated = transaction.execute(
            "UPDATE definition_set_head
             SET generation=?1, updated_unix_ms=?2
             WHERE singleton=1 AND generation=?3",
            params![
                definition_generation_to_sql(next_number)?,
                now_ms(),
                definition_generation_to_sql(current_number)?,
            ],
        )?;
        if updated != 1 {
            return Err(StoreError::DefinitionGenerationConflict(
                "definition-set head changed during reconciliation".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(next)
    }
}

fn insert_definition_generation(
    transaction: &rusqlite::Transaction<'_>,
    generation: &DefinitionSetGeneration,
) -> Result<(), StoreError> {
    generation.validate()?;
    let generation_json = serde_json::to_string(generation)?;
    if generation_json.len() > MAX_DEFINITION_SET_GENERATION_WIRE_BYTES {
        return Err(StoreError::DefinitionGenerationCorruption(
            "canonical definition-set generation exceeds its storage bound".to_owned(),
        ));
    }
    transaction.execute(
        "INSERT INTO definition_set_generations(
            generation, semantic_set_digest, validation_set_digest,
            operational_set_digest, audit_digest, generation_digest,
            generation_json, created_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            definition_generation_to_sql(generation.generation)?,
            generation.definition_set.semantic_set_digest.to_string(),
            generation.definition_set.validation_set_digest.to_string(),
            generation.definition_set.operational_set_digest.to_string(),
            generation.definition_set.audit_digest.to_string(),
            generation.digest.to_string(),
            generation_json,
            now_ms(),
        ],
    )?;
    Ok(())
}

pub(super) fn read_definition_generation(
    connection: &Connection,
    generation: u64,
) -> Result<Option<DefinitionSetGeneration>, StoreError> {
    let row = connection
        .query_row(
            "SELECT generation, semantic_set_digest, validation_set_digest,
                    operational_set_digest, audit_digest, generation_digest,
                    generation_json
             FROM definition_set_generations WHERE generation=?1",
            [definition_generation_to_sql(generation)?],
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
    row.map(decode_definition_generation_row).transpose()
}

fn decode_definition_generation_row(
    row: DefinitionGenerationRow,
) -> Result<DefinitionSetGeneration, StoreError> {
    let (generation, semantic, validation, operational, audit, digest, json) = row;
    let decoded = DefinitionSetGeneration::decode_json(json.as_bytes()).map_err(|error| {
        StoreError::DefinitionGenerationCorruption(format!(
            "stored definition-set generation JSON is invalid: {error}"
        ))
    })?;
    let stored_generation = definition_generation_from_sql(generation)?;
    let stored_semantic = definition_digest(&semantic, "semantic_set_digest")?;
    let stored_validation = definition_digest(&validation, "validation_set_digest")?;
    let stored_operational = definition_digest(&operational, "operational_set_digest")?;
    let stored_audit = definition_digest(&audit, "audit_digest")?;
    let stored_digest = definition_digest(&digest, "generation_digest")?;
    if decoded.generation != stored_generation
        || decoded.definition_set.semantic_set_digest != stored_semantic
        || decoded.definition_set.validation_set_digest != stored_validation
        || decoded.definition_set.operational_set_digest != stored_operational
        || decoded.definition_set.audit_digest != stored_audit
        || decoded.digest != stored_digest
    {
        return Err(StoreError::DefinitionGenerationCorruption(format!(
            "stored columns do not bind to definition-set generation {stored_generation}"
        )));
    }
    Ok(decoded)
}

fn definition_digest(value: &str, field: &str) -> Result<needle_core::Digest, StoreError> {
    parse_digest(value).map_err(|error| {
        StoreError::DefinitionGenerationCorruption(format!("stored {field} is invalid: {error}"))
    })
}

fn definition_generation_to_sql(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| {
        StoreError::DefinitionGenerationConflict(
            "definition-set generation exceeds SQLite integer range".to_owned(),
        )
    })
}

fn definition_generation_from_sql(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| {
        StoreError::DefinitionGenerationCorruption(
            "stored definition-set generation is negative".to_owned(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use needle_core::{DefinitionHandle, DefinitionKind, DefinitionSetEntry, Digest};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_store() -> (PathBuf, RuntimeStore) {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let path = std::env::temp_dir().join(format!(
            "needle-definition-generations-{}-{}.sqlite3",
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

    fn operationally_changed_set() -> DefinitionSet {
        let active = crate::active_definition_set();
        let mut entries = active.entries.clone();
        let index =
            entries.iter().position(|entry| entry.kind == DefinitionKind::ActionContract).unwrap();
        let prior = &entries[index];
        entries[index] = DefinitionSetEntry::new(
            prior.kind,
            DefinitionHandle::new(prior.handle.as_str()).unwrap(),
            prior.semantic_definition_digest,
            prior.validation_definition_digest,
            Some(Digest::blake3(b"changed-operational-policy")),
            Digest::blake3(b"changed-complete-definition"),
        )
        .unwrap();
        DefinitionSet::new(entries).unwrap()
    }

    #[test]
    fn initialization_reconciles_genesis_and_reopen_is_idempotent() {
        let (path, store) = temporary_store();
        store.initialize().unwrap();
        let genesis = store.current_definition_set_generation().unwrap().unwrap();
        assert_eq!(genesis.generation, 0);
        assert_eq!(&genesis.definition_set, crate::active_definition_set());

        store.initialize().unwrap();
        assert_eq!(store.current_definition_set_generation().unwrap(), Some(genesis.clone()));
        drop(store);

        let reopened = RuntimeStore::new(&path);
        reopened.initialize().unwrap();
        assert_eq!(reopened.current_definition_set_generation().unwrap(), Some(genesis));
        drop(reopened);
        cleanup(&path);
    }

    #[test]
    fn changed_set_advances_once_and_preserves_authority_isolation() {
        let (path, store) = temporary_store();
        store.initialize().unwrap();
        let genesis = store.current_definition_set_generation().unwrap().unwrap();
        let changed = operationally_changed_set();
        assert_eq!(genesis.definition_set.semantic_set_digest, changed.semantic_set_digest);
        assert_eq!(genesis.definition_set.validation_set_digest, changed.validation_set_digest);
        assert_ne!(genesis.definition_set.operational_set_digest, changed.operational_set_digest);

        let next = store.reconcile_definition_set(&changed).unwrap();
        assert_eq!(next.generation, 1);
        assert_eq!(store.reconcile_definition_set(&changed).unwrap(), next);
        assert_eq!(store.definition_set_generation(0).unwrap(), Some(genesis));
        assert_eq!(store.current_definition_set_generation().unwrap(), Some(next));
        drop(store);
        cleanup(&path);
    }

    #[test]
    fn generation_rows_are_append_only() {
        let (path, store) = temporary_store();
        store.initialize().unwrap();
        drop(store);

        let connection = Connection::open(&path).unwrap();
        assert!(
            connection.execute("UPDATE definition_set_generations SET generation=3", []).is_err()
        );
        assert!(connection.execute("DELETE FROM definition_set_generations", []).is_err());
        assert!(connection.execute("DELETE FROM definition_set_head", []).is_err());
        drop(connection);
        cleanup(&path);
    }
}
