use super::{RuntimeStore, StoreError, now_ms, parse_digest};
use crate::repository_observer::RepositoryObservation;
use needle_core::{
    DependencyLocator, Digest, MAX_REPOSITORY_GENERATION_WIRE_BYTES, MAX_STATE_DELTA_LOCATORS,
    MAX_STATE_DELTA_WIRE_BYTES, RepositoryContextId, RepositoryGeneration, StateDelta,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

type GenerationRow = (String, String, i64, String, Option<String>, bool, String, String);
type DeltaRow = (String, String, i64, i64, bool, String, String);
type ObservationRow = (String, String, i64, i64, String, String, String, bool, String);

impl RuntimeStore {
    /// Installs generation zero for one local repository/worktree context.
    /// Replaying the identical genesis record is idempotent; a different
    /// record for the same context is a conflict.
    pub fn initialize_repository_generation(
        &self,
        generation: &RepositoryGeneration,
    ) -> Result<(), StoreError> {
        self.initialize_repository_generation_inner(generation, None)
    }

    pub(crate) fn initialize_observed_repository_generation(
        &self,
        generation: &RepositoryGeneration,
        observation: &RepositoryObservation,
    ) -> Result<(), StoreError> {
        self.initialize_repository_generation_inner(generation, Some(observation))
    }

    fn initialize_repository_generation_inner(
        &self,
        generation: &RepositoryGeneration,
        observation: Option<&RepositoryObservation>,
    ) -> Result<(), StoreError> {
        generation.validate()?;
        validate_observation_binding(generation, observation)?;
        if generation.generation != 0 {
            return Err(StoreError::RepositoryGenerationConflict(
                "a repository context must start at generation zero".to_owned(),
            ));
        }
        let generation_json = serde_json::to_string(generation)?;
        if generation_json.len() > MAX_REPOSITORY_GENERATION_WIRE_BYTES {
            return Err(StoreError::RepositoryGenerationCorruption(
                "canonical generation exceeds its storage bound".to_owned(),
            ));
        }

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = read_head_generation(
            &transaction,
            generation.repository_lineage,
            generation.repository_context,
        )?;
        if let Some(current) = current {
            let stored_genesis = read_generation(
                &transaction,
                generation.repository_lineage,
                generation.repository_context,
                0,
            )?;
            match stored_genesis {
                Some(stored) if &stored == generation => {
                    ensure_observation(&transaction, generation, observation, now_ms())?;
                    transaction.commit()?;
                    return Ok(());
                }
                None => {
                    return Err(StoreError::RepositoryGenerationCorruption(format!(
                        "context {} has a head but no genesis record",
                        generation.repository_context
                    )));
                }
                Some(_) => {}
            }
            return Err(StoreError::RepositoryGenerationConflict(format!(
                "context {} already has generation {current}",
                generation.repository_context
            )));
        }
        if read_generation(
            &transaction,
            generation.repository_lineage,
            generation.repository_context,
            0,
        )?
        .is_some()
        {
            return Err(StoreError::RepositoryGenerationCorruption(format!(
                "context {} has generation zero without a head",
                generation.repository_context
            )));
        }

        let now = now_ms();
        insert_generation(&transaction, generation, &generation_json, now)?;
        ensure_observation(&transaction, generation, observation, now)?;
        transaction.execute(
            "INSERT INTO repository_generation_heads(
                repository_lineage, repository_context_id, generation, updated_unix_ms
             ) VALUES(?1, ?2, 0, ?3)",
            params![
                generation.repository_lineage.to_string(),
                generation.repository_context.to_string(),
                now,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically records one adjacent generation and its immutable delta,
    /// then advances the context head. No resolver or freshness authority is
    /// changed by this operation.
    pub fn advance_repository_generation(
        &self,
        generation: &RepositoryGeneration,
        delta: &StateDelta,
    ) -> Result<(), StoreError> {
        self.advance_repository_generation_inner(generation, delta, None)
    }

    pub(crate) fn advance_observed_repository_generation(
        &self,
        generation: &RepositoryGeneration,
        delta: &StateDelta,
        observation: &RepositoryObservation,
    ) -> Result<(), StoreError> {
        self.advance_repository_generation_inner(generation, delta, Some(observation))
    }

    fn advance_repository_generation_inner(
        &self,
        generation: &RepositoryGeneration,
        delta: &StateDelta,
        observation: Option<&RepositoryObservation>,
    ) -> Result<(), StoreError> {
        generation.validate()?;
        delta.validate()?;
        validate_transition_binding(generation, delta)?;
        validate_observation_binding(generation, observation)?;
        let generation_json = serde_json::to_string(generation)?;
        let delta_json = serde_json::to_string(delta)?;
        if generation_json.len() > MAX_REPOSITORY_GENERATION_WIRE_BYTES
            || delta_json.len() > MAX_STATE_DELTA_WIRE_BYTES
        {
            return Err(StoreError::RepositoryGenerationCorruption(
                "canonical generation transition exceeds its storage bound".to_owned(),
            ));
        }

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = read_head_generation(
            &transaction,
            generation.repository_lineage,
            generation.repository_context,
        )?
        .ok_or_else(|| {
            StoreError::RepositoryGenerationConflict(format!(
                "context {} has not been initialized",
                generation.repository_context
            ))
        })?;

        if current >= generation.generation {
            let stored_generation = read_generation(
                &transaction,
                generation.repository_lineage,
                generation.repository_context,
                generation.generation,
            )?;
            let stored_delta = read_delta(
                &transaction,
                generation.repository_lineage,
                generation.repository_context,
                delta.to_generation,
            )?;
            if stored_generation.as_ref() == Some(generation)
                && stored_delta.as_ref() == Some(delta)
            {
                ensure_observation(&transaction, generation, observation, now_ms())?;
                transaction.commit()?;
                return Ok(());
            }
            return Err(StoreError::RepositoryGenerationConflict(format!(
                "generation {} for context {} has divergent immutable material",
                generation.generation, generation.repository_context
            )));
        }
        if current != delta.from_generation {
            return Err(StoreError::RepositoryGenerationConflict(format!(
                "context {} is at generation {current}, not {}",
                generation.repository_context, delta.from_generation
            )));
        }
        if read_generation(
            &transaction,
            generation.repository_lineage,
            generation.repository_context,
            generation.generation,
        )?
        .is_some()
            || read_delta(
                &transaction,
                generation.repository_lineage,
                generation.repository_context,
                delta.to_generation,
            )?
            .is_some()
        {
            return Err(StoreError::RepositoryGenerationCorruption(format!(
                "context {} has unreachable transition material",
                generation.repository_context
            )));
        }
        read_generation(
            &transaction,
            generation.repository_lineage,
            generation.repository_context,
            current,
        )?
        .ok_or_else(|| {
            StoreError::RepositoryGenerationCorruption(format!(
                "context {} head points to a missing generation",
                generation.repository_context
            ))
        })?;

        let now = now_ms();
        insert_generation(&transaction, generation, &generation_json, now)?;
        insert_delta(&transaction, delta, &delta_json, now)?;
        ensure_observation(&transaction, generation, observation, now)?;
        let updated = transaction.execute(
            "UPDATE repository_generation_heads
             SET generation=?3, updated_unix_ms=?4
             WHERE repository_lineage=?1 AND repository_context_id=?2 AND generation=?5",
            params![
                generation.repository_lineage.to_string(),
                generation.repository_context.to_string(),
                generation_to_sql(generation.generation)?,
                now,
                generation_to_sql(delta.from_generation)?,
            ],
        )?;
        if updated != 1 {
            return Err(StoreError::RepositoryGenerationConflict(format!(
                "context {} head changed during transition",
                generation.repository_context
            )));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn current_repository_generation(
        &self,
        repository_lineage: Digest,
        repository_context: RepositoryContextId,
    ) -> Result<Option<RepositoryGeneration>, StoreError> {
        let connection = self.connection()?;
        let Some(generation) =
            read_head_generation(&connection, repository_lineage, repository_context)?
        else {
            return Ok(None);
        };
        read_generation(&connection, repository_lineage, repository_context, generation)?.map_or_else(
            || {
                Err(StoreError::RepositoryGenerationCorruption(format!(
                    "context {repository_context} head points to missing generation {generation}"
                )))
            },
            |generation| Ok(Some(generation)),
        )
    }

    pub fn repository_generation(
        &self,
        repository_lineage: Digest,
        repository_context: RepositoryContextId,
        generation: u64,
    ) -> Result<Option<RepositoryGeneration>, StoreError> {
        let connection = self.connection()?;
        read_generation(&connection, repository_lineage, repository_context, generation)
    }

    pub fn repository_state_delta(
        &self,
        repository_lineage: Digest,
        repository_context: RepositoryContextId,
        to_generation: u64,
    ) -> Result<Option<StateDelta>, StoreError> {
        let connection = self.connection()?;
        read_delta(&connection, repository_lineage, repository_context, to_generation)
    }

    pub(crate) fn repository_observation(
        &self,
        repository_lineage: Digest,
        repository_context: RepositoryContextId,
        generation: u64,
    ) -> Result<Option<RepositoryObservation>, StoreError> {
        let connection = self.connection()?;
        read_observation(&connection, repository_lineage, repository_context, generation)
    }

    pub(crate) fn attach_repository_observation(
        &self,
        generation: &RepositoryGeneration,
        observation: &RepositoryObservation,
    ) -> Result<(), StoreError> {
        generation.validate()?;
        validate_observation_binding(generation, Some(observation))?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if read_generation(
            &transaction,
            generation.repository_lineage,
            generation.repository_context,
            generation.generation,
        )?
        .as_ref()
            != Some(generation)
        {
            return Err(StoreError::RepositoryGenerationConflict(
                "observation generation does not match stored history".to_owned(),
            ));
        }
        ensure_observation(&transaction, generation, Some(observation), now_ms())?;
        transaction.commit()?;
        Ok(())
    }
}

fn validate_transition_binding(
    generation: &RepositoryGeneration,
    delta: &StateDelta,
) -> Result<(), StoreError> {
    if generation.generation == 0
        || generation.repository_lineage != delta.repository_lineage
        || generation.repository_context != delta.repository_context
        || generation.generation != delta.to_generation
    {
        return Err(StoreError::RepositoryGenerationConflict(
            "generation and state delta bindings differ".to_owned(),
        ));
    }
    Ok(())
}

fn validate_observation_binding(
    generation: &RepositoryGeneration,
    observation: Option<&RepositoryObservation>,
) -> Result<(), StoreError> {
    let Some(observation) = observation else {
        return Ok(());
    };
    observation.validate().map_err(|error| {
        StoreError::RepositoryGenerationConflict(format!("invalid repository observation: {error}"))
    })?;
    if observation.repository_lineage != generation.repository_lineage
        || observation.repository_context != generation.repository_context
        || observation.generation != generation.generation
        || observation.source_context_digest != generation.source_context_digest
        || generation.source_version_digest != Some(observation.source_version_digest())
    {
        return Err(StoreError::RepositoryGenerationConflict(
            "repository observation does not bind to its generation".to_owned(),
        ));
    }
    Ok(())
}

fn insert_generation(
    connection: &Connection,
    generation: &RepositoryGeneration,
    generation_json: &str,
    now: u64,
) -> Result<(), StoreError> {
    connection.execute(
        "INSERT INTO repository_generations(
            repository_lineage, repository_context_id, generation,
            source_context_digest, source_version_digest, reconciled,
            generation_digest, generation_json, created_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            generation.repository_lineage.to_string(),
            generation.repository_context.to_string(),
            generation_to_sql(generation.generation)?,
            generation.source_context_digest.to_string(),
            generation.source_version_digest.map(|value| value.to_string()),
            generation.reconciled,
            generation.digest.to_string(),
            generation_json,
            now,
        ],
    )?;
    Ok(())
}

fn insert_delta(
    connection: &Connection,
    delta: &StateDelta,
    delta_json: &str,
    now: u64,
) -> Result<(), StoreError> {
    connection.execute(
        "INSERT INTO repository_state_deltas(
            repository_lineage, repository_context_id, from_generation,
            to_generation, complete, delta_digest, delta_json, created_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            delta.repository_lineage.to_string(),
            delta.repository_context.to_string(),
            generation_to_sql(delta.from_generation)?,
            generation_to_sql(delta.to_generation)?,
            delta.complete,
            delta.digest.to_string(),
            delta_json,
            now,
        ],
    )?;
    Ok(())
}

fn ensure_observation(
    connection: &Connection,
    generation: &RepositoryGeneration,
    observation: Option<&RepositoryObservation>,
    now: u64,
) -> Result<(), StoreError> {
    let Some(observation) = observation else {
        return Ok(());
    };
    match read_observation(
        connection,
        generation.repository_lineage,
        generation.repository_context,
        generation.generation,
    )? {
        Some(stored) if &stored == observation => Ok(()),
        Some(_) => Err(StoreError::RepositoryGenerationConflict(format!(
            "generation {} for context {} has divergent observation material",
            generation.generation, generation.repository_context
        ))),
        None => insert_observation(connection, observation, now),
    }
}

fn insert_observation(
    connection: &Connection,
    observation: &RepositoryObservation,
    now: u64,
) -> Result<(), StoreError> {
    connection.execute(
        "INSERT INTO repository_observations(
            repository_lineage, repository_context_id, generation, format_revision,
            source_context_digest, observer_definition_digest, source_version,
            locators_complete, observation_digest, created_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            observation.repository_lineage.to_string(),
            observation.repository_context.to_string(),
            generation_to_sql(observation.generation)?,
            observation.format_revision,
            observation.source_context_digest.to_string(),
            observation.observer_definition_digest.to_string(),
            observation.source_version,
            observation.locators_complete,
            observation.digest.to_string(),
            now,
        ],
    )?;
    let zero = Digest([0; 32]).to_string();
    for locator in &observation.locators {
        let (kind, scheme, digest) = match locator {
            DependencyLocator::RepositoryPath { path_digest } => {
                (0_u8, zero.clone(), path_digest.to_string())
            }
            DependencyLocator::ProviderOpaque { scheme_definition_digest, locator_digest } => {
                (1_u8, scheme_definition_digest.to_string(), locator_digest.to_string())
            }
        };
        connection.execute(
            "INSERT INTO repository_observation_locators(
                repository_lineage, repository_context_id, generation,
                locator_kind, scheme_definition_digest, locator_digest
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                observation.repository_lineage.to_string(),
                observation.repository_context.to_string(),
                generation_to_sql(observation.generation)?,
                kind,
                scheme,
                digest,
            ],
        )?;
    }
    Ok(())
}

pub(super) fn read_head_generation(
    connection: &Connection,
    repository_lineage: Digest,
    repository_context: RepositoryContextId,
) -> Result<Option<u64>, StoreError> {
    let value = connection
        .query_row(
            "SELECT generation FROM repository_generation_heads
             WHERE repository_lineage=?1 AND repository_context_id=?2",
            params![repository_lineage.to_string(), repository_context.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    value.map(generation_from_sql).transpose()
}

pub(super) fn read_generation(
    connection: &Connection,
    repository_lineage: Digest,
    repository_context: RepositoryContextId,
    generation: u64,
) -> Result<Option<RepositoryGeneration>, StoreError> {
    let row: Option<GenerationRow> = connection
        .query_row(
            "SELECT repository_lineage, repository_context_id, generation,
                    source_context_digest, source_version_digest, reconciled,
                    generation_digest, generation_json
             FROM repository_generations
             WHERE repository_lineage=?1 AND repository_context_id=?2 AND generation=?3",
            params![
                repository_lineage.to_string(),
                repository_context.to_string(),
                generation_to_sql(generation)?,
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    row.map(decode_generation_row).transpose()
}

fn decode_generation_row(row: GenerationRow) -> Result<RepositoryGeneration, StoreError> {
    let (
        repository_lineage,
        repository_context,
        generation,
        source_context_digest,
        source_version_digest,
        reconciled,
        generation_digest,
        generation_json,
    ) = row;
    let value = RepositoryGeneration::decode_json(generation_json.as_bytes()).map_err(|error| {
        StoreError::RepositoryGenerationCorruption(format!("generation JSON: {error}"))
    })?;
    if repository_lineage != value.repository_lineage.to_string()
        || repository_context != value.repository_context.to_string()
        || generation_from_sql(generation)? != value.generation
        || source_context_digest != value.source_context_digest.to_string()
        || source_version_digest != value.source_version_digest.map(|digest| digest.to_string())
        || reconciled != value.reconciled
        || generation_digest != value.digest.to_string()
    {
        return Err(StoreError::RepositoryGenerationCorruption(
            "generation columns differ from immutable JSON".to_owned(),
        ));
    }
    Ok(value)
}

pub(super) fn read_delta(
    connection: &Connection,
    repository_lineage: Digest,
    repository_context: RepositoryContextId,
    to_generation: u64,
) -> Result<Option<StateDelta>, StoreError> {
    let row: Option<DeltaRow> = connection
        .query_row(
            "SELECT repository_lineage, repository_context_id, from_generation,
                    to_generation, complete, delta_digest, delta_json
             FROM repository_state_deltas
             WHERE repository_lineage=?1 AND repository_context_id=?2 AND to_generation=?3",
            params![
                repository_lineage.to_string(),
                repository_context.to_string(),
                generation_to_sql(to_generation)?,
            ],
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
    row.map(decode_delta_row).transpose()
}

fn decode_delta_row(row: DeltaRow) -> Result<StateDelta, StoreError> {
    let (
        repository_lineage,
        repository_context,
        from_generation,
        to_generation,
        complete,
        delta_digest,
        delta_json,
    ) = row;
    let value = StateDelta::decode_json(delta_json.as_bytes()).map_err(|error| {
        StoreError::RepositoryGenerationCorruption(format!("state delta JSON: {error}"))
    })?;
    if repository_lineage != value.repository_lineage.to_string()
        || repository_context != value.repository_context.to_string()
        || generation_from_sql(from_generation)? != value.from_generation
        || generation_from_sql(to_generation)? != value.to_generation
        || complete != value.complete
        || delta_digest != value.digest.to_string()
    {
        return Err(StoreError::RepositoryGenerationCorruption(
            "state delta columns differ from immutable JSON".to_owned(),
        ));
    }
    Ok(value)
}

fn read_observation(
    connection: &Connection,
    repository_lineage: Digest,
    repository_context: RepositoryContextId,
    generation: u64,
) -> Result<Option<RepositoryObservation>, StoreError> {
    let row: Option<ObservationRow> = connection
        .query_row(
            "SELECT repository_lineage, repository_context_id, generation, format_revision,
                    source_context_digest, observer_definition_digest, source_version,
                    locators_complete, observation_digest
             FROM repository_observations
             WHERE repository_lineage=?1 AND repository_context_id=?2 AND generation=?3",
            params![
                repository_lineage.to_string(),
                repository_context.to_string(),
                generation_to_sql(generation)?,
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let mut statement = connection.prepare_cached(
        "SELECT locator_kind, scheme_definition_digest, locator_digest
         FROM repository_observation_locators
         WHERE repository_lineage=?1 AND repository_context_id=?2 AND generation=?3
         ORDER BY locator_kind, scheme_definition_digest, locator_digest
         LIMIT ?4",
    )?;
    let locator_rows = statement
        .query_map(
            params![
                repository_lineage.to_string(),
                repository_context.to_string(),
                generation_to_sql(generation)?,
                i64::try_from(MAX_STATE_DELTA_LOCATORS + 1).unwrap_or(i64::MAX),
            ],
            |row| Ok((row.get::<_, u8>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if locator_rows.len() > MAX_STATE_DELTA_LOCATORS {
        return Err(StoreError::RepositoryGenerationCorruption(
            "repository observation exceeds the locator bound".to_owned(),
        ));
    }
    let zero = Digest([0; 32]);
    let mut locators = Vec::with_capacity(locator_rows.len());
    for (kind, scheme, locator) in locator_rows {
        let scheme = parse_digest(&scheme).map_err(|error| {
            StoreError::RepositoryGenerationCorruption(format!(
                "repository observation scheme digest: {error}"
            ))
        })?;
        let locator = parse_digest(&locator).map_err(|error| {
            StoreError::RepositoryGenerationCorruption(format!(
                "repository observation locator digest: {error}"
            ))
        })?;
        let locator = match kind {
            0 if scheme == zero => DependencyLocator::from_repository_path_digest(locator),
            1 => DependencyLocator::provider_opaque(scheme, locator),
            _ => {
                return Err(StoreError::RepositoryGenerationCorruption(
                    "repository observation locator encoding is invalid".to_owned(),
                ));
            }
        };
        locators.push(locator);
    }
    decode_observation_row(connection, row, locators)
}

fn decode_observation_row(
    connection: &Connection,
    row: ObservationRow,
    locators: Vec<DependencyLocator>,
) -> Result<Option<RepositoryObservation>, StoreError> {
    let (
        repository_lineage,
        repository_context,
        generation,
        format_revision,
        source_context_digest,
        observer_definition_digest,
        source_version,
        locators_complete,
        observation_digest,
    ) = row;
    let value = RepositoryObservation {
        format_revision: format_revision.try_into().map_err(|_| {
            StoreError::RepositoryGenerationCorruption(
                "repository observation revision is out of range".to_owned(),
            )
        })?,
        repository_lineage: parse_observation_digest(&repository_lineage, "lineage")?,
        repository_context: RepositoryContextId::new(parse_observation_digest(
            &repository_context,
            "context",
        )?),
        generation: generation_from_sql(generation)?,
        source_context_digest: parse_observation_digest(&source_context_digest, "source")?,
        observer_definition_digest: parse_observation_digest(
            &observer_definition_digest,
            "observer definition",
        )?,
        source_version,
        locators,
        locators_complete,
        digest: parse_observation_digest(&observation_digest, "observation")?,
    };
    value.validate().map_err(|error| {
        StoreError::RepositoryGenerationCorruption(format!(
            "repository observation validation: {error}"
        ))
    })?;
    let stored_generation = read_generation(
        connection,
        value.repository_lineage,
        value.repository_context,
        value.generation,
    )?
    .ok_or_else(|| {
        StoreError::RepositoryGenerationCorruption(
            "repository observation references a missing generation".to_owned(),
        )
    })?;
    if stored_generation.source_context_digest != value.source_context_digest
        || stored_generation.source_version_digest != Some(value.source_version_digest())
    {
        return Err(StoreError::RepositoryGenerationCorruption(
            "repository observation source or version differs from its generation".to_owned(),
        ));
    }
    Ok(Some(value))
}

fn parse_observation_digest(value: &str, field: &str) -> Result<Digest, StoreError> {
    parse_digest(value).map_err(|error| {
        StoreError::RepositoryGenerationCorruption(format!(
            "repository observation {field} digest: {error}"
        ))
    })
}

fn generation_to_sql(generation: u64) -> Result<i64, StoreError> {
    generation.try_into().map_err(|_| {
        StoreError::RepositoryGenerationConflict(
            "repository generation exceeds SQLite integer range".to_owned(),
        )
    })
}

fn generation_from_sql(generation: i64) -> Result<u64, StoreError> {
    generation.try_into().map_err(|_| {
        StoreError::RepositoryGenerationCorruption("repository generation is negative".to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use needle_core::{ArtifactId, DependencyLocator};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_store() -> (PathBuf, RuntimeStore) {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let path = std::env::temp_dir().join(format!(
            "needle-repository-generations-{}-{}.sqlite3",
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

    fn digest(label: impl AsRef<[u8]>) -> Digest {
        Digest::blake3(label)
    }

    fn generation(
        lineage: Digest,
        context: RepositoryContextId,
        number: u64,
        source: &str,
    ) -> RepositoryGeneration {
        RepositoryGeneration::new(
            lineage,
            context,
            number,
            digest(source),
            Some(digest(format!("version-{number}"))),
            true,
        )
    }

    fn delta(
        lineage: Digest,
        context: RepositoryContextId,
        from: u64,
        complete: bool,
    ) -> StateDelta {
        StateDelta::new(
            lineage,
            context,
            from,
            from + 1,
            vec![DependencyLocator::repository_path("src/lib.rs").unwrap()],
            vec![ArtifactId::new(digest("input"))],
            vec![digest("definition")],
            vec![digest("world")],
            complete,
        )
        .unwrap()
    }

    fn observation(
        generation: &RepositoryGeneration,
        locators: Vec<DependencyLocator>,
    ) -> RepositoryObservation {
        RepositoryObservation::new(
            generation.repository_lineage,
            generation.repository_context,
            generation.generation,
            generation.source_context_digest,
            digest("observer"),
            format!("source-{}", generation.generation),
            locators,
            true,
        )
        .unwrap()
    }

    #[test]
    fn generation_transition_is_atomic_persistent_and_idempotent() {
        let (path, store) = temporary_store();
        store.initialize().unwrap();
        let lineage = digest("repository");
        let context = RepositoryContextId::new(digest("worktree"));
        let genesis = generation(lineage, context, 0, "source-zero");
        let next = generation(lineage, context, 1, "source-one");
        let transition = delta(lineage, context, 0, true);

        store.initialize_repository_generation(&genesis).unwrap();
        store.initialize_repository_generation(&genesis).unwrap();
        store.advance_repository_generation(&next, &transition).unwrap();
        store.advance_repository_generation(&next, &transition).unwrap();
        let second = generation(lineage, context, 2, "source-two");
        let second_transition = delta(lineage, context, 1, true);
        store.advance_repository_generation(&second, &second_transition).unwrap();
        store.initialize_repository_generation(&genesis).unwrap();
        store.advance_repository_generation(&next, &transition).unwrap();
        assert_eq!(
            store.current_repository_generation(lineage, context).unwrap(),
            Some(second.clone())
        );
        assert_eq!(store.repository_generation(lineage, context, 0).unwrap(), Some(genesis));
        assert_eq!(store.repository_state_delta(lineage, context, 1).unwrap(), Some(transition));

        drop(store);
        let reopened = RuntimeStore::new(&path);
        reopened.initialize().unwrap();
        assert_eq!(reopened.current_repository_generation(lineage, context).unwrap(), Some(second));
        drop(reopened);
        cleanup(&path);
    }

    #[test]
    fn generation_conflicts_and_gaps_fail_without_advancing() {
        let (path, store) = temporary_store();
        store.initialize().unwrap();
        let lineage = digest("repository");
        let context = RepositoryContextId::new(digest("worktree"));
        let genesis = generation(lineage, context, 0, "source-zero");
        let next = generation(lineage, context, 1, "source-one");
        store.initialize_repository_generation(&genesis).unwrap();
        store.advance_repository_generation(&next, &delta(lineage, context, 0, false)).unwrap();

        let divergent = generation(lineage, context, 1, "different-source");
        assert!(matches!(
            store.advance_repository_generation(&divergent, &delta(lineage, context, 0, false)),
            Err(StoreError::RepositoryGenerationConflict(_))
        ));
        let skipped = generation(lineage, context, 3, "source-three");
        assert!(matches!(
            store.advance_repository_generation(&skipped, &delta(lineage, context, 2, true)),
            Err(StoreError::RepositoryGenerationConflict(_))
        ));
        assert_eq!(store.current_repository_generation(lineage, context).unwrap(), Some(next));

        drop(store);
        cleanup(&path);
    }

    #[test]
    fn worktree_contexts_advance_independently() {
        let (path, store) = temporary_store();
        store.initialize().unwrap();
        let lineage = digest("shared-lineage");
        let first = RepositoryContextId::new(digest("worktree-a"));
        let second = RepositoryContextId::new(digest("worktree-b"));
        store
            .initialize_repository_generation(&generation(lineage, first, 0, "source-a0"))
            .unwrap();
        let second_genesis = generation(lineage, second, 0, "source-b0");
        store.initialize_repository_generation(&second_genesis).unwrap();
        store
            .advance_repository_generation(
                &generation(lineage, first, 1, "source-a1"),
                &delta(lineage, first, 0, true),
            )
            .unwrap();

        assert_eq!(
            store.current_repository_generation(lineage, second).unwrap(),
            Some(second_genesis)
        );
        drop(store);
        cleanup(&path);
    }

    #[test]
    fn generation_and_delta_rows_are_append_only() {
        let (path, store) = temporary_store();
        store.initialize().unwrap();
        let lineage = digest("repository");
        let context = RepositoryContextId::new(digest("worktree"));
        store
            .initialize_repository_generation(&generation(lineage, context, 0, "source-zero"))
            .unwrap();
        store
            .advance_repository_generation(
                &generation(lineage, context, 1, "source-one"),
                &delta(lineage, context, 0, true),
            )
            .unwrap();
        drop(store);

        let connection = Connection::open(&path).unwrap();
        assert!(connection.execute("UPDATE repository_generations SET reconciled=0", []).is_err());
        assert!(connection.execute("DELETE FROM repository_state_deltas", []).is_err());
        drop(connection);
        cleanup(&path);
    }

    #[test]
    fn observed_generation_is_atomic_idempotent_and_provider_opaque() {
        let (path, store) = temporary_store();
        store.initialize().unwrap();
        let lineage = digest("repository");
        let context = RepositoryContextId::new(digest("worktree"));
        let unbound_genesis = generation(lineage, context, 0, "source-zero");
        let observed = observation(
            &unbound_genesis,
            vec![
                DependencyLocator::repository_path("src/lib.rs").unwrap(),
                DependencyLocator::provider_opaque(digest("scheme"), digest("opaque")),
            ],
        );
        assert!(matches!(
            store.initialize_observed_repository_generation(&unbound_genesis, &observed),
            Err(StoreError::RepositoryGenerationConflict(_))
        ));
        let genesis = RepositoryGeneration::new(
            lineage,
            context,
            0,
            unbound_genesis.source_context_digest,
            Some(observed.source_version_digest()),
            true,
        );
        store.initialize_observed_repository_generation(&genesis, &observed).unwrap();
        store.initialize_observed_repository_generation(&genesis, &observed).unwrap();
        assert_eq!(
            store.repository_observation(lineage, context, 0).unwrap(),
            Some(observed.clone())
        );

        let divergent =
            observation(&genesis, vec![DependencyLocator::repository_path("src/main.rs").unwrap()]);
        assert!(matches!(
            store.initialize_observed_repository_generation(&genesis, &divergent),
            Err(StoreError::RepositoryGenerationConflict(_))
        ));
        assert_eq!(store.repository_observation(lineage, context, 0).unwrap(), Some(observed));
        drop(store);
        cleanup(&path);
    }
}
