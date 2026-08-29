use super::*;
use crate::{
    LifecycleExploreShadowObservation, LifecycleExploreShadowResolutionKind,
    ShadowActionResolutionAuthority,
};
use needle_core::LifecycleId;
use rusqlite::TransactionBehavior;

pub const MAX_LIFECYCLE_EXPLORE_OBSERVATION_LIST_LIMIT: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleExploreShadowObservationRecord {
    pub observation: LifecycleExploreShadowObservation,
    pub recorded_unix_ms: u64,
}

type ObservationRow = (String, String, String, String, u16, String, String, String, bool, u64);

impl RuntimeStore {
    /// Persist one immutable Shadow observation for a lifecycle state.
    ///
    /// Repeating the exact observation is idempotent. A different observation
    /// for the same lifecycle state is rejected instead of overwritten.
    pub fn record_lifecycle_explore_action_observation(
        &self,
        observation: &LifecycleExploreShadowObservation,
    ) -> Result<(), StoreError> {
        observation.validate().map_err(|error| {
            StoreError::LifecycleExploreObservationValidation(error.to_string())
        })?;
        let observation_json = serde_json::to_string(observation)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lifecycle_id = observation.lifecycle.to_string();
        let expected_state_digest = observation.expected_state_digest.to_string();

        let existing = observation_row(&transaction, &lifecycle_id, &expected_state_digest)?;
        if let Some(row) = existing {
            let existing = decode_observation_row(row)?;
            if existing.observation == *observation {
                transaction.commit()?;
                return Ok(());
            }
            return Err(StoreError::LifecycleExploreObservationConflict(format!(
                "{} at {} already has a different observation",
                observation.lifecycle, observation.expected_state_digest
            )));
        }

        let current: Option<(String, String)> = transaction
            .query_row(
                "SELECT state_digest, state_json FROM change_lifecycles WHERE lifecycle_id=?1",
                [&lifecycle_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((current_state, lifecycle_json)) = current else {
            return Err(StoreError::LifecycleNotFound(format!(
                "{}: lifecycle Explore observation",
                observation.lifecycle
            )));
        };
        if current_state != expected_state_digest {
            return Err(StoreError::LifecycleExploreObservationConflict(format!(
                "{}: expected lifecycle state is stale",
                observation.lifecycle
            )));
        }
        let lifecycle: needle_core::DevelopmentLifecycle = serde_json::from_str(&lifecycle_json)
            .map_err(|error| StoreError::LifecycleCorruption(error.to_string()))?;
        lifecycle.validate()?;
        if lifecycle.id != observation.lifecycle
            || lifecycle.state_digest().to_string() != current_state
        {
            return Err(StoreError::LifecycleCorruption(format!(
                "{}: stored lifecycle projection binding",
                observation.lifecycle
            )));
        }
        let plan = lifecycle.spec.explore_action_plan.as_ref().ok_or_else(|| {
            StoreError::LifecycleExploreObservationValidation(
                "stored lifecycle has no Explore action plan".to_owned(),
            )
        })?;
        observation
            .validate_for_execution(lifecycle.id, observation.expected_state_digest, plan)
            .map_err(|error| StoreError::LifecycleExploreObservationValidation(error.to_string()))?;

        transaction.execute(
            "INSERT INTO lifecycle_explore_action_observations(
                observation_digest, lifecycle_id, expected_state_digest,
                plan_definition_digest, resolution, planned_action_count,
                observation_json, authority, adapter_invocation_required,
                recorded_unix_ms
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, 'shadow', 1, ?8)",
            params![
                observation.definition_digest.to_string(),
                lifecycle_id,
                expected_state_digest,
                observation.plan_definition_digest.to_string(),
                resolution_name(observation.resolution),
                observation.planned_action_count,
                observation_json,
                now_ms(),
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn lifecycle_explore_action_observation(
        &self,
        lifecycle: LifecycleId,
        expected_state_digest: Digest,
    ) -> Result<Option<LifecycleExploreShadowObservationRecord>, StoreError> {
        let connection = self.connection()?;
        observation_row(&connection, &lifecycle.to_string(), &expected_state_digest.to_string())?
            .map(decode_observation_row)
            .transpose()
    }

    pub fn list_lifecycle_explore_action_observations(
        &self,
        lifecycle: LifecycleId,
        limit: usize,
    ) -> Result<Vec<LifecycleExploreShadowObservationRecord>, StoreError> {
        if limit == 0 || limit > MAX_LIFECYCLE_EXPLORE_OBSERVATION_LIST_LIMIT {
            return Err(StoreError::LifecycleExploreObservationQuery(format!(
                "limit must be between 1 and {MAX_LIFECYCLE_EXPLORE_OBSERVATION_LIST_LIMIT}"
            )));
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT observation_digest, lifecycle_id, expected_state_digest,
                    plan_definition_digest, planned_action_count, resolution,
                    observation_json, authority, adapter_invocation_required, recorded_unix_ms
             FROM lifecycle_explore_action_observations
             WHERE lifecycle_id=?1
             ORDER BY recorded_unix_ms ASC, observation_digest ASC
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![lifecycle.to_string(), limit as u64], |row| {
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
                row.get(9)?,
            ))
        })?;
        rows.map(|row| decode_observation_row(row?)).collect()
    }
}

fn observation_row(
    connection: &Connection,
    lifecycle_id: &str,
    expected_state_digest: &str,
) -> Result<Option<ObservationRow>, StoreError> {
    connection
        .query_row(
            "SELECT observation_digest, lifecycle_id, expected_state_digest,
                    plan_definition_digest, planned_action_count, resolution,
                    observation_json, authority, adapter_invocation_required, recorded_unix_ms
             FROM lifecycle_explore_action_observations
             WHERE lifecycle_id=?1 AND expected_state_digest=?2",
            params![lifecycle_id, expected_state_digest],
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
                    row.get(9)?,
                ))
            },
        )
        .optional()
        .map_err(StoreError::from)
}

fn decode_observation_row(
    row: ObservationRow,
) -> Result<LifecycleExploreShadowObservationRecord, StoreError> {
    let (
        observation_digest,
        lifecycle_id,
        expected_state_digest,
        plan_definition_digest,
        planned_action_count,
        resolution,
        observation_json,
        authority,
        adapter_invocation_required,
        recorded_unix_ms,
    ) = row;
    let observation: LifecycleExploreShadowObservation = serde_json::from_str(&observation_json)
        .map_err(|error| StoreError::LifecycleExploreObservationCorruption(error.to_string()))?;
    observation
        .validate()
        .map_err(|error| StoreError::LifecycleExploreObservationCorruption(error.to_string()))?;
    let row_matches = observation.definition_digest.to_string() == observation_digest
        && observation.lifecycle.to_string() == lifecycle_id
        && observation.expected_state_digest.to_string() == expected_state_digest
        && observation.plan_definition_digest.to_string() == plan_definition_digest
        && observation.planned_action_count == planned_action_count
        && resolution_name(observation.resolution) == resolution
        && authority == "shadow"
        && observation.authority == ShadowActionResolutionAuthority::Shadow
        && observation.adapter_invocation_required == adapter_invocation_required;
    if !row_matches {
        return Err(StoreError::LifecycleExploreObservationCorruption(format!(
            "{lifecycle_id} at {expected_state_digest}: columns differ from the canonical record"
        )));
    }
    Ok(LifecycleExploreShadowObservationRecord { observation, recorded_unix_ms })
}

fn resolution_name(resolution: LifecycleExploreShadowResolutionKind) -> &'static str {
    match resolution {
        LifecycleExploreShadowResolutionKind::Unavailable => "unavailable",
        LifecycleExploreShadowResolutionKind::Miss => "miss",
        LifecycleExploreShadowResolutionKind::Partial => "partial",
        LifecycleExploreShadowResolutionKind::Resolved => "resolved",
        LifecycleExploreShadowResolutionKind::Invalid => "invalid",
    }
}
