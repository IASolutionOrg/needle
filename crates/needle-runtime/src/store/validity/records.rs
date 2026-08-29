use super::super::definition_generations::read_definition_generation;
use super::super::generations::{read_generation, read_head_generation};
use super::super::{RuntimeStore, StoreError, now_ms, parse_digest};
use crate::DependencyLocatorSet;
use needle_core::{
    Artifact, ArtifactId, ArtifactValidationCertificate, ArtifactValidationCertificateId,
    DefinitionSetGeneration, DependencyStamp, DependencyStampId, DependencyStampInput, Digest,
    MAX_DEPENDENCY_STAMP_WIRE_BYTES, MAX_OPERATIONAL_VALIDITY_MEMO_WIRE_BYTES,
    OperationalValidityMemo, OperationalValidityMemoId, OperationalValidityOutcome,
    RepositoryContextId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

type ArtifactPairRow = (String, String, String, String, String);

#[derive(Debug)]
struct StampRow {
    stamp_id: String,
    artifact_id: String,
    certificate_id: String,
    repository_lineage: String,
    repository_context: String,
    repository_generation: i64,
    repository_generation_digest: String,
    dependency_manifest_digest: String,
    dependency_locator_set_digest: String,
    intersection_definition_digest: String,
    definition_generation: i64,
    definition_generation_digest: String,
    semantic_definition_set_digest: String,
    validation_definition_set_digest: String,
    operational_definition_set_digest: String,
    semantic_world_digest: String,
    stamp_json: String,
}

#[derive(Debug)]
struct MemoRow {
    memo_id: String,
    dependency_stamp_id: String,
    artifact_id: String,
    certificate_id: String,
    repository_lineage: String,
    repository_context: String,
    source_generation: i64,
    validated_through_generation: i64,
    validated_through_generation_digest: String,
    definition_generation: i64,
    definition_generation_digest: String,
    semantic_definition_set_digest: String,
    validation_definition_set_digest: String,
    operational_definition_set_digest: String,
    input_artifact_state_digest: String,
    external_version_state_digest: String,
    delta_chain_digest: String,
    intersection_definition_digest: String,
    outcome: String,
    memo_json: String,
}

impl RuntimeStore {
    /// Records the exact repository and definition generations against which
    /// an existing validated artifact was produced.
    ///
    /// The source snapshot stored with the artifact request must equal the
    /// current reconciled repository generation. The resolver never creates or
    /// rewrites this immutable record.
    pub fn record_dependency_stamp(
        &self,
        artifact_id: ArtifactId,
        certificate_id: ArtifactValidationCertificateId,
        repository_context: RepositoryContextId,
    ) -> Result<DependencyStamp, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (artifact, certificate, source_digest) =
            load_artifact_pair(&transaction, artifact_id, certificate_id)?;
        validate_stored_pair(&artifact, &certificate)?;

        let repository_lineage = certificate.coverage.world.repository_lineage;
        let current_generation_number =
            read_head_generation(&transaction, repository_lineage, repository_context)?
                .ok_or_else(|| {
                    StoreError::DependencyValidityConflict(format!(
                        "repository context {repository_context} has no generation head"
                    ))
                })?;
        let current_generation = read_generation(
            &transaction,
            repository_lineage,
            repository_context,
            current_generation_number,
        )?
        .ok_or_else(|| {
            StoreError::DependencyValidityCorruption(format!(
                "repository context {repository_context} head is missing"
            ))
        })?;
        if !current_generation.reconciled {
            return Err(StoreError::DependencyValidityConflict(
                "current repository generation is not reconciled".to_owned(),
            ));
        }
        if source_digest != current_generation.source_context_digest {
            return Err(StoreError::DependencyValidityConflict(
                "artifact source snapshot is not the current repository generation".to_owned(),
            ));
        }

        let current_definitions =
            current_definition_generation(&transaction)?.ok_or_else(|| {
                StoreError::DependencyValidityCorruption(
                    "definition-set generation head is missing".to_owned(),
                )
            })?;
        let locator_set = DependencyLocatorSet::from_manifest(&artifact.dependency_manifest)
            .map_err(|error| StoreError::DependencyValidityConflict(error.to_string()))?;
        if certificate.coverage.dependency_manifest_digest != locator_set.dependency_manifest_digest
        {
            return Err(StoreError::DependencyValidityCorruption(
                "certificate and dependency locator set reference different manifests".to_owned(),
            ));
        }

        let stamp = DependencyStamp::new(DependencyStampInput {
            artifact: artifact_id,
            validation_certificate: certificate_id,
            repository_lineage,
            repository_context,
            repository_generation: current_generation.generation,
            repository_generation_digest: current_generation.digest,
            dependency_manifest_digest: locator_set.dependency_manifest_digest,
            dependency_locator_set_digest: locator_set.digest,
            intersection_definition_digest: locator_set.projection_definition_digest,
            definition_generation: current_definitions.generation,
            definition_generation_digest: current_definitions.digest,
            semantic_definition_set_digest: current_definitions.definition_set.semantic_set_digest,
            validation_definition_set_digest: current_definitions
                .definition_set
                .validation_set_digest,
            operational_definition_set_digest: current_definitions
                .definition_set
                .operational_set_digest,
            semantic_world_digest: certificate.coverage.world.id(),
        });

        if let Some(existing) = read_dependency_stamp_for_certificate_context(
            &transaction,
            certificate_id,
            repository_context,
        )? {
            if existing == stamp {
                transaction.commit()?;
                return Ok(existing);
            }
            return Err(StoreError::DependencyValidityConflict(
                "certificate already has a different stamp for this repository context".to_owned(),
            ));
        }

        insert_dependency_stamp(&transaction, &stamp)?;
        transaction.commit()?;
        Ok(stamp)
    }

    pub fn dependency_stamp(
        &self,
        id: DependencyStampId,
    ) -> Result<Option<DependencyStamp>, StoreError> {
        let connection = self.connection()?;
        read_dependency_stamp(&connection, id)
    }

    pub(crate) fn dependency_stamp_for_certificate_context(
        &self,
        certificate: ArtifactValidationCertificateId,
        context: RepositoryContextId,
    ) -> Result<Option<DependencyStamp>, StoreError> {
        let connection = self.connection()?;
        read_dependency_stamp_for_certificate_context(&connection, certificate, context)
    }

    pub fn operational_validity_memo(
        &self,
        id: OperationalValidityMemoId,
    ) -> Result<Option<OperationalValidityMemo>, StoreError> {
        let connection = self.connection()?;
        read_operational_validity_memo(&connection, id)
    }
}

pub(super) fn validate_stored_pair(
    artifact: &Artifact,
    certificate: &ArtifactValidationCertificate,
) -> Result<(), StoreError> {
    crate::reuse_descriptor::derive_shadow_reuse_descriptor_from_validated_pair(
        artifact,
        certificate,
    )
    .map(|_| ())
    .map_err(|error| {
        StoreError::DependencyValidityCorruption(format!(
            "stored artifact/certificate pair is invalid: {error}"
        ))
    })
}

pub(super) fn load_artifact_pair(
    connection: &Connection,
    artifact_id: ArtifactId,
    certificate_id: ArtifactValidationCertificateId,
) -> Result<(Artifact, ArtifactValidationCertificate, Digest), StoreError> {
    let row: Option<ArtifactPairRow> = connection
        .query_row(
            "SELECT a.artifact_json, c.certificate_json, r.source_digest,
                    c.dependency_manifest_digest, c.world_digest
             FROM artifacts a
             JOIN artifact_requests r ON r.request_id=a.request_id
             JOIN artifact_validation_certificates c ON c.artifact_id=a.artifact_id
             WHERE a.artifact_id=?1 AND c.certificate_id=?2",
            params![artifact_id.to_string(), certificate_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()?;
    let Some((artifact_json, certificate_json, source, manifest, world)) = row else {
        return Err(StoreError::DependencyValidityConflict(
            "artifact and validation certificate pair was not found".to_owned(),
        ));
    };
    let artifact: Artifact = serde_json::from_str(&artifact_json).map_err(|error| {
        StoreError::DependencyValidityCorruption(format!(
            "stored artifact JSON is invalid: {error}"
        ))
    })?;
    let certificate: ArtifactValidationCertificate = serde_json::from_str(&certificate_json)
        .map_err(|error| {
            StoreError::DependencyValidityCorruption(format!(
                "stored validation certificate JSON is invalid: {error}"
            ))
        })?;
    let source_digest = validity_digest(&source, "artifact source digest")?;
    if artifact.id != artifact_id.digest()
        || certificate.id != certificate_id
        || certificate.artifact != artifact_id
        || certificate.coverage.dependency_manifest_digest
            != validity_digest(&manifest, "dependency manifest digest")?
        || certificate.coverage.world.id() != validity_digest(&world, "semantic world digest")?
    {
        return Err(StoreError::DependencyValidityCorruption(
            "stored artifact columns do not match their canonical records".to_owned(),
        ));
    }
    Ok((artifact, certificate, source_digest))
}

pub(super) fn current_definition_generation(
    connection: &Connection,
) -> Result<Option<DefinitionSetGeneration>, StoreError> {
    let generation = connection
        .query_row("SELECT generation FROM definition_set_head WHERE singleton=1", [], |row| {
            row.get::<_, i64>(0)
        })
        .optional()?
        .map(validity_generation_from_sql)
        .transpose()?;
    generation
        .map(|value| read_definition_generation(connection, value))
        .transpose()
        .map(Option::flatten)
}

fn insert_dependency_stamp(
    connection: &Connection,
    stamp: &DependencyStamp,
) -> Result<(), StoreError> {
    stamp.validate()?;
    let json = serde_json::to_string(stamp)?;
    if json.len() > MAX_DEPENDENCY_STAMP_WIRE_BYTES {
        return Err(StoreError::DependencyValidityValidation(
            needle_core::DependencyValidityRecordError::WireBound {
                record: "dependency_stamp",
                actual: json.len(),
                maximum: MAX_DEPENDENCY_STAMP_WIRE_BYTES,
            },
        ));
    }
    connection.execute(
        "INSERT INTO artifact_dependency_stamps(
            stamp_id, artifact_id, certificate_id, repository_lineage,
            repository_context_id, repository_generation, repository_generation_digest,
            dependency_manifest_digest, dependency_locator_set_digest,
            intersection_definition_digest, definition_generation,
            definition_generation_digest, semantic_definition_set_digest,
            validation_definition_set_digest, operational_definition_set_digest,
            semantic_world_digest, stamp_json, created_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                  ?15, ?16, ?17, ?18)",
        params![
            stamp.id.to_string(),
            stamp.artifact.to_string(),
            stamp.validation_certificate.to_string(),
            stamp.repository_lineage.to_string(),
            stamp.repository_context.to_string(),
            validity_generation_to_sql(stamp.repository_generation)?,
            stamp.repository_generation_digest.to_string(),
            stamp.dependency_manifest_digest.to_string(),
            stamp.dependency_locator_set_digest.to_string(),
            stamp.intersection_definition_digest.to_string(),
            validity_generation_to_sql(stamp.definition_generation)?,
            stamp.definition_generation_digest.to_string(),
            stamp.semantic_definition_set_digest.to_string(),
            stamp.validation_definition_set_digest.to_string(),
            stamp.operational_definition_set_digest.to_string(),
            stamp.semantic_world_digest.to_string(),
            json,
            now_ms(),
        ],
    )?;
    Ok(())
}

pub(super) fn read_dependency_stamp(
    connection: &Connection,
    id: DependencyStampId,
) -> Result<Option<DependencyStamp>, StoreError> {
    let row = connection
        .query_row(
            "SELECT stamp_id, artifact_id, certificate_id, repository_lineage,
                    repository_context_id, repository_generation, repository_generation_digest,
                    dependency_manifest_digest, dependency_locator_set_digest,
                    intersection_definition_digest, definition_generation,
                    definition_generation_digest, semantic_definition_set_digest,
                    validation_definition_set_digest, operational_definition_set_digest,
                    semantic_world_digest, stamp_json
             FROM artifact_dependency_stamps WHERE stamp_id=?1",
            [id.to_string()],
            stamp_row,
        )
        .optional()?;
    row.map(decode_stamp_row).transpose()
}

fn read_dependency_stamp_for_certificate_context(
    connection: &Connection,
    certificate: ArtifactValidationCertificateId,
    context: RepositoryContextId,
) -> Result<Option<DependencyStamp>, StoreError> {
    let row = connection
        .query_row(
            "SELECT stamp_id, artifact_id, certificate_id, repository_lineage,
                    repository_context_id, repository_generation, repository_generation_digest,
                    dependency_manifest_digest, dependency_locator_set_digest,
                    intersection_definition_digest, definition_generation,
                    definition_generation_digest, semantic_definition_set_digest,
                    validation_definition_set_digest, operational_definition_set_digest,
                    semantic_world_digest, stamp_json
             FROM artifact_dependency_stamps
             WHERE certificate_id=?1 AND repository_context_id=?2",
            params![certificate.to_string(), context.to_string()],
            stamp_row,
        )
        .optional()?;
    row.map(decode_stamp_row).transpose()
}

fn stamp_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StampRow> {
    Ok(StampRow {
        stamp_id: row.get(0)?,
        artifact_id: row.get(1)?,
        certificate_id: row.get(2)?,
        repository_lineage: row.get(3)?,
        repository_context: row.get(4)?,
        repository_generation: row.get(5)?,
        repository_generation_digest: row.get(6)?,
        dependency_manifest_digest: row.get(7)?,
        dependency_locator_set_digest: row.get(8)?,
        intersection_definition_digest: row.get(9)?,
        definition_generation: row.get(10)?,
        definition_generation_digest: row.get(11)?,
        semantic_definition_set_digest: row.get(12)?,
        validation_definition_set_digest: row.get(13)?,
        operational_definition_set_digest: row.get(14)?,
        semantic_world_digest: row.get(15)?,
        stamp_json: row.get(16)?,
    })
}

fn decode_stamp_row(row: StampRow) -> Result<DependencyStamp, StoreError> {
    let stamp = DependencyStamp::decode_json(row.stamp_json.as_bytes()).map_err(|error| {
        StoreError::DependencyValidityCorruption(format!(
            "stored dependency stamp is invalid: {error}"
        ))
    })?;
    if stamp.id != parse_dependency_stamp_id(&row.stamp_id)?
        || stamp.artifact != parse_artifact_id(&row.artifact_id)?
        || stamp.validation_certificate != parse_certificate_id(&row.certificate_id)?
        || stamp.repository_lineage
            != validity_digest(&row.repository_lineage, "repository lineage")?
        || stamp.repository_context
            != RepositoryContextId::new(validity_digest(
                &row.repository_context,
                "repository context",
            )?)
        || stamp.repository_generation != validity_generation_from_sql(row.repository_generation)?
        || stamp.repository_generation_digest
            != validity_digest(&row.repository_generation_digest, "repository generation digest")?
        || stamp.dependency_manifest_digest
            != validity_digest(&row.dependency_manifest_digest, "dependency manifest digest")?
        || stamp.dependency_locator_set_digest
            != validity_digest(&row.dependency_locator_set_digest, "dependency locator set digest")?
        || stamp.intersection_definition_digest
            != validity_digest(
                &row.intersection_definition_digest,
                "intersection definition digest",
            )?
        || stamp.definition_generation != validity_generation_from_sql(row.definition_generation)?
        || stamp.definition_generation_digest
            != validity_digest(&row.definition_generation_digest, "definition generation digest")?
        || stamp.semantic_definition_set_digest
            != validity_digest(
                &row.semantic_definition_set_digest,
                "semantic definition set digest",
            )?
        || stamp.validation_definition_set_digest
            != validity_digest(
                &row.validation_definition_set_digest,
                "validation definition set digest",
            )?
        || stamp.operational_definition_set_digest
            != validity_digest(
                &row.operational_definition_set_digest,
                "operational definition set digest",
            )?
        || stamp.semantic_world_digest
            != validity_digest(&row.semantic_world_digest, "semantic world digest")?
    {
        return Err(StoreError::DependencyValidityCorruption(
            "stored dependency stamp columns do not match its canonical record".to_owned(),
        ));
    }
    Ok(stamp)
}

pub(super) fn insert_operational_validity_memo(
    connection: &Connection,
    memo: &OperationalValidityMemo,
) -> Result<(), StoreError> {
    memo.validate()?;
    let json = serde_json::to_string(memo)?;
    if json.len() > MAX_OPERATIONAL_VALIDITY_MEMO_WIRE_BYTES {
        return Err(StoreError::DependencyValidityValidation(
            needle_core::DependencyValidityRecordError::WireBound {
                record: "operational_validity_memo",
                actual: json.len(),
                maximum: MAX_OPERATIONAL_VALIDITY_MEMO_WIRE_BYTES,
            },
        ));
    }
    connection.execute(
        "INSERT INTO operational_validity_memos(
            memo_id, dependency_stamp_id, artifact_id, certificate_id,
            repository_lineage, repository_context_id, source_generation,
            validated_through_generation, validated_through_generation_digest,
            definition_generation, definition_generation_digest,
            semantic_definition_set_digest, validation_definition_set_digest,
            operational_definition_set_digest, input_artifact_state_digest,
            external_version_state_digest, delta_chain_digest,
            intersection_definition_digest, outcome, memo_json, created_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                  ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
        params![
            memo.id.to_string(),
            memo.dependency_stamp.to_string(),
            memo.artifact.to_string(),
            memo.validation_certificate.to_string(),
            memo.repository_lineage.to_string(),
            memo.repository_context.to_string(),
            validity_generation_to_sql(memo.source_generation)?,
            validity_generation_to_sql(memo.validated_through_generation)?,
            memo.validated_through_generation_digest.to_string(),
            validity_generation_to_sql(memo.definition_generation)?,
            memo.definition_generation_digest.to_string(),
            memo.semantic_definition_set_digest.to_string(),
            memo.validation_definition_set_digest.to_string(),
            memo.operational_definition_set_digest.to_string(),
            memo.input_artifact_state_digest.to_string(),
            memo.external_version_state_digest.to_string(),
            memo.delta_chain_digest.to_string(),
            memo.intersection_definition_digest.to_string(),
            outcome_name(memo.outcome),
            json,
            now_ms(),
        ],
    )?;
    Ok(())
}

fn read_operational_validity_memo(
    connection: &Connection,
    id: OperationalValidityMemoId,
) -> Result<Option<OperationalValidityMemo>, StoreError> {
    let row = connection
        .query_row(
            "SELECT memo_id, dependency_stamp_id, artifact_id, certificate_id,
                    repository_lineage, repository_context_id, source_generation,
                    validated_through_generation, validated_through_generation_digest,
                    definition_generation, definition_generation_digest,
                    semantic_definition_set_digest, validation_definition_set_digest,
                    operational_definition_set_digest, input_artifact_state_digest,
                    external_version_state_digest, delta_chain_digest,
                    intersection_definition_digest, outcome, memo_json
             FROM operational_validity_memos WHERE memo_id=?1",
            [id.to_string()],
            memo_row,
        )
        .optional()?;
    row.map(decode_memo_row).transpose()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn read_operational_validity_memo_for_state(
    connection: &Connection,
    stamp: DependencyStampId,
    generation_digest: Digest,
    definition_generation_digest: Digest,
    input_state: Digest,
    external_state: Digest,
    intersection_definition: Digest,
) -> Result<Option<OperationalValidityMemo>, StoreError> {
    let row = connection
        .query_row(
            "SELECT memo_id, dependency_stamp_id, artifact_id, certificate_id,
                    repository_lineage, repository_context_id, source_generation,
                    validated_through_generation, validated_through_generation_digest,
                    definition_generation, definition_generation_digest,
                    semantic_definition_set_digest, validation_definition_set_digest,
                    operational_definition_set_digest, input_artifact_state_digest,
                    external_version_state_digest, delta_chain_digest,
                    intersection_definition_digest, outcome, memo_json
             FROM operational_validity_memos
             WHERE dependency_stamp_id=?1
               AND validated_through_generation_digest=?2
               AND definition_generation_digest=?3
               AND input_artifact_state_digest=?4
               AND external_version_state_digest=?5
               AND intersection_definition_digest=?6",
            params![
                stamp.to_string(),
                generation_digest.to_string(),
                definition_generation_digest.to_string(),
                input_state.to_string(),
                external_state.to_string(),
                intersection_definition.to_string(),
            ],
            memo_row,
        )
        .optional()?;
    row.map(decode_memo_row).transpose()
}

fn memo_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoRow> {
    Ok(MemoRow {
        memo_id: row.get(0)?,
        dependency_stamp_id: row.get(1)?,
        artifact_id: row.get(2)?,
        certificate_id: row.get(3)?,
        repository_lineage: row.get(4)?,
        repository_context: row.get(5)?,
        source_generation: row.get(6)?,
        validated_through_generation: row.get(7)?,
        validated_through_generation_digest: row.get(8)?,
        definition_generation: row.get(9)?,
        definition_generation_digest: row.get(10)?,
        semantic_definition_set_digest: row.get(11)?,
        validation_definition_set_digest: row.get(12)?,
        operational_definition_set_digest: row.get(13)?,
        input_artifact_state_digest: row.get(14)?,
        external_version_state_digest: row.get(15)?,
        delta_chain_digest: row.get(16)?,
        intersection_definition_digest: row.get(17)?,
        outcome: row.get(18)?,
        memo_json: row.get(19)?,
    })
}

fn decode_memo_row(row: MemoRow) -> Result<OperationalValidityMemo, StoreError> {
    let memo = OperationalValidityMemo::decode_json(row.memo_json.as_bytes()).map_err(|error| {
        StoreError::DependencyValidityCorruption(format!(
            "stored operational validity memo is invalid: {error}"
        ))
    })?;
    if memo.id != parse_memo_id(&row.memo_id)?
        || memo.dependency_stamp != parse_dependency_stamp_id(&row.dependency_stamp_id)?
        || memo.artifact != parse_artifact_id(&row.artifact_id)?
        || memo.validation_certificate != parse_certificate_id(&row.certificate_id)?
        || memo.repository_lineage
            != validity_digest(&row.repository_lineage, "repository lineage")?
        || memo.repository_context
            != RepositoryContextId::new(validity_digest(
                &row.repository_context,
                "repository context",
            )?)
        || memo.source_generation != validity_generation_from_sql(row.source_generation)?
        || memo.validated_through_generation
            != validity_generation_from_sql(row.validated_through_generation)?
        || memo.validated_through_generation_digest
            != validity_digest(
                &row.validated_through_generation_digest,
                "validated-through generation digest",
            )?
        || memo.definition_generation != validity_generation_from_sql(row.definition_generation)?
        || memo.definition_generation_digest
            != validity_digest(&row.definition_generation_digest, "definition generation digest")?
        || memo.semantic_definition_set_digest
            != validity_digest(
                &row.semantic_definition_set_digest,
                "semantic definition set digest",
            )?
        || memo.validation_definition_set_digest
            != validity_digest(
                &row.validation_definition_set_digest,
                "validation definition set digest",
            )?
        || memo.operational_definition_set_digest
            != validity_digest(
                &row.operational_definition_set_digest,
                "operational definition set digest",
            )?
        || memo.input_artifact_state_digest
            != validity_digest(&row.input_artifact_state_digest, "input artifact state digest")?
        || memo.external_version_state_digest
            != validity_digest(&row.external_version_state_digest, "external version state digest")?
        || memo.delta_chain_digest
            != validity_digest(&row.delta_chain_digest, "delta chain digest")?
        || memo.intersection_definition_digest
            != validity_digest(
                &row.intersection_definition_digest,
                "intersection definition digest",
            )?
        || outcome_name(memo.outcome) != row.outcome
    {
        return Err(StoreError::DependencyValidityCorruption(
            "stored operational validity memo columns do not match its canonical record".to_owned(),
        ));
    }
    Ok(memo)
}

fn outcome_name(outcome: OperationalValidityOutcome) -> &'static str {
    match outcome {
        OperationalValidityOutcome::Current => "current",
        OperationalValidityOutcome::UnaffectedByDelta => "unaffected_by_delta",
    }
}

fn parse_dependency_stamp_id(value: &str) -> Result<DependencyStampId, StoreError> {
    validity_digest(value, "dependency stamp id").map(DependencyStampId::new)
}

fn parse_memo_id(value: &str) -> Result<OperationalValidityMemoId, StoreError> {
    validity_digest(value, "operational validity memo id").map(OperationalValidityMemoId::new)
}

fn parse_artifact_id(value: &str) -> Result<ArtifactId, StoreError> {
    validity_digest(value, "artifact id").map(ArtifactId::new)
}

fn parse_certificate_id(value: &str) -> Result<ArtifactValidationCertificateId, StoreError> {
    validity_digest(value, "validation certificate id").map(ArtifactValidationCertificateId::new)
}

fn validity_digest(value: &str, field: &str) -> Result<Digest, StoreError> {
    parse_digest(value).map_err(|error| {
        StoreError::DependencyValidityCorruption(format!("stored {field} is invalid: {error}"))
    })
}

fn validity_generation_to_sql(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| {
        StoreError::DependencyValidityConflict(
            "dependency validity generation exceeds SQLite integer range".to_owned(),
        )
    })
}

fn validity_generation_from_sql(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| {
        StoreError::DependencyValidityCorruption(
            "stored dependency validity generation is negative".to_owned(),
        )
    })
}
