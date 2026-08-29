use super::{RuntimeStore, StoreError, now_ms};
use crate::{ShadowPartitionManifestPublication, ShadowPartitionedActionArtifactPublication};
use needle_core::{
    ActionContractId, ActionRequest, ArtifactId, ArtifactRequestId,
    ArtifactValidationCertificateId, CanonicalHasher, CapabilityMode, Digest, MAX_NEED_IR_BYTES,
    PartitionManifestId, RepositoryContextId,
};
use rusqlite::{Connection, OptionalExtension, params};

pub const MAX_PARTITION_SOURCE_VALIDATION_WIRE_BYTES: usize = 64 * 1024;
pub const PARTITIONED_ACTION_HEAD_FORMAT_REVISION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionedActionHeadKey {
    pub format_revision: u16,
    pub id: Digest,
    pub action_contract: ActionContractId,
    pub repository_lineage: Digest,
    pub repository_context: RepositoryContextId,
    pub source_selector: String,
    pub provider_context_digest: Digest,
    pub scope_digest: Digest,
}

impl PartitionedActionHeadKey {
    pub fn new(
        action_contract: ActionContractId,
        repository_lineage: Digest,
        repository_context: RepositoryContextId,
        source_selector: impl Into<String>,
        provider_context_digest: Digest,
        scope_digest: Digest,
    ) -> Result<Self, StoreError> {
        let mut value = Self {
            format_revision: PARTITIONED_ACTION_HEAD_FORMAT_REVISION,
            id: Digest([0; 32]),
            action_contract,
            repository_lineage,
            repository_context,
            source_selector: source_selector.into(),
            provider_context_digest,
            scope_digest,
        };
        value.validate_shape()?;
        value.id = value.compute_id();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        self.validate_shape()?;
        if self.id != self.compute_id() {
            return Err(corruption("partitioned action head key digest is invalid"));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), StoreError> {
        if self.format_revision != PARTITIONED_ACTION_HEAD_FORMAT_REVISION {
            return Err(corruption("partitioned action head key revision is unsupported"));
        }
        if self.source_selector.is_empty()
            || self.source_selector.len() > MAX_NEED_IR_BYTES
            || self.source_selector.chars().any(char::is_control)
        {
            return Err(corruption("partitioned action head source selector is invalid"));
        }
        if [
            self.repository_lineage,
            self.repository_context.digest(),
            self.provider_context_digest,
            self.scope_digest,
        ]
        .contains(&Digest([0; 32]))
        {
            return Err(corruption("partitioned action head key contains a zero digest"));
        }
        Ok(())
    }

    fn compute_id(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"partitioned-action-head-key-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(self.action_contract.as_str());
        hasher.field_digest(self.repository_lineage);
        hasher.field_digest(self.repository_context.digest());
        hasher.field_str(&self.source_selector);
        hasher.field_digest(self.provider_context_digest);
        hasher.field_digest(self.scope_digest);
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionedActionHeadRecord {
    pub key: PartitionedActionHeadKey,
    pub repository_generation: u64,
    pub request: ArtifactRequestId,
    pub artifact: ArtifactId,
    pub validation_certificate: ArtifactValidationCertificateId,
    pub descriptor_definition_digest: Digest,
    pub partition_manifest: PartitionManifestId,
    pub source_validation_certificate_digest: Digest,
    pub content_digest: Digest,
    pub authority: CapabilityMode,
    pub recorded_unix_ms: u64,
}

impl PartitionedActionHeadRecord {
    fn validate(&self) -> Result<(), StoreError> {
        self.key.validate()?;
        if self.authority != CapabilityMode::Shadow
            || [
                self.request.digest(),
                self.artifact.digest(),
                self.validation_certificate.digest(),
                self.descriptor_definition_digest,
                self.partition_manifest.digest(),
                self.source_validation_certificate_digest,
                self.content_digest,
            ]
            .contains(&Digest([0; 32]))
        {
            return Err(corruption("partitioned action head record is invalid"));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct ShadowPartitionedActionHeadAdvance<'a> {
    pub key: PartitionedActionHeadKey,
    pub expected_prior_artifact: Option<ArtifactId>,
    pub repository_generation: u64,
    pub source_validation_certificate_digest: Digest,
    pub source_validation_validator_definition_digest: Digest,
    pub source_validation_json: &'a [u8],
    pub content_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowPartitionedActionHeadBase {
    pub head: PartitionedActionHeadRecord,
    pub request: ActionRequest,
    pub manifest: ShadowPartitionManifestPublication,
    pub publication: ShadowPartitionedActionArtifactPublication,
    pub source_validation_json: Vec<u8>,
}

impl RuntimeStore {
    pub fn partitioned_action_head(
        &self,
        key: &PartitionedActionHeadKey,
    ) -> Result<Option<PartitionedActionHeadRecord>, StoreError> {
        key.validate()?;
        let connection = self.connection()?;
        read_head(&connection, key)
    }

    pub fn partitioned_action_head_base(
        &self,
        key: &PartitionedActionHeadKey,
    ) -> Result<Option<ShadowPartitionedActionHeadBase>, StoreError> {
        let Some(head) = self.partitioned_action_head(key)? else {
            return Ok(None);
        };
        let (request_json, source_validation_json, source_validation_validator) = {
            let connection = self.connection()?;
            let request_json: String = connection.query_row(
                "SELECT request_json FROM artifact_requests WHERE request_id=?1",
                [head.request.to_string()],
                |row| row.get(0),
            )?;
            let (source_validation_json, source_validation_validator) = read_source_validation(
                &connection,
                head.source_validation_certificate_digest,
                &head,
            )?;
            (request_json, source_validation_json, source_validation_validator)
        };
        if request_json.len() > super::MAX_STORED_ACTION_REQUEST_JSON_BYTES {
            return Err(corruption("stored partitioned action request exceeds its bound"));
        }
        let request: ActionRequest = serde_json::from_str(&request_json)?;
        let artifact = self
            .semantic_artifact(&head.artifact.to_string())?
            .ok_or_else(|| corruption("partitioned action head artifact is missing"))?;
        let action = crate::built_in_action_for_artifact_kind(&artifact.contract.kind)
            .ok_or_else(|| corruption("partitioned action definition is unavailable"))?;
        request.validate(&action.contract).map_err(|error| corruption(error.to_string()))?;
        if request.semantic_id() != head.request || request.contract != key.action_contract {
            return Err(corruption("stored partitioned action request does not bind its head"));
        }
        let certificate = self
            .action_artifact_validation_certificate(head.validation_certificate)?
            .ok_or_else(|| corruption("partitioned action head certificate is missing"))?;
        if source_validation_validator != certificate.validator_definition_digest {
            return Err(corruption(
                "partition source validation validator does not bind the action certificate",
            ));
        }
        let descriptor = self
            .stored_reuse_descriptor(head.descriptor_definition_digest)?
            .ok_or_else(|| corruption("partitioned action head descriptor is missing"))?;
        let manifest = self
            .partition_manifest_publication(head.partition_manifest)?
            .ok_or_else(|| corruption("partitioned action head manifest is missing"))?;
        let publication =
            ShadowPartitionedActionArtifactPublication { artifact, certificate, descriptor };
        publication.validate(&request, &manifest).map_err(|error| corruption(error.to_string()))?;
        Ok(Some(ShadowPartitionedActionHeadBase {
            head,
            request,
            manifest,
            publication,
            source_validation_json,
        }))
    }

    pub(crate) fn advance_existing_partitioned_action_head(
        &self,
        advance: ShadowPartitionedActionHeadAdvance<'_>,
    ) -> Result<PartitionedActionHeadRecord, StoreError> {
        let mut connection = self.connection()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let existing = read_head(&transaction, &advance.key)?
            .ok_or_else(|| conflict("partitioned action head is missing"))?;
        let publication = load_publication_for_head(&transaction, &existing)?;
        let record = insert_head_advance(&transaction, &publication.0, &publication.1, advance)?;
        transaction.commit()?;
        Ok(record)
    }
}

pub(super) fn insert_head_advance(
    connection: &Connection,
    request: &ActionRequest,
    publication: &ShadowPartitionedActionArtifactPublication,
    advance: ShadowPartitionedActionHeadAdvance<'_>,
) -> Result<PartitionedActionHeadRecord, StoreError> {
    advance.key.validate()?;
    publication
        .validate(
            request,
            &super::partition_manifest_store::read_publication(
                connection,
                publication.certificate().partition_manifest,
            )?
            .ok_or_else(|| conflict("partitioned action head manifest is not persisted"))?,
        )
        .map_err(|error| conflict(error.to_string()))?;
    if advance.source_validation_json.is_empty()
        || advance.source_validation_json.len() > MAX_PARTITION_SOURCE_VALIDATION_WIRE_BYTES
    {
        return Err(conflict("partition source validation JSON exceeds its bound"));
    }
    let _: serde_json::Value = serde_json::from_slice(advance.source_validation_json)?;
    if advance.key.action_contract != request.contract
        || advance.key.repository_lineage
            != publication.certificate().coverage.world.repository_lineage
        || advance.key.source_selector != publication.certificate().coverage.world.source_selector
        || advance.source_validation_certificate_digest
            != publication.certificate().source_validation_certificate_digest
        || advance.source_validation_validator_definition_digest
            != publication.certificate().validator_definition_digest
        || advance.content_digest != publication.certificate().source_payload_digest
    {
        return Err(conflict("partitioned action head advance does not bind its publication"));
    }
    insert_source_validation(connection, publication, &advance)?;
    let record = PartitionedActionHeadRecord {
        key: advance.key.clone(),
        repository_generation: advance.repository_generation,
        request: request.semantic_id(),
        artifact: ArtifactId::new(publication.artifact().id),
        validation_certificate: publication.certificate().id,
        descriptor_definition_digest: publication.descriptor().definition_digest,
        partition_manifest: publication.certificate().partition_manifest,
        source_validation_certificate_digest: advance.source_validation_certificate_digest,
        content_digest: advance.content_digest,
        authority: CapabilityMode::Shadow,
        recorded_unix_ms: now_ms(),
    };
    record.validate()?;
    let existing = read_head(connection, &advance.key)?;
    match existing {
        None if advance.expected_prior_artifact.is_some() => {
            return Err(conflict("partitioned action head expected a missing prior artifact"));
        }
        None => insert_head_history(connection, &record)?,
        Some(current) if same_head_state(&current, &record) => return Ok(current),
        Some(current) => {
            if Some(current.artifact) != advance.expected_prior_artifact
                || record.repository_generation <= current.repository_generation
            {
                return Err(conflict("partitioned action head compare-and-swap failed"));
            }
            insert_head_history(connection, &record)?;
        }
    }
    upsert_head(connection, &record, advance.expected_prior_artifact)?;
    Ok(record)
}

fn same_head_state(
    left: &PartitionedActionHeadRecord,
    right: &PartitionedActionHeadRecord,
) -> bool {
    left.key == right.key
        && left.repository_generation == right.repository_generation
        && left.request == right.request
        && left.artifact == right.artifact
        && left.validation_certificate == right.validation_certificate
        && left.descriptor_definition_digest == right.descriptor_definition_digest
        && left.partition_manifest == right.partition_manifest
        && left.source_validation_certificate_digest == right.source_validation_certificate_digest
        && left.content_digest == right.content_digest
        && left.authority == right.authority
}

fn insert_source_validation(
    connection: &Connection,
    publication: &ShadowPartitionedActionArtifactPublication,
    advance: &ShadowPartitionedActionHeadAdvance<'_>,
) -> Result<(), StoreError> {
    let json = std::str::from_utf8(advance.source_validation_json)
        .map_err(|_| conflict("partition source validation JSON is not UTF-8"))?;
    let existing = connection
        .query_row(
            "SELECT action_contract_id, source_payload_digest,
                    validator_definition_digest, validation_json, authority
             FROM partitioned_action_source_validations WHERE validation_digest=?1",
            [advance.source_validation_certificate_digest.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    let expected = (
        publication.certificate().action_contract.as_str(),
        publication.certificate().source_payload_digest.to_string(),
        advance.source_validation_validator_definition_digest.to_string(),
        json,
        "shadow",
    );
    if let Some(existing) = existing {
        if existing.0 != expected.0
            || existing.1 != expected.1
            || existing.2 != expected.2
            || existing.3 != expected.3
            || existing.4 != expected.4
        {
            return Err(conflict("partition source validation digest has different content"));
        }
        return Ok(());
    }
    connection.execute(
        "INSERT INTO partitioned_action_source_validations(
            validation_digest, action_contract_id, source_payload_digest,
            validator_definition_digest, validation_json, authority, created_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, 'shadow', ?6)",
        params![
            advance.source_validation_certificate_digest.to_string(),
            publication.certificate().action_contract.as_str(),
            publication.certificate().source_payload_digest.to_string(),
            advance.source_validation_validator_definition_digest.to_string(),
            json,
            u64_to_sql(now_ms())?,
        ],
    )?;
    Ok(())
}

fn insert_head_history(
    connection: &Connection,
    record: &PartitionedActionHeadRecord,
) -> Result<(), StoreError> {
    connection.execute(
        "INSERT INTO partitioned_action_head_history(
            head_key, repository_generation, action_contract_id, repository_lineage,
            repository_context_id, source_selector, provider_context_digest, scope_digest,
            request_id, artifact_id, validation_certificate_id, descriptor_digest,
            partition_manifest_id, source_validation_digest, content_digest, authority,
            recorded_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                  'shadow', ?16)",
        rusqlite::params_from_iter(head_param_values(record)?),
    )?;
    Ok(())
}

fn upsert_head(
    connection: &Connection,
    record: &PartitionedActionHeadRecord,
    expected_prior_artifact: Option<ArtifactId>,
) -> Result<(), StoreError> {
    match expected_prior_artifact {
        None => {
            connection.execute(
                "INSERT INTO partitioned_action_heads(
                    head_key, repository_generation, action_contract_id, repository_lineage,
                    repository_context_id, source_selector, provider_context_digest, scope_digest,
                    request_id, artifact_id, validation_certificate_id, descriptor_digest,
                    partition_manifest_id, source_validation_digest, content_digest, authority,
                    recorded_unix_ms
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                          ?15, 'shadow', ?16)",
                rusqlite::params_from_iter(head_param_values(record)?),
            )?;
        }
        Some(expected) => {
            let updated = connection.execute(
                "UPDATE partitioned_action_heads SET
                    repository_generation=?2, action_contract_id=?3, repository_lineage=?4,
                    repository_context_id=?5, source_selector=?6, provider_context_digest=?7,
                    scope_digest=?8, request_id=?9, artifact_id=?10,
                    validation_certificate_id=?11, descriptor_digest=?12,
                    partition_manifest_id=?13, source_validation_digest=?14,
                    content_digest=?15, authority='shadow', recorded_unix_ms=?16
                 WHERE head_key=?1 AND artifact_id=?17",
                rusqlite::params_from_iter(
                    head_param_values(record)?
                        .into_iter()
                        .chain([rusqlite::types::Value::Text(expected.to_string())]),
                ),
            )?;
            if updated != 1 {
                return Err(conflict("partitioned action head changed during update"));
            }
        }
    }
    Ok(())
}

fn head_param_values(
    record: &PartitionedActionHeadRecord,
) -> Result<Vec<rusqlite::types::Value>, StoreError> {
    Ok(vec![
        record.key.id.to_string().into(),
        u64_to_sql(record.repository_generation)?.into(),
        record.key.action_contract.as_str().to_owned().into(),
        record.key.repository_lineage.to_string().into(),
        record.key.repository_context.to_string().into(),
        record.key.source_selector.clone().into(),
        record.key.provider_context_digest.to_string().into(),
        record.key.scope_digest.to_string().into(),
        record.request.to_string().into(),
        record.artifact.to_string().into(),
        record.validation_certificate.to_string().into(),
        record.descriptor_definition_digest.to_string().into(),
        record.partition_manifest.to_string().into(),
        record.source_validation_certificate_digest.to_string().into(),
        record.content_digest.to_string().into(),
        u64_to_sql(record.recorded_unix_ms)?.into(),
    ])
}

fn read_head(
    connection: &Connection,
    key: &PartitionedActionHeadKey,
) -> Result<Option<PartitionedActionHeadRecord>, StoreError> {
    let row = connection
        .query_row(
            "SELECT repository_generation, action_contract_id, repository_lineage,
                    repository_context_id, source_selector, provider_context_digest, scope_digest,
                    request_id, artifact_id, validation_certificate_id, descriptor_digest,
                    partition_manifest_id, source_validation_digest, content_digest, authority,
                    recorded_unix_ms
             FROM partitioned_action_heads WHERE head_key=?1",
            [key.id.to_string()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, i64>(15)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else { return Ok(None) };
    let stored_key = PartitionedActionHeadKey::new(
        ActionContractId::new(&row.1).map_err(|error| corruption(error.to_string()))?,
        parse_digest(&row.2, "repository lineage")?,
        RepositoryContextId::new(parse_digest(&row.3, "repository context")?),
        row.4,
        parse_digest(&row.5, "provider context")?,
        parse_digest(&row.6, "scope")?,
    )?;
    if stored_key != *key || row.14 != "shadow" {
        return Err(corruption("stored partitioned action head key or authority is invalid"));
    }
    let record = PartitionedActionHeadRecord {
        key: stored_key,
        repository_generation: u64::try_from(row.0)
            .map_err(|_| corruption("partitioned action head generation is negative"))?,
        request: ArtifactRequestId::new(parse_digest(&row.7, "request")?),
        artifact: ArtifactId::new(parse_digest(&row.8, "artifact")?),
        validation_certificate: ArtifactValidationCertificateId::new(parse_digest(
            &row.9,
            "validation certificate",
        )?),
        descriptor_definition_digest: parse_digest(&row.10, "descriptor")?,
        partition_manifest: PartitionManifestId::new(parse_digest(&row.11, "manifest")?),
        source_validation_certificate_digest: parse_digest(&row.12, "source validation")?,
        content_digest: parse_digest(&row.13, "content")?,
        authority: CapabilityMode::Shadow,
        recorded_unix_ms: u64::try_from(row.15)
            .map_err(|_| corruption("partitioned action head timestamp is negative"))?,
    };
    record.validate()?;
    Ok(Some(record))
}

fn read_source_validation(
    connection: &Connection,
    digest: Digest,
    head: &PartitionedActionHeadRecord,
) -> Result<(Vec<u8>, Digest), StoreError> {
    let row = connection.query_row(
        "SELECT action_contract_id, source_payload_digest,
                validator_definition_digest, validation_json, authority
         FROM partitioned_action_source_validations WHERE validation_digest=?1",
        [digest.to_string()],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        },
    )?;
    if row.0 != head.key.action_contract.as_str()
        || row.1 != head.content_digest.to_string()
        || row.4 != "shadow"
        || row.3.len() > MAX_PARTITION_SOURCE_VALIDATION_WIRE_BYTES
    {
        return Err(corruption("partition source validation columns are invalid"));
    }
    let _: serde_json::Value = serde_json::from_str(&row.3)?;
    let validator = parse_digest(&row.2, "source validation validator")?;
    Ok((row.3.into_bytes(), validator))
}

fn load_publication_for_head(
    connection: &Connection,
    head: &PartitionedActionHeadRecord,
) -> Result<(ActionRequest, ShadowPartitionedActionArtifactPublication), StoreError> {
    let request_json: String = connection.query_row(
        "SELECT request_json FROM artifact_requests WHERE request_id=?1",
        [head.request.to_string()],
        |row| row.get(0),
    )?;
    if request_json.len() > super::MAX_STORED_ACTION_REQUEST_JSON_BYTES {
        return Err(corruption("stored partitioned action request exceeds its bound"));
    }
    let request: ActionRequest = serde_json::from_str(&request_json)?;
    let artifact_json: String = connection.query_row(
        "SELECT artifact_json FROM artifacts WHERE artifact_id=?1",
        [head.artifact.to_string()],
        |row| row.get(0),
    )?;
    if artifact_json.len()
        > super::partitioned_artifacts::MAX_PARTITIONED_ACTION_ARTIFACT_WIRE_BYTES
    {
        return Err(corruption("stored partitioned action artifact exceeds its bound"));
    }
    let artifact = serde_json::from_str(&artifact_json)?;
    let certificate = super::partitioned_artifacts::read_action_certificate(
        connection,
        head.validation_certificate,
    )?
    .ok_or_else(|| corruption("partitioned action head certificate is missing"))?;
    let descriptor = super::partitioned_artifacts::read_reuse_descriptor(
        connection,
        head.descriptor_definition_digest,
    )?
    .ok_or_else(|| corruption("partitioned action head descriptor is missing"))?;
    Ok((request, ShadowPartitionedActionArtifactPublication { artifact, certificate, descriptor }))
}

fn parse_digest(value: &str, field: &'static str) -> Result<Digest, StoreError> {
    Digest::parse(value)
        .map_err(|_| corruption(format!("partitioned action head {field} is invalid")))
}

fn u64_to_sql(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| conflict("partitioned action head value exceeds SQLite range"))
}

fn conflict(message: impl Into<String>) -> StoreError {
    StoreError::PartitionedActionHeadConflict(message.into())
}

fn corruption(message: impl Into<String>) -> StoreError {
    StoreError::PartitionedActionHeadCorruption(message.into())
}

#[cfg(test)]
#[path = "partitioned_heads/tests.rs"]
mod tests;
