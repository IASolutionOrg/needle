use super::{RuntimeStore, StoreError, now_ms};
use crate::{ShadowPartitionManifestPublication, built_in_partition_for_scheme};
use needle_core::{
    ActionContractId, ArtifactRequestId, CapabilityMode, Digest,
    MAX_PARTITION_MANIFEST_CERTIFICATE_WIRE_BYTES, MAX_PARTITION_MANIFEST_ENTRIES,
    MAX_PARTITION_MANIFEST_WIRE_BYTES, ManifestClosure, ManifestTransition, ManifestTransitionId,
    PartitionManifest, PartitionManifestId, PartitionManifestValidationCertificate,
    PartitionManifestValidationCertificateId, PartitionRole, PartitionSchemeId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

pub const MAX_PARTITION_MANIFEST_LIST_LIMIT: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionManifestSummaryRecord {
    pub manifest: PartitionManifestId,
    pub certificate: PartitionManifestValidationCertificateId,
    pub action_request: ArtifactRequestId,
    pub action_contract: ActionContractId,
    pub output_contract: String,
    pub scheme: PartitionSchemeId,
    pub repository: Digest,
    pub closure: ManifestClosure,
    pub entry_count: u32,
    pub created_unix_ms: u64,
}

struct ManifestRow {
    manifest_id: String,
    scheme_id: String,
    action_request_id: String,
    action_contract_id: String,
    output_contract_id: String,
    repository_lineage: String,
    semantic_world_digest: String,
    definition_set_digest: String,
    closure: String,
    entry_count: i64,
    definition_digest: String,
    manifest_json: String,
    created_unix_ms: i64,
}

struct CertificateRow {
    certificate_id: String,
    policy_id: String,
    scheme_definition_digest: String,
    policy_definition_digest: String,
    declared_policy_authority_digest: String,
    validator_id: String,
    validator_definition_digest: String,
    adapter_definition_digest: String,
    source_payload_digest: String,
    source_validation_certificate_digest: String,
    definition_digest: String,
    issued_mode: String,
    certificate_json: String,
}

struct TransitionRow {
    transition_id: String,
    prior_manifest_id: String,
    current_manifest_id: String,
    state_delta: String,
    validator_id: String,
    definition_digest: String,
    transition_json: String,
}

pub(super) struct PreparedManifestPublication {
    manifest_json: String,
    certificate_json: String,
}

pub(super) struct PreparedManifestTransition {
    transition_json: String,
}

impl RuntimeStore {
    /// Persist a fully certified Shadow publication. This is an append-only
    /// audit boundary and does not make the manifest eligible for serving.
    pub fn publish_shadow_partition_manifest(
        &self,
        publication: &ShadowPartitionManifestPublication,
    ) -> Result<ShadowPartitionManifestPublication, StoreError> {
        let prepared = prepare_manifest_publication(publication)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_manifest_publication(&transaction, publication, &prepared, now_ms())?;
        transaction.commit()?;
        Ok(publication.clone())
    }

    pub fn partition_manifest_publication(
        &self,
        manifest: PartitionManifestId,
    ) -> Result<Option<ShadowPartitionManifestPublication>, StoreError> {
        let connection = self.connection()?;
        read_publication(&connection, manifest)
    }

    /// Lightweight bounded inspection. Full records remain available through
    /// `partition_manifest_publication` and are validated when loaded.
    pub fn list_partition_manifest_summaries(
        &self,
        limit: usize,
    ) -> Result<Vec<PartitionManifestSummaryRecord>, StoreError> {
        if limit == 0 || limit > MAX_PARTITION_MANIFEST_LIST_LIMIT {
            return Err(StoreError::PartitionManifestQuery(format!(
                "limit must be between 1 and {MAX_PARTITION_MANIFEST_LIST_LIMIT}"
            )));
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT m.manifest_id, c.certificate_id, m.action_request_id,
                    m.action_contract_id, m.output_contract_id, m.scheme_id,
                    m.repository_lineage, m.closure, m.entry_count, m.created_unix_ms
             FROM partition_manifests m
             JOIN partition_manifest_certificates c ON c.manifest_id=m.manifest_id
             ORDER BY m.created_unix_ms DESC, m.manifest_id ASC LIMIT ?1",
        )?;
        let rows = statement
            .query_map([limit as u64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().map(decode_summary).collect()
    }

    /// Record a validated Shadow transition for audit/inspection only. It is
    /// deliberately not consumed by the semantic resolver.
    pub fn record_shadow_manifest_transition(
        &self,
        transition: &ManifestTransition,
    ) -> Result<ManifestTransition, StoreError> {
        let prepared = prepare_manifest_transition(transition)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_manifest_transition(&transaction, transition, &prepared, now_ms())?;
        transaction.commit()?;
        Ok(transition.clone())
    }

    pub fn shadow_manifest_transition(
        &self,
        transition: ManifestTransitionId,
    ) -> Result<Option<ManifestTransition>, StoreError> {
        let connection = self.connection()?;
        read_transition(&connection, transition)
    }
}

pub(super) fn prepare_manifest_transition(
    transition: &ManifestTransition,
) -> Result<PreparedManifestTransition, StoreError> {
    transition.validate()?;
    let transition_json = serde_json::to_string(transition)?;
    ensure_wire_bound(
        "manifest transition",
        transition_json.len(),
        MAX_PARTITION_MANIFEST_WIRE_BYTES,
    )?;
    Ok(PreparedManifestTransition { transition_json })
}

pub(super) fn insert_manifest_transition(
    connection: &Connection,
    transition: &ManifestTransition,
    prepared: &PreparedManifestTransition,
    created_unix_ms: u64,
) -> Result<(), StoreError> {
    let prior = read_publication(connection, transition.prior)?.ok_or_else(|| {
        StoreError::PartitionManifestConflict("transition prior manifest is missing".to_owned())
    })?;
    let current = read_publication(connection, transition.current)?.ok_or_else(|| {
        StoreError::PartitionManifestConflict("transition current manifest is missing".to_owned())
    })?;
    if prior.manifest.scheme != current.manifest.scheme
        || prior.manifest.binding.action_contract != current.manifest.binding.action_contract
    {
        return Err(StoreError::PartitionManifestConflict(
            "transition manifests belong to different partition definitions".to_owned(),
        ));
    }
    let definition = built_in_partition_for_scheme(&prior.manifest.scheme).ok_or_else(|| {
        StoreError::PartitionManifestPublication(
            "transition partition definition is missing".to_owned(),
        )
    })?;
    if transition.validator != definition.policy.manifest_validator
        || transition.mappings.iter().any(|mapping| {
            !prior.manifest.contains(&mapping.prior) || !current.manifest.contains(&mapping.current)
        })
    {
        return Err(StoreError::PartitionManifestConflict(
            "transition validator or mapping does not bind stored manifests".to_owned(),
        ));
    }
    if let Some(existing) = read_transition(connection, transition.id)? {
        if existing != *transition {
            return Err(StoreError::PartitionManifestConflict(format!(
                "transition {} already has different immutable content",
                transition.id
            )));
        }
        return Ok(());
    }
    connection.execute(
        "INSERT INTO manifest_transitions(
            transition_id, prior_manifest_id, current_manifest_id, state_delta,
            validator_id, definition_digest, transition_json, created_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            transition.id.to_string(),
            transition.prior.to_string(),
            transition.current.to_string(),
            transition.state_delta.to_string(),
            transition.validator.as_str(),
            transition.definition_digest.to_string(),
            prepared.transition_json.as_str(),
            created_unix_ms,
        ],
    )?;
    for mapping in &transition.mappings {
        connection.execute(
            "INSERT INTO manifest_transition_mappings(
                transition_id, prior_manifest_id, prior_key_digest,
                current_manifest_id, current_key_digest
             ) VALUES(?1, ?2, ?3, ?4, ?5)",
            params![
                transition.id.to_string(),
                mapping.prior.manifest.to_string(),
                mapping.prior.key_digest.to_string(),
                mapping.current.manifest.to_string(),
                mapping.current.key_digest.to_string(),
            ],
        )?;
    }
    Ok(())
}

pub(super) fn prepare_manifest_publication(
    publication: &ShadowPartitionManifestPublication,
) -> Result<PreparedManifestPublication, StoreError> {
    publication
        .validate()
        .map_err(|error| StoreError::PartitionManifestPublication(error.to_string()))?;
    let manifest_json = serde_json::to_string(&publication.manifest)?;
    let certificate_json = serde_json::to_string(&publication.certificate)?;
    ensure_wire_bound(
        "partition manifest",
        manifest_json.len(),
        MAX_PARTITION_MANIFEST_WIRE_BYTES,
    )?;
    ensure_wire_bound(
        "partition manifest certificate",
        certificate_json.len(),
        MAX_PARTITION_MANIFEST_CERTIFICATE_WIRE_BYTES,
    )?;
    Ok(PreparedManifestPublication { manifest_json, certificate_json })
}

pub(super) fn insert_manifest_publication(
    connection: &Connection,
    publication: &ShadowPartitionManifestPublication,
    prepared: &PreparedManifestPublication,
    created_unix_ms: u64,
) -> Result<(), StoreError> {
    if let Some(existing) = read_publication(connection, publication.manifest.id)? {
        if existing != *publication {
            return Err(StoreError::PartitionManifestConflict(format!(
                "manifest {} already has different immutable content",
                publication.manifest.id
            )));
        }
        return Ok(());
    }

    connection.execute(
        "INSERT INTO partition_manifests(
            manifest_id, scheme_id, action_request_id, action_contract_id,
            output_contract_id, repository_lineage, semantic_world_digest,
            definition_set_digest, closure, entry_count, definition_digest,
            manifest_json, created_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            publication.manifest.id.to_string(),
            publication.manifest.scheme.as_str(),
            publication.manifest.binding.action_request.to_string(),
            publication.manifest.binding.action_contract.as_str(),
            publication.manifest.binding.output_contract.as_str(),
            publication.manifest.binding.repository.to_string(),
            publication.manifest.binding.semantic_world_digest.to_string(),
            publication.manifest.binding.definition_set_digest.to_string(),
            closure_text(publication.manifest.closure),
            publication.manifest.entries.len() as u64,
            publication.manifest.definition_digest.to_string(),
            prepared.manifest_json.as_str(),
            created_unix_ms,
        ],
    )?;
    for entry in &publication.manifest.entries {
        connection.execute(
            "INSERT INTO partition_manifest_entries(
                manifest_id, key_digest, role, payload_digest, dependency_digest
             ) VALUES(?1, ?2, ?3, ?4, ?5)",
            params![
                publication.manifest.id.to_string(),
                entry.key.digest.to_string(),
                role_text(entry.role),
                entry.payload_digest.to_string(),
                entry.dependencies.to_string(),
            ],
        )?;
    }
    let certificate = &publication.certificate;
    connection.execute(
        "INSERT INTO partition_manifest_certificates(
            certificate_id, manifest_id, policy_id, scheme_definition_digest,
            policy_definition_digest, declared_policy_authority_digest, validator_id,
            validator_definition_digest, adapter_definition_digest, source_payload_digest,
            source_validation_certificate_digest, definition_digest, issued_mode,
            certificate_json, created_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            certificate.id.to_string(),
            certificate.manifest.to_string(),
            certificate.partition_policy.as_str(),
            certificate.scheme_definition_digest.to_string(),
            certificate.policy_definition_digest.to_string(),
            certificate.declared_policy_authority_digest.to_string(),
            certificate.manifest_validator.as_str(),
            certificate.validator_definition_digest.to_string(),
            certificate.adapter_definition_digest.to_string(),
            certificate.source_payload_digest.to_string(),
            certificate.source_validation_certificate_digest.to_string(),
            certificate.definition_digest.to_string(),
            "shadow",
            prepared.certificate_json.as_str(),
            created_unix_ms,
        ],
    )?;
    Ok(())
}

pub(super) fn read_publication(
    connection: &Connection,
    manifest: PartitionManifestId,
) -> Result<Option<ShadowPartitionManifestPublication>, StoreError> {
    let manifest_row = connection
        .query_row(
            "SELECT manifest_id, scheme_id, action_request_id, action_contract_id,
                    output_contract_id, repository_lineage, semantic_world_digest,
                    definition_set_digest, closure, entry_count, definition_digest,
                    manifest_json, created_unix_ms
             FROM partition_manifests WHERE manifest_id=?1",
            [manifest.to_string()],
            |row| {
                Ok(ManifestRow {
                    manifest_id: row.get(0)?,
                    scheme_id: row.get(1)?,
                    action_request_id: row.get(2)?,
                    action_contract_id: row.get(3)?,
                    output_contract_id: row.get(4)?,
                    repository_lineage: row.get(5)?,
                    semantic_world_digest: row.get(6)?,
                    definition_set_digest: row.get(7)?,
                    closure: row.get(8)?,
                    entry_count: row.get(9)?,
                    definition_digest: row.get(10)?,
                    manifest_json: row.get(11)?,
                    created_unix_ms: row.get(12)?,
                })
            },
        )
        .optional()?;
    let Some(manifest_row) = manifest_row else {
        return Ok(None);
    };
    let scheme_id = parse_scheme_id(&manifest_row.scheme_id)?;
    let definition = built_in_partition_for_scheme(&scheme_id)
        .ok_or_else(|| corruption(format!("unknown stored partition scheme {scheme_id}")))?;
    let decoded_manifest =
        PartitionManifest::decode_json(manifest_row.manifest_json.as_bytes(), &definition.scheme)
            .map_err(|error| corruption(format!("stored manifest JSON is invalid: {error}")))?;
    definition
        .policy
        .accepts(&decoded_manifest, &definition.scheme)
        .map_err(|error| corruption(format!("stored manifest violates policy: {error}")))?;

    let certificate_row = connection
        .query_row(
            "SELECT certificate_id, policy_id, scheme_definition_digest,
                    policy_definition_digest, declared_policy_authority_digest,
                    validator_id, validator_definition_digest, adapter_definition_digest,
                    source_payload_digest, source_validation_certificate_digest,
                    definition_digest, issued_mode, certificate_json
             FROM partition_manifest_certificates WHERE manifest_id=?1",
            [manifest.to_string()],
            |row| {
                Ok(CertificateRow {
                    certificate_id: row.get(0)?,
                    policy_id: row.get(1)?,
                    scheme_definition_digest: row.get(2)?,
                    policy_definition_digest: row.get(3)?,
                    declared_policy_authority_digest: row.get(4)?,
                    validator_id: row.get(5)?,
                    validator_definition_digest: row.get(6)?,
                    adapter_definition_digest: row.get(7)?,
                    source_payload_digest: row.get(8)?,
                    source_validation_certificate_digest: row.get(9)?,
                    definition_digest: row.get(10)?,
                    issued_mode: row.get(11)?,
                    certificate_json: row.get(12)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| corruption(format!("manifest {manifest} has no certificate")))?;
    let decoded_certificate = PartitionManifestValidationCertificate::decode_json(
        certificate_row.certificate_json.as_bytes(),
    )
    .map_err(|error| corruption(format!("stored manifest certificate is invalid: {error}")))?;
    let publication =
        ShadowPartitionManifestPublication::from_parts(decoded_manifest, decoded_certificate)
            .map_err(|error| corruption(format!("stored publication is invalid: {error}")))?;
    validate_manifest_columns(&manifest_row, &publication)?;
    validate_certificate_columns(&certificate_row, &publication.certificate)?;
    validate_entry_columns(connection, &publication.manifest)?;
    Ok(Some(publication))
}

fn validate_manifest_columns(
    row: &ManifestRow,
    publication: &ShadowPartitionManifestPublication,
) -> Result<(), StoreError> {
    let manifest = &publication.manifest;
    let entry_count = usize::try_from(row.entry_count)
        .map_err(|_| corruption("stored manifest entry count is negative"))?;
    let _created = u64::try_from(row.created_unix_ms)
        .map_err(|_| corruption("stored manifest timestamp is negative"))?;
    if row.manifest_id != manifest.id.to_string()
        || row.scheme_id != manifest.scheme.as_str()
        || row.action_request_id != manifest.binding.action_request.to_string()
        || row.action_contract_id != manifest.binding.action_contract.as_str()
        || row.output_contract_id != manifest.binding.output_contract
        || row.repository_lineage != manifest.binding.repository.to_string()
        || row.semantic_world_digest != manifest.binding.semantic_world_digest.to_string()
        || row.definition_set_digest != manifest.binding.definition_set_digest.to_string()
        || row.closure != closure_text(manifest.closure)
        || entry_count != manifest.entries.len()
        || row.definition_digest != manifest.definition_digest.to_string()
    {
        return Err(corruption(format!("indexed manifest columns do not bind {}", manifest.id)));
    }
    Ok(())
}

fn validate_certificate_columns(
    row: &CertificateRow,
    certificate: &PartitionManifestValidationCertificate,
) -> Result<(), StoreError> {
    if row.certificate_id != certificate.id.to_string()
        || row.policy_id != certificate.partition_policy.as_str()
        || row.scheme_definition_digest != certificate.scheme_definition_digest.to_string()
        || row.policy_definition_digest != certificate.policy_definition_digest.to_string()
        || row.declared_policy_authority_digest
            != certificate.declared_policy_authority_digest.to_string()
        || row.validator_id != certificate.manifest_validator.as_str()
        || row.validator_definition_digest != certificate.validator_definition_digest.to_string()
        || row.adapter_definition_digest != certificate.adapter_definition_digest.to_string()
        || row.source_payload_digest != certificate.source_payload_digest.to_string()
        || row.source_validation_certificate_digest
            != certificate.source_validation_certificate_digest.to_string()
        || row.definition_digest != certificate.definition_digest.to_string()
        || row.issued_mode != "shadow"
        || certificate.issued_mode != CapabilityMode::Shadow
    {
        return Err(corruption(format!(
            "indexed certificate columns do not bind {}",
            certificate.id
        )));
    }
    Ok(())
}

fn validate_entry_columns(
    connection: &Connection,
    manifest: &PartitionManifest,
) -> Result<(), StoreError> {
    let mut statement = connection.prepare(
        "SELECT key_digest, role, payload_digest, dependency_digest
         FROM partition_manifest_entries WHERE manifest_id=?1 ORDER BY key_digest ASC",
    )?;
    let rows = statement
        .query_map([manifest.id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != manifest.entries.len()
        || rows.iter().zip(&manifest.entries).any(|(row, entry)| {
            row.0 != entry.key.digest.to_string()
                || row.1 != role_text(entry.role)
                || row.2 != entry.payload_digest.to_string()
                || row.3 != entry.dependencies.to_string()
        })
    {
        return Err(corruption(format!(
            "normalized entry rows do not bind manifest {}",
            manifest.id
        )));
    }
    Ok(())
}

fn read_transition(
    connection: &Connection,
    transition: ManifestTransitionId,
) -> Result<Option<ManifestTransition>, StoreError> {
    let row = connection
        .query_row(
            "SELECT transition_id, prior_manifest_id, current_manifest_id, state_delta,
                    validator_id, definition_digest, transition_json
             FROM manifest_transitions WHERE transition_id=?1",
            [transition.to_string()],
            |row| {
                Ok(TransitionRow {
                    transition_id: row.get(0)?,
                    prior_manifest_id: row.get(1)?,
                    current_manifest_id: row.get(2)?,
                    state_delta: row.get(3)?,
                    validator_id: row.get(4)?,
                    definition_digest: row.get(5)?,
                    transition_json: row.get(6)?,
                })
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let decoded = ManifestTransition::decode_json(row.transition_json.as_bytes())
        .map_err(|error| corruption(format!("stored manifest transition is invalid: {error}")))?;
    let prior = read_publication(connection, decoded.prior)?
        .ok_or_else(|| corruption("stored transition prior manifest is missing"))?;
    let current = read_publication(connection, decoded.current)?
        .ok_or_else(|| corruption("stored transition current manifest is missing"))?;
    let definition = built_in_partition_for_scheme(&prior.manifest.scheme)
        .ok_or_else(|| corruption("stored transition scheme is unknown"))?;
    if prior.manifest.scheme != current.manifest.scheme
        || prior.manifest.binding.action_contract != current.manifest.binding.action_contract
        || decoded.validator != definition.policy.manifest_validator
        || decoded.mappings.iter().any(|mapping| {
            !prior.manifest.contains(&mapping.prior) || !current.manifest.contains(&mapping.current)
        })
        || row.transition_id != decoded.id.to_string()
        || row.prior_manifest_id != decoded.prior.to_string()
        || row.current_manifest_id != decoded.current.to_string()
        || row.state_delta != decoded.state_delta.to_string()
        || row.validator_id != decoded.validator.as_str()
        || row.definition_digest != decoded.definition_digest.to_string()
    {
        return Err(corruption(format!("stored transition columns do not bind {}", decoded.id)));
    }
    validate_mapping_columns(connection, &decoded)?;
    Ok(Some(decoded))
}

fn validate_mapping_columns(
    connection: &Connection,
    transition: &ManifestTransition,
) -> Result<(), StoreError> {
    let mut statement = connection.prepare(
        "SELECT prior_manifest_id, prior_key_digest, current_manifest_id, current_key_digest
         FROM manifest_transition_mappings WHERE transition_id=?1
         ORDER BY prior_manifest_id, prior_key_digest",
    )?;
    let rows = statement
        .query_map([transition.id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != transition.mappings.len()
        || rows.iter().zip(&transition.mappings).any(|(row, mapping)| {
            row.0 != mapping.prior.manifest.to_string()
                || row.1 != mapping.prior.key_digest.to_string()
                || row.2 != mapping.current.manifest.to_string()
                || row.3 != mapping.current.key_digest.to_string()
        })
    {
        return Err(corruption(format!(
            "stored mapping rows do not bind transition {}",
            transition.id
        )));
    }
    Ok(())
}

type SummaryRow = (String, String, String, String, String, String, String, String, i64, i64);

fn decode_summary(row: SummaryRow) -> Result<PartitionManifestSummaryRecord, StoreError> {
    let entry_count = u32::try_from(row.8)
        .map_err(|_| corruption("stored manifest summary entry count is invalid"))?;
    if entry_count as usize > MAX_PARTITION_MANIFEST_ENTRIES {
        return Err(corruption("stored manifest summary entry count exceeds its bound"));
    }
    Ok(PartitionManifestSummaryRecord {
        manifest: parse_manifest_id(&row.0)?,
        certificate: parse_certificate_id(&row.1)?,
        action_request: ArtifactRequestId::new(parse_stored_digest(&row.2)?),
        action_contract: ActionContractId::new(row.3)
            .map_err(|error| corruption(format!("stored action contract is invalid: {error}")))?,
        output_contract: parse_identifier(row.4, "output contract")?,
        scheme: parse_scheme_id(&row.5)?,
        repository: parse_stored_digest(&row.6)?,
        closure: parse_closure(&row.7)?,
        entry_count,
        created_unix_ms: u64::try_from(row.9)
            .map_err(|_| corruption("stored manifest summary timestamp is negative"))?,
    })
}

fn ensure_wire_bound(label: &str, actual: usize, maximum: usize) -> Result<(), StoreError> {
    if actual > maximum {
        return Err(StoreError::PartitionManifestPublication(format!(
            "{label} exceeds its {maximum}-byte storage bound"
        )));
    }
    Ok(())
}

fn parse_manifest_id(value: &str) -> Result<PartitionManifestId, StoreError> {
    Ok(PartitionManifestId::new(parse_stored_digest(value)?))
}

fn parse_certificate_id(
    value: &str,
) -> Result<PartitionManifestValidationCertificateId, StoreError> {
    Ok(PartitionManifestValidationCertificateId::new(parse_stored_digest(value)?))
}

fn parse_scheme_id(value: &str) -> Result<PartitionSchemeId, StoreError> {
    PartitionSchemeId::new(value.to_owned())
        .map_err(|error| corruption(format!("stored partition scheme is invalid: {error}")))
}

fn parse_identifier(value: String, field: &str) -> Result<String, StoreError> {
    if value.is_empty()
        || value.len() > needle_core::MAX_PARTITION_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(corruption(format!("stored {field} is invalid")));
    }
    Ok(value)
}

fn parse_stored_digest(value: &str) -> Result<Digest, StoreError> {
    Digest::parse(value).map_err(|error| corruption(format!("stored digest is invalid: {error}")))
}

fn parse_closure(value: &str) -> Result<ManifestClosure, StoreError> {
    match value {
        "open" => Ok(ManifestClosure::Open),
        "closed" => Ok(ManifestClosure::Closed),
        _ => Err(corruption("stored manifest closure is invalid")),
    }
}

const fn closure_text(value: ManifestClosure) -> &'static str {
    match value {
        ManifestClosure::Open => "open",
        ManifestClosure::Closed => "closed",
    }
}

const fn role_text(value: PartitionRole) -> &'static str {
    match value {
        PartitionRole::Component => "component",
        PartitionRole::Aggregate => "aggregate",
    }
}

fn corruption(message: impl Into<String>) -> StoreError {
    StoreError::PartitionManifestCorruption(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::built_in_partition_definitions;
    use needle_core::{
        CoverageManifest, ManifestBinding, ManifestProvenance, OpaquePartitionKey, PartitionEntry,
        PartitionKeyMapping, PartitionRef, SemanticWorld, ValidatorId,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn digest(value: impl AsRef<[u8]>) -> Digest {
        Digest::blake3(value)
    }

    fn temporary_store() -> (PathBuf, RuntimeStore) {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let path = std::env::temp_dir().join(format!(
            "needle-partition-manifests-{}-{}.sqlite3",
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

    fn publication(label: &str) -> ShadowPartitionManifestPublication {
        let definition = &built_in_partition_definitions()[0];
        let repository = digest("repository");
        let source_selector = format!("source-{label}");
        let world = SemanticWorld {
            repository_lineage: repository,
            source_selector: source_selector.clone(),
            platform: "any".to_owned(),
            features: "default".to_owned(),
            configuration: None,
            toolchain: None,
        };
        let request = ArtifactRequestId::new(digest(format!("request-{label}")));
        let binding = ManifestBinding::new(
            request,
            definition.action_contract.clone(),
            definition.output_contract_id,
            needle_core::semantic_input_set_digest(&[]).unwrap(),
            world.id(),
            repository,
            &source_selector,
            digest("definition-set"),
        )
        .unwrap();
        let dependency = digest(format!("dependency-{label}"));
        let entry = PartitionEntry::new(
            OpaquePartitionKey::new(
                &definition.scheme,
                digest(format!("key-{label}")).bytes().to_vec(),
                None,
            )
            .unwrap(),
            PartitionRole::Component,
            digest(format!("payload-{label}")),
            CoverageManifest { entries: Vec::new(), world, dependency_manifest_digest: dependency },
            dependency,
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let manifest = PartitionManifest::new(
            &definition.scheme,
            binding,
            ManifestProvenance::RequestBound { request },
            ManifestClosure::Closed,
            vec![entry],
            None,
        )
        .unwrap();
        let certificate = PartitionManifestValidationCertificate::new(
            &manifest,
            &definition.scheme,
            &definition.policy,
            definition.declared_policy_authority_digest,
            definition.validator_definition_digest,
            definition.adapter_definition_digest,
            digest(format!("source-payload-{label}")),
            digest(format!("source-certificate-{label}")),
            42,
        )
        .unwrap();
        ShadowPartitionManifestPublication::from_parts(manifest, certificate).unwrap()
    }

    #[test]
    fn migration_v23_is_complete_and_append_only() {
        let (path, store) = temporary_store();
        store.initialize().unwrap();
        let publication = publication("immutable");
        store.publish_shadow_partition_manifest(&publication).unwrap();
        drop(store);

        let connection = Connection::open(&path).unwrap();
        let versions: Vec<u32> = connection
            .prepare("SELECT version FROM schema_migrations ORDER BY version")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(versions, (1..=37).collect::<Vec<_>>());
        for table in [
            "partition_manifests",
            "partition_manifest_entries",
            "partition_manifest_certificates",
            "manifest_transitions",
            "manifest_transition_mappings",
        ] {
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                        [table],
                        |row| row.get::<_, u32>(0),
                    )
                    .unwrap(),
                1,
                "missing table {table}"
            );
        }
        assert!(
            connection
                .execute(
                    "UPDATE partition_manifests SET closure='open' WHERE manifest_id=?1",
                    [publication.manifest.id.to_string()],
                )
                .is_err()
        );
        drop(connection);
        cleanup(&path);
    }

    #[test]
    fn publication_round_trip_is_idempotent_and_summary_is_bounded() {
        let (path, store) = temporary_store();
        store.initialize().unwrap();
        let publication = publication("round-trip");
        assert_eq!(store.publish_shadow_partition_manifest(&publication).unwrap(), publication);
        assert_eq!(store.publish_shadow_partition_manifest(&publication).unwrap(), publication);
        assert_eq!(
            store.partition_manifest_publication(publication.manifest.id).unwrap(),
            Some(publication.clone())
        );
        let summaries = store.list_partition_manifest_summaries(1).unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].manifest, publication.manifest.id);
        assert_eq!(summaries[0].certificate, publication.certificate.id);
        assert_eq!(summaries[0].entry_count, 1);
        assert!(store.list_partition_manifest_summaries(0).is_err());
        assert!(
            store.list_partition_manifest_summaries(MAX_PARTITION_MANIFEST_LIST_LIMIT + 1).is_err()
        );
        drop(store);
        cleanup(&path);
    }

    #[test]
    fn shadow_transition_round_trip_requires_stored_bound_manifests() {
        let (path, store) = temporary_store();
        store.initialize().unwrap();
        let prior = publication("prior");
        let current = publication("current");
        store.publish_shadow_partition_manifest(&prior).unwrap();
        store.publish_shadow_partition_manifest(&current).unwrap();
        let transition = ManifestTransition::new(
            prior.manifest.id,
            current.manifest.id,
            digest("state-delta"),
            vec![PartitionKeyMapping {
                prior: PartitionRef::new(prior.manifest.id, prior.manifest.entries[0].key.digest),
                current: PartitionRef::new(
                    current.manifest.id,
                    current.manifest.entries[0].key.digest,
                ),
            }],
            ManifestProvenance::ProducerAuthored { attempt: digest("transition-attempt") },
            ValidatorId::new(
                built_in_partition_definitions()[0].policy.manifest_validator.as_str(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(store.record_shadow_manifest_transition(&transition).unwrap(), transition);
        assert_eq!(store.record_shadow_manifest_transition(&transition).unwrap(), transition);
        assert_eq!(store.shadow_manifest_transition(transition.id).unwrap(), Some(transition));
        drop(store);
        cleanup(&path);
    }
}
