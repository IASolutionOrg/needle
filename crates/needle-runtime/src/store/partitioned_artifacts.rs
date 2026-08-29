use super::partitioned_heads::{PartitionedActionHeadRecord, ShadowPartitionedActionHeadAdvance};
use super::{
    ACTION_REQUEST_STORAGE_FORMAT_REVISION, RuntimeStore, StoreError,
    insert_action_request_observation, insert_action_request_row, now_ms,
};
use crate::{ShadowPartitionManifestPublication, ShadowPartitionedActionArtifactPublication};
use needle_core::{
    ActionArtifactValidationCertificate, ActionRequest, Artifact, ArtifactId,
    ArtifactValidationCertificateId, Digest, LifecycleUsage,
    MAX_ACTION_ARTIFACT_VALIDATION_CERTIFICATE_WIRE_BYTES, MAX_REFRESH_ATTEMPT_WIRE_BYTES,
    MAX_REFRESH_ECONOMIC_WIRE_BYTES, RefreshAttempt, RefreshEconomicAssessment,
    RefreshEconomicDecision, RefreshOutcome, ReuseDescriptor,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

pub(super) const MAX_PARTITIONED_ACTION_ARTIFACT_WIRE_BYTES: usize = 4 * 1024 * 1024;
const MAX_REUSE_DESCRIPTOR_WIRE_BYTES: usize = 4 * 1024 * 1024;

pub struct ShadowRefreshedActionArtifactPublication<'a> {
    pub request: &'a ActionRequest,
    pub manifest: &'a ShadowPartitionManifestPublication,
    pub result: &'a ShadowPartitionedActionArtifactPublication,
    pub attempt: &'a RefreshAttempt,
}

pub struct ShadowEconomicallySelectedRefreshedActionArtifactPublication<'a> {
    pub refresh: ShadowRefreshedActionArtifactPublication<'a>,
    pub assessment: &'a RefreshEconomicAssessment,
}

pub struct ShadowEconomicallyAssessedPartitionedActionArtifactPublication<'a> {
    pub request: &'a ActionRequest,
    pub manifest: &'a ShadowPartitionManifestPublication,
    pub result: &'a ShadowPartitionedActionArtifactPublication,
    pub assessment: &'a RefreshEconomicAssessment,
}

struct PreparedPublication {
    artifact_json: String,
    certificate_json: String,
    descriptor_json: String,
}

impl RuntimeStore {
    /// Publish one fully validated partitioned action artifact in fixed Shadow.
    /// This supports initial/full-compute materialization and does not make the
    /// descriptor eligible for resolver selection.
    pub fn publish_shadow_partitioned_action_artifact(
        &self,
        request: &ActionRequest,
        manifest: &ShadowPartitionManifestPublication,
        publication: &ShadowPartitionedActionArtifactPublication,
    ) -> Result<(), StoreError> {
        let prepared = prepare_publication(request, manifest, publication)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_persisted_manifest(&transaction, manifest)?;
        insert_partitioned_publication(&transaction, request, publication, &prepared)?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically publishes the review manifest, artifact, certificate,
    /// descriptor, provenance and idempotent operation completion.
    pub(crate) fn publish_shadow_partitioned_action_execution(
        &self,
        operation_id: Digest,
        request: &ActionRequest,
        manifest: &ShadowPartitionManifestPublication,
        publication: &ShadowPartitionedActionArtifactPublication,
        transition: Option<&needle_core::ManifestTransition>,
        usage: &LifecycleUsage,
    ) -> Result<(), StoreError> {
        let prepared_manifest =
            super::partition_manifest_store::prepare_manifest_publication(manifest)?;
        let prepared = prepare_publication(request, manifest, publication)?;
        let prepared_transition = transition
            .map(super::partition_manifest_store::prepare_manifest_transition)
            .transpose()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        super::partition_manifest_store::insert_manifest_publication(
            &transaction,
            manifest,
            &prepared_manifest,
            now_ms(),
        )?;
        validate_persisted_manifest(&transaction, manifest)?;
        insert_partitioned_publication(&transaction, request, publication, &prepared)?;
        if let (Some(transition), Some(prepared_transition)) = (transition, prepared_transition) {
            super::partition_manifest_store::insert_manifest_transition(
                &transaction,
                transition,
                &prepared_transition,
                now_ms(),
            )?;
        }
        super::action_execution_operations::complete_action_execution_operation_in_transaction(
            &transaction,
            operation_id,
            request.semantic_id(),
            ArtifactId::new(publication.artifact.id),
            publication.certificate.id,
            Some(manifest.manifest.id),
            usage,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn publish_shadow_partitioned_action_artifact_and_advance_head(
        &self,
        request: &ActionRequest,
        manifest: &ShadowPartitionManifestPublication,
        publication: &ShadowPartitionedActionArtifactPublication,
        advance: ShadowPartitionedActionHeadAdvance<'_>,
    ) -> Result<PartitionedActionHeadRecord, StoreError> {
        let prepared = prepare_publication(request, manifest, publication)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_persisted_manifest(&transaction, manifest)?;
        insert_partitioned_publication(&transaction, request, publication, &prepared)?;
        let head = super::partitioned_heads::insert_head_advance(
            &transaction,
            request,
            publication,
            advance,
        )?;
        transaction.commit()?;
        Ok(head)
    }

    /// Atomically publish a full-compute Shadow result and the economic
    /// assessment that rejected its refresh candidate. No selection link is
    /// created because no refresh attempt was executed.
    pub fn publish_shadow_economically_assessed_partitioned_action_artifact(
        &self,
        publication: ShadowEconomicallyAssessedPartitionedActionArtifactPublication<'_>,
    ) -> Result<(), StoreError> {
        validate_full_compute_economic_binding(&publication)?;
        let prepared =
            prepare_publication(publication.request, publication.manifest, publication.result)?;
        let assessment_json = serde_json::to_string(publication.assessment)?;
        ensure_wire_bound(
            "refresh economic assessment",
            assessment_json.len(),
            MAX_REFRESH_ECONOMIC_WIRE_BYTES,
        )?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_persisted_manifest(&transaction, publication.manifest)?;
        insert_partitioned_publication(
            &transaction,
            publication.request,
            publication.result,
            &prepared,
        )?;
        super::refresh_economics::insert_refresh_economic_assessment(
            &transaction,
            publication.assessment,
            &assessment_json,
            now_ms(),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn publish_shadow_economically_assessed_partitioned_action_artifact_and_advance_head(
        &self,
        publication: ShadowEconomicallyAssessedPartitionedActionArtifactPublication<'_>,
        advance: ShadowPartitionedActionHeadAdvance<'_>,
    ) -> Result<PartitionedActionHeadRecord, StoreError> {
        validate_full_compute_economic_binding(&publication)?;
        let prepared =
            prepare_publication(publication.request, publication.manifest, publication.result)?;
        let assessment_json = serde_json::to_string(publication.assessment)?;
        ensure_wire_bound(
            "refresh economic assessment",
            assessment_json.len(),
            MAX_REFRESH_ECONOMIC_WIRE_BYTES,
        )?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_persisted_manifest(&transaction, publication.manifest)?;
        insert_partitioned_publication(
            &transaction,
            publication.request,
            publication.result,
            &prepared,
        )?;
        super::refresh_economics::insert_refresh_economic_assessment(
            &transaction,
            publication.assessment,
            &assessment_json,
            now_ms(),
        )?;
        let head = super::partitioned_heads::insert_head_advance(
            &transaction,
            publication.request,
            publication.result,
            advance,
        )?;
        transaction.commit()?;
        Ok(head)
    }

    /// Atomically publish a successful refreshed artifact, its action-aware
    /// certificate, descriptor, exact request mapping, and immutable attempt.
    /// All records remain Shadow-only and are ignored by the live resolver.
    pub fn publish_shadow_refreshed_action_artifact(
        &self,
        publication: ShadowRefreshedActionArtifactPublication<'_>,
    ) -> Result<(), StoreError> {
        let (prepared, attempt_json) = prepare_refreshed_publication(&publication)?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_refreshed_publication(&transaction, &publication, &prepared, &attempt_json)?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically publish one economically selected Shadow refresh and its
    /// canonical assessment-to-attempt audit binding. This still grants no
    /// resolver or capability authority.
    pub fn publish_shadow_economically_selected_refreshed_action_artifact(
        &self,
        publication: ShadowEconomicallySelectedRefreshedActionArtifactPublication<'_>,
    ) -> Result<(), StoreError> {
        validate_economic_binding(&publication)?;
        let (prepared, attempt_json) = prepare_refreshed_publication(&publication.refresh)?;
        let assessment_json = serde_json::to_string(publication.assessment)?;
        ensure_wire_bound(
            "refresh economic assessment",
            assessment_json.len(),
            MAX_REFRESH_ECONOMIC_WIRE_BYTES,
        )?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_refreshed_publication(&transaction, &publication.refresh, &prepared, &attempt_json)?;
        let recorded_unix_ms = now_ms();
        super::refresh_economics::insert_refresh_economic_assessment(
            &transaction,
            publication.assessment,
            &assessment_json,
            recorded_unix_ms,
        )?;
        super::refresh_economics::insert_refresh_economic_selection(
            &transaction,
            publication.assessment,
            publication.refresh.attempt.id,
            recorded_unix_ms,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn publish_shadow_economically_selected_refreshed_action_artifact_and_advance_head(
        &self,
        publication: ShadowEconomicallySelectedRefreshedActionArtifactPublication<'_>,
        advance: ShadowPartitionedActionHeadAdvance<'_>,
    ) -> Result<PartitionedActionHeadRecord, StoreError> {
        validate_economic_binding(&publication)?;
        let (prepared, attempt_json) = prepare_refreshed_publication(&publication.refresh)?;
        let assessment_json = serde_json::to_string(publication.assessment)?;
        ensure_wire_bound(
            "refresh economic assessment",
            assessment_json.len(),
            MAX_REFRESH_ECONOMIC_WIRE_BYTES,
        )?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_refreshed_publication(&transaction, &publication.refresh, &prepared, &attempt_json)?;
        let recorded_unix_ms = now_ms();
        super::refresh_economics::insert_refresh_economic_assessment(
            &transaction,
            publication.assessment,
            &assessment_json,
            recorded_unix_ms,
        )?;
        super::refresh_economics::insert_refresh_economic_selection(
            &transaction,
            publication.assessment,
            publication.refresh.attempt.id,
            recorded_unix_ms,
        )?;
        let head = super::partitioned_heads::insert_head_advance(
            &transaction,
            publication.refresh.request,
            publication.refresh.result,
            advance,
        )?;
        transaction.commit()?;
        Ok(head)
    }

    pub fn action_artifact_validation_certificate(
        &self,
        id: ArtifactValidationCertificateId,
    ) -> Result<Option<ActionArtifactValidationCertificate>, StoreError> {
        let connection = self.connection()?;
        read_action_certificate(&connection, id)
    }

    pub fn stored_reuse_descriptor(
        &self,
        definition_digest: Digest,
    ) -> Result<Option<ReuseDescriptor>, StoreError> {
        let connection = self.connection()?;
        read_reuse_descriptor(&connection, definition_digest)
    }
}

fn prepare_refreshed_publication(
    publication: &ShadowRefreshedActionArtifactPublication<'_>,
) -> Result<(PreparedPublication, String), StoreError> {
    publication.attempt.validate()?;
    let prepared =
        prepare_publication(publication.request, publication.manifest, publication.result)?;
    let (reconstructed_artifact, validation_certificate) = match publication.attempt.outcome {
        RefreshOutcome::Succeeded { reconstructed_artifact, validation_certificate } => {
            (reconstructed_artifact, validation_certificate)
        }
        RefreshOutcome::Failed { .. } => {
            return Err(binding("a refreshed artifact publication requires a successful attempt"));
        }
    };
    if publication.attempt.request != publication.request.semantic_id()
        || publication.attempt.action_contract != publication.request.contract
        || publication.attempt.current_manifest != publication.manifest.manifest.id
        || publication.attempt.manifest_transition
            == needle_core::ManifestTransitionId::new(Digest([0; 32]))
        || reconstructed_artifact.digest() != publication.result.artifact.id
        || validation_certificate != publication.result.certificate.id
        || publication.attempt.prior_artifact == reconstructed_artifact
        || publication.result.artifact.created_unix_ms < publication.attempt.started_unix_ms
        || publication.result.artifact.created_unix_ms > publication.attempt.completed_unix_ms
    {
        return Err(binding("refresh attempt does not bind the reconstructed publication"));
    }
    let attempt_json = serde_json::to_string(publication.attempt)?;
    ensure_wire_bound("refresh attempt", attempt_json.len(), MAX_REFRESH_ATTEMPT_WIRE_BYTES)?;
    Ok((prepared, attempt_json))
}

fn insert_refreshed_publication(
    connection: &Connection,
    publication: &ShadowRefreshedActionArtifactPublication<'_>,
    prepared: &PreparedPublication,
    attempt_json: &str,
) -> Result<(), StoreError> {
    validate_persisted_manifest(connection, publication.manifest)?;
    validate_prior_artifact(connection, publication.attempt)?;
    super::refreshes::validate_storage_bindings(connection, publication.attempt)?;
    insert_partitioned_publication(connection, publication.request, publication.result, prepared)?;
    super::refreshes::insert_refresh_attempt(connection, publication.attempt, attempt_json)
}

fn validate_economic_binding(
    publication: &ShadowEconomicallySelectedRefreshedActionArtifactPublication<'_>,
) -> Result<(), StoreError> {
    publication.assessment.validate()?;
    let attempt = publication.refresh.attempt;
    if publication.assessment.decision != RefreshEconomicDecision::Refresh
        || publication.assessment.evidence.is_none()
        || publication.assessment.request != attempt.request
        || publication.assessment.action_contract != attempt.action_contract
        || publication.assessment.operator_definition_digest != attempt.operator_definition_digest
        || publication.assessment.execution_scope_digest != attempt.execution_scope_digest
        || publication.assessment.policy.refresh_policy_definition_digest
            != attempt.refresh_policy_definition_digest
        || publication.assessment.policy.action_operational_policy_digest
            != publication.refresh.request.contract_operational_policy_digest
        || publication.assessment.candidate_definition_digest == Digest([0; 32])
    {
        return Err(binding(
            "refresh economic assessment does not bind the selected successful attempt",
        ));
    }
    Ok(())
}

fn validate_full_compute_economic_binding(
    publication: &ShadowEconomicallyAssessedPartitionedActionArtifactPublication<'_>,
) -> Result<(), StoreError> {
    publication.assessment.validate()?;
    if !matches!(publication.assessment.decision, RefreshEconomicDecision::FullCompute { .. })
        || publication.assessment.request != publication.request.semantic_id()
        || publication.assessment.action_contract != publication.request.contract
        || publication.assessment.policy.action_operational_policy_digest
            != publication.request.contract_operational_policy_digest
        || publication.assessment.candidate_definition_digest == Digest([0; 32])
    {
        return Err(binding(
            "refresh economic assessment does not bind the full-compute publication",
        ));
    }
    Ok(())
}

fn prepare_publication(
    request: &ActionRequest,
    manifest: &ShadowPartitionManifestPublication,
    publication: &ShadowPartitionedActionArtifactPublication,
) -> Result<PreparedPublication, StoreError> {
    publication.validate(request, manifest).map_err(|error| binding(error.to_string()))?;
    let artifact_json = serde_json::to_string(&publication.artifact)?;
    let certificate_json = serde_json::to_string(&publication.certificate)?;
    let descriptor_json = serde_json::to_string(&publication.descriptor)?;
    ensure_wire_bound(
        "partitioned action artifact",
        artifact_json.len(),
        MAX_PARTITIONED_ACTION_ARTIFACT_WIRE_BYTES,
    )?;
    ensure_wire_bound(
        "action artifact validation certificate",
        certificate_json.len(),
        MAX_ACTION_ARTIFACT_VALIDATION_CERTIFICATE_WIRE_BYTES,
    )?;
    ensure_wire_bound("reuse descriptor", descriptor_json.len(), MAX_REUSE_DESCRIPTOR_WIRE_BYTES)?;
    Ok(PreparedPublication { artifact_json, certificate_json, descriptor_json })
}

fn insert_partitioned_publication(
    connection: &Connection,
    request: &ActionRequest,
    publication: &ShadowPartitionedActionArtifactPublication,
    prepared: &PreparedPublication,
) -> Result<(), StoreError> {
    for input in &publication.certificate.input_artifacts {
        let exists: u64 = connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM artifact_validation_certificates WHERE artifact_id=?1
                UNION ALL
                SELECT 1 FROM action_artifact_validation_certificates WHERE artifact_id=?1
                UNION ALL
                SELECT 1 FROM opaque_action_validation_certificates WHERE artifact_id=?1
             )",
            [input.to_string()],
            |row| row.get(0),
        )?;
        if exists == 0 {
            return Err(binding(format!("partitioned action input `{input}` is not certified",)));
        }
    }

    insert_action_request_row(connection, request, publication.artifact.created_unix_ms)?;
    insert_artifact(connection, &publication.artifact, &prepared.artifact_json)?;
    connection.execute(
        "INSERT OR IGNORE INTO artifact_origins(
            artifact_id, request_id, route_key, need_id, observed_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
        params![
            publication.artifact.id.to_string(),
            request.semantic_id().to_string(),
            request.artifact_request.route_key.as_str(),
            request.root_need.to_string(),
            publication.artifact.created_unix_ms,
        ],
    )?;
    insert_action_request_observation(
        connection,
        request,
        publication.artifact.id,
        publication.artifact.created_unix_ms,
    )?;
    insert_world_and_dependency_manifest(connection, publication)?;
    insert_action_certificate(connection, &publication.certificate, &prepared.certificate_json)?;
    insert_reuse_descriptor(connection, &publication.descriptor, &prepared.descriptor_json)?;
    Ok(())
}

pub(super) fn insert_artifact(
    connection: &Connection,
    artifact: &Artifact,
    artifact_json: &str,
) -> Result<(), StoreError> {
    let existing = connection
        .query_row(
            "SELECT request_id, contract_id, artifact_json, format_revision
             FROM artifacts WHERE artifact_id=?1",
            [artifact.id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u16>(3)?,
                ))
            },
        )
        .optional()?;
    if let Some((request_id, contract_id, stored_json, format_revision)) = existing {
        if request_id != artifact.request_id.to_string()
            || contract_id != artifact.contract.id
            || stored_json != artifact_json
            || format_revision != ACTION_REQUEST_STORAGE_FORMAT_REVISION
        {
            return Err(conflict(format!(
                "artifact {} already has different immutable content",
                artifact.id
            )));
        }
        return Ok(());
    }
    connection.execute(
        "INSERT INTO artifacts(
            artifact_id, request_id, contract_id, artifact_json, created_unix_ms,
            format_revision
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            artifact.id.to_string(),
            artifact.request_id.to_string(),
            artifact.contract.id,
            artifact_json,
            artifact.created_unix_ms,
            ACTION_REQUEST_STORAGE_FORMAT_REVISION,
        ],
    )?;
    Ok(())
}

fn insert_world_and_dependency_manifest(
    connection: &Connection,
    publication: &ShadowPartitionedActionArtifactPublication,
) -> Result<(), StoreError> {
    let world = &publication.certificate.coverage.world;
    let world_digest = world.id();
    let world_json = serde_json::to_string(world)?;
    insert_immutable_json(
        connection,
        "semantic_worlds",
        "world_digest",
        &world_digest.to_string(),
        "world_json",
        &world_json,
        "semantic world",
        || {
            connection.execute(
                "INSERT INTO semantic_worlds(world_digest, world_json, created_unix_ms)
                 VALUES(?1, ?2, ?3)",
                params![world_digest.to_string(), world_json, publication.artifact.created_unix_ms],
            )
        },
    )?;
    let manifest_digest = publication.certificate.coverage.dependency_manifest_digest;
    let manifest_json = serde_json::to_string(&publication.artifact.dependency_manifest)?;
    insert_immutable_json(
        connection,
        "dependency_manifests",
        "manifest_digest",
        &manifest_digest.to_string(),
        "manifest_json",
        &manifest_json,
        "dependency manifest",
        || {
            connection.execute(
                "INSERT INTO dependency_manifests(manifest_digest, manifest_json, created_unix_ms)
                 VALUES(?1, ?2, ?3)",
                params![
                    manifest_digest.to_string(),
                    manifest_json,
                    publication.artifact.created_unix_ms,
                ],
            )
        },
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn insert_immutable_json(
    connection: &Connection,
    table: &str,
    key_column: &str,
    key: &str,
    json_column: &str,
    json: &str,
    label: &str,
    insert: impl FnOnce() -> rusqlite::Result<usize>,
) -> Result<(), StoreError> {
    let query = format!("SELECT {json_column} FROM {table} WHERE {key_column}=?1");
    if let Some(existing) =
        connection.query_row(&query, [key], |row| row.get::<_, String>(0)).optional()?
    {
        if existing != json {
            return Err(conflict(format!("{label} `{key}` already has different content")));
        }
        return Ok(());
    }
    insert()?;
    Ok(())
}

fn insert_action_certificate(
    connection: &Connection,
    certificate: &ActionArtifactValidationCertificate,
    certificate_json: &str,
) -> Result<(), StoreError> {
    if let Some(existing) = read_action_certificate(connection, certificate.id)? {
        if existing != *certificate {
            return Err(conflict(format!(
                "action certificate {} already has different immutable content",
                certificate.id
            )));
        }
        return Ok(());
    }
    connection.execute(
        "INSERT INTO action_artifact_validation_certificates(
            certificate_id, artifact_id, action_contract_id,
            action_semantic_definition_digest, action_validation_definition_digest,
            output_contract_definition_digest, partition_manifest_id,
            source_payload_digest, source_validation_certificate_digest,
            dependency_manifest_digest, semantic_world_digest,
            validator_definition_digest, authority, certificate_json, issued_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'shadow', ?13, ?14)",
        params![
            certificate.id.to_string(),
            certificate.artifact.to_string(),
            certificate.action_contract.as_str(),
            certificate.action_semantic_definition_digest.to_string(),
            certificate.action_validation_definition_digest.to_string(),
            certificate.output_contract_definition_digest.to_string(),
            certificate.partition_manifest.to_string(),
            certificate.source_payload_digest.to_string(),
            certificate.source_validation_certificate_digest.to_string(),
            certificate.coverage.dependency_manifest_digest.to_string(),
            certificate.coverage.world.id().to_string(),
            certificate.validator_definition_digest.to_string(),
            certificate_json,
            u64_to_sql(certificate.issued_unix_ms)?,
        ],
    )?;
    Ok(())
}

fn insert_reuse_descriptor(
    connection: &Connection,
    descriptor: &ReuseDescriptor,
    descriptor_json: &str,
) -> Result<(), StoreError> {
    if let Some(existing) = read_reuse_descriptor(connection, descriptor.definition_digest)? {
        if existing != *descriptor {
            return Err(conflict(format!(
                "reuse descriptor {} already has different immutable content",
                descriptor.definition_digest
            )));
        }
        return Ok(());
    }
    let exact_conflict: Option<String> = connection
        .query_row(
            "SELECT descriptor_digest FROM reuse_descriptors
             WHERE exact_request_id=?1 AND artifact_id=?2",
            params![descriptor.exact_request.to_string(), descriptor.artifact.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing) = exact_conflict {
        return Err(conflict(format!(
            "request {} and artifact {} already map to descriptor {existing}",
            descriptor.exact_request, descriptor.artifact
        )));
    }
    let partition_manifest = descriptor
        .partition_manifest
        .ok_or_else(|| binding("partitioned reuse descriptor has no manifest"))?;
    connection.execute(
        "INSERT INTO reuse_descriptors(
            descriptor_digest, artifact_id, exact_request_id, origin_request_id,
            action_contract_id, validation_certificate_id, semantic_certificate_id,
            action_certificate_id, partition_manifest_id, dependency_manifest_digest,
            semantic_world_digest, descriptor_json, created_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, NULL, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            descriptor.definition_digest.to_string(),
            descriptor.artifact.to_string(),
            descriptor.exact_request.to_string(),
            descriptor.origin_request.to_string(),
            descriptor.action_contract.as_str(),
            descriptor.validation_certificate.to_string(),
            partition_manifest.to_string(),
            descriptor.dependency_manifest_digest.to_string(),
            descriptor.semantic_world_digest.to_string(),
            descriptor_json,
            u64_to_sql(now_ms())?,
        ],
    )?;
    Ok(())
}

pub(super) fn read_action_certificate(
    connection: &Connection,
    id: ArtifactValidationCertificateId,
) -> Result<Option<ActionArtifactValidationCertificate>, StoreError> {
    let row = connection
        .query_row(
            "SELECT artifact_id, action_contract_id,
                    action_semantic_definition_digest, action_validation_definition_digest,
                    output_contract_definition_digest, partition_manifest_id,
                    source_payload_digest, source_validation_certificate_digest,
                    dependency_manifest_digest, semantic_world_digest,
                    validator_definition_digest, authority, certificate_json, issued_unix_ms
             FROM action_artifact_validation_certificates WHERE certificate_id=?1",
            [id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
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
                    row.get::<_, i64>(13)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let certificate = ActionArtifactValidationCertificate::decode_json(row.12.as_bytes())
        .map_err(|error| corruption(error.to_string()))?;
    if certificate.id != id
        || row.0 != certificate.artifact.to_string()
        || row.1 != certificate.action_contract.as_str()
        || row.2 != certificate.action_semantic_definition_digest.to_string()
        || row.3 != certificate.action_validation_definition_digest.to_string()
        || row.4 != certificate.output_contract_definition_digest.to_string()
        || row.5 != certificate.partition_manifest.to_string()
        || row.6 != certificate.source_payload_digest.to_string()
        || row.7 != certificate.source_validation_certificate_digest.to_string()
        || row.8 != certificate.coverage.dependency_manifest_digest.to_string()
        || row.9 != certificate.coverage.world.id().to_string()
        || row.10 != certificate.validator_definition_digest.to_string()
        || row.11 != "shadow"
        || i64_to_u64(row.13)? != certificate.issued_unix_ms
    {
        return Err(corruption(
            "stored action certificate columns do not match its canonical record",
        ));
    }
    Ok(Some(certificate))
}

pub(super) fn read_reuse_descriptor(
    connection: &Connection,
    definition_digest: Digest,
) -> Result<Option<ReuseDescriptor>, StoreError> {
    let row = connection
        .query_row(
            "SELECT artifact_id, exact_request_id, origin_request_id, action_contract_id,
                    validation_certificate_id, action_certificate_id, partition_manifest_id,
                    dependency_manifest_digest, semantic_world_digest, descriptor_json
             FROM reuse_descriptors WHERE descriptor_digest=?1",
            [definition_digest.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let descriptor: ReuseDescriptor = serde_json::from_str(&row.9)?;
    descriptor.validate().map_err(|error| corruption(error.to_string()))?;
    let certificate_id = descriptor.validation_certificate.to_string();
    let partition_manifest = descriptor.partition_manifest.map(|value| value.to_string());
    if descriptor.definition_digest != definition_digest
        || row.0 != descriptor.artifact.to_string()
        || row.1 != descriptor.exact_request.to_string()
        || row.2 != descriptor.origin_request.to_string()
        || row.3 != descriptor.action_contract.as_str()
        || row.4 != descriptor.validation_certificate.to_string()
        || row.5.as_deref() != Some(certificate_id.as_str())
        || row.6.as_deref() != partition_manifest.as_deref()
        || row.7 != descriptor.dependency_manifest_digest.to_string()
        || row.8 != descriptor.semantic_world_digest.to_string()
    {
        return Err(corruption(
            "stored reuse descriptor columns do not match its canonical record",
        ));
    }
    Ok(Some(descriptor))
}

fn validate_persisted_manifest(
    connection: &Connection,
    manifest: &ShadowPartitionManifestPublication,
) -> Result<(), StoreError> {
    let stored =
        super::partition_manifest_store::read_publication(connection, manifest.manifest.id)?
            .ok_or_else(|| binding("partition manifest is not persisted"))?;
    if stored != *manifest {
        return Err(conflict(format!(
            "partition manifest {} has different immutable content",
            manifest.manifest.id
        )));
    }
    Ok(())
}

fn validate_prior_artifact(
    connection: &Connection,
    attempt: &RefreshAttempt,
) -> Result<(), StoreError> {
    let exists: u64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM artifacts a
            JOIN action_artifact_validation_certificates c ON c.artifact_id=a.artifact_id
            JOIN reuse_descriptors d
              ON d.artifact_id=a.artifact_id
             AND d.validation_certificate_id=c.certificate_id
             AND d.partition_manifest_id=c.partition_manifest_id
            WHERE a.artifact_id=?1
              AND c.action_contract_id=?2
              AND c.partition_manifest_id=?3
              AND d.exact_request_id=?4
         )",
        params![
            attempt.prior_artifact.to_string(),
            attempt.action_contract.as_str(),
            attempt.prior_manifest.to_string(),
            attempt.request.to_string(),
        ],
        |row| row.get(0),
    )?;
    if exists == 0 {
        return Err(binding("prior refresh artifact is not a certified partitioned publication"));
    }
    Ok(())
}

fn ensure_wire_bound(label: &'static str, actual: usize, maximum: usize) -> Result<(), StoreError> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(binding(format!("{label} contains {actual} bytes; the maximum is {maximum}",)))
    }
}

fn u64_to_sql(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| binding("value exceeds the SQLite integer range"))
}

fn i64_to_u64(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| corruption("stored value is negative"))
}

fn binding(message: impl Into<String>) -> StoreError {
    StoreError::PartitionedActionPublicationBinding(message.into())
}

fn conflict(message: impl Into<String>) -> StoreError {
    StoreError::PartitionedActionPublicationConflict(message.into())
}

fn corruption(message: impl Into<String>) -> StoreError {
    StoreError::PartitionedActionPublicationCorruption(message.into())
}

#[cfg(test)]
#[path = "partitioned_artifacts/tests.rs"]
mod tests;
