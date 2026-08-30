use super::partitioned_artifacts::{insert_artifact, insert_immutable_json};
use super::{
    ActionExecutionUsage, RuntimeStore, StoreError, insert_action_request_observation,
    insert_action_request_row,
};
use crate::ShadowOpaqueActionArtifactPublication;
use needle_core::{
    ActionContractId, ActionOutputValidationCertificate, ActionRequest, Artifact, ArtifactId,
    Digest, MAX_ACTION_OUTPUT_VALIDATION_CERTIFICATE_WIRE_BYTES,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

const MAX_OPAQUE_ACTION_ARTIFACT_WIRE_BYTES: usize = 2 * 1024 * 1024;

struct PreparedOpaquePublication {
    artifact_json: String,
    certificate_json: String,
}

impl RuntimeStore {
    pub(crate) fn ensure_certified_action_inputs(
        &self,
        inputs: &[ArtifactId],
    ) -> Result<(), StoreError> {
        let connection = self.connection()?;
        for input in inputs {
            if !certified_input_exists(&connection, *input)? {
                return Err(binding(format!("action input `{input}` is not certified")));
            }
        }
        Ok(())
    }

    /// Atomically persists one fully validated non-partitioned action output.
    /// The certificate remains Shadow and is not read by the resolver.
    pub fn publish_shadow_opaque_action_artifact(
        &self,
        request: &ActionRequest,
        publication: &ShadowOpaqueActionArtifactPublication,
    ) -> Result<(), StoreError> {
        let prepared = prepare_opaque_publication(request, publication)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_opaque_publication(&transaction, request, publication, &prepared)?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically publishes the action output and completes its idempotent
    /// operation. A crash cannot leave a committed artifact behind a running
    /// operation that the caller is then forbidden to resume.
    pub(crate) fn publish_shadow_opaque_action_execution(
        &self,
        operation_id: Digest,
        request: &ActionRequest,
        publication: &ShadowOpaqueActionArtifactPublication,
        usage: ActionExecutionUsage<'_>,
    ) -> Result<(), StoreError> {
        let prepared = prepare_opaque_publication(request, publication)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_opaque_publication(&transaction, request, publication, &prepared)?;
        super::action_execution_operations::complete_action_execution_operation_in_transaction(
            &transaction,
            operation_id,
            request.semantic_id(),
            ArtifactId::new(publication.artifact().id),
            publication.certificate().id,
            None,
            usage,
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Resolve one certified opaque action output through its typed payload
    /// identity. This is used only to carry immutable artifact references
    /// between lifecycle phases; it does not confer reuse authority.
    pub fn opaque_action_artifact_by_payload(
        &self,
        action_contract: &ActionContractId,
        source_payload_digest: Digest,
    ) -> Result<Option<Artifact>, StoreError> {
        let connection = self.connection()?;
        let json = connection
            .query_row(
                "SELECT a.artifact_json
                 FROM opaque_action_validation_certificates certificate
                 JOIN artifacts a ON a.artifact_id=certificate.artifact_id
                 WHERE certificate.action_contract_id=?1
                   AND certificate.source_payload_digest=?2
                 ORDER BY certificate.issued_unix_ms DESC, certificate.certificate_id DESC
                 LIMIT 1",
                params![action_contract.as_str(), source_payload_digest.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        json.map(|value| serde_json::from_str(&value).map_err(StoreError::from)).transpose()
    }
}

fn prepare_opaque_publication(
    request: &ActionRequest,
    publication: &ShadowOpaqueActionArtifactPublication,
) -> Result<PreparedOpaquePublication, StoreError> {
    publication.validate(request).map_err(|error| binding(error.to_string()))?;
    let artifact_json = serde_json::to_string(publication.artifact())?;
    let certificate_json = serde_json::to_string(publication.certificate())?;
    if artifact_json.len() > MAX_OPAQUE_ACTION_ARTIFACT_WIRE_BYTES
        || certificate_json.len() > MAX_ACTION_OUTPUT_VALIDATION_CERTIFICATE_WIRE_BYTES
    {
        return Err(binding("opaque action publication exceeds its wire bound"));
    }
    Ok(PreparedOpaquePublication { artifact_json, certificate_json })
}

fn insert_opaque_publication(
    connection: &rusqlite::Connection,
    request: &ActionRequest,
    publication: &ShadowOpaqueActionArtifactPublication,
    prepared: &PreparedOpaquePublication,
) -> Result<(), StoreError> {
    for input in &publication.certificate().input_artifacts {
        if !certified_input_exists(connection, *input)? {
            return Err(binding(format!("opaque action input `{input}` is not certified")));
        }
    }

    insert_action_request_row(connection, request, publication.artifact().created_unix_ms)?;
    insert_artifact(connection, publication.artifact(), &prepared.artifact_json)?;
    connection.execute(
        "INSERT OR IGNORE INTO artifact_origins(
            artifact_id, request_id, route_key, need_id, observed_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
        params![
            publication.artifact().id.to_string(),
            request.semantic_id().to_string(),
            request.artifact_request.route_key.as_str(),
            request.root_need.to_string(),
            publication.artifact().created_unix_ms,
        ],
    )?;
    insert_action_request_observation(
        connection,
        request,
        publication.artifact().id,
        publication.artifact().created_unix_ms,
    )?;
    insert_world_and_manifest(connection, publication)?;
    insert_certificate(connection, publication.certificate(), &prepared.certificate_json)?;
    Ok(())
}

fn certified_input_exists(
    connection: &rusqlite::Connection,
    input: ArtifactId,
) -> Result<bool, StoreError> {
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
    Ok(exists != 0)
}

fn insert_world_and_manifest(
    connection: &rusqlite::Connection,
    publication: &ShadowOpaqueActionArtifactPublication,
) -> Result<(), StoreError> {
    let world = &publication.certificate().world;
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
                params![
                    world_digest.to_string(),
                    world_json,
                    publication.artifact().created_unix_ms
                ],
            )
        },
    )?;

    let digest = publication.certificate().dependency_manifest_digest;
    let manifest_json = serde_json::to_string(&publication.artifact().dependency_manifest)?;
    insert_immutable_json(
        connection,
        "dependency_manifests",
        "manifest_digest",
        &digest.to_string(),
        "manifest_json",
        &manifest_json,
        "dependency manifest",
        || {
            connection.execute(
                "INSERT INTO dependency_manifests(manifest_digest, manifest_json, created_unix_ms)
                 VALUES(?1, ?2, ?3)",
                params![digest.to_string(), manifest_json, publication.artifact().created_unix_ms],
            )
        },
    )?;
    Ok(())
}

fn insert_certificate(
    connection: &rusqlite::Connection,
    certificate: &ActionOutputValidationCertificate,
    certificate_json: &str,
) -> Result<(), StoreError> {
    let existing = connection
        .query_row(
            "SELECT certificate_json FROM opaque_action_validation_certificates
             WHERE certificate_id=?1",
            [certificate.id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        if existing != certificate_json {
            return Err(conflict("opaque action certificate has different immutable content"));
        }
        return Ok(());
    }
    connection.execute(
        "INSERT INTO opaque_action_validation_certificates(
            certificate_id, artifact_id, action_contract_id,
            action_semantic_definition_digest, action_validation_definition_digest,
            output_contract_definition_digest, source_payload_digest,
            dependency_manifest_digest, semantic_world_digest,
            validator_definition_digest, authority, certificate_json, issued_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'shadow', ?11, ?12)",
        params![
            certificate.id.to_string(),
            certificate.artifact.to_string(),
            certificate.action_contract.as_str(),
            certificate.action_semantic_definition_digest.to_string(),
            certificate.action_validation_definition_digest.to_string(),
            certificate.output_contract_definition_digest.to_string(),
            certificate.source_payload_digest.to_string(),
            certificate.dependency_manifest_digest.to_string(),
            certificate.world.id().to_string(),
            certificate.validator_definition_digest.to_string(),
            certificate_json,
            certificate.issued_unix_ms,
        ],
    )?;
    Ok(())
}

fn binding(message: impl Into<String>) -> StoreError {
    StoreError::ArtifactIdentity(message.into())
}

fn conflict(message: impl Into<String>) -> StoreError {
    StoreError::ArtifactIdentity(message.into())
}
