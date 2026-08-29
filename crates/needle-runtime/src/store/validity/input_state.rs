use super::super::{RuntimeStore, StoreError, parse_digest};
use super::records::{load_artifact_pair, validate_stored_pair};
use crate::input_artifact_state::{
    ArtifactGraphNode, ArtifactGraphRevalidationReason, ArtifactGraphSnapshot,
    ArtifactGraphValidity, MAX_INPUT_ARTIFACT_STATE_NODES, validate_artifact_graph_snapshot,
    validate_artifact_input_graph_snapshot,
};
use arrayvec::ArrayVec;
use needle_core::{
    Artifact, ArtifactId, ArtifactValidationCertificate, ArtifactValidationCertificateId,
    CacheScope, Digest, MAX_NEED_INPUTS,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

impl RuntimeStore {
    /// Captures a bounded, transactionally consistent artifact graph and then
    /// validates its current filesystem evidence after releasing the store lock.
    pub fn validate_artifact_graph(
        &self,
        root_artifact: &Artifact,
        root_certificate: &ArtifactValidationCertificate,
        repository_root: &Path,
        source_snapshot_digest: Digest,
    ) -> Result<ArtifactGraphValidity, StoreError> {
        self.validate_artifact_graph_with_root_policy(
            root_artifact,
            root_certificate,
            repository_root,
            source_snapshot_digest,
            true,
        )
    }

    /// Validates the complete recursive input closure while leaving freshness
    /// of the root artifact to a narrower claim certificate. This preserves
    /// claim-level reuse when unrelated evidence in the origin artifact is stale.
    pub(crate) fn validate_artifact_input_graph(
        &self,
        root_artifact: &Artifact,
        root_certificate: &ArtifactValidationCertificate,
        repository_root: &Path,
        source_snapshot_digest: Digest,
    ) -> Result<ArtifactGraphValidity, StoreError> {
        self.validate_artifact_graph_with_root_policy(
            root_artifact,
            root_certificate,
            repository_root,
            source_snapshot_digest,
            false,
        )
    }

    fn validate_artifact_graph_with_root_policy(
        &self,
        root_artifact: &Artifact,
        root_certificate: &ArtifactValidationCertificate,
        repository_root: &Path,
        source_snapshot_digest: Digest,
        validate_root_filesystem: bool,
    ) -> Result<ArtifactGraphValidity, StoreError> {
        let snapshot = {
            let mut connection = self.connection()?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            let root_id = ArtifactId::new(root_artifact.id);
            let (stored_artifact, stored_certificate, _) =
                load_artifact_pair(&transaction, root_id, root_certificate.id)?;
            if &stored_artifact != root_artifact || &stored_certificate != root_certificate {
                return Err(StoreError::DependencyValidityConflict(
                    "root artifact pair differs from its stored canonical records".to_owned(),
                ));
            }
            if validate_root_filesystem {
                validate_stored_pair(&stored_artifact, &stored_certificate)?;
            }

            let mut nodes = BTreeMap::new();
            nodes.insert(
                root_id,
                graph_node(
                    &transaction,
                    stored_artifact,
                    stored_certificate,
                    source_snapshot_digest,
                )?,
            );
            let mut queue = VecDeque::from([root_id]);
            let mut queued = BTreeSet::from([root_id]);

            while let Some(parent_id) = queue.pop_front() {
                let parent = nodes.get(&parent_id).expect("queued graph node is loaded");
                if parent.certificate.input_artifacts.len() > MAX_NEED_INPUTS {
                    transaction.commit()?;
                    return Ok(ArtifactGraphValidity::RequiresRevalidation {
                        reason: ArtifactGraphRevalidationReason::InputArtifactBound {
                            artifact: parent_id,
                        },
                    });
                }
                let mut inputs = ArrayVec::<ArtifactId, MAX_NEED_INPUTS>::new();
                inputs
                    .try_extend_from_slice(&parent.certificate.input_artifacts)
                    .expect("certificate input bound was checked");
                inputs.sort_unstable();
                if inputs.windows(2).any(|pair| pair[0] == pair[1]) {
                    transaction.commit()?;
                    return Ok(ArtifactGraphValidity::RequiresRevalidation {
                        reason: ArtifactGraphRevalidationReason::DuplicateInputArtifact {
                            artifact: parent_id,
                        },
                    });
                }
                for input in inputs {
                    if !queued.insert(input) {
                        continue;
                    }
                    if queued.len().saturating_sub(1) > MAX_INPUT_ARTIFACT_STATE_NODES {
                        transaction.commit()?;
                        return Ok(ArtifactGraphValidity::RequiresRevalidation {
                            reason: ArtifactGraphRevalidationReason::GraphNodeBound,
                        });
                    }
                    let Some(certificate_id) = latest_certificate_id(&transaction, input)? else {
                        let reason = if artifact_exists(&transaction, input)? {
                            ArtifactGraphRevalidationReason::MissingInputCertificate {
                                artifact: input,
                            }
                        } else {
                            ArtifactGraphRevalidationReason::MissingInputArtifact {
                                artifact: input,
                            }
                        };
                        transaction.commit()?;
                        return Ok(ArtifactGraphValidity::RequiresRevalidation { reason });
                    };
                    let (artifact, certificate, _) =
                        load_artifact_pair(&transaction, input, certificate_id)?;
                    validate_stored_pair(&artifact, &certificate)?;
                    nodes.insert(
                        input,
                        graph_node(&transaction, artifact, certificate, source_snapshot_digest)?,
                    );
                    queue.push_back(input);
                }
            }
            transaction.commit()?;
            ArtifactGraphSnapshot { root: root_id, source_snapshot_digest, nodes }
        };
        Ok(if validate_root_filesystem {
            validate_artifact_graph_snapshot(&snapshot, repository_root)
        } else {
            validate_artifact_input_graph_snapshot(&snapshot, repository_root)
        })
    }
}

fn latest_certificate_id(
    connection: &Connection,
    artifact: ArtifactId,
) -> Result<Option<ArtifactValidationCertificateId>, StoreError> {
    connection
        .query_row(
            "SELECT certificate_id FROM artifact_validation_certificates
             WHERE artifact_id=?1
             ORDER BY issued_unix_ms DESC, certificate_id DESC
             LIMIT 1",
            [artifact.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|value| {
            parse_digest(&value).map(ArtifactValidationCertificateId::new).map_err(|error| {
                StoreError::DependencyValidityCorruption(format!(
                    "stored validation certificate id is invalid: {error}"
                ))
            })
        })
        .transpose()
}

fn artifact_exists(connection: &Connection, artifact: ArtifactId) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT 1 FROM artifacts WHERE artifact_id=?1 LIMIT 1",
            [artifact.to_string()],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(StoreError::from)
}

fn graph_node(
    connection: &Connection,
    artifact: Artifact,
    certificate: ArtifactValidationCertificate,
    source_snapshot_digest: Digest,
) -> Result<ArtifactGraphNode, StoreError> {
    let has_current_source = artifact.contract.cache_scope != CacheScope::SnapshotExact
        || artifact_has_source(connection, ArtifactId::new(artifact.id), source_snapshot_digest)?;
    Ok(ArtifactGraphNode { artifact, certificate, has_current_source })
}

fn artifact_has_source(
    connection: &Connection,
    artifact: ArtifactId,
    source_snapshot_digest: Digest,
) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT 1 FROM (
                 SELECT origins.artifact_id AS artifact_id,
                        requests.source_digest AS source_digest
                 FROM artifact_origins origins
                 JOIN artifact_requests requests ON requests.request_id=origins.request_id
                 UNION ALL
                 SELECT artifact_id, source_digest FROM action_request_observations
             ) observations
             WHERE observations.artifact_id=?1 AND observations.source_digest=?2
             LIMIT 1",
            params![artifact.to_string(), source_snapshot_digest.to_string()],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(StoreError::from)
}
