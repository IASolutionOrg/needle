use super::*;
use crate::certify_test_target_inventory_action_artifact;
use crate::partitioned_action_artifact::tests::fixture;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn temporary_store() -> (PathBuf, RuntimeStore) {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let path = std::env::temp_dir()
        .join(format!("needle-partitioned-head-{}-{nanos}.sqlite3", std::process::id()));
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

#[test]
fn headed_publication_round_trips_and_advances_with_compare_and_swap() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let (request, inventory, validation, world, manifest) = fixture();
    store.publish_shadow_partition_manifest(&manifest).unwrap();
    let publication = certify_test_target_inventory_action_artifact(
        &request,
        &inventory,
        &validation,
        &world,
        &manifest,
        42,
    )
    .unwrap();
    let key = PartitionedActionHeadKey::new(
        request.contract.clone(),
        inventory.repository_lineage,
        RepositoryContextId::new(Digest::blake3(b"partitioned-head-context")),
        &inventory.source_selector,
        Digest::blake3(b"cargo-provider-context"),
        inventory.scope.digest(),
    )
    .unwrap();
    let validation_json = serde_json::to_vec(&validation).unwrap();
    let first = store
        .publish_shadow_partitioned_action_artifact_and_advance_head(
            &request,
            &manifest,
            &publication,
            ShadowPartitionedActionHeadAdvance {
                key: key.clone(),
                expected_prior_artifact: None,
                repository_generation: 0,
                source_validation_certificate_digest: validation.certificate_digest,
                source_validation_validator_definition_digest: validation
                    .validator_definition_digest,
                source_validation_json: &validation_json,
                content_digest: inventory.content_digest,
            },
        )
        .unwrap();
    let loaded = store.partitioned_action_head_base(&key).unwrap().unwrap();
    assert_eq!(loaded.head, first);
    assert_eq!(loaded.request, request);
    assert_eq!(loaded.manifest, manifest);
    assert_eq!(loaded.publication, publication);
    assert_eq!(loaded.source_validation_json, validation_json);

    let second = store
        .advance_existing_partitioned_action_head(ShadowPartitionedActionHeadAdvance {
            key: key.clone(),
            expected_prior_artifact: Some(first.artifact),
            repository_generation: 1,
            source_validation_certificate_digest: validation.certificate_digest,
            source_validation_validator_definition_digest: validation.validator_definition_digest,
            source_validation_json: &validation_json,
            content_digest: inventory.content_digest,
        })
        .unwrap();
    assert_eq!(second.repository_generation, 1);
    assert_eq!(second.artifact, first.artifact);
    let replayed = store
        .advance_existing_partitioned_action_head(ShadowPartitionedActionHeadAdvance {
            key: key.clone(),
            expected_prior_artifact: Some(first.artifact),
            repository_generation: 1,
            source_validation_certificate_digest: validation.certificate_digest,
            source_validation_validator_definition_digest: validation.validator_definition_digest,
            source_validation_json: &validation_json,
            content_digest: inventory.content_digest,
        })
        .unwrap();
    assert_eq!(replayed, second);
    assert!(
        store
            .advance_existing_partitioned_action_head(ShadowPartitionedActionHeadAdvance {
                key: key.clone(),
                expected_prior_artifact: Some(ArtifactId::new(Digest::blake3(b"wrong-prior"))),
                repository_generation: 2,
                source_validation_certificate_digest: validation.certificate_digest,
                source_validation_validator_definition_digest: validation
                    .validator_definition_digest,
                source_validation_json: &validation_json,
                content_digest: inventory.content_digest,
            })
            .is_err()
    );
    assert_eq!(store.partitioned_action_head(&key).unwrap(), Some(second));
    cleanup(&path);
}

#[test]
fn failed_head_binding_rolls_back_the_new_partitioned_publication() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let (request, inventory, validation, world, manifest) = fixture();
    store.publish_shadow_partition_manifest(&manifest).unwrap();
    let publication = certify_test_target_inventory_action_artifact(
        &request,
        &inventory,
        &validation,
        &world,
        &manifest,
        42,
    )
    .unwrap();
    let key = PartitionedActionHeadKey::new(
        request.contract.clone(),
        inventory.repository_lineage,
        RepositoryContextId::new(Digest::blake3(b"partitioned-head-rollback")),
        &inventory.source_selector,
        Digest::blake3(b"cargo-provider-context"),
        inventory.scope.digest(),
    )
    .unwrap();
    let validation_json = serde_json::to_vec(&validation).unwrap();
    assert!(
        store
            .publish_shadow_partitioned_action_artifact_and_advance_head(
                &request,
                &manifest,
                &publication,
                ShadowPartitionedActionHeadAdvance {
                    key: key.clone(),
                    expected_prior_artifact: None,
                    repository_generation: 0,
                    source_validation_certificate_digest: Digest::blake3(b"wrong-validation"),
                    source_validation_validator_definition_digest: validation
                        .validator_definition_digest,
                    source_validation_json: &validation_json,
                    content_digest: inventory.content_digest,
                },
            )
            .is_err()
    );
    assert_eq!(store.semantic_artifact(&publication.artifact().id.to_string()).unwrap(), None);
    assert_eq!(store.partitioned_action_head(&key).unwrap(), None);
    cleanup(&path);
}
