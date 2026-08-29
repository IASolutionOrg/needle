use super::*;
use crate::{ShadowPartitionManifestPublication, built_in_partition_definitions};
use needle_core::{
    ActionContractId, ArtifactId, ArtifactRequestId, CapabilityMode, CoverageManifest,
    DerivationRuleId, Digest, FailedRefreshMemo, ManifestBinding, ManifestClosure,
    ManifestProvenance, ManifestTransition, OpaquePartitionKey, PartitionEntry,
    PartitionKeyMapping, PartitionManifest, PartitionManifestValidationCertificate, PartitionRef,
    PartitionRole, RefreshAttemptInput, SemanticWorld,
};
use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture {
    prior: ShadowPartitionManifestPublication,
    current: ShadowPartitionManifestPublication,
    transition: ManifestTransition,
    request: ArtifactRequestId,
    action_contract: ActionContractId,
    retained_key: Digest,
    refreshed_key: Digest,
    added_key: Digest,
    removed_key: Digest,
}

fn digest(value: impl AsRef<[u8]>) -> Digest {
    Digest::blake3(value)
}

fn temporary_store() -> (PathBuf, RuntimeStore) {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let path = std::env::temp_dir().join(format!(
        "needle-refresh-persistence-{}-{}.sqlite3",
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

fn entry(label: &str, payload: &str, world: &SemanticWorld) -> PartitionEntry {
    let definition = &built_in_partition_definitions()[0];
    let dependency = digest(format!("dependency-{label}"));
    PartitionEntry::new(
        OpaquePartitionKey::new(
            &definition.scheme,
            digest(format!("key-{label}")).bytes().to_vec(),
            None,
        )
        .unwrap(),
        PartitionRole::Component,
        digest(payload),
        CoverageManifest {
            entries: Vec::new(),
            world: world.clone(),
            dependency_manifest_digest: dependency,
        },
        dependency,
        Vec::new(),
        Vec::new(),
    )
    .unwrap()
}

fn publication(
    binding: &ManifestBinding,
    entries: Vec<PartitionEntry>,
    label: &str,
) -> ShadowPartitionManifestPublication {
    let definition = &built_in_partition_definitions()[0];
    let manifest = PartitionManifest::new(
        &definition.scheme,
        binding.clone(),
        ManifestProvenance::RequestBound { request: binding.action_request },
        ManifestClosure::Closed,
        entries,
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

fn fixture() -> Fixture {
    let definition = &built_in_partition_definitions()[0];
    let repository = digest("repository");
    let world = SemanticWorld {
        repository_lineage: repository,
        source_selector: "source-current".to_owned(),
        platform: "any".to_owned(),
        features: "default".to_owned(),
        configuration: None,
        toolchain: None,
    };
    let request = ArtifactRequestId::new(digest("request"));
    let binding = ManifestBinding::new(
        request,
        definition.action_contract.clone(),
        definition.output_contract_id,
        needle_core::semantic_input_set_digest(&[]).unwrap(),
        world.id(),
        repository,
        &world.source_selector,
        digest("definition-set"),
    )
    .unwrap();
    let prior_retained = entry("retained", "payload-retained", &world);
    let prior_refreshed = entry("refreshed", "payload-before", &world);
    let prior_removed = entry("removed", "payload-removed", &world);
    let current_retained = entry("retained", "payload-retained", &world);
    let current_refreshed = entry("refreshed", "payload-after", &world);
    let current_added = entry("added", "payload-added", &world);
    let retained_key = prior_retained.key.digest;
    let refreshed_key = prior_refreshed.key.digest;
    let removed_key = prior_removed.key.digest;
    let added_key = current_added.key.digest;
    assert_eq!(current_retained.key.digest, retained_key);
    assert_eq!(current_refreshed.key.digest, refreshed_key);
    let prior_entries = vec![prior_retained, prior_refreshed, prior_removed];
    let current_entries = vec![current_retained, current_refreshed, current_added];
    let prior = publication(&binding, prior_entries, "prior");
    let current = publication(&binding, current_entries, "current");
    let transition = ManifestTransition::new(
        prior.manifest.id,
        current.manifest.id,
        digest("state-delta"),
        vec![
            PartitionKeyMapping {
                prior: PartitionRef::new(prior.manifest.id, retained_key),
                current: PartitionRef::new(current.manifest.id, retained_key),
            },
            PartitionKeyMapping {
                prior: PartitionRef::new(prior.manifest.id, refreshed_key),
                current: PartitionRef::new(current.manifest.id, refreshed_key),
            },
        ],
        ManifestProvenance::derived(
            DerivationRuleId::new(digest("refresh-derivation")),
            vec![prior.manifest.id, current.manifest.id],
        )
        .unwrap(),
        definition.policy.manifest_validator.clone(),
    )
    .unwrap();
    Fixture {
        prior,
        current,
        transition,
        request,
        action_contract: definition.action_contract.clone(),
        retained_key,
        refreshed_key,
        added_key,
        removed_key,
    }
}

fn failed_attempt(fixture: &Fixture, execution_scope: Digest) -> RefreshAttempt {
    RefreshAttempt::new(RefreshAttemptInput {
        request: fixture.request,
        action_contract: fixture.action_contract.clone(),
        prior_artifact: ArtifactId::new(digest("prior-artifact")),
        state_delta: fixture.transition.state_delta,
        prior_manifest: fixture.prior.manifest.id,
        current_manifest: fixture.current.manifest.id,
        manifest_transition: fixture.transition.id,
        retained_partitions: vec![PartitionKeyMapping {
            prior: PartitionRef::new(fixture.prior.manifest.id, fixture.retained_key),
            current: PartitionRef::new(fixture.current.manifest.id, fixture.retained_key),
        }],
        refreshed_partitions: vec![PartitionRef::new(
            fixture.current.manifest.id,
            fixture.refreshed_key,
        )],
        added_partitions: vec![PartitionRef::new(fixture.current.manifest.id, fixture.added_key)],
        removed_partitions: vec![PartitionRef::new(fixture.prior.manifest.id, fixture.removed_key)],
        refresh_policy_definition_digest: digest("refresh-policy"),
        operator_definition_digest: digest("operator"),
        execution_scope_digest: execution_scope,
        execution_attempts: Vec::new(),
        started_unix_ms: 10,
        completed_unix_ms: 20,
        cost_microusd: None,
        outcome: RefreshOutcome::Failed {
            failure_class: RefreshFailureClass::Validation,
            failure_evidence_digest: digest("failure-evidence"),
        },
    })
    .unwrap()
}

fn persist_fixture(store: &RuntimeStore, fixture: &Fixture) {
    store.publish_shadow_partition_manifest(&fixture.prior).unwrap();
    store.publish_shadow_partition_manifest(&fixture.current).unwrap();
    store.record_shadow_manifest_transition(&fixture.transition).unwrap();
}

#[test]
fn migration_v24_is_complete_and_append_only() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let fixture = fixture();
    persist_fixture(&store, &fixture);
    let attempt = failed_attempt(&fixture, digest("scope"));
    let memo = FailedRefreshMemo::from_attempt(&attempt, Some(100)).unwrap();
    store.persist_refresh_attempt(&attempt, Some(&memo)).unwrap();
    drop(store);

    let connection = Connection::open(&path).unwrap();
    let versions = connection
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| row.get::<_, u32>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(versions, (1..=37).collect::<Vec<_>>());
    for table in ["refresh_attempts", "failed_refresh_memos"] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get::<_, u32>(0),
                )
                .unwrap(),
            1
        );
    }
    assert!(
        connection
            .execute(
                "UPDATE refresh_attempts SET created_unix_ms=0 WHERE attempt_id=?1",
                [attempt.id.to_string()],
            )
            .is_err()
    );
    assert!(
        connection
            .execute("DELETE FROM failed_refresh_memos WHERE memo_id=?1", [memo.id.to_string()])
            .is_err()
    );
    drop(connection);
    cleanup(&path);
}

#[test]
fn failed_attempt_and_narrow_memo_round_trip_idempotently() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let fixture = fixture();
    persist_fixture(&store, &fixture);
    let attempt = failed_attempt(&fixture, digest("scope"));
    let memo = FailedRefreshMemo::from_attempt(&attempt, Some(100)).unwrap();
    store.persist_refresh_attempt(&attempt, Some(&memo)).unwrap();
    store.persist_refresh_attempt(&attempt, Some(&memo)).unwrap();
    let replacement = FailedRefreshMemo::from_attempt(&attempt, Some(200)).unwrap();
    assert!(matches!(
        store.persist_refresh_attempt(&attempt, Some(&replacement)),
        Err(StoreError::RefreshPersistenceConflict(_))
    ));
    assert_eq!(store.refresh_attempt(attempt.id).unwrap(), Some(attempt.clone()));
    assert_eq!(store.failed_refresh_memo(memo.id).unwrap(), Some(memo.clone()));
    assert_eq!(store.active_failed_refresh_memo(&memo.key(), 99).unwrap(), Some(memo.clone()));
    assert_eq!(store.active_failed_refresh_memo(&memo.key(), 100).unwrap(), None);
    let mut mismatched = memo.key();
    mismatched.execution_scope_digest = digest("other-scope");
    assert_eq!(store.active_failed_refresh_memo(&mismatched, 99).unwrap(), None);

    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM refresh_attempts", [], |row| { row.get::<_, u32>(0) })
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM failed_refresh_memos", [], |row| {
                row.get::<_, u32>(0)
            })
            .unwrap(),
        1
    );
    drop(connection);
    drop(store);
    cleanup(&path);
}

#[test]
fn memo_and_transition_bindings_fail_closed() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let fixture = fixture();
    persist_fixture(&store, &fixture);
    let first = failed_attempt(&fixture, digest("scope-one"));
    let second = failed_attempt(&fixture, digest("scope-two"));
    let first_memo = FailedRefreshMemo::from_attempt(&first, Some(100)).unwrap();
    assert!(matches!(
        store.persist_refresh_attempt(&second, Some(&first_memo)),
        Err(StoreError::RefreshPersistenceBinding(_))
    ));
    drop(store);
    cleanup(&path);

    let (path, store) = temporary_store();
    store.initialize().unwrap();
    store.publish_shadow_partition_manifest(&fixture.prior).unwrap();
    store.publish_shadow_partition_manifest(&fixture.current).unwrap();
    assert!(matches!(
        store.persist_refresh_attempt(&first, None),
        Err(StoreError::RefreshPersistenceBinding(_))
    ));
    drop(store);
    cleanup(&path);
}

#[test]
fn successful_attempt_persists_without_negative_knowledge() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let fixture = fixture();
    persist_fixture(&store, &fixture);
    let failed = failed_attempt(&fixture, digest("success-scope"));
    let success = RefreshAttempt::new(RefreshAttemptInput {
        request: failed.request,
        action_contract: failed.action_contract.clone(),
        prior_artifact: failed.prior_artifact,
        state_delta: failed.state_delta,
        prior_manifest: failed.prior_manifest,
        current_manifest: failed.current_manifest,
        manifest_transition: failed.manifest_transition,
        retained_partitions: failed.retained_partitions.clone(),
        refreshed_partitions: failed.refreshed_partitions.clone(),
        added_partitions: failed.added_partitions.clone(),
        removed_partitions: failed.removed_partitions.clone(),
        refresh_policy_definition_digest: failed.refresh_policy_definition_digest,
        operator_definition_digest: failed.operator_definition_digest,
        execution_scope_digest: failed.execution_scope_digest,
        execution_attempts: failed.execution_attempts.clone(),
        started_unix_ms: failed.started_unix_ms,
        completed_unix_ms: failed.completed_unix_ms,
        cost_microusd: failed.cost_microusd,
        outcome: RefreshOutcome::Succeeded {
            reconstructed_artifact: ArtifactId::new(digest("reconstructed")),
            validation_certificate: needle_core::ArtifactValidationCertificateId::new(digest(
                "validation-certificate",
            )),
        },
    })
    .unwrap();
    assert_eq!(success.authority, CapabilityMode::Shadow);
    store.persist_refresh_attempt(&success, None).unwrap();
    assert_eq!(store.refresh_attempt(success.id).unwrap(), Some(success));
    drop(store);
    cleanup(&path);
}
