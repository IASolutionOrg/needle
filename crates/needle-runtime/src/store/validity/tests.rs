use super::super::{RuntimeStore, StoreError};
use crate::semantic_validation::validation_certificate_id;
use crate::{
    ArtifactGraphRevalidationReason, ArtifactGraphValidity, built_in_action_for_artifact_kind,
    empty_input_artifact_state_digest, manifest_digest,
};
use needle_core::{
    ActionRequest, Artifact, ArtifactContract, ArtifactId, ArtifactKind, ArtifactRequest,
    ArtifactValidationCertificate, CacheScope, CoverageEntry, CoverageManifest, DefinitionHandle,
    DefinitionKind, DefinitionSet, DefinitionSetEntry, Dependency, DependencyLocator,
    DependencyManifest, DependencyStamp, Digest, Facet, FastValidityReason, FastValidityResult,
    LocationRole, NeedFragmentId, NeedId, NeedKey, Obligation, PredicateKind, RepositoryContextId,
    RepositoryGeneration, SemanticLocation, SemanticWorkerArtifact, SemanticWorld, StateDelta,
    SubjectId,
};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn digest(label: &str) -> Digest {
    Digest::blake3(label)
}

fn temporary_store() -> (PathBuf, RuntimeStore) {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let path = std::env::temp_dir().join(format!("needle-validity-{nanos}.sqlite3"));
    (path.clone(), RuntimeStore::new(path))
}

fn cleanup(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("sqlite3-shm"));
    let _ = std::fs::remove_file(path.with_extension("sqlite3-wal"));
}

fn facets_for(predicate: PredicateKind) -> Vec<Facet> {
    match predicate {
        PredicateKind::ImplementationLocation => vec![
            Facet { key: "granularity".to_owned(), value: "exact-location".to_owned() },
            Facet { key: "polarity".to_owned(), value: "positive".to_owned() },
            Facet { key: "selection".to_owned(), value: "primary".to_owned() },
        ],
        PredicateKind::RuntimeFlow => vec![
            Facet { key: "completeness".to_owned(), value: "contract-complete".to_owned() },
            Facet { key: "granularity".to_owned(), value: "stepwise".to_owned() },
            Facet { key: "scenario".to_owned(), value: "default".to_owned() },
        ],
        PredicateKind::FocusedTests => vec![
            Facet { key: "completeness".to_owned(), value: "open-world".to_owned() },
            Facet { key: "polarity".to_owned(), value: "positive".to_owned() },
            Facet { key: "selection".to_owned(), value: "representative".to_owned() },
        ],
    }
}

fn artifact_fixture(
    kind: ArtifactKind,
    source: Digest,
    input_artifacts: Vec<ArtifactId>,
    variant: &str,
) -> (ActionRequest, Artifact, ArtifactValidationCertificate) {
    let action = built_in_action_for_artifact_kind(&kind).unwrap();
    let artifact_request = ArtifactRequest {
        contract_id: action.output_contract_id.to_owned(),
        contract_revision: action.output_contract_revision,
        repository_id: digest("repository"),
        source_snapshot_digest: source,
        route_key: NeedKey::new("locate.implementation").unwrap(),
        normalized_request: format!("find {variant}"),
        semantic_fragment_id: Some(NeedFragmentId::new(digest(&format!("fragment-{variant}")))),
        input_artifact_ids: input_artifacts.iter().map(|id| id.digest()).collect(),
    };
    let request = ActionRequest::new(
        &action.contract,
        artifact_request,
        action.contract.default_dispatch_policy,
        NeedKey::new("locate.implementation").unwrap(),
        NeedId::new(digest(&format!("need-{variant}"))),
    )
    .unwrap();
    let payload = match kind.0.as_str() {
        "code-location" => SemanticWorkerArtifact::CodeLocation {
            locations: vec![SemanticLocation {
                role: LocationRole::Primary,
                path: "src/lib.rs".to_owned(),
                symbol: Some(variant.to_owned()),
                byte_start: Some(0),
                byte_end: Some(1),
            }],
            gaps: Vec::new(),
        },
        "behavior-trace" => SemanticWorkerArtifact::BehaviorTrace {
            scenario: variant.to_owned(),
            steps: Vec::new(),
            gaps: Vec::new(),
        },
        other => panic!("unsupported fixture kind {other}"),
    };
    let contract = ArtifactContract::semantic(
        action.output_contract_id,
        action.output_contract_revision,
        kind.clone(),
        CacheScope::WorktreeSemantic,
    );
    let artifact_id = payload.canonical_artifact_id(contract.definition_digest).unwrap();
    let predicate = action.predicate().unwrap();
    let obligation = Obligation::new(
        predicate,
        SubjectId::new(digest(&format!("subject-{variant}"))),
        facets_for(predicate),
    );
    let dependency_manifest = DependencyManifest {
        scope: CacheScope::WorktreeSemantic,
        observed_files_complete: true,
        dependencies: vec![Dependency {
            path: "src/lib.rs".to_owned(),
            content_digest: digest("repository-evidence"),
            byte_start: None,
            byte_end: None,
            claims: vec![obligation.id.to_string()],
        }],
        gaps: Vec::new(),
    };
    let dependency_manifest_digest = manifest_digest(&dependency_manifest);
    let coverage = CoverageManifest {
        entries: vec![CoverageEntry { obligation, evidence: vec!["src/lib.rs:item".to_owned()] }],
        world: SemanticWorld {
            repository_lineage: digest("repository"),
            source_selector: "worktree".to_owned(),
            platform: "windows".to_owned(),
            features: "default".to_owned(),
            configuration: None,
            toolchain: None,
        },
        dependency_manifest_digest,
    };
    let validator_definition = crate::validator_definition(&kind);
    let certificate_id = validation_certificate_id(
        artifact_id,
        &input_artifacts,
        &[],
        &coverage,
        validator_definition,
        None,
    );
    let certificate = ArtifactValidationCertificate {
        id: certificate_id,
        artifact: artifact_id,
        input_artifacts,
        evidence_ids: Vec::new(),
        test_plan_evidence: None,
        coverage,
        validator_definition,
        dependency_checks_digest: dependency_manifest_digest,
        issued_unix_ms: 1,
    };
    let artifact = Artifact {
        id: artifact_id.digest(),
        request_id: request.semantic_id().digest(),
        contract,
        payload: serde_json::to_value(payload).unwrap(),
        dependency_manifest,
        validations: Vec::new(),
        created_unix_ms: 1,
    };
    (request, artifact, certificate)
}

fn initialize_generation(
    store: &RuntimeStore,
    context: RepositoryContextId,
    source: Digest,
) -> RepositoryGeneration {
    let generation = RepositoryGeneration::new(
        digest("repository"),
        context,
        0,
        source,
        Some(digest("source-version-0")),
        true,
    );
    store.initialize_repository_generation(&generation).unwrap();
    generation
}

fn advance_generation(
    store: &RuntimeStore,
    context: RepositoryContextId,
    from: u64,
    changed: Vec<DependencyLocator>,
    complete: bool,
) -> RepositoryGeneration {
    let next = RepositoryGeneration::new(
        digest("repository"),
        context,
        from + 1,
        digest(&format!("source-{}", from + 1)),
        Some(digest(&format!("source-version-{}", from + 1))),
        true,
    );
    let delta = StateDelta::new(
        digest("repository"),
        context,
        from,
        from + 1,
        changed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        complete,
    )
    .unwrap();
    store.advance_repository_generation(&next, &delta).unwrap();
    next
}

fn published_fixture(
    store: &RuntimeStore,
    source: Digest,
    context: RepositoryContextId,
) -> (Artifact, ArtifactValidationCertificate, DependencyStamp) {
    let (request, artifact, certificate) =
        artifact_fixture(ArtifactKind::code_location(), source, Vec::new(), "root");
    store.publish_action_artifact(&request, &artifact, &certificate).unwrap();
    initialize_generation(store, context, source);
    let stamp = store
        .record_dependency_stamp(ArtifactId::new(artifact.id), certificate.id, context)
        .unwrap();
    (artifact, certificate, stamp)
}

fn retarget_dependency(
    artifact: &mut Artifact,
    certificate: &mut ArtifactValidationCertificate,
    path: &str,
    bytes: &[u8],
) {
    artifact.dependency_manifest.dependencies[0].path = path.to_owned();
    artifact.dependency_manifest.dependencies[0].content_digest = Digest::blake3(bytes);
    let manifest = manifest_digest(&artifact.dependency_manifest);
    certificate.coverage.dependency_manifest_digest = manifest;
    certificate.dependency_checks_digest = manifest;
    certificate.id = validation_certificate_id(
        certificate.artifact,
        &certificate.input_artifacts,
        &certificate.evidence_ids,
        &certificate.coverage,
        certificate.validator_definition,
        certificate.test_plan_evidence,
    );
}

#[test]
fn filesystem_fallback_validates_recursive_inputs_and_detects_nested_change() {
    let (path, store) = temporary_store();
    let repository_root = path.with_extension("repo");
    std::fs::create_dir_all(&repository_root).unwrap();
    std::fs::write(repository_root.join("input.rs"), b"input-stable").unwrap();
    std::fs::write(repository_root.join("root.rs"), b"root-stable").unwrap();
    store.initialize().unwrap();
    let source = digest("source-graph");

    let (input_request, mut input_artifact, mut input_certificate) =
        artifact_fixture(ArtifactKind::code_location(), source, Vec::new(), "input");
    retarget_dependency(&mut input_artifact, &mut input_certificate, "input.rs", b"input-stable");
    store.publish_action_artifact(&input_request, &input_artifact, &input_certificate).unwrap();

    let input_id = ArtifactId::new(input_artifact.id);
    let (root_request, mut root_artifact, mut root_certificate) =
        artifact_fixture(ArtifactKind::code_location(), source, vec![input_id], "root-with-input");
    retarget_dependency(&mut root_artifact, &mut root_certificate, "root.rs", b"root-stable");
    store.publish_action_artifact(&root_request, &root_artifact, &root_certificate).unwrap();

    let input_only = store
        .validate_artifact_graph(&input_artifact, &input_certificate, &repository_root, source)
        .unwrap();
    let ArtifactGraphValidity::Fresh { state: input_state } = input_only else {
        panic!("input-only graph must be fresh: {input_only:?}");
    };
    assert_eq!(input_state.validated_input_count, 0);
    assert_eq!(input_state.input_artifact_state_digest, empty_input_artifact_state_digest());

    let recursive = store
        .validate_artifact_graph(&root_artifact, &root_certificate, &repository_root, source)
        .unwrap();
    let ArtifactGraphValidity::Fresh { state } = recursive else {
        panic!("recursive graph must be fresh: {recursive:?}");
    };
    assert_eq!(state.validated_input_count, 1);
    assert_ne!(state.input_artifact_state_digest, empty_input_artifact_state_digest());

    let root_id = ArtifactId::new(root_artifact.id);
    std::fs::write(repository_root.join("root.rs"), b"root-changed").unwrap();
    assert_eq!(
        store
            .validate_artifact_graph(&root_artifact, &root_certificate, &repository_root, source,)
            .unwrap(),
        ArtifactGraphValidity::RequiresRevalidation {
            reason: ArtifactGraphRevalidationReason::ArtifactFilesystemStale { artifact: root_id }
        }
    );
    assert!(matches!(
        store
            .validate_artifact_input_graph(
                &root_artifact,
                &root_certificate,
                &repository_root,
                source,
            )
            .unwrap(),
        ArtifactGraphValidity::Fresh { .. }
    ));
    std::fs::write(repository_root.join("root.rs"), b"root-stable").unwrap();

    std::fs::write(repository_root.join("input.rs"), b"input-changed").unwrap();
    assert_eq!(
        store
            .validate_artifact_graph(&root_artifact, &root_certificate, &repository_root, source,)
            .unwrap(),
        ArtifactGraphValidity::RequiresRevalidation {
            reason: ArtifactGraphRevalidationReason::ArtifactFilesystemStale { artifact: input_id }
        }
    );

    cleanup(&path);
    std::fs::remove_dir_all(repository_root).unwrap();
}

#[test]
fn migration_and_dependency_stamp_are_idempotent_and_immutable() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let source = digest("source-0");
    let context = RepositoryContextId::new(digest("context"));
    let (_, certificate, stamp) = published_fixture(&store, source, context);

    assert_eq!(
        store.record_dependency_stamp(stamp.artifact, certificate.id, context).unwrap(),
        stamp
    );
    assert_eq!(store.dependency_stamp(stamp.id).unwrap(), Some(stamp.clone()));

    let connection = Connection::open(&path).unwrap();
    let versions: Vec<u32> = connection
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(versions, (1..=37).collect::<Vec<_>>());
    assert!(
        connection.execute("UPDATE artifact_dependency_stamps SET created_unix_ms=0", []).is_err()
    );
    assert!(connection.execute("DELETE FROM artifact_dependency_stamps", []).is_err());
    drop(connection);
    drop(store);
    cleanup(&path);
}

#[test]
fn current_and_disjoint_generations_create_exact_memoized_results() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let source = digest("source-0");
    let context = RepositoryContextId::new(digest("context"));
    let (_, _, stamp) = published_fixture(&store, source, context);

    let current = store.evaluate_dependency_stamp(stamp.id).unwrap();
    let FastValidityResult::Current { memo: current_memo } = current else {
        panic!("expected current memo");
    };
    assert_eq!(current_memo.source_generation, 0);
    assert_eq!(current_memo.validated_through_generation, 0);
    assert_eq!(
        store.evaluate_dependency_stamp(stamp.id).unwrap(),
        FastValidityResult::Current { memo: current_memo.clone() }
    );
    assert_eq!(store.operational_validity_memo(current_memo.id).unwrap(), Some(current_memo));

    let unrelated = DependencyLocator::repository_path("README.md").unwrap();
    advance_generation(&store, context, 0, vec![unrelated], true);
    let result = store.evaluate_dependency_stamp(stamp.id).unwrap();
    let FastValidityResult::UnaffectedByDelta { updated_generation, memo } = result else {
        panic!("expected unaffected memo");
    };
    assert_eq!(updated_generation, 1);
    assert_eq!(memo.source_generation, 0);
    assert_eq!(memo.validated_through_generation, 1);
    assert_eq!(
        store.evaluate_dependency_stamp(stamp.id).unwrap(),
        FastValidityResult::UnaffectedByDelta { updated_generation: 1, memo: memo.clone() }
    );

    let connection = Connection::open(&path).unwrap();
    assert!(
        connection.execute("UPDATE operational_validity_memos SET created_unix_ms=0", []).is_err()
    );
    assert!(connection.execute("DELETE FROM operational_validity_memos", []).is_err());
    drop(connection);
    drop(store);
    cleanup(&path);
}

#[test]
fn intersection_and_incomplete_delta_fail_closed_without_a_positive_memo() {
    for (changed, complete, expected) in [
        (
            vec![DependencyLocator::repository_path("src/lib.rs").unwrap()],
            true,
            FastValidityReason::DependencyIntersection,
        ),
        (Vec::new(), false, FastValidityReason::DeltaUncertain),
    ] {
        let (path, store) = temporary_store();
        store.initialize().unwrap();
        let source = digest("source-0");
        let context = RepositoryContextId::new(digest("context"));
        let (_, _, stamp) = published_fixture(&store, source, context);
        advance_generation(&store, context, 0, changed, complete);

        assert_eq!(
            store.evaluate_dependency_stamp(stamp.id).unwrap(),
            FastValidityResult::RequiresRevalidation { reason: expected }
        );
        let connection = Connection::open(&path).unwrap();
        let count: u64 = connection
            .query_row("SELECT COUNT(*) FROM operational_validity_memos", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        drop(connection);
        drop(store);
        cleanup(&path);
    }
}

#[test]
fn definition_change_and_artifact_inputs_fail_closed() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let source = digest("source-0");
    let context = RepositoryContextId::new(digest("context"));
    let (base_artifact, _, base_stamp) = published_fixture(&store, source, context);

    let mut entries = crate::active_definition_set().entries.clone();
    entries.push(
        DefinitionSetEntry::new(
            DefinitionKind::RefreshPolicy,
            DefinitionHandle::new("needle.test.operational-change").unwrap(),
            None,
            None,
            Some(digest("changed-operational-definition")),
            digest("changed-operational-definition"),
        )
        .unwrap(),
    );
    store.reconcile_definition_set(&DefinitionSet::new(entries).unwrap()).unwrap();
    assert_eq!(
        store.evaluate_dependency_stamp(base_stamp.id).unwrap(),
        FastValidityResult::RequiresRevalidation {
            reason: FastValidityReason::DefinitionSetChanged,
        }
    );

    let (request, artifact, certificate) = artifact_fixture(
        ArtifactKind::behavior_trace(),
        source,
        vec![ArtifactId::new(base_artifact.id)],
        "with-input",
    );
    store.publish_action_artifact(&request, &artifact, &certificate).unwrap();
    let input_stamp = store
        .record_dependency_stamp(ArtifactId::new(artifact.id), certificate.id, context)
        .unwrap();
    assert_eq!(
        store.evaluate_dependency_stamp(input_stamp.id).unwrap(),
        FastValidityResult::RequiresRevalidation {
            reason: FastValidityReason::ArtifactInputsRequireRecursiveValidation,
        }
    );

    drop(store);
    cleanup(&path);
}

#[test]
fn stamp_rejects_a_source_that_is_not_the_current_generation() {
    let (path, store) = temporary_store();
    store.initialize().unwrap();
    let context = RepositoryContextId::new(digest("context"));
    let (request, artifact, certificate) = artifact_fixture(
        ArtifactKind::code_location(),
        digest("artifact-source"),
        Vec::new(),
        "mismatch",
    );
    store.publish_action_artifact(&request, &artifact, &certificate).unwrap();
    initialize_generation(&store, context, digest("different-generation-source"));

    assert!(matches!(
        store.record_dependency_stamp(ArtifactId::new(artifact.id), certificate.id, context),
        Err(StoreError::DependencyValidityConflict(message))
            if message.contains("source snapshot")
    ));
    drop(store);
    cleanup(&path);
}
