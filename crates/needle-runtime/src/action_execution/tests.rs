use super::*;
use needle_core::{
    AcceptanceCoverage, AcceptanceStatus, ActionContractId, AllowedPath, AllowedPathScope,
    ChangeActionInvocation, ChangeRequest, Facet, NeedExecutionEnvelopeV1, NeedIr, NeedKey,
    ObligationExpression, PATCH_PROPOSE_ACTION_CONTRACT, PatchArtifact, PatchFile, PatchOperation,
    PredicateKind, SubjectExpression, SubjectKind,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
struct PatchProvider {
    calls: Arc<AtomicUsize>,
}

impl ChangeActionProvider for PatchProvider {
    fn execute(
        &self,
        context: ChangeActionProviderContext<'_>,
    ) -> Result<ChangeActionProviderOutput, ChangeActionProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let source = context.request.artifact_request.source_snapshot_digest;
        let files = vec![PatchFile {
            path: "src/lib.rs".to_owned(),
            operation: PatchOperation::Update,
            before_digest: Some(Digest::blake3("before")),
            after_digest: Some(Digest::blake3("after")),
            before_bytes: 10,
            after_bytes: 12,
        }];
        let patch = PatchArtifact {
            id: PatchArtifact::compute_id(source, &files),
            change_id: context.input.change_id(source),
            revision: 1,
            source_snapshot: source,
            files,
            summary: "Update the implementation.".to_owned(),
            acceptance_coverage: vec![AcceptanceCoverage {
                criterion: "The behavior is updated.".to_owned(),
                status: AcceptanceStatus::Addressed,
                evidence: "src/lib.rs".to_owned(),
            }],
            residual_risks: Vec::new(),
            declared_output_digest: Digest::blake3("provider-output"),
            discrepancies: Vec::new(),
        };
        Ok(ChangeActionProviderOutput {
            output: ChangeActionOutput::PatchProposal(patch),
            world: context.need.world.clone(),
            dependency_manifest: DependencyManifest {
                scope: CacheScope::SnapshotExact,
                observed_files_complete: false,
                dependencies: Vec::new(),
                gaps: vec!["provider-owned-patch".to_owned()],
            },
            review_manifest: None,
            review_transition: None,
            usage: LifecycleUsage { worker_turns: 1, output_tokens: 7, cost_microusd: 11 },
        })
    }
}

fn envelope(operation_id: Digest) -> NeedExecutionEnvelopeV1 {
    NeedExecutionEnvelopeV1::new(
        operation_id,
        NeedIr {
            route_hint: Some(NeedKey::new("locate.implementation").unwrap()),
            subjects: vec![SubjectExpression {
                kind: SubjectKind::Symbol,
                canonical_name: "implementation".to_owned(),
            }],
            required: vec![ObligationExpression {
                predicate: PredicateKind::ImplementationLocation,
                facets: vec![Facet { key: "selection".to_owned(), value: "primary".to_owned() }],
            }],
            preferred: Vec::new(),
            semantic_constraints: Vec::new(),
            world: Vec::new(),
            input_artifacts: Vec::new(),
            projection: Vec::new(),
            body: "Update the implementation.".to_owned(),
            format_revision: needle_core::NEED_IR_FORMAT_REVISION,
        },
        NeedExecution::Action {
            action: ChangeActionInvocation {
                contract: ActionContractId::new(PATCH_PROPOSE_ACTION_CONTRACT).unwrap(),
                input: ChangeActionInput::PatchPropose {
                    change: ChangeRequest {
                        task: "Update the implementation.".to_owned(),
                        acceptance_criteria: vec!["The behavior is updated.".to_owned()],
                        allowed_paths: vec![AllowedPath {
                            path: "src".to_owned(),
                            scope: AllowedPathScope::Subtree,
                        }],
                        artifact_ids: Vec::new(),
                        claim_ids: Vec::new(),
                        constraints: Vec::new(),
                    },
                    prior_patch: None,
                    repair_verification: None,
                },
            },
        },
    )
}

#[test]
fn shadow_action_execution_publishes_atomically_and_replays_by_operation() {
    let suffix =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("needle-action-execution-{suffix}.sqlite3"));
    let store = RuntimeStore::new(&path);
    let calls = Arc::new(AtomicUsize::new(0));
    let service = ActionExecutionService::new(store, PatchProvider { calls: calls.clone() });
    let request = envelope(Digest::blake3("operation"));
    let repository = Digest::blake3("repository");
    let source = Digest::blake3("source");

    let first = service.execute_action(&request, repository, source).unwrap();
    assert_eq!(first.authority, CapabilityMode::Shadow);
    assert!(!first.completion_reused);
    assert!(!first.idempotent_replay);
    assert_eq!(
        first.usage,
        LifecycleUsage { worker_turns: 1, output_tokens: 7, cost_microusd: 11 }
    );
    assert_eq!(first.request.format_revision, 3);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let replay = service.execute_action(&request, repository, source).unwrap();
    assert!(replay.idempotent_replay);
    assert_eq!(replay.artifact.id, first.artifact.id);
    assert_eq!(replay.validation_certificate, first.validation_certificate);
    assert_eq!(replay.usage, first.usage);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    drop(service);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("sqlite3-wal"));
    let _ = std::fs::remove_file(path.with_extension("sqlite3-shm"));
}

#[test]
fn operation_id_cannot_be_rebound_to_different_semantics() {
    let suffix =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("needle-action-conflict-{suffix}.sqlite3"));
    let store = RuntimeStore::new(&path);
    let calls = Arc::new(AtomicUsize::new(0));
    let service = ActionExecutionService::new(store, PatchProvider { calls });
    let operation = Digest::blake3("same-operation");
    let first = envelope(operation);
    service.execute_action(&first, Digest::blake3("repository"), Digest::blake3("source")).unwrap();
    let mut changed = envelope(operation);
    let NeedExecution::Action { action } = &mut changed.execution else { unreachable!() };
    let ChangeActionInput::PatchPropose { change, .. } = &mut action.input else { unreachable!() };
    change.task = "Different semantic request.".to_owned();
    assert!(matches!(
        service.execute_action(&changed, Digest::blake3("repository"), Digest::blake3("source")),
        Err(ActionExecutionError::Store(StoreError::ActionExecutionConflict(_)))
    ));

    drop(service);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("sqlite3-wal"));
    let _ = std::fs::remove_file(path.with_extension("sqlite3-shm"));
}

#[test]
fn interrupted_non_effect_action_never_reinvokes_the_provider() {
    let suffix =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("needle-action-interrupted-{suffix}.sqlite3"));
    let store = RuntimeStore::new(&path);
    let calls = Arc::new(AtomicUsize::new(0));
    let request = envelope(Digest::blake3("interrupted-operation"));
    let repository = Digest::blake3("repository");
    let source = Digest::blake3("source");
    let compiled = compile_action_request(&request, repository, source).unwrap();
    assert_eq!(
        store
            .claim_action_execution_operation(request.operation_id, compiled.request.semantic_id())
            .unwrap(),
        crate::store::ActionExecutionOperationClaim::Execute { resumed: false }
    );

    let service = ActionExecutionService::new(store, PatchProvider { calls: calls.clone() });
    assert!(matches!(
        service.execute_action(&request, repository, source),
        Err(ActionExecutionError::OperationRecoveryRequired)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    drop(service);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("sqlite3-wal"));
    let _ = std::fs::remove_file(path.with_extension("sqlite3-shm"));
}

#[test]
fn failed_operation_completion_rolls_back_the_entire_opaque_publication() {
    let suffix =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("needle-action-atomic-rollback-{suffix}.sqlite3"));
    let store = RuntimeStore::new(&path);
    store.initialize().unwrap();
    let envelope = envelope(Digest::blake3("unclaimed-operation"));
    let source = Digest::blake3("source");
    let compiled = compile_action_request(&envelope, Digest::blake3("repository"), source).unwrap();
    let NeedExecution::Action { action } = &envelope.execution else { unreachable!() };
    let provider = PatchProvider { calls: Arc::new(AtomicUsize::new(0)) }
        .execute(ChangeActionProviderContext {
            operation_id: envelope.operation_id,
            need: &compiled.need,
            fragment: &compiled.fragment,
            request: &compiled.request,
            input: &action.input,
            definition_set_digest: crate::active_definition_set().audit_digest,
        })
        .unwrap();
    let output = provider.output;
    let source_payload_digest = output.source_payload_digest();
    let (request, publication) =
        certify_shadow_opaque_action_artifact(OpaqueActionCertificationInput {
            request: compiled.request,
            source_payload_digest,
            output,
            world: provider.world,
            dependency_manifest: provider.dependency_manifest,
            issued_unix_ms: crate::store::now_ms(),
        })
        .unwrap();
    let artifact_id = publication.artifact().id;

    assert!(matches!(
        store.publish_shadow_opaque_action_execution(
            envelope.operation_id,
            &request,
            &publication,
            &provider.usage,
        ),
        Err(StoreError::ActionExecutionConflict(_))
    ));
    assert!(store.semantic_artifact(&artifact_id.to_string()).unwrap().is_none());
    assert!(
        store
            .opaque_action_artifact_by_payload(
                &ActionContractId::new(PATCH_PROPOSE_ACTION_CONTRACT).unwrap(),
                source_payload_digest,
            )
            .unwrap()
            .is_none()
    );

    drop(store);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("sqlite3-wal"));
    let _ = std::fs::remove_file(path.with_extension("sqlite3-shm"));
}
