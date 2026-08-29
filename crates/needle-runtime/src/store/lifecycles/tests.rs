use super::*;
use crate::{
    LifecycleExploreActionResolverOutcome, LifecycleExploreShadowObservation,
    LifecycleExploreShadowResolutionKind, compile_lifecycle_explore_action_plan,
};
use needle_core::{
    AcceptanceCoverage, AcceptanceStatus, AllowedPath, AllowedPathScope, ApprovalDecisionSource,
    Artifact, ArtifactContract, ArtifactValidationCertificate, CacheScope, ChangeApplyId,
    ChangeApplyRecord, ChangeApplyStatus, CodexHost, CommandExecutionEvidence, CommandPolicy,
    CoverageManifest, DependencyManifest, Facet, FallbackPolicy, FilesystemPolicy,
    LifecycleAcceptanceReview, LifecycleArtifactKind, LifecycleArtifactRef, LifecycleBudget,
    LifecyclePatchRef, LifecycleReviewVerdict, LifecycleTestPlanBinding, LifecycleTestResult,
    LifecycleUsage, LifecycleVerificationRef, LifecycleWorkerCompletion, LocationRole, Need,
    NeedId, NeedRequest, NetworkPolicy, Obligation, PatchArtifact, PatchFile, PatchOperation,
    PredicateKind, ReasoningLevel, RepairPolicy, ReviewArtifact, RoleProfileBudget,
    RoleProfileDefinition, RoleProfileDefinitionInput, RoleProfileState, SemanticLocation,
    SemanticWorkerArtifact, SemanticWorld, ServiceTier, Subject, SubjectKind, TestPlan,
    TestPlanEvidenceStatus, TestPolicy, ToolPolicy, VerificationArtifact, VerificationPlanResult,
    VerificationStatus, VerificationTestProjection, need_fragment,
};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

fn temporary_path(name: &str) -> PathBuf {
    let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir()
        .join(format!("needle-lifecycle-{name}-{}-{suffix}.sqlite3", std::process::id()))
}

fn lifecycle_explore_plan(
    repository: Digest,
    source: Digest,
) -> needle_core::LifecycleExploreActionPlan {
    let subject = Subject::exact(repository, SubjectKind::CliOption, "--lifecycle");
    let required = vec![Obligation::new(
        PredicateKind::ImplementationLocation,
        subject.id,
        vec![Facet { key: "selection".to_owned(), value: "primary".to_owned() }],
    )];
    let request = NeedRequest {
        key: needle_core::NeedKey::new("locate.implementation").unwrap(),
        body: "Locate the lifecycle implementation.".to_owned(),
    };
    let need = Need {
        id: NeedId::new(Digest::blake3(b"store-lifecycle-explore-need")),
        subjects: vec![subject],
        required,
        preferred: Vec::new(),
        semantic_constraints: Vec::new(),
        world: SemanticWorld {
            repository_lineage: repository,
            source_selector: "worktree".to_owned(),
            platform: "windows".to_owned(),
            features: "default".to_owned(),
            configuration: None,
            toolchain: None,
        },
        input_artifacts: Vec::new(),
        residual: None,
        body_digest: Digest::blake3(request.body.as_bytes()),
        format_revision: needle_core::NEED_IR_FORMAT_REVISION,
    };
    let fragment = need_fragment(&need, need.required.clone(), Vec::new());
    compile_lifecycle_explore_action_plan(&request, &need, &fragment, repository, source).unwrap()
}

fn active_profile(store: &RuntimeStore, id: &str, role: CodexRole) -> RoleProfileProvenance {
    let test_role = matches!(role, CodexRole::TestRunner | CodexRole::Verifier);
    let implementer = role == CodexRole::Implementer;
    let definition = RoleProfileDefinition::new(RoleProfileDefinitionInput {
        profile_id: needle_core::RoleProfileId::new(id).unwrap(),
        role,
        host: CodexHost::Codex,
        model: "offline-lifecycle-worker".to_owned(),
        reasoning: ReasoningLevel::Medium,
        service_tier: ServiceTier::Default,
        timeout_seconds: 30,
        budget: RoleProfileBudget {
            max_turns: 2,
            max_output_tokens: 1_200,
            max_cost_microusd: 10_000,
        },
        prompt_profile_digest: Digest::blake3(format!("{id}:prompt")),
        output_contract_digest: Digest::blake3(format!("{id}:output")),
        tool_policy: if implementer { ToolPolicy::IsolatedWrite } else { ToolPolicy::ReadOnly },
        command_policy: if test_role {
            CommandPolicy::CertifiedTests
        } else {
            CommandPolicy::Denied
        },
        filesystem_policy: if implementer {
            FilesystemPolicy::DisposableCheckout
        } else {
            FilesystemPolicy::ReadOnlyCheckout
        },
        network_policy: NetworkPolicy::Denied,
        test_policy: if test_role { TestPolicy::Certified } else { TestPolicy::Disabled },
        repair_policy: if implementer { RepairPolicy::Once } else { RepairPolicy::None },
        fallback_policy: FallbackPolicy::Disabled,
        concurrency: 1,
        route_assignments: if role == CodexRole::Explorer {
            vec![needle_core::NeedKey::new("locate.implementation").unwrap()]
        } else {
            Vec::new()
        },
    })
    .unwrap();
    let revision = store.create_role_profile(definition).unwrap();
    let state = store.role_profile_state(&revision.profile_id).unwrap();
    let revision = store
        .activate_role_profile(&revision.profile_id, revision.revision, state.state_digest)
        .unwrap();
    assert_eq!(revision.state, RoleProfileState::Active);
    RoleProfileProvenance::from_revision(&revision).unwrap()
}

fn worker(profile: &RoleProfileProvenance) -> LifecycleWorkerCompletion {
    LifecycleWorkerCompletion {
        profile: profile.clone(),
        worker_depth: 1,
        logical_worker_spawns: 1,
        usage: LifecycleUsage { worker_turns: 1, output_tokens: 10, cost_microusd: 10 },
    }
}

fn seed_test_plan_certificate(
    store: &RuntimeStore,
    name: &str,
    source: Digest,
    plan: &TestPlan,
) -> Digest {
    let request_id = Digest::blake3(format!("{name}:test-plan-request"));
    let dependency_digest = Digest::blake3(format!("{name}:dependency-manifest"));
    let world = SemanticWorld {
        repository_lineage: Digest::blake3(format!("{name}:repository")),
        source_selector: source.to_string(),
        platform: "test".to_owned(),
        features: "offline".to_owned(),
        configuration: None,
        toolchain: None,
    };
    let worker_artifact = SemanticWorkerArtifact::TestPlan {
        runner: plan.runner.clone(),
        argv: plan.argv.clone(),
        cwd_relative: plan.cwd_relative.clone(),
        identifiers: vec![plan.test_identifier.clone()],
        selection: "focused".to_owned(),
        evidence_paths: Vec::new(),
    };
    let contract = ArtifactContract::semantic(
        format!("{name}.test-plan"),
        1,
        worker_artifact.kind(),
        CacheScope::SnapshotExact,
    );
    let artifact_id = worker_artifact.canonical_artifact_id(contract.definition_digest).unwrap();
    let artifact = Artifact {
        id: artifact_id.digest(),
        request_id,
        contract,
        payload: serde_json::to_value(&worker_artifact).unwrap(),
        dependency_manifest: DependencyManifest {
            scope: CacheScope::SnapshotExact,
            observed_files_complete: true,
            dependencies: Vec::new(),
            gaps: Vec::new(),
        },
        validations: Vec::new(),
        created_unix_ms: 1,
    };
    let coverage = CoverageManifest {
        entries: Vec::new(),
        world: world.clone(),
        dependency_manifest_digest: dependency_digest,
    };
    let validator_definition = Digest::blake3(format!("{name}:validator"));
    let certificate_id = crate::semantic_validation::validation_certificate_id(
        artifact_id,
        &[],
        &[],
        &coverage,
        validator_definition,
        Some(TestPlanEvidenceStatus::Located),
    );
    let certificate_digest = certificate_id.digest();
    let certificate = ArtifactValidationCertificate {
        id: certificate_id,
        artifact: artifact_id,
        input_artifacts: Vec::new(),
        evidence_ids: Vec::new(),
        test_plan_evidence: Some(TestPlanEvidenceStatus::Located),
        coverage,
        validator_definition,
        dependency_checks_digest: dependency_digest,
        issued_unix_ms: 1,
    };
    let connection = store.connection().unwrap();
    connection
        .execute(
            "INSERT INTO artifact_requests(
                request_id, logical_id, source_digest, contract_id, route_key,
                request_json, created_unix_ms, format_revision
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 1, 2)",
            params![
                request_id.to_string(),
                format!("{name}:test-plan"),
                source.to_string(),
                artifact.contract.id.as_str(),
                "test-plan",
                "{}",
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO artifacts(
                artifact_id, request_id, contract_id, artifact_json,
                created_unix_ms, format_revision
             ) VALUES(?1, ?2, ?3, ?4, 1, 2)",
            params![
                artifact_id.to_string(),
                request_id.to_string(),
                artifact.contract.id.as_str(),
                serde_json::to_string(&artifact).unwrap(),
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO semantic_worlds(world_digest, world_json, created_unix_ms)
             VALUES(?1, ?2, 1)",
            params![world.id().to_string(), serde_json::to_string(&world).unwrap()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO artifact_validation_certificates(
                certificate_id, artifact_id, validator_definition_digest,
                dependency_manifest_digest, world_digest, certificate_json, issued_unix_ms
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 1)",
            params![
                certificate_digest.to_string(),
                artifact_id.to_string(),
                certificate.validator_definition.to_string(),
                dependency_digest.to_string(),
                world.id().to_string(),
                serde_json::to_string(&certificate).unwrap(),
            ],
        )
        .unwrap();
    certificate_digest
}

fn seed_action_native_test_plan_certificate(
    store: &RuntimeStore,
    name: &str,
    source: Digest,
    plan: &TestPlan,
) -> Digest {
    let repository = Digest::blake3(format!("{name}:repository"));
    let subject = Subject::exact(repository, SubjectKind::Symbol, &plan.test_identifier);
    let obligation = Obligation::new(
        PredicateKind::FocusedTests,
        subject.id,
        vec![Facet { key: "selection".to_owned(), value: "representative".to_owned() }],
    );
    let need_request = NeedRequest {
        key: needle_core::NeedKey::new("tests.relevant").unwrap(),
        body: "Find the exact focused lifecycle start test.".to_owned(),
    };
    let need = Need {
        id: NeedId::new(Digest::blake3(format!("{name}:need"))),
        subjects: vec![subject],
        required: vec![obligation],
        preferred: Vec::new(),
        semantic_constraints: Vec::new(),
        world: SemanticWorld {
            repository_lineage: repository,
            source_selector: source.to_string(),
            platform: "test".to_owned(),
            features: "offline".to_owned(),
            configuration: None,
            toolchain: None,
        },
        input_artifacts: Vec::new(),
        residual: None,
        body_digest: Digest::blake3(need_request.body.as_bytes()),
        format_revision: needle_core::NEED_IR_FORMAT_REVISION,
    };
    let fragment = need_fragment(&need, need.required.clone(), Vec::new());
    let definition = crate::built_in_action_for_predicate(PredicateKind::FocusedTests);
    let request = crate::semantic_action_request::build_semantic_action_request(
        &need_request,
        &fragment,
        repository,
        source,
        definition,
    )
    .unwrap();
    let worker_artifact = SemanticWorkerArtifact::TestPlan {
        runner: plan.runner.clone(),
        argv: plan.argv.clone(),
        cwd_relative: plan.cwd_relative.clone(),
        identifiers: vec![plan.test_identifier.clone()],
        selection: "representative".to_owned(),
        evidence_paths: vec!["src/store/lifecycles/tests.rs".to_owned()],
    };
    let validated = crate::semantic_validation::validate_semantic_test_plan(
        &fragment,
        &worker_artifact,
        Path::new("."),
        request.semantic_id().digest(),
        None,
        plan,
    )
    .unwrap();
    let certificate_digest = validated.certificate.id.digest();
    store.publish_action_artifact(&request, &validated.artifact, &validated.certificate).unwrap();
    certificate_digest
}

fn seed_exploration_certificate(store: &RuntimeStore, name: &str, source: Digest) -> Digest {
    let request_id = Digest::blake3(format!("{name}:exploration-request"));
    let dependency_digest = Digest::blake3(format!("{name}:exploration-dependencies"));
    let world = SemanticWorld {
        repository_lineage: Digest::blake3(format!("{name}:repository")),
        source_selector: source.to_string(),
        platform: "test".to_owned(),
        features: "exploration".to_owned(),
        configuration: None,
        toolchain: None,
    };
    let worker_artifact = SemanticWorkerArtifact::CodeLocation {
        locations: vec![SemanticLocation {
            role: LocationRole::Primary,
            path: "fixture.txt".to_owned(),
            symbol: None,
            byte_start: Some(0),
            byte_end: Some(1),
        }],
        gaps: Vec::new(),
    };
    let contract = ArtifactContract::semantic(
        format!("{name}.exploration"),
        1,
        worker_artifact.kind(),
        CacheScope::SnapshotExact,
    );
    let artifact_id = worker_artifact.canonical_artifact_id(contract.definition_digest).unwrap();
    let artifact_digest = artifact_id.digest();
    let artifact = Artifact {
        id: artifact_digest,
        request_id,
        contract,
        payload: serde_json::to_value(&worker_artifact).unwrap(),
        dependency_manifest: DependencyManifest {
            scope: CacheScope::SnapshotExact,
            observed_files_complete: true,
            dependencies: Vec::new(),
            gaps: Vec::new(),
        },
        validations: Vec::new(),
        created_unix_ms: 1,
    };
    let coverage = CoverageManifest {
        entries: Vec::new(),
        world: world.clone(),
        dependency_manifest_digest: dependency_digest,
    };
    let validator_definition = Digest::blake3(format!("{name}:exploration-validator"));
    let certificate_id = crate::semantic_validation::validation_certificate_id(
        artifact_id,
        &[],
        &[],
        &coverage,
        validator_definition,
        None,
    );
    let certificate_digest = certificate_id.digest();
    let certificate = ArtifactValidationCertificate {
        id: certificate_id,
        artifact: artifact_id,
        input_artifacts: Vec::new(),
        evidence_ids: Vec::new(),
        test_plan_evidence: None,
        coverage,
        validator_definition,
        dependency_checks_digest: dependency_digest,
        issued_unix_ms: 1,
    };
    let connection = store.connection().unwrap();
    connection
        .execute(
            "INSERT INTO artifact_requests(
                request_id, logical_id, source_digest, contract_id, route_key,
                request_json, created_unix_ms, format_revision
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 1, 2)",
            params![
                request_id.to_string(),
                format!("{name}:exploration"),
                source.to_string(),
                artifact.contract.id.as_str(),
                "code-location",
                "{}",
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO artifacts(
                artifact_id, request_id, contract_id, artifact_json,
                created_unix_ms, format_revision
             ) VALUES(?1, ?2, ?3, ?4, 1, 2)",
            params![
                artifact_id.to_string(),
                request_id.to_string(),
                artifact.contract.id.as_str(),
                serde_json::to_string(&artifact).unwrap(),
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO semantic_worlds(world_digest, world_json, created_unix_ms)
             VALUES(?1, ?2, 1)",
            params![world.id().to_string(), serde_json::to_string(&world).unwrap()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO artifact_validation_certificates(
                certificate_id, artifact_id, validator_definition_digest,
                dependency_manifest_digest, world_digest, certificate_json, issued_unix_ms
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 1)",
            params![
                certificate_digest.to_string(),
                artifact_id.to_string(),
                certificate.validator_definition.to_string(),
                dependency_digest.to_string(),
                world.id().to_string(),
                serde_json::to_string(&certificate).unwrap(),
            ],
        )
        .unwrap();
    artifact_digest
}

fn seed_lifecycle(store: &RuntimeStore, name: &str) -> (ChangeId, LifecycleProjection) {
    seed_lifecycle_with_plan(store, name, None)
}

fn seed_lifecycle_with_explore_plan(
    store: &RuntimeStore,
    name: &str,
) -> (ChangeId, LifecycleProjection) {
    let repository = Digest::blake3(format!("{name}:repository"));
    let source = Digest::blake3(format!("{name}:source"));
    let plan = lifecycle_explore_plan(repository, source);
    seed_lifecycle_with_plan(store, name, Some(plan))
}

fn seed_lifecycle_with_plan(
    store: &RuntimeStore,
    name: &str,
    explore_action_plan: Option<needle_core::LifecycleExploreActionPlan>,
) -> (ChangeId, LifecycleProjection) {
    seed_lifecycle_with_plan_identity(
        store,
        name,
        Digest::blake3(format!("{name}:repository")),
        Digest::blake3(format!("{name}:source")),
        explore_action_plan,
    )
}

fn seed_lifecycle_with_plan_identity(
    store: &RuntimeStore,
    name: &str,
    repository: Digest,
    source: Digest,
    explore_action_plan: Option<needle_core::LifecycleExploreActionPlan>,
) -> (ChangeId, LifecycleProjection) {
    let profiles = LifecycleWorkerProfiles {
        explore: active_profile(store, &format!("{name}.explorer"), CodexRole::Explorer),
        implement: active_profile(store, &format!("{name}.implementer"), CodexRole::Implementer),
        test: active_profile(store, &format!("{name}.test"), CodexRole::TestRunner),
        review: active_profile(store, &format!("{name}.review"), CodexRole::Reviewer),
        verify: active_profile(store, &format!("{name}.verify"), CodexRole::Verifier),
    };
    let plan = TestPlan {
        runner: "cargo".to_owned(),
        argv: vec![
            "cargo".to_owned(),
            "test".to_owned(),
            "--offline".to_owned(),
            "focused".to_owned(),
            "--".to_owned(),
            "--exact".to_owned(),
        ],
        cwd_relative: ".".to_owned(),
        test_identifier: "focused".to_owned(),
        requires_approval: true,
        execution_evidence_id: None,
    };
    let certificate_digest = seed_test_plan_certificate(store, name, source, &plan);
    let request = ChangeRequest {
        task: "Implement the bounded lifecycle fixture.".to_owned(),
        acceptance_criteria: vec!["The lifecycle remains fail closed.".to_owned()],
        allowed_paths: vec![AllowedPath {
            path: "fixture.txt".to_owned(),
            scope: AllowedPathScope::Exact,
        }],
        artifact_ids: Vec::new(),
        claim_ids: Vec::new(),
        constraints: Vec::new(),
    };
    let change_id = ChangeId::from_digest(Digest::blake3(format!("{name}:change")));
    store
        .record_change_request_with_provenance(
            &change_id,
            repository,
            source,
            request.digest(source),
            &request,
            Some(&profiles.implement),
        )
        .unwrap();
    let projection = store
        .create_lifecycle(
            &change_id,
            LifecycleSpec {
                worker_depth_limit: 1,
                profiles,
                budget: LifecycleBudget {
                    max_worker_turns: 10,
                    max_output_tokens: 10_000,
                    max_cost_microusd: 100_000,
                    max_concurrent_workers: 1,
                },
                explore_action_plan,
                action_phase_plans: None,
                test_plans: vec![LifecycleTestPlanBinding { plan, certificate_digest }],
            },
        )
        .unwrap();
    (change_id, projection)
}

#[test]
fn lifecycle_start_is_atomic_idempotent_and_exactly_bound() {
    let name = "atomic-lifecycle-start";
    let path = temporary_path(name);
    let store = RuntimeStore::new(&path);
    store.initialize().unwrap();
    let repository = Digest::blake3(format!("{name}:repository"));
    let source = Digest::blake3(format!("{name}:source"));
    let profiles = LifecycleWorkerProfiles {
        explore: active_profile(&store, &format!("{name}.explorer"), CodexRole::Explorer),
        implement: active_profile(&store, &format!("{name}.implementer"), CodexRole::Implementer),
        test: active_profile(&store, &format!("{name}.test"), CodexRole::TestRunner),
        review: active_profile(&store, &format!("{name}.review"), CodexRole::Reviewer),
        verify: active_profile(&store, &format!("{name}.verify"), CodexRole::Verifier),
    };
    let plan = TestPlan {
        runner: "cargo".to_owned(),
        argv: vec![
            "cargo".to_owned(),
            "test".to_owned(),
            "focused".to_owned(),
            "--".to_owned(),
            "--exact".to_owned(),
        ],
        cwd_relative: ".".to_owned(),
        test_identifier: "focused".to_owned(),
        requires_approval: true,
        execution_evidence_id: None,
    };
    let certificate_digest = seed_test_plan_certificate(&store, name, source, &plan);
    let request = ChangeRequest {
        task: "Create one atomic lifecycle.".to_owned(),
        acceptance_criteria: vec!["The exact retry is idempotent.".to_owned()],
        allowed_paths: vec![AllowedPath {
            path: "fixture.txt".to_owned(),
            scope: AllowedPathScope::Exact,
        }],
        artifact_ids: Vec::new(),
        claim_ids: Vec::new(),
        constraints: Vec::new(),
    };
    let spec = LifecycleSpec {
        worker_depth_limit: 1,
        profiles,
        budget: LifecycleBudget {
            max_worker_turns: 10,
            max_output_tokens: 10_000,
            max_cost_microusd: 100_000,
            max_concurrent_workers: 1,
        },
        explore_action_plan: Some(lifecycle_explore_plan(repository, source)),
        action_phase_plans: None,
        test_plans: vec![LifecycleTestPlanBinding { plan, certificate_digest }],
    };
    let change_id = ChangeId::from_digest(Digest::blake3(format!("{name}:change")));

    let created = store
        .create_lifecycle_with_request(&change_id, repository, source, &request, spec.clone())
        .unwrap();
    assert!(created.created);
    let replayed = store
        .create_lifecycle_with_request(&change_id, repository, source, &request, spec.clone())
        .unwrap();
    assert!(!replayed.created);
    assert_eq!(replayed.projection, created.projection);
    assert_eq!(store.lifecycle_events(&change_id).unwrap().len(), 1);

    let mut changed_request = request.clone();
    changed_request.task.push_str(" changed");
    assert!(matches!(
        store.create_lifecycle_with_request(&change_id, repository, source, &changed_request, spec),
        Err(StoreError::ChangeConflict(_))
    ));
    assert_eq!(store.replay_lifecycle(&change_id).unwrap(), created.projection);

    drop(store);
    fs::remove_file(path).unwrap();
}

#[test]
fn lifecycle_start_failure_does_not_leave_an_orphan_change_request() {
    let name = "atomic-lifecycle-start-failure";
    let path = temporary_path(name);
    let store = RuntimeStore::new(&path);
    store.initialize().unwrap();
    let repository = Digest::blake3(format!("{name}:repository"));
    let source = Digest::blake3(format!("{name}:source"));
    let profiles = LifecycleWorkerProfiles {
        explore: active_profile(&store, &format!("{name}.explorer"), CodexRole::Explorer),
        implement: active_profile(&store, &format!("{name}.implementer"), CodexRole::Implementer),
        test: active_profile(&store, &format!("{name}.test"), CodexRole::TestRunner),
        review: active_profile(&store, &format!("{name}.review"), CodexRole::Reviewer),
        verify: active_profile(&store, &format!("{name}.verify"), CodexRole::Verifier),
    };
    let request = ChangeRequest {
        task: "Reject an invalid lifecycle atomically.".to_owned(),
        acceptance_criteria: vec!["No orphan request remains.".to_owned()],
        allowed_paths: vec![AllowedPath {
            path: "fixture.txt".to_owned(),
            scope: AllowedPathScope::Exact,
        }],
        artifact_ids: Vec::new(),
        claim_ids: Vec::new(),
        constraints: Vec::new(),
    };
    let change_id = ChangeId::from_digest(Digest::blake3(format!("{name}:change")));
    let invalid = LifecycleSpec {
        worker_depth_limit: 1,
        profiles,
        budget: LifecycleBudget {
            max_worker_turns: 10,
            max_output_tokens: 10_000,
            max_cost_microusd: 100_000,
            max_concurrent_workers: 1,
        },
        explore_action_plan: Some(lifecycle_explore_plan(repository, source)),
        action_phase_plans: None,
        test_plans: vec![LifecycleTestPlanBinding {
            plan: TestPlan {
                runner: "cargo".to_owned(),
                argv: vec![
                    "cargo".to_owned(),
                    "test".to_owned(),
                    "focused".to_owned(),
                    "--".to_owned(),
                    "--exact".to_owned(),
                ],
                cwd_relative: ".".to_owned(),
                test_identifier: "focused".to_owned(),
                requires_approval: true,
                execution_evidence_id: None,
            },
            certificate_digest: Digest::blake3(b"missing-certificate"),
        }],
    };

    assert!(matches!(
        store.create_lifecycle_with_request(&change_id, repository, source, &request, invalid),
        Err(StoreError::LifecycleConflict(_))
    ));
    assert!(store.lifecycle_change_context(&change_id).unwrap().is_none());
    assert!(store.lifecycle(&change_id).unwrap().is_none());

    drop(store);
    fs::remove_file(path).unwrap();
}

#[test]
fn lifecycle_start_test_plan_candidates_are_snapshot_bound_and_command_private() {
    let name = "lifecycle-start-test-plan-candidates";
    let path = temporary_path(name);
    let store = RuntimeStore::new(&path);
    store.initialize().unwrap();
    let source = Digest::blake3(format!("{name}:source"));
    let plan = TestPlan {
        runner: "cargo".to_owned(),
        argv: vec![
            "cargo".to_owned(),
            "test".to_owned(),
            "focused".to_owned(),
            "--".to_owned(),
            "--exact".to_owned(),
        ],
        cwd_relative: ".".to_owned(),
        test_identifier: "focused".to_owned(),
        requires_approval: true,
        execution_evidence_id: None,
    };
    let certificate_digest = seed_test_plan_certificate(&store, name, source, &plan);

    let candidates = store.lifecycle_start_test_plan_candidates(source).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].binding.plan, plan);
    assert_eq!(candidates[0].binding.certificate_digest, certificate_digest);
    assert!(
        store
            .lifecycle_start_test_plan_candidates(Digest::blake3(b"different-source"))
            .unwrap()
            .is_empty()
    );

    drop(store);
    fs::remove_file(path).unwrap();
}

#[test]
fn lifecycle_start_accepts_action_native_test_plan_candidates() {
    let name = "lifecycle-start-action-native-test-plan";
    let path = temporary_path(name);
    let store = RuntimeStore::new(&path);
    store.initialize().unwrap();
    let source = Digest::blake3(format!("{name}:source"));
    let identifier = "lifecycle_start_accepts_action_native_test_plan_candidates";
    let plan = TestPlan {
        runner: "cargo".to_owned(),
        argv: vec![
            "cargo".to_owned(),
            "test".to_owned(),
            "-p".to_owned(),
            "needle-runtime".to_owned(),
            identifier.to_owned(),
            "--".to_owned(),
            "--exact".to_owned(),
        ],
        cwd_relative: ".".to_owned(),
        test_identifier: identifier.to_owned(),
        requires_approval: true,
        execution_evidence_id: None,
    };
    let certificate_digest = seed_action_native_test_plan_certificate(&store, name, source, &plan);

    let candidates = store.lifecycle_start_test_plan_candidates(source).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].binding.plan, plan);
    assert_eq!(candidates[0].binding.certificate_digest, certificate_digest);

    let repository = Digest::blake3(format!("{name}:repository"));
    let profiles = LifecycleWorkerProfiles {
        explore: active_profile(&store, &format!("{name}.create.explorer"), CodexRole::Explorer),
        implement: active_profile(
            &store,
            &format!("{name}.create.implementer"),
            CodexRole::Implementer,
        ),
        test: active_profile(&store, &format!("{name}.create.test"), CodexRole::TestRunner),
        review: active_profile(&store, &format!("{name}.create.review"), CodexRole::Reviewer),
        verify: active_profile(&store, &format!("{name}.create.verify"), CodexRole::Verifier),
    };
    let request = ChangeRequest {
        task: "Create a lifecycle from an action-native TestPlan.".to_owned(),
        acceptance_criteria: vec!["The TestPlan remains certificate-bound.".to_owned()],
        allowed_paths: vec![AllowedPath {
            path: "src/store/lifecycles.rs".to_owned(),
            scope: AllowedPathScope::Exact,
        }],
        artifact_ids: Vec::new(),
        claim_ids: Vec::new(),
        constraints: Vec::new(),
    };
    let change_id = ChangeId::from_digest(Digest::blake3(format!("{name}:create-change")));
    let creation = store
        .create_lifecycle_with_request(
            &change_id,
            repository,
            source,
            &request,
            LifecycleSpec {
                worker_depth_limit: 1,
                profiles,
                budget: LifecycleBudget {
                    max_worker_turns: 10,
                    max_output_tokens: 10_000,
                    max_cost_microusd: 100_000,
                    max_concurrent_workers: 1,
                },
                explore_action_plan: Some(lifecycle_explore_plan(repository, source)),
                action_phase_plans: None,
                test_plans: vec![LifecycleTestPlanBinding {
                    plan: plan.clone(),
                    certificate_digest,
                }],
            },
        )
        .unwrap();
    assert!(creation.created);

    let connection = store.connection().unwrap();
    let request_json: String = connection
        .query_row(
            "SELECT request_json FROM artifact_requests
             WHERE source_digest=?1 AND format_revision=3",
            [source.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let mut request: needle_core::ActionRequest = serde_json::from_str(&request_json).unwrap();
    request.effective_dispatch_policy_digest = Digest::blake3(b"tampered-dispatch-policy");
    connection
        .execute(
            "UPDATE artifact_requests SET request_json=?2
             WHERE source_digest=?1 AND format_revision=3",
            params![source.to_string(), serde_json::to_string(&request).unwrap()],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        store.lifecycle_start_test_plan_candidates(source),
        Err(StoreError::LifecycleCorruption(_))
    ));

    drop(store);
    fs::remove_file(path).unwrap();
}

#[test]
fn explore_action_observation_is_immutable_idempotent_and_state_bound() {
    let path = temporary_path("explore-action-observation");
    let store = RuntimeStore::new(&path);
    store.initialize().unwrap();
    let (_, projection) = seed_lifecycle_with_explore_plan(&store, "explore-observation");
    let plan = projection.lifecycle.spec.explore_action_plan.as_ref().unwrap();
    let observation = LifecycleExploreShadowObservation::from_resolver_outcome(
        projection.lifecycle.id,
        projection.state_digest,
        plan,
        LifecycleExploreActionResolverOutcome::Miss,
    );

    store.record_lifecycle_explore_action_observation(&observation).unwrap();
    store.record_lifecycle_explore_action_observation(&observation).unwrap();
    let stored = store
        .lifecycle_explore_action_observation(projection.lifecycle.id, projection.state_digest)
        .unwrap()
        .unwrap();
    assert_eq!(stored.observation, observation);
    let listed =
        store.list_lifecycle_explore_action_observations(projection.lifecycle.id, 10).unwrap();
    assert_eq!(listed.as_slice(), std::slice::from_ref(&stored));

    let divergent = LifecycleExploreShadowObservation::from_resolver_outcome(
        projection.lifecycle.id,
        projection.state_digest,
        plan,
        LifecycleExploreActionResolverOutcome::Unavailable,
    );
    assert!(matches!(
        store.record_lifecycle_explore_action_observation(&divergent),
        Err(StoreError::LifecycleExploreObservationConflict(_))
    ));
    let stale = LifecycleExploreShadowObservation::from_resolver_outcome(
        projection.lifecycle.id,
        Digest::blake3(b"stale-lifecycle-state"),
        plan,
        LifecycleExploreActionResolverOutcome::Miss,
    );
    assert!(matches!(
        store.record_lifecycle_explore_action_observation(&stale),
        Err(StoreError::LifecycleExploreObservationConflict(_))
    ));
    assert!(matches!(
        store.list_lifecycle_explore_action_observations(projection.lifecycle.id, 0),
        Err(StoreError::LifecycleExploreObservationQuery(_))
    ));

    let connection = Connection::open(&path).unwrap();
    assert!(
        connection
            .execute("UPDATE lifecycle_explore_action_observations SET resolution='invalid'", [],)
            .is_err()
    );
    assert!(connection.execute("DELETE FROM lifecycle_explore_action_observations", []).is_err());
    assert_eq!(stored.observation.resolution, LifecycleExploreShadowResolutionKind::Miss);
    drop(connection);
    drop(store);
    let _ = fs::remove_file(path);
}

#[test]
fn lifecycle_adapter_invocation_is_acquired_once_and_completed_immutably() {
    let path = temporary_path("adapter-invocation");
    let store = RuntimeStore::new(&path);
    store.initialize().unwrap();
    let (change_id, projection) = seed_lifecycle_with_explore_plan(&store, "adapter-invocation");
    let context = store.lifecycle_change_context(&change_id).unwrap().unwrap();
    let request = crate::LifecyclePhaseAdapterRequest {
        schema: crate::LIFECYCLE_ADAPTER_REQUEST_SCHEMA.to_owned(),
        invocation_id: crate::lifecycle_adapter_invocation_id(&projection),
        expected_state_digest: projection.state_digest,
        phase: projection.lifecycle.phase,
        profile: projection.lifecycle.spec.profiles.explore.clone(),
        remaining_budget: crate::LifecycleRemainingBudget {
            worker_turns: projection.lifecycle.spec.budget.max_worker_turns,
            output_tokens: projection.lifecycle.spec.budget.max_output_tokens,
            cost_microusd: projection.lifecycle.spec.budget.max_cost_microusd,
        },
        lifecycle: projection.lifecycle.clone(),
        change: context,
        repair_verification: None,
    };
    let adapter_definition = Digest::blake3(b"test-lifecycle-adapter-definition");
    let mut different_change = request.clone();
    different_change.change.request.task = "A different immutable request.".to_owned();
    different_change.change.request_digest =
        different_change.change.request.digest(different_change.change.source_snapshot);
    assert!(matches!(
        store.claim_lifecycle_adapter_invocation(&different_change, adapter_definition),
        Err(StoreError::LifecycleAdapterInvocationConflict(_))
    ));
    assert_eq!(
        store.claim_lifecycle_adapter_invocation(&request, adapter_definition).unwrap(),
        crate::LifecycleAdapterInvocationClaim::Claimed
    );
    assert!(matches!(
        store.lifecycle_adapter_invocation_state(request.invocation_id).unwrap(),
        Some(crate::LifecycleAdapterInvocationState::InProgress {
            adapter_definition_digest,
            ..
        }) if adapter_definition_digest == adapter_definition
    ));
    assert!(matches!(
        store.claim_lifecycle_adapter_invocation(&request, adapter_definition).unwrap(),
        crate::LifecycleAdapterInvocationClaim::Existing(
            crate::LifecycleAdapterInvocationState::InProgress { .. }
        )
    ));
    assert!(matches!(
        store.claim_lifecycle_adapter_invocation(
            &request,
            Digest::blake3(b"different-adapter-definition")
        ),
        Err(StoreError::LifecycleAdapterInvocationConflict(_))
    ));

    let usage = LifecycleUsage { worker_turns: 1, output_tokens: 10, cost_microusd: 10 };
    let outcome = crate::LifecyclePhaseAdapterOutcome {
        schema: crate::LIFECYCLE_ADAPTER_OUTCOME_SCHEMA.to_owned(),
        invocation_id: request.invocation_id,
        expected_state_digest: request.expected_state_digest,
        phase: request.phase,
        usage: usage.clone(),
        result: crate::LifecycleAdapterResult::Completed {
            transition: Box::new(LifecycleTransition::CompleteExplore {
                worker: LifecycleWorkerCompletion {
                    profile: request.profile.clone(),
                    worker_depth: 1,
                    logical_worker_spawns: 1,
                    usage,
                },
                artifacts: vec![LifecycleArtifactRef {
                    kind: LifecycleArtifactKind::Exploration,
                    id: Digest::blake3(b"adapter-invocation-artifact"),
                    source_snapshot: projection.lifecycle.source_snapshot,
                }],
            }),
        },
        cleanup: crate::LifecycleAdapterCleanup::succeeded(),
    };
    store.complete_lifecycle_adapter_invocation(&request, adapter_definition, &outcome).unwrap();
    store.complete_lifecycle_adapter_invocation(&request, adapter_definition, &outcome).unwrap();
    assert!(matches!(
        store.lifecycle_adapter_invocation_state(request.invocation_id).unwrap(),
        Some(crate::LifecycleAdapterInvocationState::Completed {
            outcome: stored,
            ..
        }) if stored.as_ref() == &outcome
    ));
    assert!(matches!(
        store.abort_lifecycle_adapter_invocation(
            &change_id,
            projection.state_digest,
            request.invocation_id,
            crate::LifecycleAdapterRecoverySource::WebUser,
        ),
        Err(StoreError::LifecycleAdapterInvocationConflict(_))
    ));
    assert!(matches!(
        store.complete_lifecycle_adapter_invocation(
            &request,
            Digest::blake3(b"different-adapter-definition"),
            &outcome,
        ),
        Err(StoreError::LifecycleAdapterInvocationConflict(_))
    ));

    let connection = Connection::open(&path).unwrap();
    assert!(connection.execute("DELETE FROM lifecycle_adapter_outcomes", []).is_err());
    assert!(
        connection
            .execute(
                "INSERT INTO lifecycle_adapter_recoveries(
                    recovery_digest, invocation_id, lifecycle_id, expected_state_digest,
                    request_digest, adapter_definition_digest, source, recovered_unix_ms
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 'web_user', ?7)",
                params![
                    Digest::blake3(b"late-recovery").to_string(),
                    request.invocation_id.to_string(),
                    request.lifecycle.id.to_string(),
                    request.expected_state_digest.to_string(),
                    Digest::blake3(b"late-recovery-request").to_string(),
                    adapter_definition.to_string(),
                    1_u64,
                ],
            )
            .is_err()
    );
    assert!(
        connection.execute("UPDATE lifecycle_adapter_invocations SET phase='test'", []).is_err()
    );
    drop(connection);
    drop(store);
    let _ = fs::remove_file(path);
}

#[test]
fn abandoned_lifecycle_adapter_invocation_is_aborted_atomically_and_idempotently() {
    let path = temporary_path("adapter-invocation-recovery");
    let store = RuntimeStore::new(&path);
    store.initialize().unwrap();
    let (change_id, projection) =
        seed_lifecycle_with_explore_plan(&store, "adapter-invocation-recovery");
    let request = crate::LifecyclePhaseAdapterRequest {
        schema: crate::LIFECYCLE_ADAPTER_REQUEST_SCHEMA.to_owned(),
        invocation_id: crate::lifecycle_adapter_invocation_id(&projection),
        expected_state_digest: projection.state_digest,
        phase: projection.lifecycle.phase,
        profile: projection.lifecycle.spec.profiles.explore.clone(),
        remaining_budget: crate::LifecycleRemainingBudget {
            worker_turns: projection.lifecycle.spec.budget.max_worker_turns,
            output_tokens: projection.lifecycle.spec.budget.max_output_tokens,
            cost_microusd: projection.lifecycle.spec.budget.max_cost_microusd,
        },
        lifecycle: projection.lifecycle.clone(),
        change: store.lifecycle_change_context(&change_id).unwrap().unwrap(),
        repair_verification: None,
    };
    let adapter_definition = Digest::blake3(b"recoverable-adapter-definition");
    assert_eq!(
        store.claim_lifecycle_adapter_invocation(&request, adapter_definition).unwrap(),
        crate::LifecycleAdapterInvocationClaim::Claimed
    );
    assert!(matches!(
        store.abort_lifecycle_adapter_invocation(
            &change_id,
            Digest::blake3(b"stale-state"),
            request.invocation_id,
            crate::LifecycleAdapterRecoverySource::WebUser,
        ),
        Err(StoreError::LifecycleAdapterInvocationConflict(_))
    ));

    let recovered = store
        .abort_lifecycle_adapter_invocation(
            &change_id,
            projection.state_digest,
            request.invocation_id,
            crate::LifecycleAdapterRecoverySource::WebUser,
        )
        .unwrap();
    assert!(recovered.created);
    assert_eq!(recovered.recovery.invocation_id, request.invocation_id);
    assert_eq!(recovered.recovery.lifecycle_id, projection.lifecycle.id);
    assert_eq!(recovered.recovery.expected_state_digest, projection.state_digest);
    assert_eq!(recovered.recovery.adapter_definition_digest, adapter_definition);
    assert_eq!(recovered.projection.lifecycle.status, LifecycleStatus::Failed);
    assert_eq!(recovered.projection.lifecycle.generation, projection.lifecycle.generation + 1);
    assert_eq!(
        recovered.projection.lifecycle.terminal_reason.as_ref().map(|reason| reason.code.as_str()),
        Some("adapter_invocation_aborted")
    );

    let stored =
        store.latest_lifecycle_adapter_invocation(projection.lifecycle.id).unwrap().unwrap();
    assert_eq!(stored.invocation_id, request.invocation_id);
    assert_eq!(stored.expected_state_digest, projection.state_digest);
    assert_eq!(stored.phase, LifecyclePhase::Explore);
    assert!(matches!(
        &stored.state,
        crate::LifecycleAdapterInvocationState::Aborted { recovery, .. }
            if recovery.as_ref() == &recovered.recovery
    ));
    assert!(matches!(
        store.claim_lifecycle_adapter_invocation(&request, adapter_definition).unwrap(),
        crate::LifecycleAdapterInvocationClaim::Existing(
            crate::LifecycleAdapterInvocationState::Aborted { .. }
        )
    ));

    let replay = store
        .abort_lifecycle_adapter_invocation(
            &change_id,
            projection.state_digest,
            request.invocation_id,
            crate::LifecycleAdapterRecoverySource::WebUser,
        )
        .unwrap();
    assert!(!replay.created);
    assert_eq!(replay.recovery, recovered.recovery);
    assert_eq!(replay.projection, recovered.projection);

    let failure = crate::LifecyclePhaseAdapterOutcome {
        schema: crate::LIFECYCLE_ADAPTER_OUTCOME_SCHEMA.to_owned(),
        invocation_id: request.invocation_id,
        expected_state_digest: request.expected_state_digest,
        phase: request.phase,
        usage: LifecycleUsage::default(),
        result: crate::LifecycleAdapterResult::Failed {
            failure: crate::LifecycleAdapterFailure {
                code: "late_completion".to_owned(),
                detail: "completion arrived after explicit recovery".to_owned(),
            },
        },
        cleanup: crate::LifecycleAdapterCleanup::succeeded(),
    };
    assert!(matches!(
        store.complete_lifecycle_adapter_invocation(&request, adapter_definition, &failure),
        Err(StoreError::LifecycleAdapterInvocationConflict(_))
    ));

    let connection = Connection::open(&path).unwrap();
    assert!(connection.execute("DELETE FROM lifecycle_adapter_recoveries", []).is_err());
    assert!(
        connection
            .execute(
                "INSERT INTO lifecycle_adapter_outcomes(
                    invocation_id, outcome_digest, outcome_json, completed_unix_ms
                 ) VALUES(?1, ?2, '{}', ?3)",
                params![
                    request.invocation_id.to_string(),
                    Digest::blake3(b"late-outcome").to_string(),
                    recovered.recovery.recovered_unix_ms,
                ],
            )
            .is_err()
    );
    assert!(
        connection
            .execute("UPDATE lifecycle_adapter_recoveries SET source='web_user'", [],)
            .is_err()
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM lifecycle_adapter_recoveries", [], |row| {
                row.get::<_, u32>(0)
            })
            .unwrap(),
        1
    );
    drop(connection);
    drop(store);

    let reopened = RuntimeStore::new(&path);
    reopened.initialize().unwrap();
    assert!(matches!(
        reopened.lifecycle_adapter_invocation_state(request.invocation_id).unwrap(),
        Some(crate::LifecycleAdapterInvocationState::Aborted { .. })
    ));
    assert_eq!(reopened.replay_lifecycle(&change_id).unwrap(), recovered.projection);
    drop(reopened);
    let _ = fs::remove_file(path);
}

struct NeverWorker {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

struct SuccessfulExploreWorker {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::WorkerExecutor for SuccessfulExploreWorker {
    fn execute(
        &self,
        config: &needle_core::WorkerConfig,
        request: &needle_core::WorkerRequest,
    ) -> Result<needle_core::WorkerOutcome, Box<needle_core::WorkerFailure>> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            request.requested_artifact_kinds,
            vec![needle_core::ArtifactKind::code_location()]
        );
        assert!(request.semantic_fragment.is_some());
        let path = "crates/needle-runtime/src/lib.rs";
        let trace = needle_core::WorkerObservationTrace {
            observed_files: vec![path.to_owned()],
            gaps: Vec::new(),
        };
        Ok(needle_core::WorkerOutcome {
            result: needle_core::NeedResult {
                complete: true,
                summary: "Located the lifecycle runtime implementation.".to_owned(),
                claims: vec![needle_core::Claim {
                    id: "lifecycle-location".to_owned(),
                    kind: "implementation".to_owned(),
                    subject: "lifecycle runtime".to_owned(),
                    statement: "The runtime exports the lifecycle implementation.".to_owned(),
                    evidence_ids: vec!["lifecycle-source".to_owned()],
                }],
                evidence: vec![needle_core::EvidenceReference {
                    id: "lifecycle-source".to_owned(),
                    path: path.to_owned(),
                    symbol: Some("LifecycleExecutionKernel".to_owned()),
                    content_digest: Digest::blake3(b"untrusted-worker-placeholder"),
                    byte_start: None,
                    byte_end: None,
                }],
                suggested_reads: Vec::new(),
                suggested_commands: Vec::new(),
                uncertainty: Vec::new(),
            },
            artifact_result: None,
            semantic_artifact_result: Some(needle_core::SemanticArtifactResult {
                schema_id: needle_core::SEMANTIC_ARTIFACT_RESULT_SCHEMA_ID.to_owned(),
                artifacts: vec![SemanticWorkerArtifact::CodeLocation {
                    locations: vec![SemanticLocation {
                        role: LocationRole::Primary,
                        path: path.to_owned(),
                        symbol: Some("LifecycleExecutionKernel".to_owned()),
                        byte_start: None,
                        byte_end: None,
                    }],
                    gaps: Vec::new(),
                }],
                observation_trace: trace.clone(),
                artifact_traces: std::collections::BTreeMap::from([(
                    needle_core::ArtifactKind::code_location(),
                    trace,
                )]),
            }),
            worker_model: config.model.clone(),
            worker_reasoning: config.reasoning.clone(),
            codex_version: "test".to_owned(),
            input_tokens: Some(1),
            cached_input_tokens: Some(0),
            output_tokens: Some(1),
            duration_ms: 1,
            process_status: "success".to_owned(),
            logical_worker_spawns: 1,
            worker_turns: 1,
            repair_performed: false,
            discarded_facts: 0,
            worker_session_id: Some("test-lifecycle-worker".to_owned()),
            session_cleanup_success: Some(true),
            role_profile_provenance: config.role_profile_provenance.clone(),
        })
    }
}

impl crate::WorkerExecutor for NeverWorker {
    fn execute(
        &self,
        _config: &needle_core::WorkerConfig,
        _request: &needle_core::WorkerRequest,
    ) -> Result<needle_core::WorkerOutcome, Box<needle_core::WorkerFailure>> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        panic!("worker must not run when the frozen Need is unavailable")
    }
}

#[test]
fn fresh_explore_adapter_persists_pre_worker_failure_and_replays_it_without_a_worker() {
    let path = temporary_path("fresh-adapter-pre-worker-failure");
    let store = RuntimeStore::new(&path);
    store.initialize().unwrap();
    let (change_id, projection) =
        seed_lifecycle_with_explore_plan(&store, "fresh-adapter-pre-worker-failure");
    let context = store.lifecycle_change_context(&change_id).unwrap().unwrap();
    let request = crate::LifecyclePhaseAdapterRequest {
        schema: crate::LIFECYCLE_ADAPTER_REQUEST_SCHEMA.to_owned(),
        invocation_id: crate::lifecycle_adapter_invocation_id(&projection),
        expected_state_digest: projection.state_digest,
        phase: projection.lifecycle.phase,
        profile: projection.lifecycle.spec.profiles.explore.clone(),
        remaining_budget: crate::LifecycleRemainingBudget {
            worker_turns: projection.lifecycle.spec.budget.max_worker_turns,
            output_tokens: projection.lifecycle.spec.budget.max_output_tokens,
            cost_microusd: projection.lifecycle.spec.budget.max_cost_microusd,
        },
        lifecycle: projection.lifecycle,
        change: context,
        repair_verification: None,
    };
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let adapter = crate::FreshLifecycleExploreAdapter::new(
        store.clone(),
        NeverWorker { calls: calls.clone() },
        std::env::current_dir().unwrap(),
    )
    .unwrap();
    let first = crate::LifecyclePhaseAdapter::invoke(&adapter, &request);
    assert!(matches!(
        &first.result,
        crate::LifecycleAdapterResult::Failed { failure }
            if failure.code == "explore_need_unavailable"
    ));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(matches!(
        store.lifecycle_adapter_invocation_state(request.invocation_id).unwrap(),
        Some(crate::LifecycleAdapterInvocationState::Completed { outcome, .. })
            if outcome.as_ref() == &first
    ));
    let second = crate::LifecyclePhaseAdapter::invoke(&adapter, &request);
    assert_eq!(second, first);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);

    drop(adapter);
    drop(store);
    let _ = fs::remove_file(path);
}

pub(crate) struct ProviderBackedActionAssuranceFixture {
    pub path: PathBuf,
    pub store: RuntimeStore,
    pub evidence: needle_core::ActionAssuranceEvidence,
}

pub(crate) fn provider_backed_action_assurance_fixture() -> ProviderBackedActionAssuranceFixture {
    let path = temporary_path("fresh-adapter-success");
    let store = RuntimeStore::new(&path);
    store.initialize().unwrap();
    store
        .initialize_defaults(&crate::RuntimeSettings {
            codex_executable: "codex-test".to_owned(),
            worker_model: "offline-lifecycle-worker".to_owned(),
            worker_reasoning: "medium".to_owned(),
            worker_timeout_seconds: 30,
            evidence_failure_policy: needle_core::EvidenceFailurePolicy::DiscardInvalidFact,
            trusted_test_execution: false,
            multi_need_policy: needle_core::MultiNeedPolicy::default(),
        })
        .unwrap();
    let repository_root =
        fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    let (_, snapshot) = crate::capture_git_snapshot(&repository_root).unwrap();
    let need_ir = needle_core::NeedIr::parse(
        "@@need\n\
         @route locate.implementation\n\
         @subject symbol:\"LifecycleExecutionKernel\"\n\
         @require implementation-location selection=primary granularity=exact-location polarity=positive\n\
         @world source=worktree features=default\n\
         \n\
         Locate the lifecycle implementation.\n\
         @@end",
    )
    .unwrap()
    .unwrap();
    let route = needle_core::built_in_route_contracts()
        .into_iter()
        .find(|route| route.route.as_str() == "locate.implementation")
        .unwrap();
    let need = needle_core::compile_need(&need_ir, snapshot.repository_id, &route).unwrap();
    let fragment = needle_core::need_fragment(&need, need.required.clone(), Vec::new());
    let need_request = NeedRequest { key: route.route, body: need_ir.body.clone() };
    let plan = compile_lifecycle_explore_action_plan(
        &need_request,
        &need,
        &fragment,
        snapshot.repository_id,
        snapshot.source_digest,
    )
    .unwrap();
    let repository_root_text = repository_root.to_string_lossy().into_owned();
    store
        .record_session_start(
            "fresh-adapter-success-session",
            Digest::blake3(b"fresh-adapter-success-profile"),
            Some("offline-lifecycle-worker"),
            Some(&repository_root_text),
        )
        .unwrap();
    store
        .record_need_shadow(NeedShadowWrite {
            session_id: "fresh-adapter-success-session",
            turn_id: "fresh-adapter-success-turn",
            transport_digest: need_ir.transport_digest(),
            parser_definition_digest: Digest::blake3(b"fresh-adapter-success-parser"),
            prompt_profile_digest: Digest::blake3(b"fresh-adapter-success-profile"),
            need_ir: &need_ir,
            need: &need,
            fragments: std::slice::from_ref(&fragment),
        })
        .unwrap();
    let (change_id, projection) = seed_lifecycle_with_plan_identity(
        &store,
        "fresh-adapter-success",
        snapshot.repository_id,
        snapshot.source_digest,
        Some(plan),
    );
    let context = store.lifecycle_change_context(&change_id).unwrap().unwrap();
    let request = crate::LifecyclePhaseAdapterRequest {
        schema: crate::LIFECYCLE_ADAPTER_REQUEST_SCHEMA.to_owned(),
        invocation_id: crate::lifecycle_adapter_invocation_id(&projection),
        expected_state_digest: projection.state_digest,
        phase: projection.lifecycle.phase,
        profile: projection.lifecycle.spec.profiles.explore.clone(),
        remaining_budget: crate::LifecycleRemainingBudget {
            worker_turns: projection.lifecycle.spec.budget.max_worker_turns,
            output_tokens: projection.lifecycle.spec.budget.max_output_tokens,
            cost_microusd: projection.lifecycle.spec.budget.max_cost_microusd,
        },
        lifecycle: projection.lifecycle,
        change: context,
        repair_verification: None,
    };
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let adapter = crate::FreshLifecycleExploreAdapter::new(
        store.clone(),
        SuccessfulExploreWorker { calls: calls.clone() },
        &repository_root,
    )
    .unwrap();

    let outcome = crate::LifecyclePhaseAdapter::invoke(&adapter, &request);
    let artifacts = match &outcome.result {
        crate::LifecycleAdapterResult::Completed { transition } => match transition.as_ref() {
            LifecycleTransition::CompleteExplore { artifacts, .. } => artifacts,
            other => panic!("unexpected transition: {other:?}"),
        },
        other => panic!("unexpected adapter result: {other:?}"),
    };
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(artifacts.len(), 1);
    assert!(store.semantic_artifact(&artifacts[0].id.to_string()).unwrap().is_some());
    assert!(matches!(
        store.lifecycle_adapter_invocation_state(request.invocation_id).unwrap(),
        Some(crate::LifecycleAdapterInvocationState::Completed { outcome: stored, .. })
            if stored.as_ref() == &outcome
    ));
    drop(adapter);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let (request_id, certificate_id): (String, String) = connection
        .query_row(
            "SELECT a.request_id, c.certificate_id
             FROM artifacts a
             JOIN artifact_validation_certificates c ON c.artifact_id=a.artifact_id
             WHERE a.artifact_id=?1
             ORDER BY c.issued_unix_ms DESC, c.certificate_id
             LIMIT 1",
            [artifacts[0].id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    drop(connection);
    let capability = crate::implementation_location_exact_capability();
    let evidence =
        needle_core::ActionAssuranceEvidence::new(needle_core::ActionAssuranceEvidenceInput {
            capability_class: capability.id,
            capability_definition_digest: capability.definition_digest,
            action_request: needle_core::ArtifactRequestId::new(
                Digest::parse(&request_id).unwrap(),
            ),
            artifact: needle_core::ArtifactId::new(artifacts[0].id),
            validation_certificate: needle_core::ArtifactValidationCertificateId::new(
                Digest::parse(&certificate_id).unwrap(),
            ),
            repository: snapshot.repository_id,
            source_snapshot: snapshot.source_digest,
            lifecycle: request.lifecycle.id,
            adapter_invocation: request.invocation_id,
            evidence_kind: needle_core::ActionAssuranceEvidenceKind::ProviderBackedFresh,
            execution_evidence_digest: Digest::blake3(b"test-provider-backed-live-report"),
            observed_unix_ms: super::super::now_ms(),
        })
        .unwrap();
    ProviderBackedActionAssuranceFixture { path, store, evidence }
}

#[test]
fn fresh_explore_adapter_records_worker_then_publishes_validated_artifacts() {
    let fixture = provider_backed_action_assurance_fixture();
    drop(fixture.store);
    let _ = fs::remove_file(fixture.path);
}

fn lifecycle_fixture(name: &str) -> (PathBuf, RuntimeStore, ChangeId, LifecycleProjection) {
    let path = temporary_path(name);
    let store = RuntimeStore::new(&path);
    store.initialize().unwrap();
    let (change_id, projection) = seed_lifecycle(&store, name);
    (path, store, change_id, projection)
}

#[test]
fn lifecycle_summary_query_is_bounded_ordered_read_only_and_replay_validated() {
    let path = temporary_path("summary-query");
    let store = RuntimeStore::new(&path);
    store.initialize().unwrap();
    assert!(store.list_lifecycle_summaries(10).unwrap().is_empty());

    let seeded = ["summary-z", "summary-a", "summary-m"]
        .into_iter()
        .map(|name| seed_lifecycle(&store, name).0)
        .collect::<Vec<_>>();
    let mut expected = seeded.iter().map(ToString::to_string).collect::<Vec<_>>();
    expected.sort();

    let connection = rusqlite::Connection::open(&path).unwrap();
    let before: (u64, u64, String) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM change_lifecycles),
                (SELECT COUNT(*) FROM change_events),
                (SELECT group_concat(state_digest, ',')
                   FROM (SELECT state_digest FROM change_lifecycles ORDER BY change_id))",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    drop(connection);

    let summaries = store.list_lifecycle_summaries(2).unwrap();
    assert_eq!(summaries.len(), 2);
    assert_eq!(
        summaries.iter().map(|item| item.change_id.to_string()).collect::<Vec<_>>(),
        expected[..2]
    );
    let all = store.list_lifecycle_summaries(MAX_LIFECYCLE_LIST_LIMIT).unwrap();
    assert_eq!(all.iter().map(|item| item.change_id.to_string()).collect::<Vec<_>>(), expected);
    assert!(matches!(store.list_lifecycle_summaries(0), Err(StoreError::LifecycleQuery(_))));
    assert!(matches!(
        store.list_lifecycle_summaries(MAX_LIFECYCLE_LIST_LIMIT + 1),
        Err(StoreError::LifecycleQuery(_))
    ));

    let connection = rusqlite::Connection::open(&path).unwrap();
    let after: (u64, u64, String) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM change_lifecycles),
                (SELECT COUNT(*) FROM change_events),
                (SELECT group_concat(state_digest, ',')
                   FROM (SELECT state_digest FROM change_lifecycles ORDER BY change_id))",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(after, before);

    let corrupt_id = &seeded[0];
    connection.execute("DROP TRIGGER change_events_no_update", []).unwrap();
    let mut event_json: serde_json::Value = serde_json::from_str(
        &connection
            .query_row(
                "SELECT payload_json FROM change_events
                 WHERE change_id=?1 AND lifecycle_sequence=0",
                [corrupt_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
    )
    .unwrap();
    event_json["status"] = serde_json::json!("unknown_status");
    let event_json = serde_json::to_string(&event_json).unwrap();
    connection
        .execute(
            "UPDATE change_events SET payload_json=?2, payload_digest=?3
             WHERE change_id=?1 AND lifecycle_sequence=0",
            params![
                corrupt_id.to_string(),
                event_json,
                Digest::blake3(event_json.as_bytes()).to_string(),
            ],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        store.list_lifecycle_summaries(MAX_LIFECYCLE_LIST_LIMIT),
        Err(StoreError::LifecycleCorruption(_))
    ));

    drop(store);
    fs::remove_file(path).unwrap();
}

#[test]
fn full_parent_owned_journal_reaches_apply_only_after_current_user_approval() {
    let name = "full-journal";
    let (path, store, change_id, mut projection) = lifecycle_fixture(name);
    let source = projection.lifecycle.source_snapshot;
    let exploration_id = seed_exploration_certificate(&store, name, source);
    projection = store
        .parent_transition_lifecycle(
            &change_id,
            projection.state_digest,
            LifecycleTransition::CompleteExplore {
                worker: worker(&projection.lifecycle.spec.profiles.explore),
                artifacts: vec![LifecycleArtifactRef {
                    kind: LifecycleArtifactKind::Exploration,
                    id: exploration_id,
                    source_snapshot: source,
                }],
            },
        )
        .unwrap();

    let request = ChangeRequest {
        task: "Implement the bounded lifecycle fixture.".to_owned(),
        acceptance_criteria: vec!["The lifecycle remains fail closed.".to_owned()],
        allowed_paths: vec![AllowedPath {
            path: "fixture.txt".to_owned(),
            scope: AllowedPathScope::Exact,
        }],
        artifact_ids: Vec::new(),
        claim_ids: Vec::new(),
        constraints: Vec::new(),
    };
    let before = b"before\n".to_vec();
    let after = b"after\n".to_vec();
    let files = vec![PatchFile {
        path: "fixture.txt".to_owned(),
        operation: PatchOperation::Update,
        before_digest: Some(Digest::blake3(&before)),
        after_digest: Some(Digest::blake3(&after)),
        before_bytes: before.len() as u64,
        after_bytes: after.len() as u64,
    }];
    let patch_id = PatchArtifact::compute_id(source, &files);
    let patch = PatchArtifact {
        id: patch_id,
        change_id: change_id.clone(),
        revision: 1,
        source_snapshot: source,
        files,
        summary: "Bounded lifecycle patch".to_owned(),
        acceptance_coverage: vec![AcceptanceCoverage {
            criterion: request.acceptance_criteria[0].clone(),
            status: AcceptanceStatus::Addressed,
            evidence: "fixture patch".to_owned(),
        }],
        residual_risks: Vec::new(),
        declared_output_digest: Digest::blake3(b"declared-output"),
        discrepancies: Vec::new(),
    };
    let repository_id = Digest::blake3(format!("{name}:repository"));
    store
        .record_prepared_change_with_provenance(
            repository_id,
            request.digest(source),
            &request,
            &patch,
            &serde_json::json!({"summary": "Bounded lifecycle patch"}),
            &[PatchFileBlob {
                path: "fixture.txt".to_owned(),
                before: Some(before),
                after: Some(after),
            }],
            Some(&projection.lifecycle.spec.profiles.implement),
        )
        .unwrap();
    projection = store
        .parent_transition_lifecycle(
            &change_id,
            projection.state_digest,
            LifecycleTransition::CompleteImplement {
                worker: worker(&projection.lifecycle.spec.profiles.implement),
                patch: LifecyclePatchRef { patch_id, revision: 1 },
            },
        )
        .unwrap();

    let plan = projection.lifecycle.spec.test_plans[0].clone();
    let evidence = CommandExecutionEvidence {
        id: "lifecycle-focused-evidence".to_owned(),
        approval_id: "parent-selected-test".to_owned(),
        argv: plan.plan.argv.clone(),
        cwd: plan.plan.cwd_relative.clone(),
        source_snapshot_digest: source,
        runner: plan.plan.runner.clone(),
        runner_version: None,
        exit_status: Some(0),
        duration_ms: 1,
        output_digest: Digest::blake3(b"focused-test-output"),
        output_preview: "opaque provider-owned success output".to_owned(),
        test_identifier: Some(plan.plan.test_identifier.clone()),
        tests_executed: None,
        infrastructure_failure: None,
    };
    store.record_command_evidence(None, &evidence).unwrap();
    projection = store
        .parent_transition_lifecycle(
            &change_id,
            projection.state_digest,
            LifecycleTransition::CompleteTest {
                worker: worker(&projection.lifecycle.spec.profiles.test),
                results: vec![LifecycleTestResult {
                    plan_digest: plan.plan_digest(),
                    certificate_digest: plan.certificate_digest,
                    available: true,
                    executed: true,
                    passed: true,
                    evidence_id: Some(evidence.id.clone()),
                    action_evidence_artifact: None,
                    failure_code: None,
                }],
            },
        )
        .unwrap();

    let criterion = &request.acceptance_criteria[0];
    let review = ReviewArtifact::new(
        change_id.clone(),
        patch_id,
        LifecycleReviewVerdict::Approved,
        vec![LifecycleAcceptanceReview::new(
            criterion.as_bytes(),
            AcceptanceStatus::Addressed,
            b"review evidence",
        )],
        Vec::new(),
        projection.lifecycle.spec.profiles.review.definition_digest,
        projection.lifecycle.updated_unix_ms,
    )
    .unwrap();
    projection = store
        .parent_transition_lifecycle(
            &change_id,
            projection.state_digest,
            LifecycleTransition::CompleteReview {
                worker: worker(&projection.lifecycle.spec.profiles.review),
                review,
                report_artifact: None,
            },
        )
        .unwrap();

    let raw_coverage = vec![AcceptanceCoverage {
        criterion: criterion.clone(),
        status: AcceptanceStatus::Addressed,
        evidence: "verified in a fresh checkout".to_owned(),
    }];
    let plan_result = VerificationPlanResult {
        plan_digest: plan.plan_digest(),
        runner: plan.plan.runner.clone(),
        argv: plan.plan.argv.clone(),
        cwd_relative: plan.plan.cwd_relative.clone(),
        test_identifier: plan.plan.test_identifier.clone(),
        expected: true,
        available: true,
        executed: true,
        passed: true,
        evidence_id: Some(evidence.id.clone()),
        failure_reason: None,
    };
    let evidence_ids = vec![evidence.id.clone()];
    let plan_results = vec![plan_result];
    let verifier_definition = projection.lifecycle.spec.profiles.verify.definition_digest;
    let verification_id = VerificationArtifact::compute_id_with_plan_results(
        &change_id,
        patch_id,
        VerificationStatus::Verified,
        &raw_coverage,
        &[],
        VerificationTestProjection {
            evidence_ids: &evidence_ids,
            plan_results: &plan_results,
            plans_over_cap: false,
        },
        verifier_definition,
    );
    let verification = VerificationArtifact {
        id: verification_id,
        change_id: change_id.clone(),
        patch_id,
        action_request: None,
        requirements_digest: None,
        input_test_evidence_artifacts: Vec::new(),
        verdict: VerificationStatus::Verified,
        acceptance_coverage: raw_coverage,
        findings: Vec::new(),
        test_evidence_ids: evidence_ids,
        test_plan_results: plan_results,
        test_plans_over_cap: false,
        verifier_definition,
        created_unix_ms: projection.lifecycle.updated_unix_ms,
    };
    assert!(verification.is_canonical());
    store
        .record_verification_artifact_with_provenance(
            &verification,
            &serde_json::json!({"fresh_checkout": true}),
            &serde_json::json!({}),
            None,
            Some(&projection.lifecycle.spec.profiles.verify),
        )
        .unwrap();
    projection = store
        .parent_transition_lifecycle(
            &change_id,
            projection.state_digest,
            LifecycleTransition::CompleteVerify {
                worker: worker(&projection.lifecycle.spec.profiles.verify),
                verification: LifecycleVerificationRef {
                    verification_id,
                    patch_id,
                    verdict: VerificationStatus::Verified,
                },
            },
        )
        .unwrap();
    assert_eq!(projection.lifecycle.status, LifecycleStatus::AwaitingApproval);

    let mut apply_time =
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64 + 1;
    let mut apply = ChangeApplyRecord {
        id: ChangeApplyId(Digest::blake3(b"full-journal-apply")),
        operation_id: None,
        change_id: change_id.clone(),
        patch_id,
        repository_root: "C:/bounded/repository".to_owned(),
        pre_snapshot: source,
        post_snapshot: None,
        status: ChangeApplyStatus::Applying,
        created_unix_ms: apply_time,
        completed_unix_ms: None,
    };
    let change_digest = store.change_digest(&change_id).unwrap().unwrap();
    assert!(matches!(
        store.begin_change_apply(&apply, &serde_json::json!({}), change_digest),
        Err(StoreError::LifecycleConflict(_))
    ));
    projection = store
        .approve_lifecycle_apply(
            &change_id,
            projection.state_digest,
            ApprovalDecisionSource::WebUser,
        )
        .unwrap();
    assert_eq!(projection.lifecycle.status, LifecycleStatus::Approved);
    apply_time = projection.lifecycle.updated_unix_ms + 1;
    apply.created_unix_ms = apply_time;
    assert!(matches!(
        store.begin_change_apply_with_lifecycle(
            &apply,
            &serde_json::json!({}),
            change_digest,
            Some(Digest::blake3(b"stale-lifecycle")),
        ),
        Err(StoreError::LifecycleConflict(_))
    ));
    assert_eq!(
        store.lifecycle(&change_id).unwrap().unwrap().lifecycle.status,
        LifecycleStatus::Approved
    );
    let barrier = Arc::new(Barrier::new(2));
    let handles = (0..2)
        .map(|_| {
            let path = path.clone();
            let apply = apply.clone();
            let barrier = Arc::clone(&barrier);
            let lifecycle_digest = projection.state_digest;
            thread::spawn(move || {
                let store = RuntimeStore::new(path);
                store.initialize().unwrap();
                barrier.wait();
                store.begin_change_apply_with_lifecycle(
                    &apply,
                    &serde_json::json!({}),
                    change_digest,
                    Some(lifecycle_digest),
                )
            })
        })
        .collect::<Vec<_>>();
    let outcomes = handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_err()).count(), 1);
    assert_eq!(
        store.lifecycle(&change_id).unwrap().unwrap().lifecycle.status,
        LifecycleStatus::Applying
    );
    store
        .finish_change_apply(
            apply.id,
            ChangeApplyStatus::Applied,
            Some(Digest::blake3(b"post-apply")),
            apply_time + 1,
        )
        .unwrap();
    let replayed = store.replay_lifecycle(&change_id).unwrap();
    assert_eq!(replayed.lifecycle.status, LifecycleStatus::Completed);
    assert_eq!(
        replayed.lifecycle.terminal_outcome,
        Some(needle_core::LifecycleTerminalOutcome::Applied)
    );
    assert!(matches!(
        store.record_change_failure(&change_id, "late preparation failure"),
        Err(StoreError::LifecycleConflict(_))
    ));
    assert_eq!(
        store.replay_lifecycle(&change_id).unwrap().lifecycle.status,
        LifecycleStatus::Completed
    );

    drop(store);
    fs::remove_file(path).unwrap();
}

#[test]
fn creation_rejects_stale_test_plan_source_and_inactive_profiles() {
    let name = "creation-anchors";
    let (path, store, _change_id, projection) = lifecycle_fixture(name);
    let request = ChangeRequest {
        task: "Implement the bounded lifecycle fixture.".to_owned(),
        acceptance_criteria: vec!["The lifecycle remains fail closed.".to_owned()],
        allowed_paths: vec![AllowedPath {
            path: "fixture.txt".to_owned(),
            scope: AllowedPathScope::Exact,
        }],
        artifact_ids: Vec::new(),
        claim_ids: Vec::new(),
        constraints: Vec::new(),
    };
    let stale_source = Digest::blake3(b"different-source");
    let stale_change = ChangeId::from_digest(Digest::blake3(b"stale-plan-change"));
    store
        .record_change_request_with_provenance(
            &stale_change,
            Digest::blake3(b"creation-anchors-repository"),
            stale_source,
            request.digest(stale_source),
            &request,
            Some(&projection.lifecycle.spec.profiles.implement),
        )
        .unwrap();
    assert!(matches!(
        store.create_lifecycle(&stale_change, projection.lifecycle.spec.clone()),
        Err(StoreError::LifecycleConflict(_))
    ));
    assert!(store.lifecycle(&stale_change).unwrap().is_none());

    let repository_mismatch_change =
        ChangeId::from_digest(Digest::blake3(b"repository-mismatch-plan-change"));
    let repository = Digest::blake3(b"creation-anchors-repository");
    let source = projection.lifecycle.source_snapshot;
    store
        .record_change_request_with_provenance(
            &repository_mismatch_change,
            repository,
            source,
            request.digest(source),
            &request,
            Some(&projection.lifecycle.spec.profiles.implement),
        )
        .unwrap();
    let mut repository_mismatch_spec = projection.lifecycle.spec.clone();
    repository_mismatch_spec.explore_action_plan =
        Some(lifecycle_explore_plan(Digest::blake3(b"different-repository"), source));
    assert!(matches!(
        store.create_lifecycle(&repository_mismatch_change, repository_mismatch_spec),
        Err(StoreError::LifecycleConflict(_))
    ));
    assert!(store.lifecycle(&repository_mismatch_change).unwrap().is_none());

    let explore_profile = &projection.lifecycle.spec.profiles.explore;
    let profile_state = store.role_profile_state(&explore_profile.profile_id).unwrap();
    store.deactivate_role_profile(&explore_profile.profile_id, profile_state.state_digest).unwrap();
    let inactive_change = ChangeId::from_digest(Digest::blake3(b"inactive-profile-change"));
    let source = projection.lifecycle.source_snapshot;
    store
        .record_change_request_with_provenance(
            &inactive_change,
            Digest::blake3(b"creation-anchors-repository"),
            source,
            request.digest(source),
            &request,
            Some(&projection.lifecycle.spec.profiles.implement),
        )
        .unwrap();
    assert!(matches!(
        store.create_lifecycle(&inactive_change, projection.lifecycle.spec),
        Err(StoreError::LifecycleConflict(_))
    ));
    assert!(store.lifecycle(&inactive_change).unwrap().is_none());

    drop(store);
    fs::remove_file(path).unwrap();
}

#[test]
fn exploration_rejects_test_plan_and_stale_source_artifacts_without_mutation() {
    let name = "exploration-typing";
    let (path, store, change_id, projection) = lifecycle_fixture(name);
    let completion = worker(&projection.lifecycle.spec.profiles.explore);
    let connection = store.connection().unwrap();
    let test_plan_artifact: String = connection
        .query_row(
            "SELECT a.artifact_id FROM artifacts a
             JOIN artifact_requests r ON r.request_id=a.request_id
             WHERE r.logical_id=?1",
            [format!("{name}:test-plan")],
            |row| row.get(0),
        )
        .unwrap();
    let test_plan_artifact = Digest::parse(&test_plan_artifact).unwrap();
    drop(connection);
    assert!(matches!(
        store.parent_transition_lifecycle(
            &change_id,
            projection.state_digest,
            LifecycleTransition::CompleteExplore {
                worker: completion.clone(),
                artifacts: vec![LifecycleArtifactRef {
                    kind: LifecycleArtifactKind::Exploration,
                    id: test_plan_artifact,
                    source_snapshot: projection.lifecycle.source_snapshot,
                }],
            },
        ),
        Err(StoreError::LifecycleConflict(_))
    ));
    let stale_artifact = seed_exploration_certificate(
        &store,
        "exploration-typing-stale",
        Digest::blake3(b"stale-source"),
    );
    assert!(matches!(
        store.parent_transition_lifecycle(
            &change_id,
            projection.state_digest,
            LifecycleTransition::CompleteExplore {
                worker: completion,
                artifacts: vec![LifecycleArtifactRef {
                    kind: LifecycleArtifactKind::Exploration,
                    id: stale_artifact,
                    source_snapshot: projection.lifecycle.source_snapshot,
                }],
            },
        ),
        Err(StoreError::LifecycleConflict(_))
    ));
    assert_eq!(store.lifecycle(&change_id).unwrap().unwrap(), projection);
    assert_eq!(store.lifecycle_events(&change_id).unwrap().len(), 1);

    drop(store);
    fs::remove_file(path).unwrap();
}

#[test]
fn projection_and_event_payload_digests_are_verified_on_read() {
    let (path, store, change_id, projection) = lifecycle_fixture("stored-digests");
    let connection = store.connection().unwrap();
    connection.execute("DROP TRIGGER change_lifecycles_transition_shape", []).unwrap();
    connection
        .execute(
            "UPDATE change_lifecycles SET state_digest=?2 WHERE change_id=?1",
            params![change_id.to_string(), Digest::blake3(b"tampered-state").to_string()],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(store.lifecycle(&change_id), Err(StoreError::LifecycleCorruption(_))));

    let connection = store.connection().unwrap();
    connection
        .execute(
            "UPDATE change_lifecycles SET state_digest=?2 WHERE change_id=?1",
            params![change_id.to_string(), projection.state_digest.to_string()],
        )
        .unwrap();
    connection.execute("DROP TRIGGER change_events_no_update", []).unwrap();
    connection
        .execute(
            "UPDATE change_events SET payload_digest=?2
             WHERE change_id=?1 AND lifecycle_sequence=0",
            params![change_id.to_string(), Digest::blake3(b"tampered-event").to_string()],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(store.lifecycle_events(&change_id), Err(StoreError::LifecycleCorruption(_))));

    drop(store);
    fs::remove_file(path).unwrap();
}

#[test]
fn concurrent_cancellation_has_one_winner_and_replays_after_restart() {
    let (path, store, change_id, projection) = lifecycle_fixture("cancel-race");
    let barrier = Arc::new(Barrier::new(2));
    let expected_state_digest = projection.state_digest;
    let transition = LifecycleTransition::Cancel {
        reason: LifecycleReason::new("user_cancelled", b"bounded user cancellation").unwrap(),
    };
    let handles = (0..2)
        .map(|_| {
            let path = path.clone();
            let change_id = change_id.clone();
            let barrier = Arc::clone(&barrier);
            let transition = transition.clone();
            thread::spawn(move || {
                let store = RuntimeStore::new(path);
                store.initialize().unwrap();
                barrier.wait();
                store.parent_transition_lifecycle(&change_id, expected_state_digest, transition)
            })
        })
        .collect::<Vec<_>>();
    let outcomes = handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_err()).count(), 1);
    drop(store);

    let restarted = RuntimeStore::new(&path);
    restarted.initialize().unwrap();
    let replayed = restarted.replay_lifecycle(&change_id).unwrap();
    assert_eq!(replayed.lifecycle.status, LifecycleStatus::Cancelled);
    assert_eq!(replayed.lifecycle.generation, 1);
    assert_eq!(restarted.lifecycle_events(&change_id).unwrap().len(), 2);

    let connection = rusqlite::Connection::open(&path).unwrap();
    assert!(
        connection
            .execute(
                "UPDATE change_events SET event_type='tampered' WHERE change_id=?1",
                [change_id.to_string()],
            )
            .is_err()
    );
    assert!(
        connection
            .execute("DELETE FROM change_events WHERE change_id=?1", [change_id.to_string()])
            .is_err()
    );
    assert!(
        connection
            .execute("DELETE FROM change_lifecycles WHERE change_id=?1", [change_id.to_string()],)
            .is_err()
    );
    drop(connection);
    drop(restarted);
    fs::remove_file(path).unwrap();
}

#[test]
fn unavailable_exploration_artifact_leaves_projection_unchanged() {
    let (path, store, change_id, projection) = lifecycle_fixture("missing-artifact");
    let worker = LifecycleWorkerCompletion {
        profile: projection.lifecycle.spec.profiles.explore.clone(),
        worker_depth: 1,
        logical_worker_spawns: 1,
        usage: LifecycleUsage { worker_turns: 1, output_tokens: 10, cost_microusd: 10 },
    };
    let result = store.parent_transition_lifecycle(
        &change_id,
        projection.state_digest,
        LifecycleTransition::CompleteExplore {
            worker,
            artifacts: vec![LifecycleArtifactRef {
                kind: LifecycleArtifactKind::Exploration,
                id: Digest::blake3(b"missing-artifact"),
                source_snapshot: projection.lifecycle.source_snapshot,
            }],
        },
    );
    assert!(matches!(result, Err(StoreError::LifecycleConflict(_))));
    assert_eq!(store.lifecycle(&change_id).unwrap().unwrap(), projection);
    assert_eq!(store.lifecycle_events(&change_id).unwrap().len(), 1);
    drop(store);
    fs::remove_file(path).unwrap();
}

#[test]
fn lifecycle_operation_id_is_durably_bound_to_exact_invocation() {
    let (path, store, change_id, projection) = lifecycle_fixture("operation-binding");
    let change = store.lifecycle_change_context(&change_id).unwrap().unwrap();
    let operation_id = Digest::blake3(b"lifecycle-operation");
    let request_digest = Digest::blake3(b"lifecycle-operational-request");

    let first = store
        .create_lifecycle_for_operation(
            operation_id,
            request_digest,
            &change_id,
            change.repository_id,
            change.source_snapshot,
            &change.request,
            projection.lifecycle.spec.clone(),
        )
        .unwrap();
    assert!(!first.created);
    let replay = store
        .create_lifecycle_for_operation(
            operation_id,
            request_digest,
            &change_id,
            change.repository_id,
            change.source_snapshot,
            &change.request,
            projection.lifecycle.spec.clone(),
        )
        .unwrap();
    assert_eq!(replay.projection, first.projection);
    assert!(matches!(
        store.create_lifecycle_for_operation(
            operation_id,
            Digest::blake3(b"different-operational-request"),
            &change_id,
            change.repository_id,
            change.source_snapshot,
            &change.request,
            projection.lifecycle.spec,
        ),
        Err(StoreError::LifecycleConflict(_))
    ));

    drop(store);
    fs::remove_file(path).unwrap();
}
