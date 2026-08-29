use needle_core::{
    AcceptanceStatus, ActionContractId, AllowedPath, AllowedPathScope, ArtifactId, ArtifactRequest,
    ChangeActionInput, ChangeActionInvocation, ChangeId, ChangeRequest, CodexHost, CodexRole,
    CommandPolicy, Digest, EvidenceFailurePolicy, Facet, FallbackPolicy, FilesystemPolicy,
    LifecycleBudget, LifecyclePhase, LifecycleSpec, LifecycleStatus, LifecycleWorkerProfiles,
    MultiNeedPolicy, NeedExecution, NeedExecutionEnvelopeV1, NeedIr, NeedKey, NeedRequest,
    NetworkPolicy, ObligationExpression, PATCH_APPLY_ACTION_CONTRACT,
    PATCH_PROPOSE_ACTION_CONTRACT, PATCH_VERIFY_ACTION_CONTRACT, PatchActionInputRef,
    PredicateKind, REVIEW_DIFF_ACTION_CONTRACT, ReasoningLevel, RepairPolicy, RepositorySnapshot,
    RoleProfileBudget, RoleProfileDefinition, RoleProfileDefinitionInput, RoleProfileId,
    RoleProfileProvenance, RoleProfileState, ServiceTier, SubjectExpression, SubjectKind,
    TESTS_EXECUTE_ACTION_CONTRACT, TestPlan, ToolPolicy, VerificationActionInputRef,
    VerificationStatus, built_in_route_contracts, compile_need, need_fragment,
};
use needle_platform_codex::{CodexChangeActionProvider, CodexLifecycleActionAdapter, CodexWorker};
use needle_runtime::{
    ActionExecutionService, ChangeActionOutput, FreshLifecycleExploreAdapter,
    LifecycleExecutionDisposition, LifecycleExecutionKernel, LifecyclePhaseAdapters,
    NeedShadowWrite, NeverCancel, RuntimeSettings, RuntimeStore, capture_git_snapshot,
    compile_lifecycle_explore_action_plan, validate_semantic_test_plan,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const SIMULATOR: &str = env!("CARGO_BIN_EXE_needle-sim-codex");

#[test]
fn action_native_path_is_fresh_until_explicit_idempotent_apply() {
    let root = temporary_root();
    let repository = root.join("source");
    let data = root.join("data");
    let codex_home = root.join("codex-home");
    fs::create_dir_all(repository.join("tests")).unwrap();
    fs::create_dir_all(&codex_home).unwrap();
    fs::write(codex_home.join(".needle-simulation-worker-scenario"), "action_native_lifecycle\n")
        .unwrap();
    git(&repository, &["init", "--quiet"]);
    git(&repository, &["config", "user.email", "needle@example.invalid"]);
    git(&repository, &["config", "user.name", "Needle Test"]);
    fs::write(repository.join("fixture.txt"), "original active content\n").unwrap();
    fs::write(repository.join("tests/fixture.rs"), "#[test] fn focused() {}\n").unwrap();
    git(&repository, &["add", "fixture.txt", "tests/fixture.rs"]);
    git(&repository, &["commit", "--quiet", "-m", "fixture"]);

    let store = RuntimeStore::new(data.join("needle.sqlite3"));
    store
        .initialize_defaults(&RuntimeSettings {
            codex_executable: SIMULATOR.to_owned(),
            worker_model: "gpt-5.6-luna".to_owned(),
            worker_reasoning: "medium".to_owned(),
            worker_timeout_seconds: 10,
            evidence_failure_policy: EvidenceFailurePolicy::DiscardInvalidFact,
            trusted_test_execution: true,
            multi_need_policy: MultiNeedPolicy::default(),
        })
        .unwrap();
    let provenance = active_profile(&store, "offline.action-lifecycle", CodexRole::Implementer);
    let config = store.worker_config_for_provenance(&provenance, SIMULATOR).unwrap();
    let (_, snapshot) = capture_git_snapshot(&repository).unwrap();
    let test_plan_artifact =
        publish_test_plan(&store, &repository, &snapshot, TestEcosystem::Cargo);
    let change = ChangeRequest {
        task: "Update the fixture text.".to_owned(),
        acceptance_criteria: vec!["The fixture changes.".to_owned()],
        allowed_paths: vec![AllowedPath {
            path: "fixture.txt".to_owned(),
            scope: AllowedPathScope::Exact,
        }],
        artifact_ids: vec![test_plan_artifact],
        claim_ids: Vec::new(),
        constraints: vec!["Keep the active worktree unchanged until Apply.".to_owned()],
    };
    let requirements_digest = change.digest(snapshot.source_digest);
    let provider =
        CodexChangeActionProvider::new(&data, &repository, config).with_codex_home(&codex_home);
    let service = ActionExecutionService::new(store.clone(), provider);
    let need = action_need();

    let patch_result = execute(
        &service,
        "patch",
        &need,
        ChangeActionInput::PatchPropose { change, prior_patch: None, repair_verification: None },
        snapshot.repository_id,
        snapshot.source_digest,
    );
    let ChangeActionOutput::PatchProposal(patch) = patch_result.output else { unreachable!() };
    let patch_ref = PatchActionInputRef {
        artifact: ArtifactId::new(patch_result.artifact.id),
        patch: patch.id,
    };
    assert_eq!(
        fs::read_to_string(repository.join("fixture.txt")).unwrap(),
        "original active content\n"
    );

    let test_result = execute(
        &service,
        "test",
        &need,
        ChangeActionInput::TestsExecute {
            change_id: patch.change_id.clone(),
            requirements_digest,
            patch: patch_ref,
            test_plan_artifact,
        },
        snapshot.repository_id,
        snapshot.source_digest,
    );
    let ChangeActionOutput::TestExecution(test_evidence) = test_result.output else {
        unreachable!()
    };
    assert_eq!(test_evidence.status, needle_core::TestExecutionStatus::Passed);

    let review_result = execute(
        &service,
        "review",
        &need,
        ChangeActionInput::ReviewDiff {
            change_id: patch.change_id.clone(),
            requirements_digest,
            patch: patch_ref,
            prior_review_artifacts: Vec::new(),
        },
        snapshot.repository_id,
        snapshot.source_digest,
    );
    let ChangeActionOutput::Review(review) = review_result.output else { unreachable!() };
    assert_eq!(review.verdict, needle_core::ReviewReportVerdict::Approved);
    assert!(review.findings.is_empty());
    assert!(
        review
            .acceptance_coverage
            .iter()
            .all(|item| { item.status == AcceptanceStatus::Addressed })
    );

    let verification_result = execute(
        &service,
        "verify",
        &need,
        ChangeActionInput::PatchVerify {
            change_id: patch.change_id.clone(),
            requirements_digest,
            patch: patch_ref,
            test_evidence_artifacts: vec![ArtifactId::new(test_result.artifact.id)],
        },
        snapshot.repository_id,
        snapshot.source_digest,
    );
    let ChangeActionOutput::PatchVerification(verification) = verification_result.output else {
        unreachable!()
    };
    assert_eq!(verification.verdict, VerificationStatus::Verified);
    assert_eq!(
        fs::read_to_string(repository.join("fixture.txt")).unwrap(),
        "original active content\n"
    );

    let expected_state_digest = store.change_digest(&patch.change_id).unwrap().unwrap();
    let apply_input = ChangeActionInput::PatchApply {
        change_id: patch.change_id.clone(),
        requirements_digest,
        patch: patch_ref,
        verification: VerificationActionInputRef {
            artifact: ArtifactId::new(verification_result.artifact.id),
            verification: verification.id,
        },
        expected_state_digest,
        confirm: true,
    };
    let apply = execute(
        &service,
        "apply",
        &need,
        apply_input.clone(),
        snapshot.repository_id,
        snapshot.source_digest,
    );
    let ChangeActionOutput::ApplyReceipt(receipt) = &apply.output else { unreachable!() };
    assert_eq!(receipt.operation_id, Digest::blake3(b"operation-apply"));
    assert_eq!(
        fs::read_to_string(repository.join("fixture.txt")).unwrap(),
        "changed by isolated patcher\n"
    );

    let replay = execute(
        &service,
        "apply",
        &need,
        apply_input.clone(),
        snapshot.repository_id,
        snapshot.source_digest,
    );
    assert!(replay.idempotent_replay);
    assert_eq!(replay.artifact.id, apply.artifact.id);
    assert!(
        execute_result(
            &service,
            "second-apply-operation",
            &need,
            apply_input,
            snapshot.repository_id,
            snapshot.source_digest,
        )
        .is_err()
    );
    assert_eq!(
        fs::read_to_string(repository.join("fixture.txt")).unwrap(),
        "changed by isolated patcher\n"
    );

    drop(service);
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn persisted_lifecycle_reaches_awaiting_approval_and_applies_once() {
    for ecosystem in [TestEcosystem::Cargo, TestEcosystem::Node] {
        run_persisted_lifecycle(ecosystem, true);
    }
}

#[test]
fn persisted_lifecycle_discovers_a_missing_test_plan_once() {
    for ecosystem in [TestEcosystem::Cargo, TestEcosystem::Node] {
        run_persisted_lifecycle(ecosystem, false);
    }
}

#[derive(Clone, Copy)]
enum TestEcosystem {
    Cargo,
    Node,
}

impl TestEcosystem {
    fn plan(self) -> TestPlan {
        match self {
            Self::Cargo => TestPlan {
                runner: "cargo".to_owned(),
                argv: ["cargo", "test", "suite::focused", "--", "--exact"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                cwd_relative: ".".to_owned(),
                test_identifier: "suite::focused".to_owned(),
                requires_approval: true,
                execution_evidence_id: None,
            },
            Self::Node => TestPlan {
                runner: "node".to_owned(),
                argv: ["node", "--test", "tests/fixture.test.js"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                cwd_relative: ".".to_owned(),
                test_identifier: "tests/fixture.test.js".to_owned(),
                requires_approval: true,
                execution_evidence_id: None,
            },
        }
    }

    fn evidence(self) -> (&'static str, &'static str) {
        match self {
            Self::Cargo => {
                ("tests/fixture.rs", "// covers flag_definition\n#[test] fn focused() {}\n")
            }
            Self::Node => (
                "tests/fixture.test.js",
                "// tests/fixture.test.js focused covers flag_definition\nexport const focused = true;\n",
            ),
        }
    }
}

fn run_persisted_lifecycle(ecosystem: TestEcosystem, prepublish_test_plan: bool) {
    let root = temporary_root();
    let repository = root.join("source");
    let data = root.join("data");
    let codex_home = root.join("codex-home");
    fs::create_dir_all(repository.join("src")).unwrap();
    fs::create_dir_all(repository.join("tests")).unwrap();
    fs::create_dir_all(&codex_home).unwrap();
    fs::write(codex_home.join(".needle-simulation-worker-scenario"), "action_native_lifecycle\n")
        .unwrap();
    git(&repository, &["init", "--quiet"]);
    git(&repository, &["config", "user.email", "needle@example.invalid"]);
    git(&repository, &["config", "user.name", "Needle Test"]);
    fs::write(repository.join("fixture.txt"), "original active content\n").unwrap();
    fs::write(repository.join("src/lib.rs"), "pub fn flag_definition() {}\n").unwrap();
    let (test_path, test_contents) = ecosystem.evidence();
    fs::write(repository.join(test_path), test_contents).unwrap();
    git(&repository, &["add", "."]);
    git(&repository, &["commit", "--quiet", "-m", "fixture"]);

    let store = RuntimeStore::new(data.join("needle.sqlite3"));
    store
        .initialize_defaults(&RuntimeSettings {
            codex_executable: SIMULATOR.to_owned(),
            worker_model: "gpt-5.6-luna".to_owned(),
            worker_reasoning: "medium".to_owned(),
            worker_timeout_seconds: 10,
            evidence_failure_policy: EvidenceFailurePolicy::DiscardInvalidFact,
            trusted_test_execution: true,
            multi_need_policy: MultiNeedPolicy::default(),
        })
        .unwrap();
    let profiles = LifecycleWorkerProfiles {
        explore: active_profile(&store, "offline.lifecycle.explore", CodexRole::Explorer),
        implement: active_profile(&store, "offline.lifecycle.implement", CodexRole::Implementer),
        test: active_profile(&store, "offline.lifecycle.test", CodexRole::TestRunner),
        review: active_profile(&store, "offline.lifecycle.review", CodexRole::Reviewer),
        verify: active_profile(&store, "offline.lifecycle.verify", CodexRole::Verifier),
    };
    let (_, snapshot) = capture_git_snapshot(&repository).unwrap();
    if prepublish_test_plan {
        publish_test_plan(&store, &repository, &snapshot, ecosystem);
    }
    let need_ir = NeedIr::parse(
        "@@need\n\
         @route locate.implementation\n\
         @subject symbol:\"flag_definition\"\n\
         @require implementation-location selection=primary granularity=exact-location\n\
         @world source=current features=default\n\
         \n\
         Locate the primary fixture implementation.\n\
         @@end",
    )
    .unwrap()
    .unwrap();
    let route = built_in_route_contracts()
        .into_iter()
        .find(|route| route.route.as_str() == "locate.implementation")
        .unwrap();
    let need = compile_need(&need_ir, snapshot.repository_id, &route).unwrap();
    let fragment = need_fragment(&need, need.required.clone(), Vec::new());
    let repository_root = repository.to_string_lossy();
    store
        .record_session_start(
            "action-native-lifecycle",
            Digest::blake3(b"lifecycle-explore-session"),
            Some("gpt-5.6-luna"),
            Some(repository_root.as_ref()),
        )
        .unwrap();
    store
        .record_need_shadow(NeedShadowWrite {
            session_id: "action-native-lifecycle",
            turn_id: "explore",
            transport_digest: Digest::blake3(b"lifecycle-transport"),
            parser_definition_digest: Digest::blake3(b"lifecycle-parser"),
            prompt_profile_digest: profiles.explore.definition_digest,
            need_ir: &need_ir,
            need: &need,
            fragments: std::slice::from_ref(&fragment),
        })
        .unwrap();
    let need_request = NeedRequest { key: route.route.clone(), body: need_ir.body.clone() };
    let explore_plan = compile_lifecycle_explore_action_plan(
        &need_request,
        &need,
        &fragment,
        snapshot.repository_id,
        snapshot.source_digest,
    )
    .unwrap();
    let change = ChangeRequest {
        task: "Update the fixture text.".to_owned(),
        acceptance_criteria: vec!["The fixture changes.".to_owned()],
        allowed_paths: vec![AllowedPath {
            path: "fixture.txt".to_owned(),
            scope: AllowedPathScope::Exact,
        }],
        artifact_ids: Vec::new(),
        claim_ids: Vec::new(),
        constraints: vec!["Keep the active worktree unchanged until Apply.".to_owned()],
    };
    let requirements_digest = change.digest(snapshot.source_digest);
    let change_id = ChangeId::from_digest(requirements_digest);
    store
        .create_lifecycle_with_request(
            &change_id,
            snapshot.repository_id,
            snapshot.source_digest,
            &change,
            LifecycleSpec {
                worker_depth_limit: 1,
                profiles: profiles.clone(),
                budget: LifecycleBudget {
                    max_worker_turns: 20,
                    max_output_tokens: 100_000,
                    max_cost_microusd: 100_000,
                    max_concurrent_workers: 1,
                },
                explore_action_plan: Some(explore_plan),
                action_phase_plans: Some(CodexLifecycleActionAdapter::phase_plans().unwrap()),
                test_plans: Vec::new(),
            },
        )
        .unwrap();

    let explore = FreshLifecycleExploreAdapter::new(
        store.clone(),
        CodexWorker::with_codex_home(&data, &codex_home),
        &repository,
    )
    .unwrap();
    let phase_adapter = |phase| {
        CodexLifecycleActionAdapter::new(store.clone(), &data, &repository, phase)
            .unwrap()
            .with_codex_home(&codex_home)
    };
    let implement = phase_adapter(LifecyclePhase::Implement);
    let test = phase_adapter(LifecyclePhase::Test);
    let review = phase_adapter(LifecyclePhase::Review);
    let verify = phase_adapter(LifecyclePhase::Verify);
    let kernel = LifecycleExecutionKernel::new(
        &store,
        LifecyclePhaseAdapters {
            explore: &explore,
            implement: &implement,
            test: &test,
            review: &review,
            verify: &verify,
        },
        &NeverCancel,
    );
    let mut discovery_worker_runs = None;
    let mut discovery_resume_checked = prepublish_test_plan;
    for _ in 0..8 {
        let before = store.replay_lifecycle(&change_id).unwrap();
        let discovering_test_plan = !prepublish_test_plan
            && before.lifecycle.phase == LifecyclePhase::Test
            && before.lifecycle.resolved_test_plans.is_empty();
        let worker_runs_before = store.worker_run_count().unwrap();
        let outcome = kernel.step(&change_id).unwrap();
        let worker_runs_after = store.worker_run_count().unwrap();
        if discovering_test_plan {
            assert_eq!(worker_runs_after, worker_runs_before + 1);
            assert_eq!(outcome.projection.lifecycle.phase, LifecyclePhase::Test);
            assert!(
                !outcome.projection.lifecycle.resolved_test_plans.is_empty(),
                "TestPlan discovery did not bind a plan; disposition: {:?}",
                outcome.disposition
            );
            discovery_worker_runs = Some(worker_runs_after);
        } else if let Some(discovery_runs) = discovery_worker_runs
            && before.lifecycle.phase == LifecyclePhase::Test
        {
            assert_eq!(worker_runs_after, discovery_runs);
            discovery_resume_checked = true;
        }
        if outcome.projection.lifecycle.status == LifecycleStatus::AwaitingApproval {
            break;
        }
        assert!(
            matches!(
                outcome.disposition,
                LifecycleExecutionDisposition::Advanced
                    | LifecycleExecutionDisposition::RepairResumed
            ),
            "unexpected lifecycle outcome: {:?}",
            outcome.disposition
        );
    }
    let awaiting = store.replay_lifecycle(&change_id).unwrap();
    assert!(discovery_resume_checked);
    assert_eq!(awaiting.lifecycle.status, LifecycleStatus::AwaitingApproval);
    assert_eq!(awaiting.lifecycle.phase, LifecyclePhase::Apply);
    assert_eq!(
        fs::read_to_string(repository.join("fixture.txt")).unwrap(),
        "original active content\n"
    );
    let patch = awaiting.lifecycle.patch.as_ref().unwrap();
    let verification = awaiting.lifecycle.verification.as_ref().unwrap();
    let patch_artifact = store
        .opaque_action_artifact_by_payload(
            &ActionContractId::new(PATCH_PROPOSE_ACTION_CONTRACT).unwrap(),
            patch.patch_id.0,
        )
        .unwrap()
        .unwrap();
    let verification_artifact = store
        .opaque_action_artifact_by_payload(
            &ActionContractId::new(PATCH_VERIFY_ACTION_CONTRACT).unwrap(),
            verification.verification_id.0,
        )
        .unwrap()
        .unwrap();
    let apply_input = ChangeActionInput::PatchApply {
        change_id: change_id.clone(),
        requirements_digest,
        patch: PatchActionInputRef {
            artifact: ArtifactId::new(patch_artifact.id),
            patch: patch.patch_id,
        },
        verification: VerificationActionInputRef {
            artifact: ArtifactId::new(verification_artifact.id),
            verification: verification.verification_id,
        },
        expected_state_digest: awaiting.state_digest,
        confirm: true,
    };
    let apply_config = store.worker_config_for_provenance(&profiles.implement, SIMULATOR).unwrap();
    let apply_service = ActionExecutionService::new(
        store.clone(),
        CodexChangeActionProvider::new(&data, &repository, apply_config)
            .with_codex_home(&codex_home),
    );
    let applied = execute(
        &apply_service,
        "lifecycle-apply",
        &need_ir,
        apply_input.clone(),
        snapshot.repository_id,
        snapshot.source_digest,
    );
    assert!(matches!(applied.output, ChangeActionOutput::ApplyReceipt(_)));
    assert_eq!(
        store.replay_lifecycle(&change_id).unwrap().lifecycle.status,
        LifecycleStatus::Completed
    );
    assert_eq!(
        fs::read_to_string(repository.join("fixture.txt")).unwrap(),
        "changed by isolated patcher\n"
    );
    let replay = execute(
        &apply_service,
        "lifecycle-apply",
        &need_ir,
        apply_input.clone(),
        snapshot.repository_id,
        snapshot.source_digest,
    );
    assert!(replay.idempotent_replay);
    assert!(
        execute_result(
            &apply_service,
            "lifecycle-duplicate-apply",
            &need_ir,
            apply_input,
            snapshot.repository_id,
            snapshot.source_digest,
        )
        .is_err()
    );
    let safety = store.action_safety_metrics().unwrap();
    assert!(safety.is_clean(), "action safety metrics are non-zero: {safety:?}");

    drop(apply_service);
    drop(verify);
    drop(review);
    drop(test);
    drop(implement);
    drop(explore);
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

fn execute(
    service: &ActionExecutionService<CodexChangeActionProvider>,
    label: &str,
    need: &NeedIr,
    input: ChangeActionInput,
    repository_id: Digest,
    source_snapshot: Digest,
) -> needle_runtime::ActionExecutionResult {
    execute_result(service, label, need, input, repository_id, source_snapshot).unwrap()
}

fn execute_result(
    service: &ActionExecutionService<CodexChangeActionProvider>,
    label: &str,
    need: &NeedIr,
    input: ChangeActionInput,
    repository_id: Digest,
    source_snapshot: Digest,
) -> Result<needle_runtime::ActionExecutionResult, needle_runtime::ActionExecutionError> {
    let contract = ActionContractId::new(input.contract_id()).unwrap();
    let envelope = NeedExecutionEnvelopeV1::new(
        Digest::blake3(format!("operation-{label}")),
        need.clone(),
        NeedExecution::Action { action: ChangeActionInvocation { contract, input } },
    );
    service.execute_action(&envelope, repository_id, source_snapshot)
}

fn action_need() -> NeedIr {
    NeedIr {
        route_hint: Some(NeedKey::new("locate.implementation").unwrap()),
        subjects: vec![SubjectExpression {
            kind: SubjectKind::Symbol,
            canonical_name: "fixture".to_owned(),
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
        body: "Update the fixture text.".to_owned(),
        format_revision: needle_core::NEED_IR_FORMAT_REVISION,
    }
}

fn publish_test_plan(
    store: &RuntimeStore,
    repository: &Path,
    snapshot: &RepositorySnapshot,
    ecosystem: TestEcosystem,
) -> ArtifactId {
    let ir = NeedIr::parse(
        "@@need\n\
         @route tests.relevant\n\
         @subject symbol:\"focused\"\n\
         @require focused-tests selection=representative completeness=open-world polarity=positive\n\
         @world source=current features=default\n\
         \n\
         Find the focused fixture test.\n\
         @@end",
    )
    .unwrap()
    .unwrap();
    let route = built_in_route_contracts()
        .into_iter()
        .find(|route| route.route.as_str() == "tests.relevant")
        .unwrap();
    let need = compile_need(&ir, snapshot.repository_id, &route).unwrap();
    let fragment = need_fragment(&need, need.required.clone(), Vec::new());
    store
        .record_need_shadow(NeedShadowWrite {
            session_id: "action-lifecycle-offline",
            turn_id: "test-plan",
            transport_digest: Digest::blake3(b"offline-transport"),
            parser_definition_digest: Digest::blake3(b"offline-parser"),
            prompt_profile_digest: Digest::blake3(b"offline-test-plan-prompt"),
            need_ir: &ir,
            need: &need,
            fragments: std::slice::from_ref(&fragment),
        })
        .unwrap();
    let plan = ecosystem.plan();
    let (evidence_path, _) = ecosystem.evidence();
    let artifact = needle_core::SemanticWorkerArtifact::TestPlan {
        runner: plan.runner.clone(),
        argv: plan.argv.clone(),
        cwd_relative: plan.cwd_relative.clone(),
        identifiers: vec![plan.test_identifier.clone()],
        selection: "representative".to_owned(),
        evidence_paths: vec![evidence_path.to_owned()],
    };
    let request = ArtifactRequest {
        contract_id: "needle.semantic.test-plan".to_owned(),
        contract_revision: 2,
        repository_id: snapshot.repository_id,
        source_snapshot_digest: snapshot.source_digest,
        route_key: route.route.clone(),
        normalized_request: "focused certified fixture plan".to_owned(),
        semantic_fragment_id: Some(fragment.id),
        input_artifact_ids: Vec::new(),
    };
    let validated = validate_semantic_test_plan(
        &fragment,
        &artifact,
        repository,
        request.semantic_id().digest(),
        None,
        &plan,
    )
    .unwrap();
    store
        .publish_semantic_artifact(&request, &need, &validated.artifact, &validated.certificate)
        .unwrap();
    ArtifactId::new(validated.artifact.id)
}

fn active_profile(
    store: &RuntimeStore,
    profile_id: &str,
    role: CodexRole,
) -> RoleProfileProvenance {
    let executes_tests = matches!(role, CodexRole::TestRunner | CodexRole::Verifier);
    let writes_isolated_checkout = role == CodexRole::Implementer;
    let definition = RoleProfileDefinition::new(RoleProfileDefinitionInput {
        profile_id: RoleProfileId::new(profile_id).unwrap(),
        role,
        host: CodexHost::Codex,
        model: "gpt-5.6-luna".to_owned(),
        reasoning: ReasoningLevel::Medium,
        service_tier: ServiceTier::Default,
        timeout_seconds: 10,
        budget: RoleProfileBudget {
            max_turns: 2,
            max_output_tokens: 1_200,
            max_cost_microusd: 10_000,
        },
        prompt_profile_digest: Digest::blake3(format!("{profile_id}:prompt")),
        output_contract_digest: Digest::blake3(format!("{profile_id}:output")),
        tool_policy: if writes_isolated_checkout {
            ToolPolicy::IsolatedWrite
        } else {
            ToolPolicy::ReadOnly
        },
        command_policy: if executes_tests {
            CommandPolicy::CertifiedTests
        } else {
            CommandPolicy::Denied
        },
        filesystem_policy: if writes_isolated_checkout {
            FilesystemPolicy::DisposableCheckout
        } else {
            FilesystemPolicy::ReadOnlyCheckout
        },
        network_policy: NetworkPolicy::Denied,
        test_policy: if executes_tests {
            needle_core::TestPolicy::Certified
        } else {
            needle_core::TestPolicy::Disabled
        },
        repair_policy: if writes_isolated_checkout {
            RepairPolicy::Once
        } else {
            RepairPolicy::None
        },
        fallback_policy: FallbackPolicy::Disabled,
        concurrency: 1,
        route_assignments: if role == CodexRole::Explorer {
            vec![NeedKey::new("locate.implementation").unwrap()]
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

fn temporary_root() -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("needle-action-lifecycle-offline-{nanos}"))
}

fn git(repository: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .args(arguments)
        .current_dir(repository)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?} failed");
}

#[test]
fn action_contract_constants_are_the_expected_public_surface() {
    assert_eq!(PATCH_PROPOSE_ACTION_CONTRACT, "needle.patch.propose");
    assert_eq!(TESTS_EXECUTE_ACTION_CONTRACT, "needle.tests.execute");
    assert_eq!(REVIEW_DIFF_ACTION_CONTRACT, "needle.review.diff");
    assert_eq!(PATCH_VERIFY_ACTION_CONTRACT, "needle.patch.verify");
    assert_eq!(PATCH_APPLY_ACTION_CONTRACT, "needle.patch.apply");
}
