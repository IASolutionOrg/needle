use super::*;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use axum::middleware;
use needle_core::{
    AllowedPath, AllowedPathScope, ArtifactRequest, ChangeApplyId, ChangeRequest, CodexHost,
    CodexRole, CommandPolicy, DevelopmentLifecycle, Facet, FallbackPolicy, FilesystemPolicy,
    LifecycleArtifactKind, LifecycleArtifactRef, LifecycleBudget, LifecycleEvent,
    LifecycleExploreActionPlan, LifecycleSpec, LifecycleTestPlanBinding, LifecycleTransition,
    LifecycleUsage, LifecycleWorkerCompletion, LifecycleWorkerProfiles, Need, NeedId, NeedIr,
    NeedRequest, NetworkPolicy, Obligation, PatchId, PredicateKind, ReasoningLevel, RepairPolicy,
    RoleProfileBudget, RoleProfileDefinition, RoleProfileDefinitionInput, RoleProfileId,
    RoleProfileProvenance, RoleProfileState, SemanticWorkerArtifact, SemanticWorld, ServiceTier,
    Subject, SubjectKind, TestPlan, TestPolicy, ToolPolicy, built_in_route_contracts, compile_need,
    need_fragment,
};
use needle_runtime::{
    LifecycleAdapterCleanup, LifecycleAdapterResult, LifecycleExecutionKernel,
    LifecycleExploreActionResolver, LifecycleExploreActionResolverOutcome,
    LifecycleExploreShadowObservation, LifecyclePhaseAdapter, LifecyclePhaseAdapterOutcome,
    LifecyclePhaseAdapterRequest, LifecyclePhaseAdapters, NeedShadowWrite, NeverCancel,
    capture_git_snapshot, compile_lifecycle_explore_action_plan, validate_semantic_test_plan,
};
use rusqlite::{Connection, params};
use serde_json::Value;
use std::fs;
use std::path::{Path as FilePath, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

static TEST_DATABASE_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

fn test_state() -> (AppState, PathBuf) {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let sequence = TEST_DATABASE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join(format!("needle-lifecycle-http-{}-{nanos}-{sequence}.sqlite3", std::process::id()));
    let store = needle_runtime::RuntimeStore::new(&path);
    store.initialize().unwrap();
    (
        AppState {
            store,
            data_directory: path.with_extension("data"),
            lifecycle_step_host: std::sync::Arc::new(
                super::super::lifecycle_host::UnavailableLifecycleStepHost,
            ),
            lifecycle_step_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            authority: "127.0.0.1:43210".to_owned(),
            launch_token: "launch".to_owned(),
            session_token: "session".to_owned(),
            csrf_token: "csrf".to_owned(),
            ipc_endpoint: "test".to_owned(),
            repository_root: PathBuf::from("."),
            repository_watcher_health:
                super::super::runtime_health::RepositoryRuntimeHealth::unavailable(),
            apply_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            launch_consumed: std::sync::Arc::new(std::sync::Mutex::new(false)),
        },
        path,
    )
}

fn test_router(state: AppState) -> Router {
    routes(Router::new())
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, super::super::security))
}

async fn get(app: &Router, path: &str, authenticated: bool) -> (StatusCode, Value) {
    let mut builder =
        Request::builder().method(Method::GET).uri(path).header(header::HOST, "127.0.0.1:43210");
    if authenticated {
        builder = builder.header(header::COOKIE, "needle_session=session");
    }
    let response = app.clone().oneshot(builder.body(Body::empty()).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

async fn post_json(
    app: &Router,
    path: &str,
    authenticated: bool,
    csrf: bool,
    body: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::HOST, "127.0.0.1:43210")
        .header(header::CONTENT_TYPE, "application/json");
    if authenticated {
        builder = builder.header(header::COOKIE, "needle_session=session");
    }
    if csrf {
        builder = builder.header("x-csrf-token", "csrf");
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(serde_json::to_vec(&body).unwrap())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

struct MissResolver;

impl LifecycleExploreActionResolver for MissResolver {
    fn resolve(
        &self,
        _plan: &LifecycleExploreActionPlan,
        _change: &needle_runtime::LifecycleChangeContext,
    ) -> LifecycleExploreActionResolverOutcome {
        LifecycleExploreActionResolverOutcome::Miss
    }
}

struct CompletingAdapter<'a> {
    calls: &'a AtomicUsize,
    artifact_id: Digest,
}

impl LifecyclePhaseAdapter for CompletingAdapter<'_> {
    fn invoke(&self, request: &LifecyclePhaseAdapterRequest) -> LifecyclePhaseAdapterOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let usage = LifecycleUsage { worker_turns: 1, output_tokens: 20, cost_microusd: 30 };
        LifecyclePhaseAdapterOutcome {
            schema: needle_runtime::LIFECYCLE_ADAPTER_OUTCOME_SCHEMA.to_owned(),
            invocation_id: request.invocation_id,
            expected_state_digest: request.expected_state_digest,
            phase: request.phase,
            usage: usage.clone(),
            result: LifecycleAdapterResult::Completed {
                transition: Box::new(LifecycleTransition::CompleteExplore {
                    worker: LifecycleWorkerCompletion {
                        profile: request.profile.clone(),
                        worker_depth: 1,
                        logical_worker_spawns: 1,
                        usage,
                    },
                    artifacts: vec![LifecycleArtifactRef {
                        kind: LifecycleArtifactKind::Exploration,
                        id: self.artifact_id,
                        source_snapshot: request.lifecycle.source_snapshot,
                    }],
                }),
            },
            cleanup: LifecycleAdapterCleanup::succeeded(),
        }
    }
}

struct TestLifecycleStepHost {
    store: needle_runtime::RuntimeStore,
    calls: Arc<AtomicUsize>,
    artifact_id: Digest,
}

impl super::super::lifecycle_host::LifecycleStepHost for TestLifecycleStepHost {
    fn step(
        &self,
        change_id: &ChangeId,
    ) -> Result<
        needle_runtime::LifecycleExecutionOutcome,
        super::super::lifecycle_host::LifecycleStepHostError,
    > {
        let adapter = CompletingAdapter { calls: &self.calls, artifact_id: self.artifact_id };
        let adapters = LifecyclePhaseAdapters {
            explore: &adapter,
            implement: &adapter,
            test: &adapter,
            review: &adapter,
            verify: &adapter,
        };
        LifecycleExecutionKernel::new_with_explore_resolver(
            &self.store,
            adapters,
            &NeverCancel,
            &MissResolver,
        )
        .step(change_id)
        .map_err(super::super::lifecycle_host::LifecycleStepHostError::Execution)
    }
}

fn profile(id: &str) -> RoleProfileProvenance {
    RoleProfileProvenance::new(RoleProfileId::new(id).unwrap(), 1, Digest::blake3(id)).unwrap()
}

fn active_start_profile(
    store: &needle_runtime::RuntimeStore,
    id: &str,
    role: CodexRole,
) -> RoleProfileProvenance {
    let test_role = matches!(role, CodexRole::TestRunner | CodexRole::Verifier);
    let implementer = role == CodexRole::Implementer;
    let definition = RoleProfileDefinition::new(RoleProfileDefinitionInput {
        profile_id: RoleProfileId::new(id).unwrap(),
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
            vec![needle_core::NeedKey::new("tests.relevant").unwrap()]
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

fn profile_ref(profile: &RoleProfileProvenance) -> Value {
    serde_json::json!({
        "profile_id": profile.profile_id,
        "definition_digest": profile.definition_digest,
    })
}

fn seed_lifecycle_start_prerequisites(state: &AppState) -> (Value, Digest, NeedId) {
    let repository_root = fs::canonicalize(&state.repository_root).unwrap();
    let (_, snapshot) = capture_git_snapshot(&repository_root).unwrap();
    let identifier = "lifecycle_start_creation_is_authenticated_bounded_and_idempotent";
    let need_ir = NeedIr::parse(&format!(
        "@@need\n\
         @route tests.relevant\n\
         @subject symbol:\"{identifier}\"\n\
         @require focused-tests selection=representative completeness=open-world polarity=positive\n\
         @world source=current features=default\n\
         \n\
         Find the exact focused lifecycle start test.\n\
         @@end"
    ))
    .unwrap()
    .unwrap();
    let route = built_in_route_contracts()
        .into_iter()
        .find(|route| route.route.as_str() == "tests.relevant")
        .unwrap();
    let need = compile_need(&need_ir, snapshot.repository_id, &route).unwrap();
    let fragment = need_fragment(&need, need.required.clone(), Vec::new());
    let repository_root_text = repository_root.to_string_lossy().into_owned();
    state
        .store
        .record_session_start(
            "lifecycle-start-session",
            Digest::blake3(b"lifecycle-start-session-profile"),
            Some("offline-lifecycle-worker"),
            Some(&repository_root_text),
        )
        .unwrap();
    state
        .store
        .record_need_shadow(NeedShadowWrite {
            session_id: "lifecycle-start-session",
            turn_id: "lifecycle-start-turn",
            transport_digest: need_ir.transport_digest(),
            parser_definition_digest: Digest::blake3(b"lifecycle-start-parser"),
            prompt_profile_digest: Digest::blake3(b"lifecycle-start-session-profile"),
            need_ir: &need_ir,
            need: &need,
            fragments: std::slice::from_ref(&fragment),
        })
        .unwrap();

    let argv = vec![
        "cargo".to_owned(),
        "test".to_owned(),
        "-p".to_owned(),
        "needle-app".to_owned(),
        identifier.to_owned(),
        "--".to_owned(),
        "--exact".to_owned(),
    ];
    let test_plan = TestPlan {
        runner: "cargo".to_owned(),
        argv: argv.clone(),
        cwd_relative: ".".to_owned(),
        test_identifier: identifier.to_owned(),
        requires_approval: true,
        execution_evidence_id: None,
    };
    let worker_artifact = SemanticWorkerArtifact::TestPlan {
        runner: "cargo".to_owned(),
        argv,
        cwd_relative: ".".to_owned(),
        identifiers: vec![identifier.to_owned()],
        selection: "representative".to_owned(),
        evidence_paths: vec!["src/server/lifecycles/tests.rs".to_owned()],
    };
    let artifact_request = ArtifactRequest {
        contract_id: "needle.semantic.test-plan".to_owned(),
        contract_revision: 2,
        repository_id: snapshot.repository_id,
        source_snapshot_digest: snapshot.source_digest,
        route_key: route.route,
        normalized_request: need_ir.body.clone(),
        semantic_fragment_id: Some(fragment.id),
        input_artifact_ids: Vec::new(),
    };
    let validated = validate_semantic_test_plan(
        &fragment,
        &worker_artifact,
        &repository_root,
        artifact_request.semantic_id().digest(),
        None,
        &test_plan,
    )
    .unwrap();
    state
        .store
        .publish_semantic_artifact(
            &artifact_request,
            &need,
            &validated.artifact,
            &validated.certificate,
        )
        .unwrap();

    let explore = active_start_profile(&state.store, "start.explorer", CodexRole::Explorer);
    let implement = active_start_profile(&state.store, "start.implementer", CodexRole::Implementer);
    let test = active_start_profile(&state.store, "start.test", CodexRole::TestRunner);
    let review = active_start_profile(&state.store, "start.reviewer", CodexRole::Reviewer);
    let verify = active_start_profile(&state.store, "start.verifier", CodexRole::Verifier);
    let body = serde_json::json!({
        "operation_id": "a".repeat(64),
        "expected_source_snapshot": snapshot.source_digest,
        "need_id": need.id,
        "change": {
            "task": "Create a bounded lifecycle from the operator UI.",
            "acceptance_criteria": ["The lifecycle is created exactly once."],
            "allowed_paths": [{
                "path": "src/server/lifecycles/tests.rs",
                "scope": "exact"
            }],
            "artifact_ids": [],
            "claim_ids": [],
            "constraints": []
        },
        "profiles": {
            "explore": profile_ref(&explore),
            "implement": profile_ref(&implement),
            "test": profile_ref(&test),
            "review": profile_ref(&review),
            "verify": profile_ref(&verify)
        },
        "budget": {
            "max_worker_turns": 10,
            "max_output_tokens": 10000,
            "max_cost_microusd": 100000
        },
        "test_plan_certificates": [validated.certificate.id.digest()]
    });
    (body, snapshot.source_digest, need.id)
}

fn lifecycle_spec(
    name: &str,
    explore_action_plan: Option<LifecycleExploreActionPlan>,
) -> LifecycleSpec {
    let test_identifier = "opaque-sensitive-sentinel".to_owned();
    LifecycleSpec {
        worker_depth_limit: 1,
        profiles: LifecycleWorkerProfiles {
            explore: profile(&format!("{name}.explore")),
            implement: profile(&format!("{name}.implement")),
            test: profile(&format!("{name}.test")),
            review: profile(&format!("{name}.review")),
            verify: profile(&format!("{name}.verify")),
        },
        budget: LifecycleBudget {
            max_worker_turns: 10,
            max_output_tokens: 10_000,
            max_cost_microusd: 100_000,
            max_concurrent_workers: 1,
        },
        explore_action_plan,
        action_phase_plans: None,
        test_plans: vec![LifecycleTestPlanBinding {
            plan: TestPlan {
                runner: "cargo".to_owned(),
                argv: vec![
                    "cargo".to_owned(),
                    "test".to_owned(),
                    test_identifier.clone(),
                    "--".to_owned(),
                    "--exact".to_owned(),
                ],
                cwd_relative: ".".to_owned(),
                test_identifier,
                requires_approval: true,
                execution_evidence_id: None,
            },
            certificate_digest: Digest::blake3(format!("{name}:certificate")),
        }],
    }
}

fn insert_event(connection: &Connection, event: &LifecycleEvent) {
    let payload = serde_json::to_string(event).unwrap();
    connection
        .execute(
            "INSERT INTO change_events(
                change_id, event_type, payload_digest, payload_json,
                created_unix_ms, lifecycle_sequence
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                event.change_id.to_string(),
                if event.sequence == 0 { "lifecycle_created" } else { "lifecycle_transitioned" },
                Digest::blake3(payload.as_bytes()).to_string(),
                payload,
                event.created_unix_ms,
                event.sequence,
            ],
        )
        .unwrap();
}

fn seed_lifecycle(
    state: &AppState,
    database: &FilePath,
    name: &str,
    with_transition: bool,
    explore_action_plan: Option<LifecycleExploreActionPlan>,
    action_phase_plans: Option<needle_core::LifecycleActionPhasePlans>,
) -> ChangeId {
    let source = Digest::blake3(format!("{name}:source"));
    let change_id = ChangeId::from_digest(Digest::blake3(format!("{name}:change")));
    let request = ChangeRequest {
        task: "Expose bounded lifecycle state.".to_owned(),
        acceptance_criteria: vec!["Only safe projections are returned.".to_owned()],
        allowed_paths: vec![AllowedPath {
            path: "fixture.txt".to_owned(),
            scope: AllowedPathScope::Exact,
        }],
        artifact_ids: Vec::new(),
        claim_ids: Vec::new(),
        constraints: Vec::new(),
    };
    state
        .store
        .record_change_request(
            &change_id,
            Digest::blake3(format!("{name}:repository")),
            source,
            request.digest(source),
            &request,
        )
        .unwrap();

    let mut spec = lifecycle_spec(name, explore_action_plan);
    spec.action_phase_plans = action_phase_plans;
    let initial = DevelopmentLifecycle::new(change_id.clone(), source, spec, 10).unwrap();
    let created = LifecycleEvent::created(&initial).unwrap();
    let (lifecycle, transitioned) = if with_transition {
        let exploration_id = Digest::blake3(format!("{name}:exploration"));
        let worker = LifecycleWorkerCompletion {
            profile: initial.spec.profiles.explore.clone(),
            worker_depth: 1,
            logical_worker_spawns: 1,
            usage: LifecycleUsage { worker_turns: 1, output_tokens: 20, cost_microusd: 30 },
        };
        let (next, event) = initial
            .transition(
                LifecycleTransition::CompleteExplore {
                    worker,
                    artifacts: vec![LifecycleArtifactRef {
                        kind: LifecycleArtifactKind::Exploration,
                        id: exploration_id,
                        source_snapshot: source,
                    }],
                },
                11,
            )
            .unwrap();
        (next, Some(event))
    } else {
        (initial, None)
    };
    let state_json = serde_json::to_string(&lifecycle).unwrap();
    let state_digest = lifecycle.state_digest();
    let connection = Connection::open(database).unwrap();
    connection
        .execute(
            "INSERT INTO change_lifecycles(
                lifecycle_id, change_id, source_snapshot_digest, state_digest,
                generation, state_json, created_unix_ms, updated_unix_ms
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                lifecycle.id.to_string(),
                change_id.to_string(),
                source.to_string(),
                state_digest.to_string(),
                lifecycle.generation,
                state_json,
                lifecycle.created_unix_ms,
                lifecycle.updated_unix_ms,
            ],
        )
        .unwrap();
    insert_event(&connection, &created);
    if let Some(event) = transitioned {
        insert_event(&connection, &event);
    }
    change_id
}

fn seed_recovery(database: &FilePath, change_id: &ChangeId) {
    let patch_id = PatchId(Digest::blake3(b"http:patch"));
    let apply_id = ChangeApplyId(Digest::blake3(b"http:apply"));
    let older_apply_id = ChangeApplyId(Digest::blake3(b"http:older-apply"));
    let connection = Connection::open(database).unwrap();
    connection
        .execute(
            "INSERT INTO patch_artifacts(
                patch_id, change_id, revision, source_snapshot_digest, patch_digest,
                artifact_json, manifest_json, declared_output_json, discrepancies_json,
                created_unix_ms
             ) VALUES(?1, ?2, 1, ?3, ?4, '{}', '{}', '{}', '[]', 12)",
            params![
                patch_id.to_string(),
                change_id.to_string(),
                Digest::blake3(b"http:source").to_string(),
                Digest::blake3(b"http:patch-digest").to_string(),
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO change_applies(
                apply_id, change_id, patch_id, repository_root, pre_snapshot_digest,
                post_snapshot_digest, status, journal_json, created_unix_ms, completed_unix_ms
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 'applied', '{}', 11, 12)",
            params![
                older_apply_id.to_string(),
                change_id.to_string(),
                patch_id.to_string(),
                "C:\\opaque-sensitive-sentinel\\older-repository",
                Digest::blake3(b"http:older-pre").to_string(),
                Digest::blake3(b"http:older-post").to_string(),
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO change_applies(
                apply_id, change_id, patch_id, repository_root, pre_snapshot_digest,
                post_snapshot_digest, status, journal_json, created_unix_ms, completed_unix_ms
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 'recovery_conflict', ?7, 13, 14)",
            params![
                apply_id.to_string(),
                change_id.to_string(),
                patch_id.to_string(),
                "C:\\opaque-sensitive-sentinel\\repository",
                Digest::blake3(b"http:pre").to_string(),
                Digest::blake3(b"http:post").to_string(),
                r#"{"transcript":"opaque-sensitive-sentinel"}"#,
            ],
        )
        .unwrap();
}

fn lifecycle_snapshot(database: &FilePath) -> (u64, u64, u64, u64, String, String) {
    let connection = Connection::open(database).unwrap();
    connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM change_lifecycles),
                (SELECT COUNT(*) FROM change_events),
                (SELECT COUNT(*) FROM change_applies),
                (SELECT COUNT(*) FROM lifecycle_explore_action_observations),
                (SELECT group_concat(state_digest, ',')
                   FROM (SELECT state_digest FROM change_lifecycles ORDER BY change_id)),
                (SELECT group_concat(payload_digest, ',')
                   FROM (SELECT payload_digest FROM change_events ORDER BY event_id))",
            [],
            |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
            },
        )
        .unwrap()
}

fn lifecycle_explore_plan(name: &str) -> LifecycleExploreActionPlan {
    let repository = Digest::blake3(format!("{name}:repository"));
    let source = Digest::blake3(format!("{name}:source"));
    let request = NeedRequest {
        key: needle_core::NeedKey::new("locate.implementation").unwrap(),
        body: "Locate the lifecycle implementation.".to_owned(),
    };
    let subject = Subject::exact(repository, SubjectKind::Symbol, "lifecycle");
    let required = vec![Obligation::new(
        PredicateKind::ImplementationLocation,
        subject.id,
        vec![Facet { key: "selection".to_owned(), value: "primary".to_owned() }],
    )];
    let need = Need {
        id: NeedId::new(Digest::blake3(format!("{name}:need"))),
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

fn assert_safe(value: &Value) {
    let text = value.to_string();
    for forbidden in [
        "opaque-sensitive-sentinel",
        "repository_root",
        "journal_json",
        "transcript",
        "credentials",
        "cwd_relative",
        "argv",
    ] {
        assert!(!text.contains(forbidden), "response leaked {forbidden}");
    }
}

#[tokio::test]
async fn lifecycle_routes_are_authenticated_bounded_ordered_safe_and_read_only() {
    let (state, database) = test_state();
    let app = test_router(state.clone());

    let (status, _) = get(&app, "/api/v1/lifecycles", false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, empty) = get(&app, "/api/v1/lifecycles", true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(empty["schema"], LIST_SCHEMA);
    assert!(empty["items"].as_array().unwrap().is_empty());

    let mut change_ids = [
        seed_lifecycle(&state, &database, "http-z", false, None, None),
        seed_lifecycle(&state, &database, "http-a", true, None, None),
        seed_lifecycle(&state, &database, "http-m", false, None, None),
    ];
    change_ids.sort_by_key(ToString::to_string);
    let transitioned_id = ChangeId::from_digest(Digest::blake3("http-a:change"));
    seed_recovery(&database, &transitioned_id);
    let before = lifecycle_snapshot(&database);

    let (status, list) = get(&app, "/api/v1/lifecycles?limit=2", true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["schema"], LIST_SCHEMA);
    assert_eq!(list["limit"], 2);
    assert_eq!(
        list["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["change_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        change_ids[..2].iter().map(ChangeId::as_str).collect::<Vec<_>>()
    );
    assert_safe(&list);

    let (status, maximum) = get(&app, "/api/v1/lifecycles?limit=100", true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(maximum["limit"], 100);
    assert_eq!(maximum["items"].as_array().unwrap().len(), 3);
    assert_safe(&maximum);

    for path in [
        "/api/v1/lifecycles?limit=0",
        "/api/v1/lifecycles?limit=101",
        "/api/v1/lifecycles?limit=abc",
        "/api/v1/lifecycles?unknown=1",
    ] {
        let (status, error) = get(&app, path, true).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error["schema"], ERROR_SCHEMA);
    }

    let detail_path = format!("/api/v1/lifecycles/{transitioned_id}");
    let (status, detail) = get(&app, &detail_path, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["schema"], DETAIL_SCHEMA);
    assert_eq!(detail["lifecycle"]["change_id"], transitioned_id.as_str());
    assert_eq!(detail["lifecycle"]["phase"], "implement");
    assert_eq!(detail["lifecycle"]["recovery"]["status"], "recovery_conflict");
    assert_safe(&detail);

    let events_path = format!("{detail_path}/events");
    let (status, events) = get(&app, &events_path, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(events["schema"], EVENTS_SCHEMA);
    assert_eq!(events["limit"], needle_core::MAX_LIFECYCLE_EVENTS);
    assert_eq!(
        events["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["sequence"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert_eq!(events["items"][0]["action"]["kind"], "created");
    assert_eq!(events["items"][1]["action"]["kind"], "complete_explore");
    assert_safe(&events);
    let observations_path = format!("{detail_path}/action-observations");
    let (status, observations) = get(&app, &observations_path, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(observations["schema"], ACTION_OBSERVATIONS_SCHEMA);
    assert!(observations["items"].as_array().unwrap().is_empty());
    assert_safe(&observations);

    let missing = ChangeId::from_digest(Digest::blake3(b"http:missing"));
    let (status, missing_body) = get(&app, &format!("/api/v1/lifecycles/{missing}"), true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(missing_body["code"], "not_found");
    let (status, malformed) = get(&app, "/api/v1/lifecycles/not-a-change", true).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(malformed["code"], "invalid_change_id");

    assert_eq!(lifecycle_snapshot(&database), before);

    let connection = Connection::open(&database).unwrap();
    connection.execute("DROP TRIGGER change_events_no_update", []).unwrap();
    let payload = connection
        .query_row(
            "SELECT payload_json FROM change_events
             WHERE change_id=?1 AND lifecycle_sequence=0",
            [transitioned_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    let mut payload: Value = serde_json::from_str(&payload).unwrap();
    payload["status"] = serde_json::json!("unknown_status");
    let payload = serde_json::to_string(&payload).unwrap();
    connection
        .execute(
            "UPDATE change_events SET payload_json=?2, payload_digest=?3
             WHERE change_id=?1 AND lifecycle_sequence=0",
            params![
                transitioned_id.to_string(),
                &payload,
                Digest::blake3(payload.as_bytes()).to_string(),
            ],
        )
        .unwrap();
    drop(connection);
    for path in ["/api/v1/lifecycles".to_owned(), detail_path, events_path, observations_path] {
        let (status, error) = get(&app, &path, true).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error["code"], "lifecycle_corruption");
        assert_safe(&error);
    }

    drop(app);
    drop(state);
    std::fs::remove_file(database).unwrap();
}

#[tokio::test]
async fn action_observations_are_authenticated_bounded_safe_and_corruption_checked() {
    let (state, database) = test_state();
    let app = test_router(state.clone());
    let name = "http-action-observation";
    let plan = lifecycle_explore_plan(name);
    let change_id = seed_lifecycle(&state, &database, name, false, Some(plan.clone()), None);
    let projection = state.store.replay_lifecycle(&change_id).unwrap();
    let observation = LifecycleExploreShadowObservation::from_resolver_outcome(
        projection.lifecycle.id,
        projection.state_digest,
        &plan,
        LifecycleExploreActionResolverOutcome::Miss,
    );
    state.store.record_lifecycle_explore_action_observation(&observation).unwrap();
    let before = lifecycle_snapshot(&database);
    let path = format!("/api/v1/lifecycles/{change_id}/action-observations");

    let (status, _) = get(&app, &path, false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = get(&app, &format!("{path}?limit=1"), true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["schema"], ACTION_OBSERVATIONS_SCHEMA);
    assert_eq!(body["change_id"], change_id.as_str());
    assert_eq!(body["limit"], 1);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    let item = &body["items"][0];
    assert_eq!(item["observation_digest"], observation.definition_digest.to_string());
    assert_eq!(item["expected_state_digest"], observation.expected_state_digest.to_string());
    assert_eq!(item["resolution"], "miss");
    assert_eq!(item["authority"], "shadow");
    assert_eq!(item["adapter_invocation_required"], true);
    assert_eq!(item["planned_action_count"], 1);
    assert!(item["actions"].as_array().unwrap().is_empty());
    assert_safe(&body);

    for suffix in ["?limit=0", "?limit=101", "?limit=abc", "?unknown=1"] {
        let (status, error) = get(&app, &format!("{path}{suffix}"), true).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error["schema"], ERROR_SCHEMA);
    }
    let missing = ChangeId::from_digest(Digest::blake3(b"http:missing-observation"));
    assert_eq!(
        get(&app, &format!("/api/v1/lifecycles/{missing}/action-observations"), true,).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&app, "/api/v1/lifecycles/not-a-change/action-observations", true).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(lifecycle_snapshot(&database), before);

    let connection = Connection::open(&database).unwrap();
    connection.execute("DROP TRIGGER lifecycle_explore_action_observations_no_update", []).unwrap();
    connection
        .execute(
            "UPDATE lifecycle_explore_action_observations
             SET plan_definition_digest=?1",
            [Digest::blake3(b"tampered-observation-plan").to_string()],
        )
        .unwrap();
    drop(connection);
    let (status, error) = get(&app, &path, true).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error["code"], "lifecycle_corruption");
    assert_safe(&error);

    drop(app);
    drop(state);
    std::fs::remove_file(database).unwrap();
}

#[tokio::test]
async fn lifecycle_start_creation_is_authenticated_bounded_and_idempotent() {
    let (state, database) = test_state();
    let (body, source_snapshot, need_id) = seed_lifecycle_start_prerequisites(&state);
    let app = test_router(state.clone());

    assert_eq!(get(&app, "/api/v1/lifecycles/preflight", false).await.0, StatusCode::UNAUTHORIZED);
    let (status, preflight) = get(&app, "/api/v1/lifecycles/preflight", true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(preflight["schema"], "needle.lifecycle-start-preflight/1");
    assert_eq!(preflight["eligible"], true);
    assert_eq!(preflight["source_snapshot"], source_snapshot.to_string());
    assert!(
        preflight["needs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| { item["need_id"] == serde_json::to_value(need_id).unwrap() })
    );
    assert_eq!(preflight["profiles"].as_array().unwrap().len(), 5);
    assert_eq!(preflight["test_plans"].as_array().unwrap().len(), 1);
    let preflight_text = preflight.to_string();
    for forbidden in ["cargo", "argv", "cwd_relative", "test_identifier"] {
        assert!(!preflight_text.contains(forbidden), "preflight leaked {forbidden}");
    }

    assert_eq!(
        post_json(&app, "/api/v1/lifecycles", false, true, body.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post_json(&app, "/api/v1/lifecycles", true, false, body.clone()).await.0,
        StatusCode::FORBIDDEN
    );
    let mut unknown = body.clone();
    unknown.as_object_mut().unwrap().insert("unknown".to_owned(), Value::Bool(true));
    assert_eq!(
        post_json(&app, "/api/v1/lifecycles", true, true, unknown).await.0,
        StatusCode::BAD_REQUEST
    );
    let mut stale = body.clone();
    stale["expected_source_snapshot"] =
        serde_json::to_value(Digest::blake3(b"stale-source")).unwrap();
    let (status, stale_body) = post_json(&app, "/api/v1/lifecycles", true, true, stale).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(stale_body["code"], "stale_source");

    let (status, created) = post_json(&app, "/api/v1/lifecycles", true, true, body.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["schema"], "needle.lifecycle-create/1");
    assert_eq!(created["created"], true);
    assert_eq!(created["phase"], "explore");
    assert_eq!(created["status"], "active");
    let change_id = created["change_id"].as_str().unwrap();
    let state_digest = created["state_digest"].clone();
    let (status, replayed) = post_json(&app, "/api/v1/lifecycles", true, true, body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replayed["created"], false);
    assert_eq!(replayed["change_id"], change_id);
    assert_eq!(replayed["state_digest"], state_digest);

    let (status, detail) = get(&app, &format!("/api/v1/lifecycles/{change_id}"), true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["lifecycle"]["state_digest"], state_digest);
    assert_eq!(state.store.list_lifecycle_summaries(10).unwrap().len(), 1);

    drop(app);
    drop(state);
    fs::remove_file(database).unwrap();
}

#[tokio::test]
async fn explicit_explore_step_requires_cas_and_invokes_the_shadow_host_once() {
    let (mut state, database) = test_state();
    let name = "http-explicit-explore-step";
    let plan = lifecycle_explore_plan(name);
    let action = &plan.actions[0];
    let worker_artifact = needle_core::SemanticWorkerArtifact::CodeLocation {
        locations: vec![needle_core::SemanticLocation {
            role: needle_core::LocationRole::Primary,
            path: "src/server/lifecycles.rs".to_owned(),
            symbol: Some("step_lifecycle".to_owned()),
            byte_start: None,
            byte_end: None,
        }],
        gaps: Vec::new(),
    };
    let validated = needle_runtime::validate_semantic_artifact(
        &plan.fragment,
        &worker_artifact,
        FilePath::new("."),
        action.semantic_id().digest(),
    )
    .unwrap();
    state
        .store
        .publish_action_artifact(action, &validated.artifact, &validated.certificate)
        .unwrap();
    let artifact_id = validated.artifact.id;
    let change_id = seed_lifecycle(&state, &database, name, false, Some(plan), None);
    let initial = state.store.replay_lifecycle(&change_id).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    state.lifecycle_step_host = Arc::new(TestLifecycleStepHost {
        store: state.store.clone(),
        calls: calls.clone(),
        artifact_id,
    });
    let app = test_router(state.clone());
    let path = format!("/api/v1/lifecycles/{change_id}/step");
    let body = serde_json::json!({"expected_state_digest": initial.state_digest});

    assert_eq!(
        post_json(&app, &path, false, false, body.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(post_json(&app, &path, true, false, body.clone()).await.0, StatusCode::FORBIDDEN);
    assert_eq!(
        post_json(
            &app,
            &path,
            true,
            true,
            serde_json::json!({
                "expected_state_digest": initial.state_digest,
                "unknown": true
            }),
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_json(
            &app,
            &path,
            true,
            true,
            serde_json::json!({"expected_state_digest": Digest::blake3(b"stale-http-step")}),
        )
        .await
        .0,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let guard = state.lifecycle_step_lock.clone().lock_owned().await;
    let (status, busy) = post_json(&app, &path, true, true, body.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(busy["code"], "lifecycle_step_busy");
    drop(guard);

    let (status, result) = post_json(&app, &path, true, true, body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["schema"], STEP_SCHEMA);
    assert_eq!(result["change_id"], change_id.as_str());
    assert_eq!(result["disposition"], "advanced");
    assert_eq!(result["phase"], "implement");
    assert_eq!(result["status"], "active");
    assert_eq!(result["generation"], 1);
    assert_eq!(result["observation"]["resolution"], "miss");
    assert_eq!(result["observation"]["authority"], "shadow");
    assert_eq!(result["observation"]["adapter_invocation_required"], true);
    assert_eq!(result["observation_persistence"], "stored");
    assert!(result["reuse"].is_null());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_safe(&result);

    let current = state.store.replay_lifecycle(&change_id).unwrap();
    assert_eq!(current.lifecycle.phase, needle_core::LifecyclePhase::Implement);
    assert_eq!(current.lifecycle.generation, 1);
    let observations =
        state.store.list_lifecycle_explore_action_observations(initial.lifecycle.id, 10).unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].observation.authority,
        needle_runtime::ShadowActionResolutionAuthority::Shadow
    );
    assert!(observations[0].observation.adapter_invocation_required);

    let (status, stale) = post_json(&app, &path, true, true, body).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(stale["code"], "stale_state");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    drop(app);
    drop(state);
    std::fs::remove_file(database).unwrap();
}

#[tokio::test]
async fn lifecycle_apply_route_is_closed_confirmed_and_phase_bound() {
    let (state, database) = test_state();
    let change_id =
        seed_lifecycle(&state, &database, "http-lifecycle-apply-preconditions", false, None, None);
    let projection = state.store.replay_lifecycle(&change_id).unwrap();
    let app = test_router(state.clone());
    let path = format!("/api/v1/lifecycles/{change_id}/apply");
    let confirmed = serde_json::json!({
        "expected_state_digest": projection.state_digest,
        "confirm": true,
    });

    assert_eq!(
        post_json(&app, &path, false, false, confirmed.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post_json(&app, &path, true, false, confirmed.clone()).await.0,
        StatusCode::FORBIDDEN
    );
    let (status, invalid) = post_json(
        &app,
        &path,
        true,
        true,
        serde_json::json!({
            "expected_state_digest": projection.state_digest,
            "confirm": true,
            "unknown": true,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid["code"], "invalid_body");
    let (status, unconfirmed) = post_json(
        &app,
        &path,
        true,
        true,
        serde_json::json!({
            "expected_state_digest": projection.state_digest,
            "confirm": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(unconfirmed["code"], "confirmation_required");
    let (status, unavailable) = post_json(&app, &path, true, true, confirmed).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(unavailable["code"], "apply_unavailable");

    drop(app);
    drop(state);
    fs::remove_file(database).unwrap();
}

#[test]
fn lifecycle_step_accepts_frozen_action_phases_but_not_legacy_unplanned_records() {
    let (state, database) = test_state();
    let legacy_change =
        seed_lifecycle(&state, &database, "http-legacy-implement-step", true, None, None);
    let legacy = state.store.replay_lifecycle(&legacy_change).unwrap();
    assert_eq!(legacy.lifecycle.phase, LifecyclePhase::Implement);
    let rejection = match prepare_lifecycle_step(&state, &legacy_change, legacy.state_digest) {
        Err(PrepareLifecycleStepError::Rejection(rejection)) => rejection,
        _ => panic!("legacy lifecycle without frozen action plans must be rejected"),
    };
    assert_eq!(rejection.status, StatusCode::CONFLICT);
    assert_eq!(rejection.code, "lifecycle_step_unavailable");

    let planned_change = seed_lifecycle(
        &state,
        &database,
        "http-action-implement-step",
        true,
        None,
        Some(needle_platform_codex::CodexLifecycleActionAdapter::phase_plans().unwrap()),
    );
    let planned = state.store.replay_lifecycle(&planned_change).unwrap();
    assert_eq!(planned.lifecycle.phase, LifecyclePhase::Implement);
    let prepared = match prepare_lifecycle_step(&state, &planned_change, planned.state_digest) {
        Ok(prepared) => prepared,
        Err(_) => panic!("frozen action phase must be runnable"),
    };
    assert_eq!(prepared.state_digest, planned.state_digest);

    drop(state);
    fs::remove_file(database).unwrap();
}

#[tokio::test]
async fn abandoned_adapter_recovery_requires_confirmation_and_never_reinvokes_the_host() {
    let (state, database) = test_state();
    let name = "http-adapter-recovery";
    let plan = lifecycle_explore_plan(name);
    let change_id = seed_lifecycle(&state, &database, name, false, Some(plan), None);
    let initial = state.store.replay_lifecycle(&change_id).unwrap();
    let request = LifecyclePhaseAdapterRequest {
        schema: needle_runtime::LIFECYCLE_ADAPTER_REQUEST_SCHEMA.to_owned(),
        invocation_id: lifecycle_adapter_invocation_id(&initial),
        expected_state_digest: initial.state_digest,
        phase: initial.lifecycle.phase,
        profile: initial.lifecycle.spec.profiles.explore.clone(),
        remaining_budget: needle_runtime::LifecycleRemainingBudget {
            worker_turns: initial.lifecycle.spec.budget.max_worker_turns,
            output_tokens: initial.lifecycle.spec.budget.max_output_tokens,
            cost_microusd: initial.lifecycle.spec.budget.max_cost_microusd,
        },
        lifecycle: initial.lifecycle.clone(),
        change: state.store.lifecycle_change_context(&change_id).unwrap().unwrap(),
        repair_verification: None,
    };
    let adapter_definition = Digest::blake3(b"http-abandoned-adapter");
    assert_eq!(
        state.store.claim_lifecycle_adapter_invocation(&request, adapter_definition).unwrap(),
        needle_runtime::LifecycleAdapterInvocationClaim::Claimed
    );
    let app = test_router(state.clone());
    let inspection_path = format!("/api/v1/lifecycles/{change_id}/adapter-invocation");
    let recovery_path = format!("/api/v1/lifecycles/{change_id}/adapter-invocation/recover");
    let body = serde_json::json!({
        "invocation_id": request.invocation_id,
        "expected_state_digest": initial.state_digest,
        "confirm_provider_stopped": true,
    });

    assert_eq!(get(&app, &inspection_path, false).await.0, StatusCode::UNAUTHORIZED);
    let (status, inspected) = get(&app, &inspection_path, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected["schema"], ADAPTER_INVOCATION_SCHEMA);
    assert_eq!(inspected["invocation"]["status"], "in_progress");
    assert_eq!(inspected["invocation"]["invocation_id"], request.invocation_id.to_string());
    assert_eq!(inspected["invocation"]["expected_state_digest"], initial.state_digest.to_string());

    assert_eq!(
        post_json(&app, &recovery_path, false, false, body.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post_json(&app, &recovery_path, true, false, body.clone()).await.0,
        StatusCode::FORBIDDEN
    );
    let (status, confirmation) = post_json(
        &app,
        &recovery_path,
        true,
        true,
        serde_json::json!({
            "invocation_id": request.invocation_id,
            "expected_state_digest": initial.state_digest,
            "confirm_provider_stopped": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(confirmation["code"], "confirmation_required");
    assert_eq!(
        post_json(
            &app,
            &recovery_path,
            true,
            true,
            serde_json::json!({
                "invocation_id": request.invocation_id,
                "expected_state_digest": initial.state_digest,
                "confirm_provider_stopped": true,
                "unknown": true,
            }),
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );

    let guard = state.lifecycle_step_lock.clone().lock_owned().await;
    let (status, busy) = post_json(&app, &recovery_path, true, true, body.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(busy["code"], "lifecycle_step_busy");
    drop(guard);

    let (status, conflict) = post_json(
        &app,
        &recovery_path,
        true,
        true,
        serde_json::json!({
            "invocation_id": Digest::blake3(b"different-invocation"),
            "expected_state_digest": initial.state_digest,
            "confirm_provider_stopped": true,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(conflict["code"], "adapter_invocation_conflict");

    let (status, recovered) = post_json(&app, &recovery_path, true, true, body.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(recovered["schema"], ADAPTER_RECOVERY_SCHEMA);
    assert_eq!(recovered["created"], true);
    assert_eq!(recovered["invocation"]["status"], "aborted");
    assert_eq!(recovered["invocation"]["recovery"]["source"], "web_user");
    assert_eq!(recovered["lifecycle"]["status"], "failed");
    assert_eq!(recovered["lifecycle"]["generation"], 1);
    assert_eq!(recovered["lifecycle"]["terminal_reason"]["code"], "adapter_invocation_aborted");

    let (status, replay) = post_json(&app, &recovery_path, true, true, body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay["created"], false);
    assert_eq!(
        replay["invocation"]["recovery"]["recovery_digest"],
        recovered["invocation"]["recovery"]["recovery_digest"]
    );

    let (status, inspected) = get(&app, &inspection_path, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected["invocation"]["status"], "aborted");
    assert_eq!(
        state.store.replay_lifecycle(&change_id).unwrap().lifecycle.status,
        LifecycleStatus::Failed
    );

    drop(app);
    drop(state);
    std::fs::remove_file(database).unwrap();
}
