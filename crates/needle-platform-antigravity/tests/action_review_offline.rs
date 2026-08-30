use needle_core::{
    AcceptanceCoverage, AcceptanceStatus, ActionContractId, AgentHost, AllowedPath,
    AllowedPathScope, ArtifactId, CacheScope, ChangeActionInput, ChangeActionInvocation,
    ChangeRequest, CodexRole, CommandPolicy, DependencyManifest, Digest, EvidenceFailurePolicy,
    Facet, FallbackPolicy, FilesystemPolicy, LifecycleUsage, MultiNeedPolicy, NeedExecution,
    NeedExecutionEnvelopeV1, NeedIr, NeedKey, NetworkPolicy, ObligationExpression,
    PatchActionInputRef, PatchArtifact, PatchFile, PatchOperation, PredicateKind, ReasoningLevel,
    RepairPolicy, RoleProfileBudget, RoleProfileDefinition, RoleProfileDefinitionInput,
    RoleProfileId, RoleProfileProvenance, ServiceTier, SubjectExpression, SubjectKind, TestPolicy,
    ToolPolicy,
};
use needle_platform_antigravity::AntigravityChangeActionProvider;
use needle_runtime::{
    ActionExecutionService, ChangeActionOutput, ChangeActionProvider, ChangeActionProviderContext,
    ChangeActionProviderError, ChangeActionProviderOutput, PatchFileBlob, RuntimeSettings,
    RuntimeStore, capture_git_snapshot,
};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const SIMULATOR: &str = env!("CARGO_BIN_EXE_needle-sim-antigravity");

#[test]
fn standalone_review_is_isolated_persisted_and_idempotent() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let provenance = active_antigravity_reviewer(&store, 10, 1_200);
    let config = store.worker_config_for_provenance(&provenance, SIMULATOR).unwrap();
    let (_, snapshot) = capture_git_snapshot(&fixture.repository).unwrap();
    let record_path = fixture.root.join("review-invocations.txt");
    let change = ChangeRequest {
        task: format!("SIM_APPEND_RECORD:{}", record_path.display()),
        acceptance_criteria: vec!["src/lib.rs returns 43.".to_owned()],
        allowed_paths: vec![AllowedPath {
            path: "src/lib.rs".to_owned(),
            scope: AllowedPathScope::Exact,
        }],
        artifact_ids: Vec::new(),
        claim_ids: Vec::new(),
        constraints: vec!["Keep the active worktree unchanged.".to_owned()],
    };
    let requirements_digest = change.digest(snapshot.source_digest);
    let need = action_need();
    let patch_result = seed_patch(&store, &need, change.clone(), &snapshot);
    let ChangeActionOutput::PatchProposal(patch) = patch_result.output else { unreachable!() };
    let patch_ref = PatchActionInputRef {
        artifact: ArtifactId::new(patch_result.artifact.id),
        patch: patch.id,
    };
    assert_active_checkout_unchanged(&fixture.repository);

    let review_envelope = action_envelope(
        b"antigravity-review-operation",
        &need,
        ChangeActionInput::ReviewDiff {
            change_id: patch.change_id.clone(),
            requirements_digest,
            patch: patch_ref,
            prior_review_artifacts: Vec::new(),
        },
    );
    let provider =
        AntigravityChangeActionProvider::new(&fixture.data, &fixture.repository, config.clone());
    let service = ActionExecutionService::new(store.clone(), provider);
    let result = service
        .execute_action(&review_envelope, snapshot.repository_id, snapshot.source_digest)
        .unwrap();
    let ChangeActionOutput::Review(report) = &result.output else { unreachable!() };
    assert_eq!(report.verdict, needle_core::ReviewReportVerdict::Approved);
    assert_eq!(report.patch_id, patch.id);
    assert_eq!(report.requirements_digest, requirements_digest);
    assert!(report.findings.is_empty());
    assert!(
        report
            .acceptance_coverage
            .iter()
            .all(|coverage| { coverage.status == AcceptanceStatus::Addressed })
    );
    assert_eq!(result.usage.worker_turns, 1);
    assert_eq!(result.usage.output_tokens, 5);
    assert_eq!(
        result.host_usage,
        Some(needle_core::HostUsage {
            input_tokens: 10,
            output_tokens: 5,
            thinking_tokens: 2,
            cache_read_tokens: 3,
            total_tokens: 15,
        })
    );
    assert!(!result.idempotent_replay);
    assert!(store.semantic_artifact(&result.artifact.id.to_string()).unwrap().is_some());
    assert!(
        store
            .action_artifact_validation_certificate(result.validation_certificate)
            .unwrap()
            .is_some()
    );
    let manifest_id = result.partition_manifest.expect("review publishes a partition manifest");
    assert!(store.partition_manifest_publication(manifest_id).unwrap().is_some());
    assert_eq!(invocation_count(&record_path), 1);
    assert_active_checkout_unchanged(&fixture.repository);
    assert_directory_empty_or_absent(&fixture.data.join("antigravity-review-runs"));

    let replay = service
        .execute_action(&review_envelope, snapshot.repository_id, snapshot.source_digest)
        .unwrap();
    assert!(replay.idempotent_replay);
    assert_eq!(replay.artifact.id, result.artifact.id);
    assert_eq!(replay.host_usage, result.host_usage);
    assert_eq!(invocation_count(&record_path), 1);

    let unsupported = ActionExecutionService::new(
        store,
        AntigravityChangeActionProvider::new(
            &fixture.data,
            &fixture.repository,
            needle_core::WorkerConfig {
                executable: fixture.root.join("must-not-run.exe").display().to_string(),
                ..config
            },
        ),
    )
    .execute_action(
        &action_envelope(
            b"antigravity-unsupported-patch",
            &need,
            ChangeActionInput::PatchPropose {
                change,
                prior_patch: None,
                repair_verification: None,
            },
        ),
        snapshot.repository_id,
        snapshot.source_digest,
    )
    .unwrap_err();
    assert!(unsupported.to_string().contains("supports only needle.review.diff"));
    assert_directory_empty_or_absent(&fixture.data.join("antigravity-runs"));
}

#[test]
#[ignore = "requires one explicitly approved live Antigravity Review provider session"]
fn live_standalone_review_uses_one_turn_without_retry() {
    const APPROVAL: &str = "APPROVO_1_SESSIONE_ANTIGRAVITY_REVIEW_SENZA_TOKEN_CAP";
    const LIVE_MAX_OUTPUT_TOKENS: u32 = needle_core::HARD_RESULT_TOKENS as u32;
    assert_eq!(std::env::var("NEEDLE_AGY_REVIEW_LIVE_APPROVAL").as_deref(), Ok(APPROVAL));
    let executable = PathBuf::from(
        std::env::var("NEEDLE_AGY_EXECUTABLE").expect("NEEDLE_AGY_EXECUTABLE is required"),
    );
    let report_path = PathBuf::from(
        std::env::var("NEEDLE_AGY_REVIEW_LIVE_REPORT")
            .expect("NEEDLE_AGY_REVIEW_LIVE_REPORT is required"),
    );
    assert!(executable.is_file());
    assert!(!report_path.exists(), "live Review report must be append-only");

    let fixture = Fixture::new();
    let store = fixture.store();
    let provenance = active_antigravity_reviewer(&store, 180, LIVE_MAX_OUTPUT_TOKENS);
    let config =
        store.worker_config_for_provenance(&provenance, executable.display().to_string()).unwrap();
    let (_, before) = capture_git_snapshot(&fixture.repository).unwrap();
    let change = ChangeRequest {
        task: "Review the prepared change from 42 to 43 in the compact fixture.".to_owned(),
        acceptance_criteria: vec!["src/lib.rs returns 43.".to_owned()],
        allowed_paths: vec![AllowedPath {
            path: "src/lib.rs".to_owned(),
            scope: AllowedPathScope::Exact,
        }],
        artifact_ids: Vec::new(),
        claim_ids: Vec::new(),
        constraints: vec![
            "Review only the prepared patch and do not modify the repository.".to_owned(),
        ],
    };
    let requirements_digest = change.digest(before.source_digest);
    let need = action_need();
    let patch_result = seed_patch(&store, &need, change, &before);
    let ChangeActionOutput::PatchProposal(patch) = patch_result.output else { unreachable!() };
    let envelope = action_envelope(
        b"antigravity-review-live-operation",
        &need,
        ChangeActionInput::ReviewDiff {
            change_id: patch.change_id.clone(),
            requirements_digest,
            patch: PatchActionInputRef {
                artifact: ArtifactId::new(patch_result.artifact.id),
                patch: patch.id,
            },
            prior_review_artifacts: Vec::new(),
        },
    );
    let service = ActionExecutionService::new(
        store.clone(),
        AntigravityChangeActionProvider::new(&fixture.data, &fixture.repository, config),
    );
    let started = Instant::now();
    let outcome = service.execute_action(&envelope, before.repository_id, before.source_digest);
    let (_, after) = capture_git_snapshot(&fixture.repository).unwrap();
    let active_checkout_unchanged = before == after;
    let checkout_cleanup_completed =
        directory_empty_or_absent(&fixture.data.join("antigravity-review-runs"));
    let outcome_json = match &outcome {
        Ok(result) => json!({
            "status": "success",
            "operation_id": result.operation_id,
            "action_request_id": result.request.semantic_id(),
            "artifact_id": result.artifact.id,
            "validation_certificate_id": result.validation_certificate,
            "partition_manifest_id": result.partition_manifest,
            "usage": result.usage,
            "host_usage": result.host_usage,
            "authority": result.authority,
            "idempotent_replay": result.idempotent_replay,
            "output": result.output.to_value().unwrap(),
        }),
        Err(error) => json!({
            "status": "failed",
            "error": error.to_string(),
        }),
    };
    let report = json!({
        "schema": "needle.antigravity-review-accounting-live-smoke/1",
        "contract": "needle.review.diff",
        "model": "gemini-3.7-flash-medium",
        "reasoning": "medium",
        "maximum_provider_sessions": 1,
        "automatic_retries": 0,
        "profile_output_token_limit": LIVE_MAX_OUTPUT_TOKENS,
        "hard_output_token_limit_available": false,
        "host_usage_projected_to_action_result": true,
        "active_checkout_unchanged": active_checkout_unchanged,
        "checkout_cleanup_completed": checkout_cleanup_completed,
        "wall_time_ms": started.elapsed().as_millis(),
        "outcome": outcome_json,
    });
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&report_path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{}", serde_json::to_string(&report).unwrap());

    let result = outcome.unwrap_or_else(|error| {
        panic!("live Antigravity Review failed after writing {}: {error}", report_path.display())
    });
    let ChangeActionOutput::Review(review) = result.output else { unreachable!() };
    assert_eq!(review.verdict, needle_core::ReviewReportVerdict::Approved);
    assert_eq!(review.patch_id, patch.id);
    assert_eq!(review.requirements_digest, requirements_digest);
    assert_eq!(result.usage.worker_turns, 1);
    let host_usage = result.host_usage.expect("live Review must project exact host usage");
    assert_eq!(host_usage.output_tokens, result.usage.output_tokens);
    assert!(host_usage.output_tokens <= u64::from(LIVE_MAX_OUTPUT_TOKENS));
    assert!(!result.idempotent_replay);
    assert!(active_checkout_unchanged);
    assert!(checkout_cleanup_completed);
}

#[test]
fn standalone_review_does_not_publish_when_observed_usage_exceeds_profile_budget() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let provenance = active_antigravity_reviewer(&store, 10, 4);
    let config = store.worker_config_for_provenance(&provenance, SIMULATOR).unwrap();
    let (_, snapshot) = capture_git_snapshot(&fixture.repository).unwrap();
    let record_path = fixture.root.join("over-budget-invocations.txt");
    let change = ChangeRequest {
        task: format!("SIM_APPEND_RECORD:{}", record_path.display()),
        acceptance_criteria: vec!["src/lib.rs returns 43.".to_owned()],
        allowed_paths: vec![AllowedPath {
            path: "src/lib.rs".to_owned(),
            scope: AllowedPathScope::Exact,
        }],
        artifact_ids: Vec::new(),
        claim_ids: Vec::new(),
        constraints: Vec::new(),
    };
    let requirements_digest = change.digest(snapshot.source_digest);
    let need = action_need();
    let patch_result = seed_patch(&store, &need, change, &snapshot);
    let ChangeActionOutput::PatchProposal(patch) = patch_result.output else { unreachable!() };
    let envelope = action_envelope(
        b"antigravity-review-over-budget",
        &need,
        ChangeActionInput::ReviewDiff {
            change_id: patch.change_id,
            requirements_digest,
            patch: PatchActionInputRef {
                artifact: ArtifactId::new(patch_result.artifact.id),
                patch: patch.id,
            },
            prior_review_artifacts: Vec::new(),
        },
    );
    let error = ActionExecutionService::new(
        store.clone(),
        AntigravityChangeActionProvider::new(&fixture.data, &fixture.repository, config),
    )
    .execute_action(&envelope, snapshot.repository_id, snapshot.source_digest)
    .unwrap_err();
    assert!(error.to_string().contains("exceeded the frozen role-profile budget"));
    assert_eq!(invocation_count(&record_path), 1);
    assert!(store.list_partition_manifest_summaries(1).unwrap().is_empty());
    assert_active_checkout_unchanged(&fixture.repository);
    assert_directory_empty_or_absent(&fixture.data.join("antigravity-review-runs"));
}

fn seed_patch(
    store: &RuntimeStore,
    need: &NeedIr,
    change: ChangeRequest,
    snapshot: &needle_core::RepositorySnapshot,
) -> needle_runtime::ActionExecutionResult {
    let seed = ActionExecutionService::new(
        store.clone(),
        SeedPatchProvider {
            store: store.clone(),
            before: b"pub fn answer() -> u8 { 42 }\n".to_vec(),
            after: b"pub fn answer() -> u8 { 43 }\n".to_vec(),
        },
    );
    seed.execute_action(
        &action_envelope(
            b"antigravity-review-seed",
            need,
            ChangeActionInput::PatchPropose {
                change,
                prior_patch: None,
                repair_verification: None,
            },
        ),
        snapshot.repository_id,
        snapshot.source_digest,
    )
    .unwrap()
}

struct SeedPatchProvider {
    store: RuntimeStore,
    before: Vec<u8>,
    after: Vec<u8>,
}

impl ChangeActionProvider for SeedPatchProvider {
    fn execute(
        &self,
        context: ChangeActionProviderContext<'_>,
    ) -> Result<ChangeActionProviderOutput, ChangeActionProviderError> {
        let ChangeActionInput::PatchPropose { change, .. } = context.input else {
            return Err(ChangeActionProviderError::new("seed provider accepts only PatchPropose"));
        };
        let source = context.request.artifact_request.source_snapshot_digest;
        let file = PatchFile {
            path: "src/lib.rs".to_owned(),
            operation: PatchOperation::Update,
            before_digest: Some(Digest::blake3(&self.before)),
            after_digest: Some(Digest::blake3(&self.after)),
            before_bytes: self.before.len() as u64,
            after_bytes: self.after.len() as u64,
        };
        let files = vec![file];
        let declared = json!({"summary": "offline seeded patch"});
        let patch = PatchArtifact {
            id: PatchArtifact::compute_id(source, &files),
            change_id: context.input.change_id(source),
            revision: 1,
            source_snapshot: source,
            files,
            summary: "Update the fixture return value.".to_owned(),
            acceptance_coverage: change
                .acceptance_criteria
                .iter()
                .map(|criterion| AcceptanceCoverage {
                    criterion: criterion.clone(),
                    status: AcceptanceStatus::Addressed,
                    evidence: "offline seeded patch updates src/lib.rs".to_owned(),
                })
                .collect(),
            residual_risks: Vec::new(),
            declared_output_digest: Digest::blake3(
                serde_json::to_vec(&declared).expect("declared patch output serializes"),
            ),
            discrepancies: Vec::new(),
        };
        self.store
            .record_prepared_change(
                context.request.artifact_request.repository_id,
                change.digest(source),
                change,
                &patch,
                &declared,
                &[PatchFileBlob {
                    path: "src/lib.rs".to_owned(),
                    before: Some(self.before.clone()),
                    after: Some(self.after.clone()),
                }],
            )
            .map_err(|error| ChangeActionProviderError::new(error.to_string()))?;
        Ok(ChangeActionProviderOutput {
            output: ChangeActionOutput::PatchProposal(patch),
            world: context.need.world.clone(),
            dependency_manifest: DependencyManifest {
                scope: CacheScope::SnapshotExact,
                observed_files_complete: true,
                dependencies: Vec::new(),
                gaps: Vec::new(),
            },
            review_manifest: None,
            review_transition: None,
            usage: LifecycleUsage { worker_turns: 0, output_tokens: 0, cost_microusd: 0 },
            host_usage: None,
        })
    }
}

fn active_antigravity_reviewer(
    store: &RuntimeStore,
    timeout_seconds: u64,
    max_output_tokens: u32,
) -> RoleProfileProvenance {
    let definition = RoleProfileDefinition::new(RoleProfileDefinitionInput {
        profile_id: RoleProfileId::new("offline.antigravity-reviewer").unwrap(),
        role: CodexRole::Reviewer,
        host: AgentHost::Antigravity,
        model: "gemini-3.7-flash-medium".to_owned(),
        reasoning: ReasoningLevel::Medium,
        service_tier: ServiceTier::Default,
        timeout_seconds,
        budget: RoleProfileBudget { max_turns: 1, max_output_tokens, max_cost_microusd: 10_000 },
        prompt_profile_digest: Digest::blake3(b"offline-antigravity-review-prompt"),
        output_contract_digest: Digest::blake3(b"offline-antigravity-review-output"),
        tool_policy: ToolPolicy::ReadOnly,
        command_policy: CommandPolicy::Denied,
        filesystem_policy: FilesystemPolicy::ReadOnlyCheckout,
        network_policy: NetworkPolicy::Denied,
        test_policy: TestPolicy::Disabled,
        repair_policy: RepairPolicy::None,
        fallback_policy: FallbackPolicy::Disabled,
        concurrency: 1,
        route_assignments: Vec::new(),
    })
    .unwrap();
    let revision = store.create_role_profile(definition).unwrap();
    let state = store.role_profile_state(&revision.profile_id).unwrap();
    let active = store
        .activate_role_profile(&revision.profile_id, revision.revision, state.state_digest)
        .unwrap();
    RoleProfileProvenance::from_revision(&active).unwrap()
}

fn action_envelope(
    label: &[u8],
    need: &NeedIr,
    input: ChangeActionInput,
) -> NeedExecutionEnvelopeV1 {
    NeedExecutionEnvelopeV1::new(
        Digest::blake3(label),
        need.clone(),
        NeedExecution::Action {
            action: ChangeActionInvocation {
                contract: ActionContractId::new(input.contract_id()).unwrap(),
                input,
            },
        },
    )
}

fn action_need() -> NeedIr {
    NeedIr {
        route_hint: Some(NeedKey::new("locate.implementation").unwrap()),
        subjects: vec![SubjectExpression {
            kind: SubjectKind::Symbol,
            canonical_name: "answer".to_owned(),
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
        body: "Review the bounded fixture change.".to_owned(),
        format_revision: needle_core::NEED_IR_FORMAT_REVISION,
    }
}

struct Fixture {
    root: PathBuf,
    repository: PathBuf,
    data: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir()
            .join(format!("needle-antigravity-action-review-{}-{suffix}", std::process::id()));
        let repository = root.join("repository");
        let data = root.join("data");
        fs::create_dir_all(repository.join("src")).unwrap();
        fs::create_dir_all(&data).unwrap();
        git(&repository, &["init", "--quiet"]);
        git(&repository, &["config", "user.email", "needle@example.invalid"]);
        git(&repository, &["config", "user.name", "Needle Fixture"]);
        fs::write(repository.join("src/lib.rs"), "pub fn answer() -> u8 { 42 }\n").unwrap();
        git(&repository, &["add", "src/lib.rs"]);
        git(&repository, &["commit", "--quiet", "-m", "fixture"]);
        Self { root, repository, data }
    }

    fn store(&self) -> RuntimeStore {
        let store = RuntimeStore::new(self.data.join("needle.sqlite3"));
        store
            .initialize_defaults(&RuntimeSettings {
                codex_executable: "codex".to_owned(),
                worker_model: "gpt-5.6-luna".to_owned(),
                worker_reasoning: "medium".to_owned(),
                worker_timeout_seconds: 10,
                evidence_failure_policy: EvidenceFailurePolicy::DiscardInvalidFact,
                trusted_test_execution: false,
                multi_need_policy: MultiNeedPolicy::default(),
            })
            .unwrap();
        store
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn invocation_count(path: &Path) -> usize {
    fs::read_to_string(path).unwrap().lines().count()
}

fn assert_active_checkout_unchanged(repository: &Path) {
    assert_eq!(
        fs::read_to_string(repository.join("src/lib.rs")).unwrap(),
        "pub fn answer() -> u8 { 42 }\n"
    );
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["status", "--porcelain"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
}

fn assert_directory_empty_or_absent(path: &Path) {
    assert!(directory_empty_or_absent(path), "{} is not empty", path.display());
}

fn directory_empty_or_absent(path: &Path) -> bool {
    !path.exists() || fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_none())
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
