use super::*;
use needle_bench::{
    ReviewChangeImpactEvidenceClass, ReviewChangeImpactGateCampaign, ReviewChangeImpactGateCase,
    evaluate_review_change_impact_gate,
};
use needle_core::{
    ActionRequest, AllowedPath, AllowedPathScope, ArtifactId, ArtifactRequest, ChangeActionInput,
    ChangeRequest, DependencyLocator, ManifestProvenance, ManifestTransition, NeedFragmentId,
    NeedId, NeedKey, PartitionKeyMapping, PartitionRef, PatchActionInputRef, PatchArtifact,
    PatchFile, PatchOperation, RepositoryContextId, ReviewReport, SemanticWorld,
};
use needle_runtime::{
    PatchFileBlob, RuntimeStore, ShadowManifestContext, built_in_action_contracts,
    built_in_partition_for_action, derive_review_shadow_manifest, review_finding_partition_key,
};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::process::Command;

const EXECUTION_CONFIRMATION: &str = "I_ACCEPT_6_PROVIDER_REVIEW_CALLS";
const DEFINITION_SET: &[u8] = b"needle-review-change-impact-gate-a6-live-v1";
const MAX_LIVE_OUTPUT_ROOT_UTF8_BYTES: usize = 96;
const MAX_FAILED_RUN_DIAGNOSTIC_BYTES: usize = 2_048;
const LIVE_STAGES: [&str; 3] = ["prior", "refresh", "full"];

#[derive(Clone, Copy)]
struct FixtureFile {
    path: &'static str,
    base: &'static str,
    prior: Option<&'static str>,
    current: Option<&'static str>,
}

struct FixtureDefinition {
    id: &'static str,
    ecosystem: &'static str,
    files: &'static [FixtureFile],
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedRunMetadata {
    schema: &'static str,
    provider_calls: u16,
    codex_version: String,
    model: String,
    reasoning: String,
    service_tier: Option<String>,
    campaign_digest: Digest,
    gate_passed: bool,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedProviderObservation<'a> {
    schema: &'static str,
    stage: &'static str,
    verdict: ReviewReportVerdict,
    acceptance_coverage: &'a [ReviewCoverage],
    findings: &'a [ReviewFinding],
    reviewer_definition: Digest,
    dependency_digest: Digest,
    provider_observation_digest: Digest,
    inspection_context_digest: Option<Digest>,
    inspection_coverage: &'a [ReviewInspectionCoverage],
    created_unix_ms: u64,
    output_tokens: Option<u64>,
    worker_turns: u32,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedStageRecords<'a> {
    schema: &'static str,
    stage: &'static str,
    report: &'a ReviewReport,
    manifest: &'a needle_core::PartitionManifest,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct FailedRunMetadata {
    schema: &'static str,
    fixture: String,
    diagnostic: String,
    completed_provider_calls: u16,
    normalized_provider_observations: u16,
    failed_provider_output_tokens: Option<u64>,
}

struct GateA6FixtureError {
    diagnostic: String,
    provider_turn_completed: bool,
    output_tokens: Option<u64>,
}

impl GateA6FixtureError {
    fn review(stage: &str, error: ReviewRunError) -> Self {
        Self {
            diagnostic: format!("{stage} review failed: {}", error.diagnostic),
            provider_turn_completed: error.provider_turn_completed,
            output_tokens: error.output_tokens,
        }
    }
}

impl From<String> for GateA6FixtureError {
    fn from(diagnostic: String) -> Self {
        Self { diagnostic, provider_turn_completed: false, output_tokens: None }
    }
}

impl std::fmt::Display for GateA6FixtureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.diagnostic)
    }
}

const RUST_FILES: &[FixtureFile] = &[
    FixtureFile {
        path: "src/changed.rs",
        base: "pub fn divide(left: i32, right: i32) -> i32 { left / right }\n",
        prior: Some("pub fn divide(left: i32, right: i32) -> i32 { left * right }\n"),
        current: None,
    },
    FixtureFile {
        path: "src/stable.rs",
        base: "pub fn is_even(value: i32) -> bool { value % 2 == 0 }\n",
        prior: Some("pub fn is_even(_value: i32) -> bool { true }\n"),
        current: Some("pub fn is_even(_value: i32) -> bool { true }\n"),
    },
    FixtureFile {
        path: "src/new.rs",
        base: "pub fn average(left: i32, right: i32) -> i32 { (left + right) / 2 }\n",
        prior: None,
        current: Some("pub fn average(left: i32, right: i32) -> i32 { left + right }\n"),
    },
    FixtureFile {
        path: "src/lib.rs",
        base: "pub mod changed;\npub mod new;\npub mod stable;\n",
        prior: None,
        current: None,
    },
];

const JAVASCRIPT_FILES: &[FixtureFile] = &[
    FixtureFile {
        path: "src/changed.js",
        base: "export function clamp(value, min, max) { return Math.min(max, Math.max(min, value)); }\n",
        prior: Some("export function clamp(value, _min, _max) { return value; }\n"),
        current: None,
    },
    FixtureFile {
        path: "src/stable.js",
        base: "export function isEven(value) { return value % 2 === 0; }\n",
        prior: Some("export function isEven(_value) { return true; }\n"),
        current: Some("export function isEven(_value) { return true; }\n"),
    },
    FixtureFile {
        path: "src/new.js",
        base: "export function average(left, right) { return (left + right) / 2; }\n",
        prior: None,
        current: Some("export function average(left, right) { return left + right; }\n"),
    },
    FixtureFile {
        path: "package.json",
        base: "{\"name\":\"needle-gate-a6-js\",\"private\":true,\"type\":\"module\"}\n",
        prior: None,
        current: None,
    },
];

#[test]
fn zero_provider_gate_a6_preflight_exercises_the_complete_typed_campaign() {
    let fixtures = [
        FixtureDefinition {
            id: "javascript-review-refresh",
            ecosystem: "javascript",
            files: JAVASCRIPT_FILES,
        },
        FixtureDefinition { id: "rust-review-refresh", ecosystem: "rust", files: RUST_FILES },
    ];
    for fixture in &fixtures {
        live_storage_preflight(fixture).unwrap();
    }
    let cases = fixtures.iter().map(synthetic_gate_case).collect::<Vec<_>>();
    let campaign =
        ReviewChangeImpactGateCampaign::new(ReviewChangeImpactEvidenceClass::Synthetic, cases)
            .unwrap();
    let report = evaluate_review_change_impact_gate(&campaign).unwrap();

    assert_eq!(campaign.cases.len(), 2);
    assert!(campaign.cases.iter().all(|case| case.transition.mappings.len() == 1));
    assert!(campaign.cases.iter().all(|case| case.invalidated_prior_partition_keys.len() == 1));
    assert!(report.language_agnostic_fixture_coverage);
    assert!(report.cases.iter().all(|case| case.passed));
    assert!(!report.gate_eligible);
    assert!(!report.passed);
}

fn live_storage_preflight(fixture: &FixtureDefinition) -> Result<(), String> {
    let temporary_root = env::temp_dir();
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let root = temporary_root
        .join(format!("needle-gate-a6-storage-preflight-{}-{nonce}", std::process::id()));
    if root.exists() || root.parent() != Some(temporary_root.as_path()) {
        return Err("Gate A6 storage preflight root is unsafe".to_owned());
    }
    let outcome = (|| {
        let repository = root.join("repository");
        initialize_repository(&repository, fixture.files);
        let (_, snapshot) = capture_git_snapshot(&repository)
            .map_err(|error| format!("cannot snapshot Gate A6 preflight repository: {error}"))?;
        let request = change_request();
        let requirements_digest = request.digest(snapshot.source_digest);
        let change_id = ChangeId::from_digest(requirements_digest);
        let prior_patch = patch(&change_id, snapshot.source_digest, 1, fixture.files, false);
        let current_patch = patch(&change_id, snapshot.source_digest, 1, fixture.files, true);
        prepare_store(
            &root.join("prior-data"),
            snapshot.repository_id,
            requirements_digest,
            &request,
            &prior_patch,
            fixture.files,
            false,
        )?;
        prepare_store(
            &root.join("current-data"),
            snapshot.repository_id,
            requirements_digest,
            &request,
            &current_patch,
            fixture.files,
            true,
        )?;
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&root)
        .map_err(|error| format!("cannot clean Gate A6 storage preflight: {error}"));
    match (outcome, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; {cleanup}")),
    }
}

#[test]
fn live_output_root_preflight_rejects_relative_and_long_paths() {
    assert!(validate_live_output_root(Path::new("relative-a6")).is_err());
    let short = if cfg!(windows) { PathBuf::from(r"C:\a6") } else { PathBuf::from("/tmp/a6") };
    assert_eq!(validate_live_output_root(&short), Ok(()));
    let long = short.join("x".repeat(MAX_LIVE_OUTPUT_ROOT_UTF8_BYTES));
    assert!(validate_live_output_root(&long).is_err());
}

fn synthetic_gate_case(fixture: &FixtureDefinition) -> ReviewChangeImpactGateCase {
    let repository_id = Digest::blake3(format!("{}:synthetic-repository", fixture.id));
    let source_snapshot = Digest::blake3(format!("{}:synthetic-source", fixture.id));
    let request = change_request();
    let requirements_digest = request.digest(source_snapshot);
    let change_id = ChangeId::from_digest(requirements_digest);
    let prior_patch = patch(&change_id, source_snapshot, 1, fixture.files, false);
    let current_patch = patch(&change_id, source_snapshot, 1, fixture.files, true);
    let world = semantic_world(repository_id);

    let prior_request = action_request(
        fixture.id,
        "prior",
        &request,
        &change_id,
        requirements_digest,
        &prior_patch,
        Vec::new(),
        repository_id,
        source_snapshot,
    );
    let prior = synthetic_review_output(
        fixture,
        "prior",
        100,
        prior_response(fixture, &request),
        &request,
        None,
    );
    let (prior_report, prior_manifest) = report_and_manifest(
        &prior_request,
        &world,
        &change_id,
        requirements_digest,
        &prior_patch,
        &prior,
    )
    .unwrap();

    let advisory = refresh_advisory(
        repository_id,
        fixture.id,
        &prior_patch,
        &current_patch,
        &prior_report,
        &prior_manifest,
    );
    assert_eq!(advisory.retained_findings.len(), 1);
    assert_eq!(advisory.invalidated_partition_keys.len(), 1);
    let state_delta = advisory.state_delta.clone();
    let refresh = synthetic_review_output(
        fixture,
        "refresh",
        200,
        refresh_response(fixture, &request, &advisory),
        &request,
        Some(&advisory),
    );
    assert_eq!(refresh.findings.len(), 2, "exact duplicate must be canonicalized once");
    let prior_artifact = ArtifactId::new(prior_report.id);
    let refresh_request = action_request(
        fixture.id,
        "refresh",
        &request,
        &change_id,
        requirements_digest,
        &current_patch,
        vec![prior_artifact],
        repository_id,
        source_snapshot,
    );
    let (refresh_report, refresh_manifest) = report_and_manifest(
        &refresh_request,
        &world,
        &change_id,
        requirements_digest,
        &current_patch,
        &refresh,
    )
    .unwrap();

    let full = synthetic_review_output(
        fixture,
        "full",
        300,
        full_response(fixture, &request),
        &request,
        None,
    );
    let full_request = action_request(
        fixture.id,
        "full",
        &request,
        &change_id,
        requirements_digest,
        &current_patch,
        Vec::new(),
        repository_id,
        source_snapshot,
    );
    let (full_report, full_manifest) = report_and_manifest(
        &full_request,
        &world,
        &change_id,
        requirements_digest,
        &current_patch,
        &full,
    )
    .unwrap();
    let (transition, invalidated_prior_partition_keys) = transition(
        &prior_manifest,
        &refresh_manifest,
        &state_delta,
        refresh.provider_observation_digest,
    )
    .unwrap();

    ReviewChangeImpactGateCase {
        id: fixture.id.to_owned(),
        ecosystem: fixture.ecosystem.to_owned(),
        state_delta,
        prior_report,
        refresh_report,
        full_report,
        prior_manifest,
        refresh_manifest,
        full_manifest,
        transition,
        invalidated_prior_partition_keys,
        prior_execution_digest: prior.provider_observation_digest,
        refresh_execution_digest: refresh.provider_observation_digest,
        full_execution_digest: full.provider_observation_digest,
    }
}

fn synthetic_review_output(
    fixture: &FixtureDefinition,
    stage: &'static str,
    created_unix_ms: u64,
    response: serde_json::Value,
    request: &ChangeRequest,
    advisory: Option<&ReviewRefreshAdvisory>,
) -> ReviewRunOutput {
    let normalized = normalize_review_turn(
        Ok(crate::app_server::AppServerTurn {
            response,
            input_tokens: Some(1),
            cached_input_tokens: Some(0),
            output_tokens: Some(1),
            approval_wait: std::time::Duration::ZERO,
            command_evidence: Vec::new(),
            test_evidence: Vec::new(),
            observation_trace: Default::default(),
            file_change_approvals_granted: 0,
        }),
        request,
        advisory,
    )
    .unwrap();
    let provider_observation_digest =
        Digest::blake3(format!("{}:{stage}:synthetic-provider-observation", fixture.id));
    ReviewRunOutput {
        verdict: normalized.verdict,
        acceptance_coverage: normalized.acceptance_coverage,
        findings: normalized.findings,
        reviewer_definition: Digest::blake3("gate-a6-synthetic-reviewer-definition-v1"),
        dependency_digest: Digest::blake3(format!(
            "{}:{stage}:{}",
            fixture.id, normalized.response_digest
        )),
        provider_observation_digest,
        inspection_context_digest: normalized.inspection_context_digest,
        inspection_coverage: normalized.inspection_coverage,
        created_unix_ms,
        output_tokens: normalized.output_tokens,
        worker_turns: 1,
    }
}

fn prior_response(fixture: &FixtureDefinition, request: &ChangeRequest) -> serde_json::Value {
    review_response(
        request,
        vec![
            new_finding(
                "stable.unconditional",
                fixture.files[1].path,
                "The stable function returns a constant.",
                "The changed body ignores its input.",
            ),
            new_finding(
                "changed.incorrect",
                fixture.files[0].path,
                "The changed function violates its mathematical contract.",
                "The implementation no longer computes the documented result.",
            ),
        ],
    )
}

fn refresh_response(
    fixture: &FixtureDefinition,
    request: &ChangeRequest,
    advisory: &ReviewRefreshAdvisory,
) -> serde_json::Value {
    let inspection_results = advisory
        .inspection_targets
        .iter()
        .map(|target| match target.kind {
            ReviewInspectionTargetKind::RetainedFinding => json!({
                "target_id": target.id,
                "outcome": "still_valid",
                "evidence": "The retained defect remains present in the current source."
            }),
            ReviewInspectionTargetKind::ChangedPath if target.path == fixture.files[2].path => {
                json!({
                    "target_id": target.id,
                    "outcome": "findings",
                    "evidence": "The newly added path contains a contract violation.",
                    "findings": [new_finding(
                        "new.incorrect",
                        fixture.files[2].path,
                        "The new function violates its mathematical contract.",
                        "The implementation omits the required operation.",
                    )]
                })
            }
            ReviewInspectionTargetKind::ChangedPath => json!({
                "target_id": target.id,
                "outcome": "clean",
                "evidence": "The prior defect is absent from the changed path."
            }),
        })
        .collect::<Vec<_>>();
    let acceptance_coverage = request
        .acceptance_criteria
        .iter()
        .map(|criterion| {
            json!({
                "criterion": criterion,
                "status": "unaddressed",
                "evidence": "At least one reported defect prevents acceptance."
            })
        })
        .collect::<Vec<_>>();
    json!({
        "verdict": "rejected",
        "acceptance_coverage": acceptance_coverage,
        "inspection_results": inspection_results
    })
}

fn full_response(fixture: &FixtureDefinition, request: &ChangeRequest) -> serde_json::Value {
    review_response(
        request,
        vec![
            new_finding(
                "oracle.stable",
                fixture.files[1].path,
                "Independent review found the unchanged defect.",
                "The function is unconditional.",
            ),
            new_finding(
                "oracle.new",
                fixture.files[2].path,
                "Independent review found the newly introduced defect.",
                "The result differs from the documented formula.",
            ),
        ],
    )
}

fn review_response(request: &ChangeRequest, findings: Vec<serde_json::Value>) -> serde_json::Value {
    let acceptance_coverage = request
        .acceptance_criteria
        .iter()
        .map(|criterion| {
            json!({
                "criterion": criterion,
                "status": "unaddressed",
                "evidence": "At least one reported defect prevents acceptance."
            })
        })
        .collect::<Vec<_>>();
    json!({
        "verdict": "rejected",
        "acceptance_coverage": acceptance_coverage,
        "findings": findings
    })
}

fn new_finding(rule: &str, path: &str, message: &str, evidence: &str) -> serde_json::Value {
    json!({
        "kind": "new",
        "rule": rule,
        "severity": "error",
        "path": path,
        "line": 1,
        "message": message,
        "evidence": evidence
    })
}

#[test]
#[ignore = "requires the explicit six-call provider confirmation and an authenticated Codex CLI"]
fn provider_backed_review_refresh_is_noninferior_across_two_opaque_ecosystems() {
    assert_eq!(required_env("NEEDLE_GATE_A6_EXECUTE_PROVIDER"), EXECUTION_CONFIRMATION);
    let output_root = PathBuf::from(required_env("NEEDLE_GATE_A6_OUTPUT_DIR"));
    validate_live_output_root(&output_root).unwrap();
    assert!(!output_root.exists(), "Gate A6 output directory must be new");

    let executable = required_env("NEEDLE_GATE_A6_CODEX");
    let model = required_env("NEEDLE_GATE_A6_MODEL");
    let reasoning = required_env("NEEDLE_GATE_A6_REASONING");
    let service_tier = env::var("NEEDLE_GATE_A6_SERVICE_TIER").ok();
    let timeout_seconds = env::var("NEEDLE_GATE_A6_TIMEOUT_SECONDS")
        .ok()
        .map(|value| value.parse::<u64>().expect("invalid Gate A6 timeout"))
        .unwrap_or(300);
    let config = WorkerConfig {
        executable: executable.clone(),
        model: model.clone(),
        reasoning: reasoning.clone(),
        service_tier: service_tier.clone(),
        timeout_seconds,
        max_turns: 2,
        evidence_failure_policy: needle_core::EvidenceFailurePolicy::DiscardInvalidFact,
        role_profile_provenance: None,
    };
    let isolation = CodexWorker::verify_isolation(&executable).unwrap();
    assert!(isolation.verified(), "Codex isolation is not verified");
    let codex_home =
        DedicatedCodexHome::new(Path::new(&required_env("NEEDLE_GATE_A6_AUTH_SOURCE")));
    fs::create_dir_all(&output_root).unwrap();

    let fixtures = [
        FixtureDefinition {
            id: "javascript-review-refresh",
            ecosystem: "javascript",
            files: JAVASCRIPT_FILES,
        },
        FixtureDefinition { id: "rust-review-refresh", ecosystem: "rust", files: RUST_FILES },
    ];
    let mut cases = Vec::with_capacity(fixtures.len());
    for fixture in &fixtures {
        match run_fixture(&output_root, fixture, &config, codex_home.path()) {
            Ok(case) => cases.push(case),
            Err(error) => {
                let normalized_provider_observations =
                    completed_provider_calls(&output_root, &fixtures);
                let failed = FailedRunMetadata {
                    schema: "needle.review-change-impact-gate-a6-failed-run/2",
                    fixture: fixture.id.to_owned(),
                    diagnostic: bounded_diagnostic(&error.diagnostic),
                    completed_provider_calls: normalized_provider_observations
                        .saturating_add(u16::from(error.provider_turn_completed)),
                    normalized_provider_observations,
                    failed_provider_output_tokens: error.output_tokens,
                };
                fs::write(
                    output_root.join("failed-run.json"),
                    serde_json::to_vec_pretty(&failed).unwrap(),
                )
                .unwrap();
                panic!("Gate A6 fixture `{}` failed: {error}", fixture.id);
            }
        }
    }
    let campaign =
        ReviewChangeImpactGateCampaign::new(ReviewChangeImpactEvidenceClass::ProviderBacked, cases)
            .unwrap();
    let report = evaluate_review_change_impact_gate(&campaign).unwrap();
    fs::write(output_root.join("campaign.json"), serde_json::to_vec_pretty(&campaign).unwrap())
        .unwrap();
    fs::write(output_root.join("report.json"), serde_json::to_vec_pretty(&report).unwrap())
        .unwrap();
    let metadata = RetainedRunMetadata {
        schema: "needle.review-change-impact-gate-a6-live-run/1",
        provider_calls: 6,
        codex_version: isolation.codex_version,
        model,
        reasoning,
        service_tier,
        campaign_digest: campaign.campaign_digest,
        gate_passed: report.passed,
    };
    fs::write(output_root.join("run.json"), serde_json::to_vec_pretty(&metadata).unwrap()).unwrap();
    assert!(report.passed, "Gate A6 failed: {:#?}", report.cases);
}

fn run_fixture(
    output_root: &Path,
    fixture: &FixtureDefinition,
    config: &WorkerConfig,
    codex_home: &Path,
) -> Result<ReviewChangeImpactGateCase, GateA6FixtureError> {
    let fixture_root = output_root.join(fixture.id);
    let repository = fixture_root.join("repository");
    initialize_repository(&repository, fixture.files);
    let (_, snapshot) = capture_git_snapshot(&repository).unwrap();
    let request = change_request();
    let requirements_digest = request.digest(snapshot.source_digest);
    let change_id = ChangeId::from_digest(requirements_digest);
    let prior_patch = patch(&change_id, snapshot.source_digest, 1, fixture.files, false);
    let current_patch = patch(&change_id, snapshot.source_digest, 1, fixture.files, true);

    let prior_data = fixture_root.join("prior-data");
    prepare_store(
        &prior_data,
        snapshot.repository_id,
        requirements_digest,
        &request,
        &prior_patch,
        fixture.files,
        false,
    )?;
    let current_data = fixture_root.join("current-data");
    prepare_store(
        &current_data,
        snapshot.repository_id,
        requirements_digest,
        &request,
        &current_patch,
        fixture.files,
        true,
    )?;
    let prior = review(
        &prior_data,
        codex_home,
        ReviewActionRequest {
            config,
            repository_root: &repository,
            change_id: &change_id,
            requirements_digest,
            patch_id: prior_patch.id,
            source_snapshot: prior_patch.source_snapshot,
            advisory: None,
        },
    )
    .map_err(|error| GateA6FixtureError::review("prior", error))?;
    write_provider_observation(&fixture_root, "prior", &prior)?;
    let world = semantic_world(snapshot.repository_id);
    let prior_request = action_request(
        fixture.id,
        "prior",
        &request,
        &change_id,
        requirements_digest,
        &prior_patch,
        Vec::new(),
        snapshot.repository_id,
        snapshot.source_digest,
    );
    let (prior_report, prior_manifest) = report_and_manifest(
        &prior_request,
        &world,
        &change_id,
        requirements_digest,
        &prior_patch,
        &prior,
    )?;
    write_stage_records(&fixture_root, "prior", &prior_report, &prior_manifest)?;

    let advisory = refresh_advisory(
        snapshot.repository_id,
        fixture.id,
        &prior_patch,
        &current_patch,
        &prior_report,
        &prior_manifest,
    );
    let state_delta = advisory.state_delta.clone();
    let refresh = review(
        &current_data,
        codex_home,
        ReviewActionRequest {
            config,
            repository_root: &repository,
            change_id: &change_id,
            requirements_digest,
            patch_id: current_patch.id,
            source_snapshot: current_patch.source_snapshot,
            advisory: Some(&advisory),
        },
    )
    .map_err(|error| GateA6FixtureError::review("refresh", error))?;
    write_provider_observation(&fixture_root, "refresh", &refresh)?;
    let prior_artifact = ArtifactId::new(prior_report.id);
    let refresh_request = action_request(
        fixture.id,
        "refresh",
        &request,
        &change_id,
        requirements_digest,
        &current_patch,
        vec![prior_artifact],
        snapshot.repository_id,
        snapshot.source_digest,
    );
    let (refresh_report, refresh_manifest) = report_and_manifest(
        &refresh_request,
        &world,
        &change_id,
        requirements_digest,
        &current_patch,
        &refresh,
    )?;
    write_stage_records(&fixture_root, "refresh", &refresh_report, &refresh_manifest)?;

    let full = review(
        &current_data,
        codex_home,
        ReviewActionRequest {
            config,
            repository_root: &repository,
            change_id: &change_id,
            requirements_digest,
            patch_id: current_patch.id,
            source_snapshot: current_patch.source_snapshot,
            advisory: None,
        },
    )
    .map_err(|error| GateA6FixtureError::review("full", error))?;
    write_provider_observation(&fixture_root, "full", &full)?;
    let full_request = action_request(
        fixture.id,
        "full",
        &request,
        &change_id,
        requirements_digest,
        &current_patch,
        Vec::new(),
        snapshot.repository_id,
        snapshot.source_digest,
    );
    let (full_report, full_manifest) = report_and_manifest(
        &full_request,
        &world,
        &change_id,
        requirements_digest,
        &current_patch,
        &full,
    )?;
    write_stage_records(&fixture_root, "full", &full_report, &full_manifest)?;
    let (transition, invalidated_prior_partition_keys) = transition(
        &prior_manifest,
        &refresh_manifest,
        &state_delta,
        refresh.provider_observation_digest,
    )?;
    Ok(ReviewChangeImpactGateCase {
        id: fixture.id.to_owned(),
        ecosystem: fixture.ecosystem.to_owned(),
        state_delta,
        prior_report,
        refresh_report,
        full_report,
        prior_manifest,
        refresh_manifest,
        full_manifest,
        transition,
        invalidated_prior_partition_keys,
        prior_execution_digest: prior.provider_observation_digest,
        refresh_execution_digest: refresh.provider_observation_digest,
        full_execution_digest: full.provider_observation_digest,
    })
}

fn review(
    data: &Path,
    codex_home: &Path,
    request: ReviewActionRequest<'_>,
) -> Result<ReviewRunOutput, ReviewRunError> {
    let worker = CodexReviewWorker::new(data).with_codex_home(codex_home);
    worker.review(request)
}

fn write_provider_observation(
    fixture_root: &Path,
    stage: &'static str,
    output: &ReviewRunOutput,
) -> Result<(), String> {
    validate_stage(stage)?;
    let retained = RetainedProviderObservation {
        schema: "needle.review-change-impact-gate-a6-provider-observation/1",
        stage,
        verdict: output.verdict,
        acceptance_coverage: &output.acceptance_coverage,
        findings: &output.findings,
        reviewer_definition: output.reviewer_definition,
        dependency_digest: output.dependency_digest,
        provider_observation_digest: output.provider_observation_digest,
        inspection_context_digest: output.inspection_context_digest,
        inspection_coverage: &output.inspection_coverage,
        created_unix_ms: output.created_unix_ms,
        output_tokens: output.output_tokens,
        worker_turns: output.worker_turns,
    };
    write_retained_json(&fixture_root.join(format!("{stage}-provider.json")), &retained)
}

fn write_stage_records(
    fixture_root: &Path,
    stage: &'static str,
    report: &ReviewReport,
    manifest: &needle_core::PartitionManifest,
) -> Result<(), String> {
    validate_stage(stage)?;
    let retained = RetainedStageRecords {
        schema: "needle.review-change-impact-gate-a6-stage-records/1",
        stage,
        report,
        manifest,
    };
    write_retained_json(&fixture_root.join(format!("{stage}-records.json")), &retained)
}

fn write_retained_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("cannot serialize retained Gate A6 evidence: {error}"))?;
    fs::write(path, bytes)
        .map_err(|error| format!("cannot persist retained Gate A6 evidence: {error}"))
}

fn validate_stage(stage: &str) -> Result<(), String> {
    if LIVE_STAGES.contains(&stage) { Ok(()) } else { Err("unknown Gate A6 stage".to_owned()) }
}

fn validate_live_output_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("Gate A6 output directory must be absolute".to_owned());
    }
    let rendered =
        path.to_str().ok_or_else(|| "Gate A6 output directory must be valid UTF-8".to_owned())?;
    if rendered.len() > MAX_LIVE_OUTPUT_ROOT_UTF8_BYTES {
        return Err(format!(
            "Gate A6 output directory exceeds {MAX_LIVE_OUTPUT_ROOT_UTF8_BYTES} UTF-8 bytes"
        ));
    }
    Ok(())
}

fn completed_provider_calls(output_root: &Path, fixtures: &[FixtureDefinition]) -> u16 {
    fixtures
        .iter()
        .flat_map(|fixture| {
            LIVE_STAGES
                .map(|stage| output_root.join(fixture.id).join(format!("{stage}-provider.json")))
        })
        .filter(|path| path.is_file())
        .count()
        .try_into()
        .unwrap_or(u16::MAX)
}

fn bounded_diagnostic(value: &str) -> String {
    if value.len() <= MAX_FAILED_RUN_DIAGNOSTIC_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_FAILED_RUN_DIAGNOSTIC_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

struct DedicatedCodexHome {
    path: PathBuf,
}

impl DedicatedCodexHome {
    fn new(auth_source: &Path) -> Self {
        assert!(auth_source.is_file(), "Gate A6 auth source is missing");
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let path = env::temp_dir()
            .join(format!("needle-gate-a6-codex-home-{}-{nonce}", std::process::id()));
        assert!(!path.exists(), "dedicated Gate A6 Codex home already exists");
        fs::create_dir_all(&path).unwrap();
        fs::copy(auth_source, path.join("auth.json")).unwrap();
        fs::write(path.join("config.toml"), b"").unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for DedicatedCodexHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn change_request() -> ChangeRequest {
    ChangeRequest {
        task: "Preserve every exported function's documented mathematical behavior.".to_owned(),
        acceptance_criteria: vec![
            "Every exported function returns the documented result for representative inputs."
                .to_owned(),
            "The patch introduces no unconditional or mathematically incorrect return value."
                .to_owned(),
        ],
        allowed_paths: vec![AllowedPath {
            path: "src".to_owned(),
            scope: AllowedPathScope::Subtree,
        }],
        constraints: vec![
            "Review each changed file independently and report one stable rule identifier per distinct defect."
                .to_owned(),
        ],
        artifact_ids: Vec::new(),
        claim_ids: Vec::new(),
    }
}

fn patch(
    change_id: &ChangeId,
    source_snapshot: Digest,
    revision: u32,
    files: &[FixtureFile],
    current: bool,
) -> PatchArtifact {
    let files = patch_files(files, current)
        .into_iter()
        .map(|blob| PatchFile {
            path: blob.path,
            operation: PatchOperation::Update,
            before_digest: blob.before.as_deref().map(Digest::blake3),
            after_digest: blob.after.as_deref().map(Digest::blake3),
            before_bytes: blob.before.as_ref().map_or(0, Vec::len) as u64,
            after_bytes: blob.after.as_ref().map_or(0, Vec::len) as u64,
        })
        .collect::<Vec<_>>();
    PatchArtifact {
        id: PatchArtifact::compute_id(source_snapshot, &files),
        change_id: change_id.clone(),
        revision,
        source_snapshot,
        files,
        summary: if current {
            "Fix the changed defect while preserving one stable defect and adding one new defect."
                .to_owned()
        } else {
            "Introduce one changed-path defect and one stable-path defect.".to_owned()
        },
        acceptance_coverage: Vec::new(),
        residual_risks: Vec::new(),
        declared_output_digest: Digest::blake3(if current {
            b"gate-a6-current-patch".as_slice()
        } else {
            b"gate-a6-prior-patch".as_slice()
        }),
        discrepancies: Vec::new(),
    }
}

fn patch_files(files: &[FixtureFile], current: bool) -> Vec<PatchFileBlob> {
    files
        .iter()
        .filter_map(|file| {
            let after = if current { file.current } else { file.prior }?;
            Some(PatchFileBlob {
                path: file.path.to_owned(),
                before: Some(file.base.as_bytes().to_vec()),
                after: Some(after.as_bytes().to_vec()),
            })
        })
        .collect()
}

fn prepare_store(
    data: &Path,
    repository_id: Digest,
    requirements_digest: Digest,
    request: &ChangeRequest,
    patch: &PatchArtifact,
    files: &[FixtureFile],
    current: bool,
) -> Result<(), String> {
    fs::create_dir_all(data)
        .map_err(|error| format!("cannot create Gate A6 store directory: {error}"))?;
    let store = RuntimeStore::new(data.join("needle.sqlite3"));
    store.initialize().map_err(|error| format!("cannot initialize Gate A6 store: {error}"))?;
    store
        .record_prepared_change(
            repository_id,
            requirements_digest,
            request,
            patch,
            &json!({"gate": "a6", "revision": patch.revision}),
            &patch_files(files, current),
        )
        .map_err(|error| format!("cannot prepare Gate A6 change: {error}"))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn action_request(
    fixture: &str,
    arm: &str,
    change: &ChangeRequest,
    change_id: &ChangeId,
    requirements_digest: Digest,
    patch: &PatchArtifact,
    prior_review_artifacts: Vec<ArtifactId>,
    repository_id: Digest,
    source_snapshot: Digest,
) -> ActionRequest {
    let definition = built_in_action_contracts()
        .iter()
        .find(|definition| {
            definition.contract.id.as_str() == needle_core::REVIEW_DIFF_ACTION_CONTRACT
        })
        .unwrap();
    let patch_artifact = ArtifactId::new(Digest::blake3(format!("patch-artifact:{}", patch.id)));
    let input = ChangeActionInput::ReviewDiff {
        change_id: change_id.clone(),
        requirements_digest,
        patch: PatchActionInputRef { artifact: patch_artifact, patch: patch.id },
        prior_review_artifacts: prior_review_artifacts.clone(),
    };
    let mut input_artifact_ids = vec![patch_artifact.digest()];
    input_artifact_ids.extend(prior_review_artifacts.iter().map(|artifact| artifact.digest()));
    input_artifact_ids.sort_unstable();
    ActionRequest::new_with_semantic_parameters(
        &definition.contract,
        ArtifactRequest {
            contract_id: definition.output_contract_id.to_owned(),
            contract_revision: definition.output_contract_revision,
            repository_id,
            source_snapshot_digest: source_snapshot,
            route_key: NeedKey::new("locate.implementation").unwrap(),
            normalized_request: change.task.clone(),
            semantic_fragment_id: Some(NeedFragmentId::new(Digest::blake3(format!(
                "{fixture}:{arm}:fragment"
            )))),
            input_artifact_ids,
        },
        input.semantic_parameter_digest(source_snapshot),
        definition.contract.default_dispatch_policy,
        NeedKey::new("locate.implementation").unwrap(),
        NeedId::new(Digest::blake3(format!("{fixture}:need"))),
    )
    .unwrap()
}

fn report_and_manifest(
    request: &ActionRequest,
    world: &SemanticWorld,
    change_id: &ChangeId,
    requirements_digest: Digest,
    patch: &PatchArtifact,
    output: &ReviewRunOutput,
) -> Result<(ReviewReport, needle_core::PartitionManifest), String> {
    let manifest = derive_review_shadow_manifest(
        ShadowManifestContext {
            request,
            world,
            definition_set_digest: Digest::blake3(DEFINITION_SET),
        },
        &output.findings,
        output.dependency_digest,
    )
    .map_err(|error| format!("review manifest derivation failed: {error}"))?;
    let report = ReviewReport::new(
        request.semantic_id(),
        change_id.clone(),
        patch.id,
        requirements_digest,
        output.reviewer_definition,
        output.verdict,
        output.acceptance_coverage.clone(),
        output.findings.clone(),
        Some(manifest.id),
        output.created_unix_ms,
    )
    .map_err(|error| format!("review report construction failed: {error}"))?;
    let report = match output.inspection_context_digest {
        Some(context_digest) => report
            .with_inspection_coverage(context_digest, output.inspection_coverage.clone())
            .map_err(|error| format!("review inspection coverage construction failed: {error}"))?,
        None if output.inspection_coverage.is_empty() => report,
        None => return Err("review inspection coverage has no context".to_owned()),
    };
    Ok((report, manifest))
}

fn refresh_advisory(
    repository_id: Digest,
    fixture: &str,
    prior_patch: &PatchArtifact,
    current_patch: &PatchArtifact,
    prior_report: &ReviewReport,
    prior_manifest: &needle_core::PartitionManifest,
) -> ReviewRefreshAdvisory {
    let prior = prior_patch.files.iter().map(|file| (&file.path, file)).collect::<BTreeMap<_, _>>();
    let current =
        current_patch.files.iter().map(|file| (&file.path, file)).collect::<BTreeMap<_, _>>();
    let changed_paths = prior
        .keys()
        .chain(current.keys())
        .filter(|path| prior.get(*path) != current.get(*path))
        .map(|path| (*path).clone())
        .collect::<BTreeSet<_>>();
    let changed_locators = changed_paths
        .iter()
        .map(|path| DependencyLocator::repository_path(path))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let state_delta = StateDelta::new(
        repository_id,
        RepositoryContextId::new(Digest::blake3(format!("{fixture}:repository-context"))),
        1,
        2,
        changed_locators,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        true,
    )
    .unwrap();
    let manifest_keys = prior_manifest
        .entries
        .iter()
        .map(|entry| {
            let bytes: [u8; 32] = entry.key.value.as_slice().try_into().unwrap();
            (Digest(bytes), entry.key.digest)
        })
        .collect::<BTreeMap<_, _>>();
    let mut retained = Vec::new();
    let mut invalidated = Vec::new();
    let mut invalidated_by_path = BTreeMap::<String, Vec<Digest>>::new();
    for finding in &prior_report.findings {
        let key = manifest_keys[&review_finding_partition_key(finding)];
        if changed_paths.contains(&finding.path) {
            invalidated.push(key);
            invalidated_by_path.entry(finding.path.clone()).or_default().push(key);
        } else {
            retained.push(finding.clone());
        }
    }
    retained.sort_by_key(|finding| finding.id);
    invalidated.sort_unstable();
    for keys in invalidated_by_path.values_mut() {
        keys.sort_unstable();
    }
    let inspection_context_digest =
        review_inspection_context_digest(state_delta.digest, prior_manifest.id, current_patch.id);
    let mut inspection_targets = retained
        .iter()
        .map(|finding| {
            ReviewInspectionTarget::retained_finding(
                inspection_context_digest,
                finding.path.clone(),
                finding.id,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    for path in changed_paths {
        inspection_targets.push(
            ReviewInspectionTarget::changed_path(
                inspection_context_digest,
                path.clone(),
                invalidated_by_path.remove(&path).unwrap_or_default(),
            )
            .unwrap(),
        );
    }
    assert!(invalidated_by_path.is_empty());
    inspection_targets.sort_by_key(|target| target.id);
    ReviewRefreshAdvisory {
        state_delta,
        prior_manifest: prior_manifest.id,
        retained_findings: retained,
        invalidated_partition_keys: invalidated,
        inspection_context_digest,
        inspection_targets,
    }
}

fn transition(
    prior: &needle_core::PartitionManifest,
    current: &needle_core::PartitionManifest,
    delta: &StateDelta,
    attempt: Digest,
) -> Result<(ManifestTransition, Vec<Digest>), String> {
    let current_by_value = current
        .entries
        .iter()
        .map(|entry| (entry.key.value.as_slice(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut mappings = Vec::new();
    let mut invalidated = Vec::new();
    for entry in &prior.entries {
        match current_by_value.get(entry.key.value.as_slice()) {
            Some(current_entry) if current_entry.payload_digest == entry.payload_digest => {
                mappings.push(PartitionKeyMapping {
                    prior: PartitionRef::new(prior.id, entry.key.digest),
                    current: PartitionRef::new(current.id, current_entry.key.digest),
                });
            }
            _ => invalidated.push(entry.key.digest),
        }
    }
    if mappings.is_empty() {
        return Err("Gate A6 requires at least one exact provider-revalidated retained partition"
            .to_owned());
    }
    invalidated.sort_unstable();
    let review_action =
        needle_core::ActionContractId::new(needle_core::REVIEW_DIFF_ACTION_CONTRACT).unwrap();
    let definition = built_in_partition_for_action(&review_action).unwrap();
    Ok((
        ManifestTransition::new(
            prior.id,
            current.id,
            delta.digest,
            mappings,
            ManifestProvenance::ProducerAuthored { attempt },
            definition.policy.manifest_validator.clone(),
        )
        .map_err(|error| format!("manifest transition construction failed: {error}"))?,
        invalidated,
    ))
}

fn semantic_world(repository_id: Digest) -> SemanticWorld {
    SemanticWorld {
        repository_lineage: repository_id,
        source_selector: "gate-a6-base".to_owned(),
        platform: "codex".to_owned(),
        features: "default".to_owned(),
        configuration: None,
        toolchain: None,
    }
}

fn initialize_repository(root: &Path, files: &[FixtureFile]) {
    fs::create_dir_all(root).unwrap();
    git(root, &["init", "--quiet"]);
    git(root, &["config", "core.autocrlf", "false"]);
    git(root, &["config", "user.name", "Needle Gate A6"]);
    git(root, &["config", "user.email", "needle-gate-a6@example.invalid"]);
    for file in files {
        let path = root.join(file.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, file.base).unwrap();
    }
    git(root, &["add", "."]);
    git(root, &["commit", "--quiet", "-m", "Gate A6 base"]);
}

fn git(root: &Path, arguments: &[&str]) {
    let status = Command::new("git").arg("-C").arg(root).args(arguments).status().unwrap();
    assert!(status.success(), "git command failed: {arguments:?}");
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}
