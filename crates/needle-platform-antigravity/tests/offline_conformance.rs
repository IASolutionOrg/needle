use needle_core::{
    AgentHost, ArtifactKind, EvidenceFailurePolicy, HostTerminalStatus, NeedKey, Preset,
    WorkerConfig, WorkerRequest,
};
use needle_platform_antigravity::{
    AntigravityCliAdapter, AntigravityExecutionRequest, AntigravityWorker,
};
use needle_runtime::{WorkerExecutor, capture_git_snapshot};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SIMULATOR: &str = env!("CARGO_BIN_EXE_needle-sim-antigravity");

struct Fixture {
    root: PathBuf,
    data: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let base = std::env::temp_dir().join(format!("needle-antigravity-{name}-{suffix}"));
        let root = base.join("repository");
        let data = base.join("data");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(&data).unwrap();
        run(&root, &["init"]);
        run(&root, &["config", "user.email", "needle@example.invalid"]);
        run(&root, &["config", "user.name", "Needle Fixture"]);
        fs::write(root.join("src/lib.rs"), "pub fn answer() -> u8 { 42 }\n").unwrap();
        run(&root, &["add", "."]);
        run(&root, &["commit", "-m", "fixture"]);
        Self { root, data }
    }

    fn request(&self, timeout: Duration) -> AntigravityExecutionRequest {
        let (_, snapshot) = capture_git_snapshot(&self.root).unwrap();
        AntigravityExecutionRequest {
            repository_root: self.root.clone(),
            repository_snapshot: snapshot,
            prompt: "Inspect the repository and return the requested artifact.".to_owned(),
            output_schema: output_schema(),
            model: "gemini-3.7-flash-medium".to_owned(),
            reasoning: "medium".to_owned(),
            timeout,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.root.parent().unwrap());
    }
}

#[test]
fn preflight_requires_the_official_headless_surface() {
    let report = AntigravityCliAdapter::preflight(SIMULATOR).unwrap();
    assert!(report.verified());
    assert_eq!(report.host_version, "1.1.22");
    assert_eq!(report.contract.host, AgentHost::Antigravity);
}

#[test]
fn structured_stream_is_normalized_and_active_checkout_is_unchanged() {
    let fixture = Fixture::new("success");
    let (_, before) = capture_git_snapshot(&fixture.root).unwrap();
    let record = fixture.data.join("invocation.json");
    let mut request = fixture.request(Duration::from_secs(5));
    request.prompt = format!("SIM_RECORD:{}\nInspect the repository.", record.display());
    let result = AntigravityCliAdapter::new(&fixture.data, SIMULATOR).execute(&request).unwrap();

    assert_eq!(result.status, HostTerminalStatus::Success);
    assert_eq!(result.host, AgentHost::Antigravity);
    assert!(result.sandboxed);
    assert!(result.process_cleanup_completed);
    assert!(result.checkout_cleanup_completed);
    assert_eq!(result.usage.input_tokens, 10);
    assert_eq!(result.tool_events.len(), 1);
    assert_eq!(result.tool_events[0].name, "read_file");
    assert_eq!(result.structured_output["schema"], "needle.simulated-artifact/1");

    let invocation: Value = serde_json::from_slice(&fs::read(record).unwrap()).unwrap();
    let arguments = invocation["arguments"].as_array().unwrap();
    for required in [
        "--print",
        "--output-format",
        "stream-json",
        "--json-schema",
        "--model",
        "--effort",
        "--print-timeout",
        "--sandbox",
        "--add-dir",
    ] {
        assert!(arguments.iter().any(|argument| argument == required), "missing {required}");
    }
    assert!(!arguments.iter().any(|argument| argument == "--dangerously-skip-permissions"));
    let cwd = PathBuf::from(invocation["cwd"].as_str().unwrap());
    let add_dir_index = arguments.iter().position(|argument| argument == "--add-dir").unwrap();
    assert_eq!(arguments[add_dir_index + 1], invocation["cwd"]);
    let prompt_index = arguments.iter().position(|argument| argument == "--print").unwrap();
    let prompt = arguments[prompt_index + 1].as_str().unwrap();
    assert!(prompt.contains("Needle workspace binding (trusted adapter data)"));
    let serialized_cwd = serde_json::to_string(invocation["cwd"].as_str().unwrap()).unwrap();
    assert!(prompt.contains(&serialized_cwd));
    assert!(prompt.contains("Return repository-relative paths"));
    assert_ne!(cwd, fs::canonicalize(&fixture.root).unwrap());
    assert!(!cwd.exists(), "the disposable checkout must be removed after execution");
    let (_, after) = capture_git_snapshot(&fixture.root).unwrap();
    assert_eq!(before, after);
}

#[test]
fn cancellation_reaps_process_and_cleans_checkout() {
    let fixture = Fixture::new("cancel");
    let cancellation = Arc::new(AtomicBool::new(false));
    let adapter = AntigravityCliAdapter::new(&fixture.data, SIMULATOR)
        .with_cancellation(cancellation.clone());
    let mut request = fixture.request(Duration::from_secs(10));
    request.prompt = "SIM_SLEEP_MS:5000\nWait for cancellation.".to_owned();
    let started = Instant::now();
    let cancel = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        cancellation.store(true, Ordering::SeqCst);
    });
    let failure = adapter.execute(&request).unwrap_err();
    cancel.join().unwrap();

    assert_eq!(failure.code, "canceled");
    assert!(failure.process_cleanup_completed);
    assert!(failure.checkout_cleanup_completed);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(directory_is_empty_or_absent(&fixture.data.join("antigravity-runs")));
}

#[test]
fn unsafe_permission_mode_fails_closed() {
    let fixture = Fixture::new("permissions");
    let mut request = fixture.request(Duration::from_secs(5));
    request.prompt = "SIM_UNSAFE_PERMISSIONS\nInspect the repository.".to_owned();
    let failure =
        AntigravityCliAdapter::new(&fixture.data, SIMULATOR).execute(&request).unwrap_err();
    assert_eq!(failure.code, "host_protocol_invalid");
    assert!(failure.diagnostic.contains("always-proceed"));
    assert!(failure.checkout_cleanup_completed);
}

#[test]
fn missing_structured_output_preserves_terminal_failure_metadata() {
    let fixture = Fixture::new("missing-structured-output");
    let mut request = fixture.request(Duration::from_secs(5));
    request.prompt = "SIM_MISSING_STRUCTURED_OUTPUT\nInspect the repository.".to_owned();

    let failure =
        AntigravityCliAdapter::new(&fixture.data, SIMULATOR).execute(&request).unwrap_err();

    assert_eq!(failure.code, "host_protocol_invalid");
    assert!(failure.diagnostic.contains("no structured_output"));
    assert!(failure.diagnostic.contains("ListDir was soft-denied"));
    let observation = failure.observation.as_deref().unwrap();
    assert_eq!(observation.conversation_id.as_deref(), Some("sim-antigravity-conversation"));
    assert_eq!(observation.terminal_status, Some(HostTerminalStatus::Success));
    assert_eq!(observation.usage.as_ref().map(|usage| usage.input_tokens), Some(10));
    assert_eq!(observation.worker_turns, 1);
    assert!(failure.process_cleanup_completed);
    assert!(failure.checkout_cleanup_completed);
}

#[test]
fn host_tool_names_are_opaque_to_needle() {
    let fixture = Fixture::new("opaque-tools");
    let mut request = fixture.request(Duration::from_secs(5));
    request.prompt = "SIM_OPAQUE_TOOL_NAMES\nInspect the repository.".to_owned();

    let result = AntigravityCliAdapter::new(&fixture.data, SIMULATOR).execute(&request).unwrap();

    assert_eq!(result.status, HostTerminalStatus::Success);
    assert_eq!(result.tool_events[0].name, "host_internal_tool");
}

#[test]
fn worker_maps_host_native_output_into_the_existing_explore_contract() {
    let fixture = Fixture::new("worker");
    let (_, before) = capture_git_snapshot(&fixture.root).unwrap();
    let output = json!({
        "schema": needle_core::ARTIFACT_RESULT_SCHEMA_ID,
        "artifacts": [{
            "kind": "code-location",
            "path": "src/lib.rs",
            "symbol": "answer",
            "facts": ["answer returns the fixture value"]
        }],
        "test_plan": null
    });
    let (_, snapshot) = capture_git_snapshot(&fixture.root).unwrap();
    let request = WorkerRequest {
        root_task: "locate answer".to_owned(),
        need_key: NeedKey::new("implementation-location").unwrap(),
        need_body: format!("SIM_STRUCTURED_OUTPUT:{output}\nLocate answer."),
        preset: Preset::new("offline", "offline", "Inspect only what is required."),
        repository_root: fixture.root.display().to_string(),
        repository_snapshot: snapshot,
        declared_test_plan: None,
        trusted_test_execution: false,
        requested_artifact_kinds: vec![ArtifactKind::code_location()],
        preferred_artifact_kinds: Vec::new(),
        semantic_fragment: None,
    };
    let config = WorkerConfig {
        executable: SIMULATOR.to_owned(),
        model: "gemini-3.7-flash-medium".to_owned(),
        reasoning: "medium".to_owned(),
        service_tier: None,
        timeout_seconds: 5,
        max_turns: 1,
        evidence_failure_policy: EvidenceFailurePolicy::DiscardInvalidFact,
        role_profile_provenance: None,
    };

    let outcome = AntigravityWorker::new(&fixture.data).execute(&config, &request).unwrap();

    assert!(outcome.result.complete);
    assert_eq!(outcome.result.claims.len(), 1);
    assert_eq!(outcome.codex_version, "1.1.22");
    assert_eq!(outcome.worker_turns, 1);
    let artifacts = outcome.artifact_result.unwrap();
    assert_eq!(artifacts.artifacts[0].path, "src/lib.rs");
    assert_eq!(
        artifacts.observation_trace.gaps,
        ["antigravity_tool_paths_not_attested_by_host_protocol"]
    );
    let (_, after) = capture_git_snapshot(&fixture.root).unwrap();
    assert_eq!(before, after);
    assert!(directory_is_empty_or_absent(&fixture.data.join("antigravity-runs")));
}

#[test]
#[ignore = "requires one explicitly approved live Antigravity provider session"]
fn live_worker_smoke_uses_one_turn_without_retry() {
    const APPROVAL: &str = "APPROVO_1_SESSIONE_ANTIGRAVITY_SENZA_TOKEN_CAP";
    assert_eq!(std::env::var("NEEDLE_AGY_LIVE_SMOKE_APPROVAL").as_deref(), Ok(APPROVAL));
    let executable = PathBuf::from(
        std::env::var("NEEDLE_AGY_EXECUTABLE").expect("NEEDLE_AGY_EXECUTABLE is required"),
    );
    let report_path = PathBuf::from(
        std::env::var("NEEDLE_AGY_LIVE_SMOKE_REPORT")
            .expect("NEEDLE_AGY_LIVE_SMOKE_REPORT is required"),
    );
    let data_directory = PathBuf::from(
        std::env::var("NEEDLE_AGY_LIVE_SMOKE_DATA_DIR")
            .expect("NEEDLE_AGY_LIVE_SMOKE_DATA_DIR is required"),
    );
    assert!(executable.is_file());
    assert!(!report_path.exists(), "live smoke report must be append-only");
    fs::create_dir_all(&data_directory).unwrap();
    let fixture = Fixture::new("live-worker");
    let (_, before) = capture_git_snapshot(&fixture.root).unwrap();
    let request = WorkerRequest {
        root_task: "Locate the compact fixture implementation".to_owned(),
        need_key: NeedKey::new("implementation-location").unwrap(),
        need_body: "Locate the function named answer in this compact repository. Return only the exact repository-relative implementation location and one concise factual statement supported by that file. Do not execute commands, tests, builds, scripts, network requests, or subagents.".to_owned(),
        preset: Preset::new(
            "antigravity-live-smoke",
            "Antigravity live smoke",
            "Inspect the compact repository narrowly and return bounded structured evidence.",
        ),
        repository_root: fixture.root.display().to_string(),
        repository_snapshot: before.clone(),
        declared_test_plan: None,
        trusted_test_execution: false,
        requested_artifact_kinds: vec![ArtifactKind::code_location()],
        preferred_artifact_kinds: Vec::new(),
        semantic_fragment: None,
    };
    let config = WorkerConfig {
        executable: executable.display().to_string(),
        model: "gemini-3.7-flash-medium".to_owned(),
        reasoning: "medium".to_owned(),
        service_tier: None,
        timeout_seconds: 180,
        max_turns: 1,
        evidence_failure_policy: EvidenceFailurePolicy::DiscardInvalidFact,
        role_profile_provenance: None,
    };
    let started = Instant::now();
    let outcome = AntigravityWorker::new(&data_directory).execute(&config, &request);
    let (_, after) = capture_git_snapshot(&fixture.root).unwrap();
    let active_checkout_unchanged = before == after;
    let checkout_cleanup_completed =
        directory_is_empty_or_absent(&data_directory.join("antigravity-runs"));

    let report = json!({
        "schema": "needle.antigravity-live-smoke/2",
        "model": config.model,
        "reasoning": config.reasoning,
        "maximum_provider_sessions": 1,
        "automatic_retries": 0,
        "hard_output_token_limit_available": false,
        "structured_output_capture_limit_bytes": needle_core::MAX_HOST_STRUCTURED_OUTPUT_BYTES,
        "workspace_binding": {
            "current_directory": "isolated_checkout",
            "explicit_add_dir": true,
            "trusted_prompt_binding": true,
            "global_read_permission_required": false
        },
        "active_checkout_unchanged": active_checkout_unchanged,
        "checkout_cleanup_completed": checkout_cleanup_completed,
        "wall_time_ms": started.elapsed().as_millis(),
        "outcome": &outcome,
    });
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&report_path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{}", serde_json::to_string(&report).unwrap());

    let outcome = outcome.unwrap_or_else(|failure| {
        panic!("live Antigravity smoke failed after writing {}: {failure}", report_path.display())
    });
    assert!(active_checkout_unchanged);
    assert_eq!(outcome.logical_worker_spawns, 1);
    assert_eq!(outcome.worker_turns, 1);
    assert!(!outcome.repair_performed);
    assert!(outcome.result.complete);
    assert!(outcome.result.evidence.iter().any(|evidence| evidence.path == "src/lib.rs"));
    assert!(checkout_cleanup_completed);
}

fn output_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["schema", "facts"],
        "properties": {
            "schema": {"type": "string"},
            "facts": {"type": "array", "items": {"type": "string"}}
        }
    })
}

fn run(root: &Path, arguments: &[&str]) {
    let output = Command::new("git").arg("-C").arg(root).args(arguments).output().unwrap();
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        arguments,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn directory_is_empty_or_absent(path: &Path) -> bool {
    !path.exists() || fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_none())
}
