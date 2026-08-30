use needle_core::{
    AgentHost, Digest, HOST_EXECUTION_RESULT_SCHEMA_V1, HostCapability, HostExecutionContractV1,
    HostExecutionResultV1, HostTerminalStatus, HostToolEvent, HostUsage,
    MAX_HOST_CONVERSATION_ID_BYTES, MAX_HOST_STRUCTURED_OUTPUT_BYTES, RepositorySnapshot,
};
use needle_runtime::{IsolatedCheckout, capture_git_snapshot};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

mod action_provider;
mod reviewer;
mod worker;

pub use action_provider::AntigravityChangeActionProvider;
pub use worker::AntigravityWorker;

const ADAPTER_ID: &str = "needle.antigravity-cli";
const ADAPTER_REVISION: u32 = 1;
const MAX_PROMPT_BYTES: usize = 16 * 1024;
const MAX_BOUND_PROMPT_BYTES: usize = 20 * 1024;
const MAX_MODEL_BYTES: usize = 128;
const MAX_REASONING_BYTES: usize = 32;
const MAX_PROCESS_OUTPUT_BYTES: usize = 512 * 1024;
const MAX_HOST_DIAGNOSTIC_BYTES: usize = 4 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntigravityInstallationReport {
    pub cli_executable: Option<PathBuf>,
    pub cli_preflight: Option<AntigravityPreflightReport>,
    pub cli_error: Option<String>,
    pub ide_executable: Option<PathBuf>,
}

pub fn inspect_installation() -> AntigravityInstallationReport {
    let cli_executable = discover_cli();
    let (cli_preflight, cli_error) = match cli_executable.as_deref() {
        Some(executable) => match AntigravityCliAdapter::preflight(executable) {
            Ok(report) => (Some(report), None),
            Err(error) => (None, Some(error)),
        },
        None => (None, None),
    };
    AntigravityInstallationReport {
        cli_executable,
        cli_preflight,
        cli_error,
        ide_executable: discover_ide(),
    }
}

fn discover_cli() -> Option<PathBuf> {
    let names: &[&str] =
        if cfg!(windows) { &["agy.exe", "agy.cmd", "agy.bat", "agy"] } else { &["agy"] };
    let from_path = env::var_os("PATH").and_then(|path| {
        env::split_paths(&path).find_map(|directory| {
            names.iter().map(|name| directory.join(name)).find(|candidate| candidate.is_file())
        })
    });
    #[cfg(windows)]
    let installed = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|root| root.join("agy/bin/agy.exe"))
        .filter(|candidate| candidate.is_file());
    #[cfg(not(windows))]
    let installed = None;
    from_path.or(installed)
}

fn discover_ide() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let local = env::var_os("LOCALAPPDATA").map(PathBuf::from)?;
        [
            local.join("Programs/Antigravity/Antigravity.exe"),
            local.join("Programs/Antigravity IDE/Antigravity IDE.exe"),
        ]
        .into_iter()
        .find(|candidate| candidate.is_file())
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntigravityPreflightReport {
    pub host_version: String,
    pub native_launcher: String,
    pub contract: HostExecutionContractV1,
    pub required_flags_present: bool,
    pub supported: bool,
    pub incompatibility_reason: Option<String>,
}

impl AntigravityPreflightReport {
    pub fn verified(&self) -> bool {
        self.supported && self.required_flags_present && self.contract.validate().is_ok()
    }
}

#[derive(Clone, Debug)]
pub struct AntigravityExecutionRequest {
    pub repository_root: PathBuf,
    pub repository_snapshot: RepositorySnapshot,
    pub prompt: String,
    pub output_schema: Value,
    pub model: String,
    pub reasoning: String,
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct AntigravityCliAdapter {
    data_directory: PathBuf,
    executable: PathBuf,
    cancellation: Option<Arc<AtomicBool>>,
}

#[derive(Debug)]
pub struct AntigravityCompletedExecution {
    pub result: HostExecutionResultV1,
    checkout: IsolatedCheckout,
}

impl AntigravityCompletedExecution {
    pub fn checkout_root(&self) -> &Path {
        self.checkout.checkout_root()
    }

    pub fn cleanup(mut self) -> Result<HostExecutionResultV1, AntigravityExecutionFailure> {
        self.checkout.cleanup().map_err(|error| {
            failure_with_cleanup("checkout_cleanup_failed", error.to_string(), true, false)
        })?;
        self.result.checkout_cleanup_completed = true;
        self.result.validate(&AntigravityCliAdapter::contract()).map_err(|error| {
            failure_with_cleanup("host_result_invalid", error.to_string(), true, true)
        })?;
        Ok(self.result)
    }
}

impl AntigravityCliAdapter {
    pub fn new(data_directory: impl Into<PathBuf>, executable: impl Into<PathBuf>) -> Self {
        Self {
            data_directory: data_directory.into(),
            executable: executable.into(),
            cancellation: None,
        }
    }

    pub fn with_cancellation(mut self, cancellation: Arc<AtomicBool>) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    pub fn contract() -> HostExecutionContractV1 {
        HostExecutionContractV1::new(
            AgentHost::Antigravity,
            ADAPTER_ID,
            ADAPTER_REVISION,
            [
                HostCapability::Headless,
                HostCapability::StructuredOutput,
                HostCapability::StreamEvents,
                HostCapability::Usage,
                HostCapability::Cancellation,
                HostCapability::Sandbox,
            ],
        )
        .expect("the built-in Antigravity contract is valid")
    }

    pub fn preflight(executable: impl AsRef<Path>) -> Result<AntigravityPreflightReport, String> {
        let executable = executable.as_ref();
        let version_output = bounded_command_output(executable, &["--version"])?;
        if !version_output.status.success() {
            return Err("Antigravity CLI --version failed".to_owned());
        }
        let version_text = combined_text(&version_output);
        let host_version = version_text
            .split_whitespace()
            .find(|part| part.bytes().next().is_some_and(|byte| byte.is_ascii_digit()))
            .unwrap_or_default()
            .trim_matches(|character: char| !character.is_ascii_digit() && character != '.')
            .to_owned();
        if host_version.is_empty() {
            return Err("Antigravity CLI --version did not report a version".to_owned());
        }
        let help_output = bounded_command_output(executable, &["--help"])?;
        if !help_output.status.success() {
            return Err("Antigravity CLI --help failed".to_owned());
        }
        let help = combined_text(&help_output);
        let required = [
            "--print",
            "--output-format",
            "--json-schema",
            "--model",
            "--effort",
            "--print-timeout",
            "--sandbox",
            "--add-dir",
        ];
        let missing =
            required.iter().filter(|flag| !help.contains(**flag)).copied().collect::<Vec<_>>();
        let required_flags_present = missing.is_empty();
        Ok(AntigravityPreflightReport {
            host_version,
            native_launcher: executable.display().to_string(),
            contract: Self::contract(),
            required_flags_present,
            supported: required_flags_present,
            incompatibility_reason: (!required_flags_present).then(|| {
                format!("Antigravity CLI is missing required flags: {}", missing.join(", "))
            }),
        })
    }

    pub fn execute(
        &self,
        request: &AntigravityExecutionRequest,
    ) -> Result<HostExecutionResultV1, AntigravityExecutionFailure> {
        self.execute_retained(request)?.cleanup()
    }

    pub fn execute_retained(
        &self,
        request: &AntigravityExecutionRequest,
    ) -> Result<AntigravityCompletedExecution, AntigravityExecutionFailure> {
        validate_request(request).map_err(|diagnostic| failure("request_invalid", diagnostic))?;
        let preflight = Self::preflight(&self.executable)
            .map_err(|diagnostic| failure("preflight_failed", diagnostic))?;
        if !preflight.verified() {
            return Err(failure(
                "host_incompatible",
                preflight
                    .incompatibility_reason
                    .unwrap_or_else(|| "Antigravity CLI preflight failed".to_owned()),
            ));
        }

        let repository_root = fs::canonicalize(&request.repository_root).map_err(|error| {
            failure("repository_unavailable", format!("cannot resolve repository root: {error}"))
        })?;
        let sandbox = IsolatedCheckout::materialize(
            &repository_root,
            &self.data_directory.join("antigravity-runs"),
        )
        .map_err(|error| failure("sandbox_materialization_failed", error.to_string()))?;
        if sandbox.snapshot().source_digest != request.repository_snapshot.source_digest {
            let cleanup = sandbox.cleanup().is_ok();
            return Err(failure_with_cleanup(
                "source_snapshot_changed",
                "requested source snapshot changed before Antigravity execution".to_owned(),
                true,
                cleanup,
            ));
        }

        self.execute_materialized(request, preflight, sandbox)
    }

    pub(crate) fn execute_prepared_retained(
        &self,
        request: &AntigravityExecutionRequest,
        sandbox: IsolatedCheckout,
    ) -> Result<AntigravityCompletedExecution, AntigravityExecutionFailure> {
        if let Err(diagnostic) = validate_request(request) {
            let cleanup = sandbox.cleanup().is_ok();
            return Err(failure_with_cleanup("request_invalid", diagnostic, true, cleanup));
        }
        let preflight = match Self::preflight(&self.executable) {
            Ok(preflight) => preflight,
            Err(diagnostic) => {
                let cleanup = sandbox.cleanup().is_ok();
                return Err(failure_with_cleanup("preflight_failed", diagnostic, true, cleanup));
            }
        };
        if !preflight.verified() {
            let diagnostic = preflight
                .incompatibility_reason
                .unwrap_or_else(|| "Antigravity CLI preflight failed".to_owned());
            let cleanup = sandbox.cleanup().is_ok();
            return Err(failure_with_cleanup("host_incompatible", diagnostic, true, cleanup));
        }
        let requested_root = match fs::canonicalize(&request.repository_root) {
            Ok(root) => root,
            Err(error) => {
                let cleanup = sandbox.cleanup().is_ok();
                return Err(failure_with_cleanup(
                    "repository_unavailable",
                    format!("cannot resolve repository root: {error}"),
                    true,
                    cleanup,
                ));
            }
        };
        let checkout_root = match fs::canonicalize(sandbox.checkout_root()) {
            Ok(root) => root,
            Err(error) => {
                let cleanup = sandbox.cleanup().is_ok();
                return Err(failure_with_cleanup(
                    "sandbox_unavailable",
                    format!("cannot resolve prepared checkout: {error}"),
                    true,
                    cleanup,
                ));
            }
        };
        if requested_root != checkout_root {
            return Err(failure_with_cleanup(
                "sandbox_binding_changed",
                "prepared Antigravity checkout does not match the requested repository root"
                    .to_owned(),
                true,
                sandbox.cleanup().is_ok(),
            ));
        }
        let observed = match capture_git_snapshot(&checkout_root) {
            Ok(observed) => observed,
            Err(error) => {
                let cleanup = sandbox.cleanup().is_ok();
                return Err(failure_with_cleanup(
                    "source_snapshot_unavailable",
                    error.to_string(),
                    true,
                    cleanup,
                ));
            }
        };
        if observed.1.source_digest != request.repository_snapshot.source_digest {
            return Err(failure_with_cleanup(
                "source_snapshot_changed",
                "prepared Antigravity checkout changed before execution".to_owned(),
                true,
                sandbox.cleanup().is_ok(),
            ));
        }
        self.execute_materialized(request, preflight, sandbox)
    }

    fn execute_materialized(
        &self,
        request: &AntigravityExecutionRequest,
        preflight: AntigravityPreflightReport,
        sandbox: IsolatedCheckout,
    ) -> Result<AntigravityCompletedExecution, AntigravityExecutionFailure> {
        let schema = serde_json::to_vec(&request.output_schema).map_err(|error| {
            failure("schema_invalid", format!("cannot serialize output schema: {error}"))
        })?;
        let schema_path = sandbox.temp_root().join("needle-output-schema.json");
        if let Err(error) = fs::write(&schema_path, schema) {
            let cleanup = sandbox.cleanup().is_ok();
            return Err(failure_with_cleanup(
                "schema_write_failed",
                format!("cannot write bounded output schema: {error}"),
                true,
                cleanup,
            ));
        }
        let timeout_seconds = request.timeout.as_secs().max(1);
        let expected_cwd = sandbox.checkout_root().to_path_buf();
        let workspace_path = serde_json::to_string(&expected_cwd.to_string_lossy())
            .expect("serializing a path string cannot fail");
        let bound_prompt = format!(
            "Needle workspace binding (trusted adapter data):\n\
             - The repository checkout for this task is exactly {workspace_path}.\n\
             - Treat that directory as the workspace root. Resolve every repository-relative path against it.\n\
             - Do not inspect parent directories or any sibling workspace.\n\
             - Return repository-relative paths in the structured result.\n\n{}",
            request.prompt
        );
        if bound_prompt.len() > MAX_BOUND_PROMPT_BYTES {
            let cleanup = sandbox.cleanup().is_ok();
            return Err(failure_with_cleanup(
                "workspace_prompt_too_large",
                "workspace-bound Antigravity prompt exceeds its byte limit".to_owned(),
                true,
                cleanup,
            ));
        }
        let mut command = Command::new(&self.executable);
        command
            .current_dir(sandbox.checkout_root())
            .arg("--print")
            .arg(bound_prompt)
            .args(["--output-format", "stream-json", "--json-schema"])
            .arg(&schema_path)
            .args(["--model", request.model.as_str(), "--effort", request.reasoning.as_str()])
            .arg("--print-timeout")
            .arg(format!("{timeout_seconds}s"))
            .arg("--sandbox")
            .arg("--add-dir")
            .arg(sandbox.checkout_root())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let started = Instant::now();
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let cleanup = sandbox.cleanup().is_ok();
                return Err(failure_with_cleanup(
                    "launch_failed",
                    format!("cannot launch Antigravity CLI: {error}"),
                    true,
                    cleanup,
                ));
            }
        };
        let process = wait_for_process(
            child,
            request.timeout + Duration::from_secs(2),
            self.cancellation.as_deref(),
        );
        let process = match process {
            Ok(process) => process,
            Err(mut error) => {
                error.checkout_cleanup_completed = sandbox.cleanup().is_ok();
                return Err(error);
            }
        };
        if process.stdout.len() > MAX_PROCESS_OUTPUT_BYTES
            || process.stderr.len() > MAX_PROCESS_OUTPUT_BYTES
        {
            return Err(failure_with_cleanup(
                "host_output_too_large",
                "Antigravity CLI output exceeded its bounded capture".to_owned(),
                true,
                sandbox.cleanup().is_ok(),
            ));
        }
        if !process.status.success() {
            return Err(failure_with_cleanup(
                "host_failed",
                bounded_diagnostic(&process.stderr),
                true,
                sandbox.cleanup().is_ok(),
            ));
        }

        let parsed = match parse_stream(&process.stdout, &request.output_schema, &expected_cwd) {
            Ok(parsed) => parsed,
            Err(diagnostic) => {
                let observation = terminal_observation(&process.stdout);
                let duration_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                let checkout_cleanup_completed = sandbox.cleanup().is_ok();
                return Err(observed_protocol_failure(
                    diagnostic,
                    observation,
                    preflight.host_version,
                    duration_ms,
                    checkout_cleanup_completed,
                ));
            }
        };
        let worker_turns = parsed.worker_turns;
        let result = HostExecutionResultV1 {
            schema: HOST_EXECUTION_RESULT_SCHEMA_V1.to_owned(),
            host: AgentHost::Antigravity,
            host_version: preflight.host_version,
            contract_digest: preflight.contract.definition_digest,
            conversation_id: parsed.conversation_id,
            status: parsed.status,
            structured_output: parsed.structured_output,
            usage: parsed.usage,
            duration_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            sandboxed: parsed.sandboxed,
            process_cleanup_completed: true,
            checkout_cleanup_completed: false,
            tool_events: parsed.tool_events,
        };
        if result.status != HostTerminalStatus::Success {
            let checkout_cleanup_completed = sandbox.cleanup().is_ok();
            let mut failure = failure_with_cleanup(
                "host_terminal_failure",
                format!("Antigravity CLI ended with {:?}", result.status),
                true,
                checkout_cleanup_completed,
            );
            failure.observation = Some(Box::new(AntigravityFailureObservation {
                host_version: result.host_version,
                conversation_id: Some(result.conversation_id),
                terminal_status: Some(result.status),
                usage: Some(result.usage),
                duration_ms: result.duration_ms,
                worker_turns,
            }));
            return Err(failure);
        }
        Ok(AntigravityCompletedExecution { result, checkout: sandbox })
    }
}

#[derive(Debug, Error)]
#[error("{code}: {diagnostic}")]
pub struct AntigravityExecutionFailure {
    pub code: String,
    pub diagnostic: String,
    pub process_cleanup_completed: bool,
    pub checkout_cleanup_completed: bool,
    pub observation: Option<Box<AntigravityFailureObservation>>,
}

#[derive(Clone, Debug)]
pub struct AntigravityFailureObservation {
    pub host_version: String,
    pub conversation_id: Option<String>,
    pub terminal_status: Option<HostTerminalStatus>,
    pub usage: Option<HostUsage>,
    pub duration_ms: u64,
    pub worker_turns: u32,
}

fn failure(code: &str, diagnostic: String) -> AntigravityExecutionFailure {
    failure_with_cleanup(code, diagnostic, true, true)
}

fn failure_with_cleanup(
    code: &str,
    diagnostic: String,
    process_cleanup_completed: bool,
    checkout_cleanup_completed: bool,
) -> AntigravityExecutionFailure {
    AntigravityExecutionFailure {
        code: code.to_owned(),
        diagnostic,
        process_cleanup_completed,
        checkout_cleanup_completed,
        observation: None,
    }
}

fn validate_request(request: &AntigravityExecutionRequest) -> Result<(), String> {
    if request.prompt.is_empty() || request.prompt.len() > MAX_PROMPT_BYTES {
        return Err(format!("prompt must contain 1 to {MAX_PROMPT_BYTES} bytes"));
    }
    if request.model.is_empty()
        || request.model.len() > MAX_MODEL_BYTES
        || request.model.chars().any(char::is_whitespace)
    {
        return Err("model is invalid".to_owned());
    }
    if !matches!(request.reasoning.as_str(), "low" | "medium" | "high")
        || request.reasoning.len() > MAX_REASONING_BYTES
    {
        return Err("Antigravity effort must be low, medium, or high".to_owned());
    }
    if request.timeout.is_zero() || request.timeout > Duration::from_secs(3_600) {
        return Err("timeout must be between one second and one hour".to_owned());
    }
    let schema_bytes = serde_json::to_vec(&request.output_schema)
        .map_err(|error| format!("output schema is invalid: {error}"))?;
    if schema_bytes.is_empty() || schema_bytes.len() > MAX_HOST_STRUCTURED_OUTPUT_BYTES {
        return Err("output schema exceeds its bound".to_owned());
    }
    Ok(())
}

struct ProcessOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn wait_for_process(
    mut child: Child,
    timeout: Duration,
    cancellation: Option<&AtomicBool>,
) -> Result<ProcessOutput, AntigravityExecutionFailure> {
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");
    let stdout_reader = thread::spawn(move || read_bounded(stdout));
    let stderr_reader = thread::spawn(move || read_bounded(stderr));
    let deadline = Instant::now() + timeout;
    let (status, interrupted_code) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, None),
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(failure("process_wait_failed", error.to_string()));
            }
        }
        let canceled = cancellation.is_some_and(|flag| flag.load(Ordering::SeqCst));
        let timed_out = Instant::now() >= deadline;
        if canceled || timed_out {
            let _ = child.kill();
            let status = child.wait().map_err(|error| {
                failure("process_cleanup_failed", format!("cannot reap Antigravity CLI: {error}"))
            })?;
            break (status, Some(if canceled { "canceled" } else { "timeout" }));
        }
        thread::sleep(POLL_INTERVAL);
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| failure("stdout_capture_failed", "stdout reader panicked".to_owned()))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| failure("stderr_capture_failed", "stderr reader panicked".to_owned()))??;
    if let Some(code) = interrupted_code {
        return Err(failure_with_cleanup(
            code,
            format!("Antigravity CLI execution {code}"),
            true,
            false,
        ));
    }
    Ok(ProcessOutput { status, stdout, stderr })
}

fn read_bounded(mut reader: impl Read) -> Result<Vec<u8>, AntigravityExecutionFailure> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((MAX_PROCESS_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| failure("host_output_read_failed", error.to_string()))?;
    Ok(bytes)
}

fn bounded_command_output(executable: &Path, arguments: &[&str]) -> Result<ProcessOutput, String> {
    let child = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot execute Antigravity CLI: {error}"))?;
    wait_for_process(child, Duration::from_secs(10), None).map_err(|error| error.to_string())
}

fn combined_text(output: &ProcessOutput) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    if !text.is_empty() && !output.stderr.is_empty() {
        text.push('\n');
    }
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

#[derive(Deserialize)]
struct StreamEnvelope {
    event: String,
    #[serde(default)]
    init: Option<InitEvent>,
    #[serde(default)]
    step_update: Option<StepUpdate>,
    #[serde(default)]
    result: Option<ResultEvent>,
}

#[derive(Deserialize)]
struct InitEvent {
    cwd: PathBuf,
    permission_mode: String,
    #[serde(default)]
    json_schema: Option<Value>,
}

#[derive(Deserialize)]
struct StepUpdate {
    state: String,
    step_type: String,
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    tool_info: Option<ToolInfo>,
}

#[derive(Deserialize)]
struct ToolInfo {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    parameters: Option<Value>,
    #[serde(default)]
    output: Option<Value>,
    #[serde(default)]
    error: Option<Value>,
}

#[derive(Deserialize)]
struct ResultEvent {
    conversation_id: String,
    status: String,
    #[serde(default)]
    response: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    num_turns: Option<u32>,
    #[serde(default)]
    structured_output: Option<Value>,
    #[serde(default)]
    json_schema: Option<Value>,
    #[serde(default)]
    usage: Option<HostUsage>,
}

struct TerminalObservation {
    conversation_id: Option<String>,
    status: Option<HostTerminalStatus>,
    response: Option<String>,
    error: Option<String>,
    usage: Option<HostUsage>,
    worker_turns: u32,
}

struct ParsedStream {
    conversation_id: String,
    status: HostTerminalStatus,
    structured_output: Value,
    usage: HostUsage,
    worker_turns: u32,
    sandboxed: bool,
    tool_events: Vec<HostToolEvent>,
}

fn parse_stream(
    bytes: &[u8],
    expected_schema: &Value,
    expected_cwd: &Path,
) -> Result<ParsedStream, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "Antigravity stream is not valid UTF-8".to_owned())?;
    let mut init = None;
    let mut result = None;
    let mut tool_events = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let event: StreamEnvelope = serde_json::from_str(line)
            .map_err(|error| format!("Antigravity stream contains invalid JSON: {error}"))?;
        match event.event.as_str() {
            "init" => {
                if init
                    .replace(event.init.ok_or_else(|| "init event has no payload".to_owned())?)
                    .is_some()
                {
                    return Err("Antigravity stream contains more than one init event".to_owned());
                }
            }
            "step_update" => {
                let update = event
                    .step_update
                    .ok_or_else(|| "step_update event has no payload".to_owned())?;
                if update.step_type == "tool" {
                    if tool_events.len() >= needle_core::MAX_HOST_TOOL_EVENTS {
                        return Err("Antigravity stream exceeds the tool-event bound".to_owned());
                    }
                    let info = update.tool_info;
                    let name = update
                        .tool_name
                        .or_else(|| info.as_ref().and_then(|value| value.name.clone()))
                        .ok_or_else(|| "tool event has no name".to_owned())?;
                    tool_events.push(HostToolEvent {
                        name,
                        completed: update.state == "DONE",
                        parameters_digest: info
                            .as_ref()
                            .and_then(|value| value.parameters.as_ref())
                            .map(digest_json)
                            .transpose()?,
                        output_digest: info
                            .as_ref()
                            .and_then(|value| value.output.as_ref())
                            .map(digest_json)
                            .transpose()?,
                        failed: info.as_ref().is_some_and(|value| value.error.is_some()),
                    });
                }
            }
            "result" => {
                if result
                    .replace(event.result.ok_or_else(|| "result event has no payload".to_owned())?)
                    .is_some()
                {
                    return Err("Antigravity stream contains more than one result event".to_owned());
                }
            }
            other => return Err(format!("unsupported Antigravity stream event {other}")),
        }
    }
    let init = init.ok_or_else(|| "Antigravity stream has no init event".to_owned())?;
    if init.permission_mode == "always-proceed" {
        return Err("Antigravity stream reports unsafe always-proceed permissions".to_owned());
    }
    if init.cwd != expected_cwd {
        return Err("Antigravity stream cwd differs from the disposable checkout".to_owned());
    }
    if init.json_schema.as_ref() != Some(expected_schema) {
        return Err("Antigravity init schema differs from the requested schema".to_owned());
    }
    let result = result.ok_or_else(|| "Antigravity stream has no terminal result".to_owned())?;
    if result.json_schema.as_ref() != Some(expected_schema) {
        return Err("Antigravity result schema differs from the requested schema".to_owned());
    }
    let status = terminal_status(result.status.as_str())
        .ok_or_else(|| format!("unsupported Antigravity terminal status {}", result.status))?;
    let worker_turns = result.num_turns.unwrap_or_default();
    if worker_turns != 1 {
        return Err(format!(
            "Antigravity result reports {worker_turns} turns for a single-turn execution"
        ));
    }
    let structured_output = result
        .structured_output
        .ok_or_else(|| "Antigravity result has no structured_output".to_owned())?;
    Ok(ParsedStream {
        conversation_id: result.conversation_id,
        status,
        structured_output,
        usage: result.usage.ok_or_else(|| "Antigravity result has no usage metadata".to_owned())?,
        worker_turns,
        sandboxed: true,
        tool_events,
    })
}

fn terminal_observation(bytes: &[u8]) -> Option<TerminalObservation> {
    let text = std::str::from_utf8(bytes).ok()?;
    let result = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<StreamEnvelope>(line).ok())
        .find_map(|event| (event.event == "result").then_some(event.result).flatten())?;
    let conversation_id = (!result.conversation_id.is_empty()
        && result.conversation_id.len() <= MAX_HOST_CONVERSATION_ID_BYTES)
        .then_some(result.conversation_id);
    Some(TerminalObservation {
        conversation_id,
        status: terminal_status(result.status.as_str()),
        response: result.response.map(|value| bounded_text(&value)),
        error: result.error.map(|value| bounded_text(&value)),
        usage: result.usage,
        worker_turns: result.num_turns.unwrap_or_default(),
    })
}

fn terminal_status(status: &str) -> Option<HostTerminalStatus> {
    match status {
        "SUCCESS" => Some(HostTerminalStatus::Success),
        "ERROR" => Some(HostTerminalStatus::Error),
        "CANCELED" => Some(HostTerminalStatus::Canceled),
        "INTERRUPTED" => Some(HostTerminalStatus::Interrupted),
        "INVALID" => Some(HostTerminalStatus::Invalid),
        "WAITING" => Some(HostTerminalStatus::Waiting),
        "RUNNING" => Some(HostTerminalStatus::Running),
        _ => None,
    }
}

fn bounded_text(value: &str) -> String {
    value.chars().take(MAX_HOST_DIAGNOSTIC_BYTES).collect()
}

fn observed_protocol_failure(
    diagnostic: String,
    observation: Option<TerminalObservation>,
    host_version: String,
    duration_ms: u64,
    checkout_cleanup_completed: bool,
) -> AntigravityExecutionFailure {
    let mut failure =
        failure_with_cleanup("host_protocol_invalid", diagnostic, true, checkout_cleanup_completed);
    let mut failure_observation = AntigravityFailureObservation {
        host_version,
        conversation_id: None,
        terminal_status: None,
        usage: None,
        duration_ms,
        worker_turns: 0,
    };
    if let Some(observation) = observation {
        let detail = observation.error.as_deref().or(observation.response.as_deref());
        if let Some(detail) = detail.filter(|value| !value.trim().is_empty()) {
            failure.diagnostic =
                bounded_text(&format!("{}; host detail: {detail}", failure.diagnostic));
        }
        failure_observation.conversation_id = observation.conversation_id;
        failure_observation.terminal_status = observation.status;
        failure_observation.usage = observation.usage;
        failure_observation.worker_turns = observation.worker_turns;
    }
    failure.observation = Some(Box::new(failure_observation));
    failure
}

fn digest_json(value: &Value) -> Result<Digest, String> {
    serde_json::to_vec(value)
        .map(Digest::blake3)
        .map_err(|error| format!("cannot digest Antigravity tool event: {error}"))
}

fn bounded_diagnostic(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim();
    if text.is_empty() {
        "Antigravity CLI exited unsuccessfully".to_owned()
    } else {
        bounded_text(text)
    }
}
