use crate::{AppError, product_data_directory};
use needle_core::{
    ArtifactKind, CanonicalHasher, Digest, MAX_REFRESH_ECONOMIC_COST_MICROUSD,
    MAX_REFRESH_ECONOMIC_LATENCY_MICROS, RefreshCostEvidenceBasis, RefreshEconomicPolicy,
    RefreshEconomicPolicyInput, TestTargetInventoryScope,
};
use needle_runtime::{
    MAX_CARGO_METADATA_INPUT_BYTES, MAX_CARGO_VERSION_BYTES, RepositoryReconciliation,
    RuntimeStore, ShadowCargoTestTargetHostExecution, ShadowCargoTestTargetHostInput,
    ShadowRefreshCostEstimate, ShadowTestTargetRefreshExecution, built_in_action_for_artifact_kind,
    execute_shadow_cargo_test_target_host, reconcile_git_repository,
    test_target_inventory_refresh_definition,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_PROVIDER_TIMEOUT_SECONDS: u64 = 30;
const MAX_PROVIDER_TIMEOUT_SECONDS: u64 = 120;
const MAX_PROVIDER_STDERR_BYTES: usize = 64 * 1024;

pub(crate) fn run(arguments: &[String]) -> Result<(), AppError> {
    if matches!(arguments, [argument] if argument == "--help" || argument == "-h") {
        println!(
            "Usage: needle experiment test-target-refresh-shadow --repository <path> \
             --estimated-fresh-microusd <n> --estimated-refresh-microusd <n> \
             --estimated-refresh-latency-micros <n> --minimum-net-microusd <n> \
             --maximum-refresh-latency-micros <n> --evidence-digest <b3:digest> \
             [--pricing-revision <b3:digest>] [--observed-refresh-cost-microusd <n>] \
             [--provider-timeout-seconds <1..120>] [--cargo <path>] [--data-dir <path>]"
        );
        return Ok(());
    }
    let parsed = Arguments::parse(arguments)?;
    let repository_root = fs::canonicalize(&parsed.repository).map_err(|error| {
        AppError::Runtime(format!(
            "cannot resolve repository {}: {error}",
            parsed.repository.display()
        ))
    })?;
    if !repository_root.is_dir() {
        return Err(AppError::Runtime(format!(
            "repository is not a directory: {}",
            repository_root.display()
        )));
    }
    let data_directory = product_data_directory(arguments)?;
    fs::create_dir_all(&data_directory)?;
    let store = RuntimeStore::new(data_directory.join("needle.sqlite3"));
    store.initialize().map_err(runtime_error)?;

    let started_unix_ms = now_ms()?;
    let before = reconcile_git_repository(&store, &repository_root)
        .map_err(|error| AppError::Runtime(error.to_string()))?;
    let snapshot = acquire_cargo_snapshot(
        &parsed.cargo,
        &repository_root,
        Duration::from_secs(parsed.provider_timeout_seconds),
    )
    .map_err(AppError::Runtime)?;
    let after = reconcile_git_repository(&store, &repository_root)
        .map_err(|error| AppError::Runtime(error.to_string()))?;
    ensure_stable_generation(&before, &after)?;

    let delta = store
        .repository_state_delta(
            after.generation.repository_lineage,
            after.generation.repository_context,
            after.generation.generation,
        )
        .map_err(runtime_error)?;
    let action = built_in_action_for_artifact_kind(&ArtifactKind::test_target_inventory())
        .ok_or_else(|| AppError::Runtime("test-target action is unavailable".to_owned()))?;
    let policy = RefreshEconomicPolicy::new(RefreshEconomicPolicyInput {
        action_operational_policy_digest: action.contract.operational_policy_digest,
        refresh_policy_definition_digest: test_target_inventory_refresh_definition(),
        minimum_expected_net_microusd: parsed.minimum_net_microusd,
        maximum_refresh_latency_micros: Some(parsed.maximum_refresh_latency_micros),
    })
    .map_err(|error| AppError::Runtime(error.to_string()))?;
    let execution_scope_digest = execution_scope_digest(
        after.generation.repository_context.digest(),
        &snapshot.cargo_version,
        &policy,
    );
    let execution = execute_shadow_cargo_test_target_host(
        &store,
        ShadowCargoTestTargetHostInput {
            repository_root: &repository_root,
            generation: &after.generation,
            delta: delta.as_ref(),
            source_selector: "worktree",
            scope: TestTargetInventoryScope::all(),
            metadata_json: &snapshot.metadata_json,
            cargo_version: &snapshot.cargo_version,
            platform: std::env::consts::OS,
            economic_policy: &policy,
            cost_estimate: Some(ShadowRefreshCostEstimate {
                basis: RefreshCostEvidenceBasis::ConfiguredStatic,
                evidence_digest: parsed.evidence_digest,
                pricing_revision: parsed.pricing_revision,
                estimated_fresh_total_microusd: parsed.estimated_fresh_microusd,
                estimated_refresh_total_microusd: parsed.estimated_refresh_microusd,
                estimated_refresh_latency_micros: Some(parsed.estimated_refresh_latency_micros),
            }),
            execution_scope_digest,
            execution_attempts: &[],
            started_unix_ms,
            observed_refresh_cost_microusd: parsed.observed_refresh_cost_microusd,
        },
    )
    .map_err(|error| AppError::Runtime(error.to_string()))?;
    println!("{}", serde_json::to_string_pretty(&project_execution(&execution))?);
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Arguments {
    repository: PathBuf,
    cargo: PathBuf,
    provider_timeout_seconds: u64,
    estimated_fresh_microusd: u64,
    estimated_refresh_microusd: u64,
    estimated_refresh_latency_micros: u64,
    minimum_net_microusd: u64,
    maximum_refresh_latency_micros: u64,
    evidence_digest: Digest,
    pricing_revision: Option<Digest>,
    observed_refresh_cost_microusd: Option<u64>,
}

impl Arguments {
    fn parse(arguments: &[String]) -> Result<Self, AppError> {
        validate_arguments(arguments)?;
        let value = Self {
            repository: PathBuf::from(required(arguments, "--repository")?),
            cargo: PathBuf::from(optional(arguments, "--cargo").unwrap_or_else(|| "cargo".into())),
            provider_timeout_seconds: provider_timeout_seconds(arguments)?,
            estimated_fresh_microusd: required_u64(arguments, "--estimated-fresh-microusd")?,
            estimated_refresh_microusd: required_u64(arguments, "--estimated-refresh-microusd")?,
            estimated_refresh_latency_micros: required_u64(
                arguments,
                "--estimated-refresh-latency-micros",
            )?,
            minimum_net_microusd: required_u64(arguments, "--minimum-net-microusd")?,
            maximum_refresh_latency_micros: required_u64(
                arguments,
                "--maximum-refresh-latency-micros",
            )?,
            evidence_digest: required_digest(arguments, "--evidence-digest")?,
            pricing_revision: optional(arguments, "--pricing-revision")
                .map(|value| parse_digest(&value, "--pricing-revision"))
                .transpose()?,
            observed_refresh_cost_microusd: optional_u64(
                arguments,
                "--observed-refresh-cost-microusd",
            )?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), AppError> {
        for (name, value) in [
            ("--estimated-fresh-microusd", self.estimated_fresh_microusd),
            ("--estimated-refresh-microusd", self.estimated_refresh_microusd),
            ("--minimum-net-microusd", self.minimum_net_microusd),
        ] {
            if value > MAX_REFRESH_ECONOMIC_COST_MICROUSD {
                return Err(AppError::Usage(format!("{name} exceeds the economic bound")));
            }
        }
        if self
            .observed_refresh_cost_microusd
            .is_some_and(|value| value > MAX_REFRESH_ECONOMIC_COST_MICROUSD)
        {
            return Err(AppError::Usage(
                "--observed-refresh-cost-microusd exceeds the economic bound".to_owned(),
            ));
        }
        for (name, value) in [
            ("--estimated-refresh-latency-micros", self.estimated_refresh_latency_micros),
            ("--maximum-refresh-latency-micros", self.maximum_refresh_latency_micros),
        ] {
            if value > MAX_REFRESH_ECONOMIC_LATENCY_MICROS {
                return Err(AppError::Usage(format!("{name} exceeds the latency bound")));
            }
        }
        Ok(())
    }
}

fn validate_arguments(arguments: &[String]) -> Result<(), AppError> {
    const OPTIONS: &[&str] = &[
        "--repository",
        "--data-dir",
        "--cargo",
        "--provider-timeout-seconds",
        "--estimated-fresh-microusd",
        "--estimated-refresh-microusd",
        "--estimated-refresh-latency-micros",
        "--minimum-net-microusd",
        "--maximum-refresh-latency-micros",
        "--evidence-digest",
        "--pricing-revision",
        "--observed-refresh-cost-microusd",
    ];
    let mut index = 0;
    let mut seen = BTreeSet::new();
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if !OPTIONS.contains(&argument) {
            return Err(AppError::Usage(format!(
                "unknown test-target-refresh-shadow argument `{argument}`"
            )));
        }
        if arguments.get(index + 1).is_none() {
            return Err(AppError::Usage(format!("{argument} requires a value")));
        }
        if !seen.insert(argument) {
            return Err(AppError::Usage(format!("duplicate argument `{argument}`")));
        }
        index += 2;
    }
    Ok(())
}

fn ensure_stable_generation(
    before: &RepositoryReconciliation,
    after: &RepositoryReconciliation,
) -> Result<(), AppError> {
    if before.generation != after.generation {
        return Err(AppError::Runtime(
            "repository changed while the Cargo provider snapshot was being acquired; retry"
                .to_owned(),
        ));
    }
    Ok(())
}

fn provider_timeout_seconds(arguments: &[String]) -> Result<u64, AppError> {
    let value = optional_u64(arguments, "--provider-timeout-seconds")?
        .unwrap_or(DEFAULT_PROVIDER_TIMEOUT_SECONDS);
    if !(1..=MAX_PROVIDER_TIMEOUT_SECONDS).contains(&value) {
        return Err(AppError::Usage(format!(
            "--provider-timeout-seconds must be between 1 and {MAX_PROVIDER_TIMEOUT_SECONDS}"
        )));
    }
    Ok(value)
}

struct CargoSnapshot {
    metadata_json: Vec<u8>,
    cargo_version: String,
}

fn acquire_cargo_snapshot(
    cargo: &Path,
    repository_root: &Path,
    timeout: Duration,
) -> Result<CargoSnapshot, String> {
    acquire_cargo_snapshot_with(|arguments, maximum| {
        run_bounded_cargo(cargo, repository_root, arguments, maximum, timeout)
    })
}

fn acquire_cargo_snapshot_with<F>(mut run: F) -> Result<CargoSnapshot, String>
where
    F: FnMut(&[&str], usize) -> Result<Vec<u8>, String>,
{
    let version_bytes = run(&["--version"], MAX_CARGO_VERSION_BYTES)?;
    let cargo_version = std::str::from_utf8(&version_bytes)
        .map_err(|_| "cargo --version output is not UTF-8".to_owned())?
        .trim()
        .to_owned();
    if cargo_version.is_empty()
        || cargo_version.len() > MAX_CARGO_VERSION_BYTES
        || cargo_version.chars().any(char::is_control)
    {
        return Err("cargo --version output is outside the provider bound".to_owned());
    }
    let metadata_json = run(
        &["metadata", "--format-version", "1", "--no-deps", "--locked"],
        MAX_CARGO_METADATA_INPUT_BYTES,
    )?;
    Ok(CargoSnapshot { metadata_json, cargo_version })
}

fn run_bounded_cargo(
    cargo: &Path,
    repository_root: &Path,
    arguments: &[&str],
    maximum_stdout_bytes: usize,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let mut command = Command::new(cargo);
    command
        .args(arguments)
        .current_dir(repository_root)
        .env("CARGO_NET_OFFLINE", "true")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        format!("cannot launch {} {}: {error}", cargo.display(), arguments.join(" "))
    })?;
    let stdout = child.stdout.take().ok_or_else(|| "cargo stdout is unavailable".to_owned())?;
    let stderr = child.stderr.take().ok_or_else(|| "cargo stderr is unavailable".to_owned())?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, maximum_stdout_bytes));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, MAX_PROVIDER_STDERR_BYTES));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(format!("cargo provider timed out after {} seconds", timeout.as_secs()));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = join_reader(stdout_reader, "stdout")?;
    let stderr = join_reader(stderr_reader, "stderr")?;
    if stdout.overflow || stderr.overflow {
        return Err("cargo provider output exceeded its bound".to_owned());
    }
    if !status.success() {
        let detail = String::from_utf8_lossy(&stderr.bytes);
        return Err(format!(
            "cargo {} failed with {status}: {}",
            arguments.join(" "),
            detail.trim()
        ));
    }
    Ok(stdout.bytes)
}

struct BoundedRead {
    bytes: Vec<u8>,
    overflow: bool,
}

fn read_bounded(mut reader: impl Read, maximum: usize) -> std::io::Result<BoundedRead> {
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    reader.by_ref().take((maximum as u64).saturating_add(1)).read_to_end(&mut bytes)?;
    let overflow = bytes.len() > maximum;
    if overflow {
        bytes.truncate(maximum);
    }
    Ok(BoundedRead { bytes, overflow })
}

fn join_reader(
    handle: thread::JoinHandle<std::io::Result<BoundedRead>>,
    stream: &str,
) -> Result<BoundedRead, String> {
    handle
        .join()
        .map_err(|_| format!("cargo {stream} reader panicked"))?
        .map_err(|error| format!("cannot read cargo {stream}: {error}"))
}

fn project_execution(execution: &ShadowCargoTestTargetHostExecution) -> Value {
    match execution {
        ShadowCargoTestTargetHostExecution::BootstrapPublished {
            publication,
            repository_generation,
        } => publication_json("bootstrap_published", *repository_generation, publication),
        ShadowCargoTestTargetHostExecution::PriorRemainsCurrent {
            publication,
            repository_generation,
        } => publication_json("prior_remains_current", *repository_generation, publication),
        ShadowCargoTestTargetHostExecution::RebaselinePublished {
            publication,
            repository_generation,
            trigger,
        } => {
            let mut value =
                publication_json("rebaseline_published", *repository_generation, publication);
            value["trigger"] = json!(match trigger {
                needle_runtime::ShadowCargoTestTargetHostRebaseline::GenerationGap => {
                    "generation_gap"
                }
                needle_runtime::ShadowCargoTestTargetHostRebaseline::MissingAdjacentDelta => {
                    "missing_adjacent_delta"
                }
                needle_runtime::ShadowCargoTestTargetHostRebaseline::DefinitionSetChanged => {
                    "definition_set_changed"
                }
            });
            value
        }
        ShadowCargoTestTargetHostExecution::RefreshExecuted {
            execution,
            from_repository_generation,
            to_repository_generation,
        } => {
            let (status, publication, attempt, assessment) = match execution {
                ShadowTestTargetRefreshExecution::RefreshPublished {
                    publication,
                    attempt,
                    assessment,
                } => (
                    "refresh_published",
                    publication,
                    Some(attempt.to_string()),
                    Some(assessment.to_string()),
                ),
                ShadowTestTargetRefreshExecution::FullComputePublished {
                    publication,
                    assessment,
                    ..
                } => (
                    "full_compute_published",
                    publication,
                    None,
                    assessment.map(|value| value.to_string()),
                ),
                ShadowTestTargetRefreshExecution::PriorRemainsCurrent { publication, .. } => {
                    ("prior_remains_current", publication, None, None)
                }
            };
            let mut value = publication_json(status, *to_repository_generation, publication);
            value["from_repository_generation"] = json!(from_repository_generation);
            value["attempt_id"] = json!(attempt);
            value["assessment_digest"] = json!(assessment);
            value
        }
    }
}

fn publication_json(
    status: &str,
    repository_generation: u64,
    publication: &needle_runtime::ShadowTestTargetPublicationReceipt,
) -> Value {
    json!({
        "status": status,
        "authority": "shadow",
        "repository_generation": repository_generation,
        "request_id": publication.request.to_string(),
        "artifact_id": publication.artifact.to_string(),
        "validation_certificate_id": publication.validation_certificate.to_string(),
        "descriptor_digest": publication.descriptor_definition_digest.to_string(),
        "partition_manifest_id": publication.partition_manifest.to_string(),
        "content_digest": publication.content_digest.to_string(),
    })
}

fn execution_scope_digest(
    repository_context: Digest,
    cargo_version: &str,
    policy: &RefreshEconomicPolicy,
) -> Digest {
    let mut hasher = CanonicalHasher::new(b"test-target-refresh-shadow-cli-scope-v1");
    hasher.field_digest(repository_context);
    hasher.field_str(cargo_version);
    hasher.field_digest(policy.definition_digest);
    hasher.finish()
}

fn required(arguments: &[String], name: &str) -> Result<String, AppError> {
    optional(arguments, name).ok_or_else(|| AppError::Usage(format!("{name} is required")))
}

fn optional(arguments: &[String], name: &str) -> Option<String> {
    arguments.windows(2).find(|pair| pair[0] == name).map(|pair| pair[1].clone())
}

fn required_u64(arguments: &[String], name: &str) -> Result<u64, AppError> {
    let value = required(arguments, name)?;
    parse_u64(&value, name)
}

fn optional_u64(arguments: &[String], name: &str) -> Result<Option<u64>, AppError> {
    optional(arguments, name).map(|value| parse_u64(&value, name)).transpose()
}

fn parse_u64(value: &str, name: &str) -> Result<u64, AppError> {
    value.parse().map_err(|error| AppError::Usage(format!("invalid {name}: {error}")))
}

fn required_digest(arguments: &[String], name: &str) -> Result<Digest, AppError> {
    parse_digest(&required(arguments, name)?, name)
}

fn parse_digest(value: &str, name: &str) -> Result<Digest, AppError> {
    let digest = Digest::parse(value)
        .map_err(|error| AppError::Usage(format!("invalid {name}: {error}")))?;
    if digest == Digest([0; 32]) {
        return Err(AppError::Usage(format!("{name} must not be the zero digest")));
    }
    Ok(digest)
}

fn now_ms() -> Result<u64, AppError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::Runtime("system clock precedes the Unix epoch".to_owned()))?
        .as_millis()
        .try_into()
        .map_err(|_| AppError::Runtime("system clock exceeds the runtime bound".to_owned()))
}

fn runtime_error(error: needle_runtime::StoreError) -> AppError {
    AppError::Runtime(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn required_arguments() -> Vec<String> {
        vec![
            "--repository",
            ".",
            "--estimated-fresh-microusd",
            "1000",
            "--estimated-refresh-microusd",
            "200",
            "--estimated-refresh-latency-micros",
            "10000",
            "--minimum-net-microusd",
            "100",
            "--maximum-refresh-latency-micros",
            "50000",
            "--evidence-digest",
            &Digest::blake3(b"evidence").to_string(),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn arguments_require_explicit_cost_evidence_and_reject_unknown_options() {
        let parsed = Arguments::parse(&required_arguments()).unwrap();
        assert_eq!(parsed.estimated_fresh_microusd, 1_000);
        let mut missing = required_arguments();
        missing.truncate(missing.len() - 2);
        assert!(Arguments::parse(&missing).is_err());
        let mut unknown = required_arguments();
        unknown.extend(["--automatic".to_owned(), "true".to_owned()]);
        assert!(Arguments::parse(&unknown).is_err());
        let mut duplicate = required_arguments();
        duplicate.extend(["--repository".to_owned(), ".".to_owned()]);
        assert!(Arguments::parse(&duplicate).is_err());
        let mut oversized = required_arguments();
        let index =
            oversized.iter().position(|argument| argument == "--estimated-fresh-microusd").unwrap();
        oversized[index + 1] = u64::MAX.to_string();
        assert!(Arguments::parse(&oversized).is_err());
    }

    #[test]
    fn provider_acquisition_uses_the_closed_read_only_cargo_surface() {
        let mut calls = Vec::new();
        let snapshot = acquire_cargo_snapshot_with(|arguments, maximum| {
            calls.push((
                arguments.iter().map(|value| (*value).to_owned()).collect::<Vec<_>>(),
                maximum,
            ));
            if arguments == ["--version"] {
                Ok(b"cargo 1.90.0\n".to_vec())
            } else {
                Ok(br#"{"packages":[],"workspace_members":[],"workspace_root":"C:/repo"}"#.to_vec())
            }
        })
        .unwrap();
        assert_eq!(snapshot.cargo_version, "cargo 1.90.0");
        assert_eq!(calls[0].0, ["--version"]);
        assert_eq!(calls[1].0, ["metadata", "--format-version", "1", "--no-deps", "--locked"]);
        assert_eq!(calls[1].1, MAX_CARGO_METADATA_INPUT_BYTES);
    }

    #[test]
    fn bounded_reader_reports_overflow_without_retaining_the_excess() {
        let read = read_bounded(&b"12345"[..], 4).unwrap();
        assert!(read.overflow);
        assert_eq!(read.bytes, b"1234");
    }
}
