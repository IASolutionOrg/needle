use needle_bench::{
    LiveCargoSnapshot, LiveRefreshCostProvenanceInput, LiveRefreshMutationObservation,
    LiveTestTargetRefreshCalibrationInput, MAX_LIVE_TEST_TARGET_REFRESH_REPORT_BYTES,
    evaluate_live_test_target_refresh_calibration,
};
use needle_core::{
    DependencyLocator, Digest, MAX_REFRESH_ECONOMIC_COST_MICROUSD,
    MAX_REFRESH_ECONOMIC_LATENCY_MICROS,
};
use needle_runtime::{
    MAX_CARGO_METADATA_INPUT_BYTES, MAX_CARGO_VERSION_BYTES, MAX_TEST_TARGET_MANIFEST_BYTES,
};
use std::collections::BTreeSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_PROVIDER_TIMEOUT_SECONDS: u64 = 30;
const MAX_PROVIDER_TIMEOUT_SECONDS: u64 = 120;
const DEFAULT_SAMPLES: usize = 12;
const DEFAULT_P95_BUDGET_MICROS: u64 = 250_000;
const MAX_PROCESS_STDERR_BYTES: usize = 64 * 1024;
const MAX_GIT_OUTPUT_BYTES: usize = 256 * 1024;
const CALIBRATION_COMMENT: &[u8] = b"# Needle Gate A4 paired Shadow calibration mutation.\n";

fn main() {
    if let Err(error) = run() {
        eprintln!("test-target-inventory-refresh-live: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse(env::args().skip(1))?;
    let workspace = env::current_dir()?.canonicalize()?;
    let repository_root = fs::canonicalize(&arguments.repository)?;
    if !repository_root.is_dir() {
        return Err("the calibration repository must be a directory".into());
    }
    let output = safe_absolute_from(
        &workspace,
        arguments
            .output
            .clone()
            .unwrap_or_else(|| PathBuf::from("target/test-target-refresh-live/calibration.json")),
    )?;
    if output.starts_with(&repository_root) {
        return Err("the report output must be outside the measured repository".into());
    }
    let timeout = Duration::from_secs(arguments.provider_timeout_seconds);
    let before = source_state(&repository_root, timeout)?;
    if !before.changed_paths.is_empty() {
        return Err("the calibration repository must start clean".into());
    }
    let changed_path = arguments
        .changed_paths
        .iter()
        .next()
        .expect("argument validation requires one changed path");
    ensure_tracked_path(&repository_root, changed_path, timeout)?;
    let mutation_path = repository_root.join(changed_path);
    let original = read_bounded_file(&mutation_path, MAX_TEST_TARGET_MANIFEST_BYTES)?;

    let evaluation = evaluate_live_test_target_refresh_calibration(
        LiveTestTargetRefreshCalibrationInput {
            prior_repository_root: &repository_root,
            current_repository_root: &repository_root,
            source_repository: &arguments.source_repository,
            source_sha: &before.head,
            changed_paths: arguments.changed_paths.iter().cloned().collect(),
            samples: arguments.samples,
            p95_budget_micros: arguments.p95_budget_micros,
            provider_timeout_seconds: arguments.provider_timeout_seconds,
            platform: std::env::consts::OS,
            cost_provenance: arguments.cost_provenance(),
        },
        |root| acquire_cargo_snapshot(&arguments.cargo, root, timeout),
        || {
            let mutation = apply_calibration_comment(&mutation_path, &original)?;
            let current = source_state(&repository_root, timeout)?;
            if current.head != before.head || current.changed_paths != arguments.changed_paths {
                return Err(
                    "the activated mutation does not exactly match the declaration".to_owned()
                );
            }
            Ok(mutation)
        },
    );

    fs::write(&mutation_path, &original)?;
    let after = source_state(&repository_root, timeout)?;
    if after != before {
        return Err("the repository did not return to its exact clean source state".into());
    }
    let report = evaluation?;
    write_report_create_new(&output, &report)?;
    println!("{}", output.display());
    println!("report_digest={}", report.report_digest);
    println!("fresh_p95_micros={}", report.fresh_p95_micros);
    println!("refresh_p95_micros={}", report.refresh_p95_micros);
    println!("gate_a4_observation_eligible={}", report.gate_a4_observation_eligible);
    println!("gate_a4_closed={}", report.gate_a4_closed);
    if arguments.require_observation_pass && !report.gate_a4_observation_eligible {
        return Err("the live Shadow observation did not satisfy Gate A4 criteria".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceState {
    head: String,
    changed_paths: BTreeSet<String>,
}

fn source_state(repository: &Path, timeout: Duration) -> Result<SourceState, String> {
    let head = run_bounded_process(
        Path::new("git"),
        repository,
        &["rev-parse", "HEAD"],
        MAX_GIT_OUTPUT_BYTES,
        timeout,
        false,
    )?;
    let head = std::str::from_utf8(&head)
        .map_err(|_| "git HEAD is not UTF-8".to_owned())?
        .trim()
        .to_ascii_lowercase();
    if !valid_git_sha(&head) {
        return Err("git HEAD is not a full SHA".to_owned());
    }
    let status = run_bounded_process(
        Path::new("git"),
        repository,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"],
        MAX_GIT_OUTPUT_BYTES,
        timeout,
        false,
    )?;
    Ok(SourceState { head, changed_paths: parse_status_paths(&status)? })
}

fn parse_status_paths(bytes: &[u8]) -> Result<BTreeSet<String>, String> {
    let mut paths = BTreeSet::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let relative_end = bytes[offset..]
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| "git status output is not NUL terminated".to_owned())?;
        let end = offset + relative_end;
        let record = &bytes[offset..end];
        if record.len() < 4 || record[2] != b' ' {
            return Err("git status emitted an unsupported record".to_owned());
        }
        if matches!(record[0], b'R' | b'C') || matches!(record[1], b'R' | b'C') {
            return Err("renamed or copied paths are not supported by this calibration".to_owned());
        }
        let path = std::str::from_utf8(&record[3..])
            .map_err(|_| "git status path is not UTF-8".to_owned())?
            .replace('\\', "/");
        if path.is_empty() || !paths.insert(path) {
            return Err("git status paths are empty or duplicated".to_owned());
        }
        offset = end + 1;
    }
    Ok(paths)
}

fn ensure_tracked_path(repository: &Path, path: &str, timeout: Duration) -> Result<(), String> {
    run_bounded_process(
        Path::new("git"),
        repository,
        &["ls-files", "--error-unmatch", "--", path],
        MAX_GIT_OUTPUT_BYTES,
        timeout,
        false,
    )?;
    Ok(())
}

fn read_bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("cannot inspect mutation source {}: {error}", path.display()))?;
    if metadata.len() > maximum as u64 {
        return Err("mutation source exceeds the manifest byte bound".to_owned());
    }
    let file = fs::File::open(path)
        .map_err(|error| format!("cannot read mutation source {}: {error}", path.display()))?;
    let read = read_bounded(file, maximum).map_err(|error| error.to_string())?;
    if read.overflow {
        return Err("mutation source exceeds the manifest byte bound".to_owned());
    }
    Ok(read.bytes)
}

fn apply_calibration_comment(
    path: &Path,
    original: &[u8],
) -> Result<LiveRefreshMutationObservation, String> {
    if path.file_name().and_then(|value| value.to_str()) != Some("Cargo.toml")
        || original.windows(CALIBRATION_COMMENT.len()).any(|window| window == CALIBRATION_COMMENT)
    {
        return Err("the calibration mutation requires an unmodified Cargo.toml".to_owned());
    }
    let extra_newline = usize::from(!original.ends_with(b"\n"));
    let current_len = original
        .len()
        .checked_add(extra_newline)
        .and_then(|value| value.checked_add(CALIBRATION_COMMENT.len()))
        .ok_or_else(|| "calibration mutation size overflow".to_owned())?;
    if current_len > MAX_TEST_TARGET_MANIFEST_BYTES {
        return Err("calibration mutation would exceed the manifest byte bound".to_owned());
    }
    let mut current = Vec::with_capacity(current_len);
    current.extend_from_slice(original);
    if extra_newline != 0 {
        current.push(b'\n');
    }
    current.extend_from_slice(CALIBRATION_COMMENT);
    fs::write(path, &current)
        .map_err(|error| format!("cannot activate calibration mutation: {error}"))?;
    Ok(LiveRefreshMutationObservation {
        definition_digest: Digest::blake3(b"append-inert-cargo-manifest-comment-v1"),
        prior_content_digest: Digest::blake3(original),
        current_content_digest: Digest::blake3(&current),
    })
}

fn acquire_cargo_snapshot(
    cargo: &Path,
    repository: &Path,
    timeout: Duration,
) -> Result<LiveCargoSnapshot, String> {
    let version = run_bounded_process(
        cargo,
        repository,
        &["--version"],
        MAX_CARGO_VERSION_BYTES,
        timeout,
        true,
    )?;
    let cargo_version = std::str::from_utf8(&version)
        .map_err(|_| "cargo --version output is not UTF-8".to_owned())?
        .trim()
        .to_owned();
    if cargo_version.is_empty()
        || cargo_version.len() > MAX_CARGO_VERSION_BYTES
        || cargo_version.chars().any(char::is_control)
    {
        return Err("cargo --version output is outside the provider bound".to_owned());
    }
    let metadata_json = run_bounded_process(
        cargo,
        repository,
        &["metadata", "--format-version", "1", "--no-deps", "--locked"],
        MAX_CARGO_METADATA_INPUT_BYTES,
        timeout,
        true,
    )?;
    Ok(LiveCargoSnapshot { metadata_json, cargo_version })
}

fn run_bounded_process(
    program: &Path,
    repository: &Path,
    arguments: &[&str],
    maximum_stdout_bytes: usize,
    timeout: Duration,
    cargo_offline: bool,
) -> Result<Vec<u8>, String> {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .current_dir(repository)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if cargo_offline {
        command.env("CARGO_NET_OFFLINE", "true");
    } else {
        command.env("GIT_OPTIONAL_LOCKS", "0");
    }
    let mut child = command.spawn().map_err(|error| {
        format!("cannot launch {} {}: {error}", program.display(), arguments.join(" "))
    })?;
    let stdout = child.stdout.take().ok_or_else(|| "process stdout is unavailable".to_owned())?;
    let stderr = child.stderr.take().ok_or_else(|| "process stderr is unavailable".to_owned())?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, maximum_stdout_bytes));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, MAX_PROCESS_STDERR_BYTES));
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
            return Err(format!("process timed out after {} seconds", timeout.as_secs()));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = join_reader(stdout_reader, "stdout")?;
    let stderr = join_reader(stderr_reader, "stderr")?;
    if stdout.overflow || stderr.overflow {
        return Err("process output exceeded its bound".to_owned());
    }
    if !status.success() {
        return Err(format!(
            "{} {} failed with {status}: {}",
            program.display(),
            arguments.join(" "),
            String::from_utf8_lossy(&stderr.bytes).trim()
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
        .map_err(|_| format!("process {stream} reader panicked"))?
        .map_err(|error| format!("cannot read process {stream}: {error}"))
}

fn write_report_create_new(
    path: &Path,
    report: &needle_bench::LiveTestTargetRefreshCalibrationReport,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = serde_json::to_vec_pretty(report)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_LIVE_TEST_TARGET_REFRESH_REPORT_BYTES {
        return Err("serialized report exceeds its wire bound".into());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Arguments {
    repository: PathBuf,
    source_repository: String,
    changed_paths: BTreeSet<String>,
    cargo: PathBuf,
    provider_timeout_seconds: u64,
    samples: usize,
    p95_budget_micros: u64,
    output: Option<PathBuf>,
    require_observation_pass: bool,
    observed_fresh_microusd: Option<u64>,
    observed_refresh_microusd: Option<u64>,
    pricing_revision: Option<Digest>,
    cost_evidence_digest: Option<Digest>,
}

impl Arguments {
    fn parse(values: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut values = values.peekable();
        let mut repository = None;
        let mut source_repository = None;
        let mut changed_paths = BTreeSet::new();
        let mut cargo = None;
        let mut provider_timeout_seconds = None;
        let mut samples = None;
        let mut p95_budget_micros = None;
        let mut output = None;
        let mut require_observation_pass = false;
        let mut observed_fresh_microusd = None;
        let mut observed_refresh_microusd = None;
        let mut pricing_revision = None;
        let mut cost_evidence_digest = None;
        while let Some(argument) = values.next() {
            match argument.as_str() {
                "--repository" => {
                    set_once(&mut repository, next_path(&mut values, &argument)?, &argument)?
                }
                "--source-repository" => set_once(
                    &mut source_repository,
                    next_value(&mut values, &argument)?,
                    &argument,
                )?,
                "--changed-path" => {
                    let path = next_value(&mut values, &argument)?.replace('\\', "/");
                    if !changed_paths.insert(path) {
                        return Err("duplicate --changed-path".to_owned());
                    }
                }
                "--cargo" => set_once(&mut cargo, next_path(&mut values, &argument)?, &argument)?,
                "--provider-timeout-seconds" => set_once(
                    &mut provider_timeout_seconds,
                    parse_u64(&mut values, &argument)?,
                    &argument,
                )?,
                "--samples" => {
                    set_once(&mut samples, parse_usize(&mut values, &argument)?, &argument)?
                }
                "--p95-budget-micros" => {
                    set_once(&mut p95_budget_micros, parse_u64(&mut values, &argument)?, &argument)?
                }
                "--output" => set_once(&mut output, next_path(&mut values, &argument)?, &argument)?,
                "--require-observation-pass" => {
                    if require_observation_pass {
                        return Err("duplicate --require-observation-pass".to_owned());
                    }
                    require_observation_pass = true;
                }
                "--observed-fresh-microusd" => set_once(
                    &mut observed_fresh_microusd,
                    parse_u64(&mut values, &argument)?,
                    &argument,
                )?,
                "--observed-refresh-microusd" => set_once(
                    &mut observed_refresh_microusd,
                    parse_u64(&mut values, &argument)?,
                    &argument,
                )?,
                "--pricing-revision" => set_once(
                    &mut pricing_revision,
                    parse_digest(&mut values, &argument)?,
                    &argument,
                )?,
                "--cost-evidence-digest" => set_once(
                    &mut cost_evidence_digest,
                    parse_digest(&mut values, &argument)?,
                    &argument,
                )?,
                _ => return Err(format!("unknown argument `{argument}`")),
            }
        }
        let value = Self {
            repository: required(repository, "--repository")?,
            source_repository: required(source_repository, "--source-repository")?,
            changed_paths,
            cargo: cargo.unwrap_or_else(|| PathBuf::from("cargo")),
            provider_timeout_seconds: provider_timeout_seconds
                .unwrap_or(DEFAULT_PROVIDER_TIMEOUT_SECONDS),
            samples: samples.unwrap_or(DEFAULT_SAMPLES),
            p95_budget_micros: p95_budget_micros.unwrap_or(DEFAULT_P95_BUDGET_MICROS),
            output,
            require_observation_pass,
            observed_fresh_microusd,
            observed_refresh_microusd,
            pricing_revision,
            cost_evidence_digest,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), String> {
        if self.source_repository.is_empty()
            || self.source_repository.chars().any(char::is_control)
            || self.changed_paths.len() != 1
            || self.changed_paths.iter().any(|path| {
                Path::new(path).file_name().and_then(|value| value.to_str()) != Some("Cargo.toml")
                    || DependencyLocator::repository_path(path).is_err()
            })
            || !(1..=MAX_PROVIDER_TIMEOUT_SECONDS).contains(&self.provider_timeout_seconds)
            || self.samples < needle_bench::MIN_LIVE_TEST_TARGET_REFRESH_SAMPLES
            || self.samples > needle_bench::MAX_LIVE_TEST_TARGET_REFRESH_SAMPLES
            || self.p95_budget_micros == 0
            || self.p95_budget_micros > MAX_REFRESH_ECONOMIC_LATENCY_MICROS
        {
            return Err("live calibration arguments are missing or outside their bounds".to_owned());
        }
        let cost_fields = [
            self.observed_fresh_microusd.is_some(),
            self.observed_refresh_microusd.is_some(),
            self.pricing_revision.is_some(),
            self.cost_evidence_digest.is_some(),
        ];
        if cost_fields.iter().any(|present| *present) && !cost_fields.iter().all(|present| *present)
        {
            return Err(
                "cost provenance requires both observed costs, pricing revision, and evidence digest"
                    .to_owned(),
            );
        }
        if self
            .observed_fresh_microusd
            .into_iter()
            .chain(self.observed_refresh_microusd)
            .any(|value| value > MAX_REFRESH_ECONOMIC_COST_MICROUSD)
        {
            return Err("observed cost exceeds the core economic bound".to_owned());
        }
        Ok(())
    }

    fn cost_provenance(&self) -> Option<LiveRefreshCostProvenanceInput> {
        Some(LiveRefreshCostProvenanceInput {
            observed_fresh_microusd: self.observed_fresh_microusd?,
            observed_refresh_microusd: self.observed_refresh_microusd?,
            pricing_revision: self.pricing_revision?,
            evidence_digest: self.cost_evidence_digest?,
        })
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("duplicate {flag}"));
    }
    Ok(())
}

fn required<T>(value: Option<T>, flag: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("{flag} is required"))
}

fn next_value(
    values: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    flag: &str,
) -> Result<String, String> {
    values.next().ok_or_else(|| format!("{flag} requires a value"))
}

fn next_path(
    values: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    flag: &str,
) -> Result<PathBuf, String> {
    next_value(values, flag).map(PathBuf::from)
}

fn parse_u64(
    values: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    flag: &str,
) -> Result<u64, String> {
    next_value(values, flag)?.parse().map_err(|_| format!("{flag} must be a u64"))
}

fn parse_usize(
    values: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    flag: &str,
) -> Result<usize, String> {
    next_value(values, flag)?.parse().map_err(|_| format!("{flag} must be a usize"))
}

fn parse_digest(
    values: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    flag: &str,
) -> Result<Digest, String> {
    let value = next_value(values, flag)?;
    let digest = Digest::parse(&value).map_err(|_| format!("{flag} must be a b3 digest"))?;
    if digest == Digest([0; 32]) {
        return Err(format!("{flag} must not be zero"));
    }
    Ok(digest)
}

fn safe_absolute_from(workspace: &Path, path: PathBuf) -> Result<PathBuf, String> {
    if path.components().any(|component| matches!(component, std::path::Component::ParentDir)) {
        return Err("the report output must not contain parent-directory components".to_owned());
    }
    Ok(if path.is_absolute() { path } else { workspace.join(path) })
}

fn valid_git_sha(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn required_arguments() -> Vec<String> {
        vec![
            "--repository".to_owned(),
            "repository".to_owned(),
            "--source-repository".to_owned(),
            "https://github.com/dtolnay/thiserror".to_owned(),
            "--changed-path".to_owned(),
            "impl/Cargo.toml".to_owned(),
        ]
    }

    #[test]
    fn arguments_are_closed_and_cost_provenance_is_all_or_none() {
        assert!(Arguments::parse(required_arguments().into_iter()).is_ok());
        let mut unknown = required_arguments();
        unknown.push("--unknown".to_owned());
        assert!(Arguments::parse(unknown.into_iter()).is_err());
        let mut incomplete_cost = required_arguments();
        incomplete_cost.extend(["--observed-fresh-microusd".to_owned(), "10".to_owned()]);
        assert!(Arguments::parse(incomplete_cost.into_iter()).is_err());
    }

    #[test]
    fn arguments_require_exactly_one_cargo_manifest_mutation() {
        let mut non_manifest = required_arguments();
        let index = non_manifest.iter().position(|value| value == "impl/Cargo.toml").unwrap();
        non_manifest[index] = "README.md".to_owned();
        assert!(Arguments::parse(non_manifest.into_iter()).is_err());

        let mut multiple = required_arguments();
        multiple.extend(["--changed-path".to_owned(), "other/Cargo.toml".to_owned()]);
        assert!(Arguments::parse(multiple.into_iter()).is_err());

        let mut escaping = required_arguments();
        let index = escaping.iter().position(|value| value == "impl/Cargo.toml").unwrap();
        escaping[index] = "../outside/Cargo.toml".to_owned();
        assert!(Arguments::parse(escaping.into_iter()).is_err());
        assert!(
            safe_absolute_from(Path::new("C:/workspace"), PathBuf::from("../report.json")).is_err()
        );
    }

    #[test]
    fn status_parser_is_nul_bounded_and_rejects_renames() {
        assert_eq!(
            parse_status_paths(b" M impl/Cargo.toml\0?? new.txt\0").unwrap(),
            BTreeSet::from(["impl/Cargo.toml".to_owned(), "new.txt".to_owned()])
        );
        assert!(parse_status_paths(b"R  new.txt\0old.txt\0").is_err());
        assert!(parse_status_paths(b" M unterminated").is_err());
    }
}
