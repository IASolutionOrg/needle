use needle_bench::{
    LiveTestTargetRefreshCalibrationReport, LiveTestTargetRefreshGateAcceptance,
    MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_BYTES, MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTED_REPORTS,
    MAX_LIVE_TEST_TARGET_REFRESH_REPORT_BYTES, read_bounded_file,
};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SOURCE_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_GIT_OUTPUT_BYTES: usize = 256 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("test-target-inventory-refresh-live-accept: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse(env::args().skip(1))?;
    arguments.validate()?;
    let workspace = arguments.workspace_root.unwrap_or(env::current_dir()?).canonicalize()?;
    let reviewer_id = required(arguments.reviewer_id, "--reviewer-id")?;
    let reviewed_unix_ms = required(arguments.reviewed_unix_ms, "--reviewed-unix-ms")?;
    let output = safe_absolute_from(
        &workspace,
        arguments.output.unwrap_or_else(|| {
            PathBuf::from("target/test-target-refresh-live/gate-a4-acceptance.json")
        }),
    )?;

    let mut reports = Vec::with_capacity(arguments.reports.len());
    let mut source_bindings = Vec::with_capacity(arguments.reports.len());
    for (report_path, source_checkout) in
        arguments.reports.into_iter().zip(arguments.source_checkouts)
    {
        let report_path = absolute_from(&workspace, report_path);
        let source_checkout = absolute_from(&workspace, source_checkout).canonicalize()?;
        if !source_checkout.is_dir() {
            return Err("every --source-checkout must be a directory".into());
        }
        if output.starts_with(&source_checkout) {
            return Err("the acceptance output must be outside every reviewed checkout".into());
        }
        let report = LiveTestTargetRefreshCalibrationReport::decode_json(&read_bounded_file(
            &report_path,
            MAX_LIVE_TEST_TARGET_REFRESH_REPORT_BYTES,
        )?)?;
        verify_clean_source(&source_checkout, &report)?;
        source_bindings.push((
            source_checkout,
            report.source_repository.clone(),
            report.source_sha.clone(),
        ));
        reports.push(report);
    }

    let acceptance = LiveTestTargetRefreshGateAcceptance::new(
        &reports,
        reviewer_id,
        reviewed_unix_ms,
        arguments.limitations,
    )?;
    acceptance.validate_for_reports(&reports)?;
    for (source_checkout, source_repository, source_sha) in &source_bindings {
        verify_clean_source_identity(source_checkout, source_repository, source_sha)?;
    }
    write_json_create_new(&output, &acceptance)?;
    println!("{}", output.display());
    println!("acceptance_digest={}", acceptance.acceptance_digest);
    println!("report_set_digest={}", acceptance.report_set_digest);
    println!("local_shadow_evidence_accepted=true");
    println!("authority_promotion_approved=false");
    println!("gate_a4_closed=false");
    Ok(())
}

fn verify_clean_source(
    repository: &Path,
    report: &LiveTestTargetRefreshCalibrationReport,
) -> Result<(), String> {
    verify_clean_source_identity(repository, &report.source_repository, &report.source_sha)
}

fn verify_clean_source_identity(
    repository: &Path,
    expected_source: &str,
    expected_sha: &str,
) -> Result<(), String> {
    let head = git_text(repository, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    if !head.trim().eq_ignore_ascii_case(expected_sha) {
        return Err(format!("source HEAD does not match the reviewed report SHA {expected_sha}"));
    }
    let origin = git_text(repository, &["remote", "get-url", "origin"])?;
    if normalize_repository(origin.trim()) != normalize_repository(expected_source) {
        return Err("source origin does not match the reviewed report repository".to_owned());
    }
    let status = git_output_bounded(
        repository,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"],
    )?;
    if !status.is_empty() {
        return Err("source checkout must be exactly clean during acceptance".to_owned());
    }
    Ok(())
}

fn normalize_repository(value: &str) -> String {
    value
        .trim_end_matches('/')
        .strip_suffix(".git")
        .unwrap_or_else(|| value.trim_end_matches('/'))
        .to_owned()
}

fn git_text(repository: &Path, arguments: &[&str]) -> Result<String, String> {
    String::from_utf8(git_output_bounded(repository, arguments)?)
        .map_err(|error| format!("git output is not UTF-8: {error}"))
}

fn git_output_bounded(repository: &Path, arguments: &[&str]) -> Result<Vec<u8>, String> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("git could not be started: {error}"))?;
    let stdout = child.stdout.take().ok_or_else(|| "git stdout is unavailable".to_owned())?;
    let stderr = child.stderr.take().ok_or_else(|| "git stderr is unavailable".to_owned())?;
    let stdout_reader = thread::spawn(move || read_process_output(stdout));
    let stderr_reader = thread::spawn(move || read_process_output(stderr));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if started.elapsed() >= SOURCE_VERIFICATION_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err("git source verification timed out".to_owned());
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = join_process_reader(stdout_reader, "stdout")?;
    let stderr = join_process_reader(stderr_reader, "stderr")?;
    if stdout.overflow || stderr.overflow {
        return Err("git source verification output exceeded its bound".to_owned());
    }
    if !status.success() {
        return Err(format!(
            "git {} failed with {status}: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&stderr.bytes).trim()
        ));
    }
    Ok(stdout.bytes)
}

struct BoundedProcessOutput {
    bytes: Vec<u8>,
    overflow: bool,
}

fn read_process_output(mut reader: impl Read) -> std::io::Result<BoundedProcessOutput> {
    let mut bytes = Vec::with_capacity(MAX_GIT_OUTPUT_BYTES.min(64 * 1024));
    reader
        .by_ref()
        .take((MAX_GIT_OUTPUT_BYTES as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    let overflow = bytes.len() > MAX_GIT_OUTPUT_BYTES;
    if overflow {
        bytes.truncate(MAX_GIT_OUTPUT_BYTES);
    }
    Ok(BoundedProcessOutput { bytes, overflow })
}

fn join_process_reader(
    handle: thread::JoinHandle<std::io::Result<BoundedProcessOutput>>,
    stream: &str,
) -> Result<BoundedProcessOutput, String> {
    handle
        .join()
        .map_err(|_| format!("git {stream} reader panicked"))?
        .map_err(|error| format!("cannot read git {stream}: {error}"))
}

fn write_json_create_new(
    path: &Path,
    value: &LiveTestTargetRefreshGateAcceptance,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_BYTES {
        return Err("serialized acceptance exceeds its wire bound".into());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

#[derive(Default)]
struct Arguments {
    workspace_root: Option<PathBuf>,
    reports: Vec<PathBuf>,
    source_checkouts: Vec<PathBuf>,
    reviewer_id: Option<String>,
    reviewed_unix_ms: Option<u64>,
    limitations: Vec<String>,
    output: Option<PathBuf>,
    confirm_latency_primary_shadow: bool,
}

impl Arguments {
    fn parse(values: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut values = values.peekable();
        let mut output = Self::default();
        while let Some(argument) = values.next() {
            match argument.as_str() {
                "--workspace-root" => {
                    output.workspace_root = Some(next_path(&mut values, &argument)?);
                }
                "--report" => output.reports.push(next_path(&mut values, &argument)?),
                "--source-checkout" => {
                    output.source_checkouts.push(next_path(&mut values, &argument)?);
                }
                "--reviewer-id" => {
                    output.reviewer_id = Some(next_value(&mut values, &argument)?);
                }
                "--reviewed-unix-ms" => {
                    output.reviewed_unix_ms = Some(
                        next_value(&mut values, &argument)?
                            .parse()
                            .map_err(|_| "--reviewed-unix-ms must be a u64".to_owned())?,
                    );
                }
                "--limitation" => output.limitations.push(next_value(&mut values, &argument)?),
                "--output" => output.output = Some(next_path(&mut values, &argument)?),
                "--confirm-latency-primary-shadow" => {
                    output.confirm_latency_primary_shadow = true;
                }
                _ => return Err(format!("unknown argument: {argument}")),
            }
        }
        Ok(output)
    }

    fn validate(&self) -> Result<(), String> {
        if self.reports.is_empty()
            || self.reports.len() > MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTED_REPORTS
        {
            return Err(format!(
                "between 1 and {MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTED_REPORTS} --report values are required"
            ));
        }
        if self.reports.len() != self.source_checkouts.len() {
            return Err("each --report requires one positional --source-checkout".to_owned());
        }
        if self.limitations.is_empty() {
            return Err("at least one --limitation is required".to_owned());
        }
        if !self.confirm_latency_primary_shadow {
            return Err("--confirm-latency-primary-shadow is required".to_owned());
        }
        Ok(())
    }
}

fn required<T>(value: Option<T>, name: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("{name} is required"))
}

fn next_value(
    values: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    option: &str,
) -> Result<String, String> {
    values.next().ok_or_else(|| format!("{option} requires a value"))
}

fn next_path(
    values: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    option: &str,
) -> Result<PathBuf, String> {
    next_value(values, option).map(PathBuf::from)
}

fn absolute_from(workspace: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() { path } else { workspace.join(path) }
}

fn safe_absolute_from(workspace: &Path, path: PathBuf) -> Result<PathBuf, String> {
    if path.components().any(|component| matches!(component, std::path::Component::ParentDir)) {
        return Err("the acceptance output must not contain parent-directory components".to_owned());
    }
    Ok(absolute_from(workspace, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn arguments_require_positional_pairs_and_explicit_confirmation() {
        let parsed = Arguments::parse(
            [
                "--report",
                "report.json",
                "--source-checkout",
                "source",
                "--reviewer-id",
                "local-owner",
                "--reviewed-unix-ms",
                "1754000000000",
                "--limitation",
                "bounded",
                "--confirm-latency-primary-shadow",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .unwrap();
        assert!(parsed.validate().is_ok());

        let missing_source = Arguments::parse(
            [
                "--report",
                "report.json",
                "--limitation",
                "bounded",
                "--confirm-latency-primary-shadow",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .unwrap();
        assert!(missing_source.validate().is_err());
        assert!(Arguments::parse(["--unknown".to_owned()].into_iter()).is_err());
    }

    #[test]
    fn source_verification_binds_origin_sha_and_cleanliness() {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = env::temp_dir()
            .join(format!("needle-live-refresh-accept-{}-{suffix}", std::process::id()));
        fs::create_dir(&root).unwrap();
        git_text(&root, &["init"]).unwrap();
        git_text(&root, &["config", "user.email", "needle@example.invalid"]).unwrap();
        git_text(&root, &["config", "user.name", "Needle Test"]).unwrap();
        git_text(&root, &["remote", "add", "origin", "https://github.com/example/source.git"])
            .unwrap();
        fs::write(root.join("source.txt"), b"accepted source\n").unwrap();
        git_text(&root, &["add", "source.txt"]).unwrap();
        git_text(&root, &["commit", "-m", "fixture"]).unwrap();
        let head = git_text(&root, &["rev-parse", "HEAD"]).unwrap();
        assert!(
            verify_clean_source_identity(&root, "https://github.com/example/source", head.trim())
                .is_ok()
        );
        assert!(
            verify_clean_source_identity(&root, "https://github.com/example/other", head.trim())
                .unwrap_err()
                .contains("origin")
        );
        fs::write(root.join("untracked.txt"), b"dirty\n").unwrap();
        assert!(
            verify_clean_source_identity(&root, "https://github.com/example/source", head.trim())
                .unwrap_err()
                .contains("clean")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
