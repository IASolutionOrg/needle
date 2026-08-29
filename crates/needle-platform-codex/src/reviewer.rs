use crate::app_server::{AppServerSession, AppServerTurnFailure};
use crate::{CodexWorker, codex_change_action_provider_definition};
use needle_core::{
    AcceptanceStatus, CanonicalHasher, ChangeId, ChangeRequest, Digest, PatchId, ReviewCoverage,
    ReviewFinding, ReviewInspectionCoverage, ReviewInspectionOutcome, ReviewInspectionTarget,
    ReviewInspectionTargetKind, ReviewReportVerdict, ReviewSeverity, StateDelta, WorkerConfig,
    review_inspection_context_digest,
};
use needle_runtime::{
    IsolatedCheckout, RuntimeStore, capture_git_snapshot, materialize_patch_artifact,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const REVIEW_REFRESH_INSTRUCTIONS: &str = "Return exactly one inspection result for every supplied target_id. Retained-finding targets must be revalidated as still_valid or stale. Changed-path targets must be inspected as clean or findings. Use inconclusive only when the target cannot be inspected; Needle will discard the refresh and run a fresh full review. Include the findings field only when the outcome is findings, and include every newly discovered finding for that target. Produce a fresh whole-review verdict after completing every target.";
const REVIEW_FINDING_FORMAT_INSTRUCTIONS: &str = "Every new finding rule must contain only ASCII letters, digits, dot, underscore, or hyphen. Every new finding path must be a repository-relative forward-slash path with no empty, dot, or parent components. Keep all finding and evidence material within the declared schema bounds.";

#[derive(Clone, Debug)]
pub(crate) struct CodexReviewWorker {
    data_directory: PathBuf,
    codex_home: Option<PathBuf>,
    cancellation: Option<Arc<AtomicBool>>,
}

#[derive(Clone, Debug)]
pub(crate) struct ReviewRunOutput {
    pub verdict: ReviewReportVerdict,
    pub acceptance_coverage: Vec<ReviewCoverage>,
    pub findings: Vec<ReviewFinding>,
    pub reviewer_definition: Digest,
    pub dependency_digest: Digest,
    pub provider_observation_digest: Digest,
    pub inspection_context_digest: Option<Digest>,
    pub inspection_coverage: Vec<ReviewInspectionCoverage>,
    pub created_unix_ms: u64,
    pub output_tokens: Option<u64>,
    pub worker_turns: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReviewRefreshAdvisory {
    pub state_delta: StateDelta,
    pub prior_manifest: needle_core::PartitionManifestId,
    pub retained_findings: Vec<ReviewFinding>,
    pub invalidated_partition_keys: Vec<Digest>,
    pub inspection_context_digest: Digest,
    pub inspection_targets: Vec<ReviewInspectionTarget>,
}

#[derive(Debug)]
pub(crate) struct ReviewRunError {
    pub diagnostic: String,
    pub full_fallback_required: bool,
    pub output_tokens: Option<u64>,
    pub provider_turn_completed: bool,
}

impl ReviewRunError {
    fn failure(diagnostic: impl Into<String>) -> Self {
        Self {
            diagnostic: diagnostic.into(),
            full_fallback_required: false,
            output_tokens: None,
            provider_turn_completed: false,
        }
    }

    fn fallback(diagnostic: impl Into<String>, output_tokens: Option<u64>) -> Self {
        Self {
            diagnostic: diagnostic.into(),
            full_fallback_required: true,
            output_tokens,
            provider_turn_completed: true,
        }
    }
}

impl std::error::Error for ReviewRunError {}

impl std::fmt::Display for ReviewRunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.diagnostic)
    }
}

impl From<String> for ReviewRunError {
    fn from(diagnostic: String) -> Self {
        Self::failure(diagnostic)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ReviewActionRequest<'a> {
    pub config: &'a WorkerConfig,
    pub repository_root: &'a Path,
    pub change_id: &'a ChangeId,
    pub requirements_digest: Digest,
    pub patch_id: PatchId,
    pub source_snapshot: Digest,
    pub advisory: Option<&'a ReviewRefreshAdvisory>,
}

impl CodexReviewWorker {
    pub(crate) fn new(data_directory: impl Into<PathBuf>) -> Self {
        Self { data_directory: data_directory.into(), codex_home: None, cancellation: None }
    }

    pub(crate) fn with_codex_home(mut self, codex_home: impl Into<PathBuf>) -> Self {
        self.codex_home = Some(codex_home.into());
        self
    }

    pub(crate) fn with_cancellation(mut self, cancellation: Arc<AtomicBool>) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    pub(crate) fn review(
        &self,
        request: ReviewActionRequest<'_>,
    ) -> Result<ReviewRunOutput, ReviewRunError> {
        let ReviewActionRequest {
            config,
            repository_root,
            change_id,
            requirements_digest,
            patch_id,
            source_snapshot,
            advisory,
        } = request;
        let store = RuntimeStore::new(self.data_directory.join("needle.sqlite3"));
        let prepared = store
            .prepared_change(change_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("change `{change_id}` is not prepared"))?;
        if prepared.patch.id != patch_id
            || prepared.source_snapshot != source_snapshot
            || prepared.request_digest != requirements_digest
            || prepared.request_digest != prepared.request.digest(source_snapshot)
        {
            return Err("review patch binding is stale or inconsistent".to_owned().into());
        }
        if let Some(advisory) = advisory {
            validate_refresh_advisory(advisory, patch_id)?;
        }
        let isolation = CodexWorker::verify_isolation(&config.executable)?;
        if !isolation.verified() {
            return Err(format!(
                "reviewer isolation is not verified for Codex {}",
                isolation.codex_version
            )
            .into());
        }
        let repository_root = fs::canonicalize(repository_root)
            .map_err(|error| format!("cannot resolve review repository: {error}"))?;
        let sandbox = IsolatedCheckout::materialize(
            &repository_root,
            &self.data_directory.join("review-runs"),
        )
        .map_err(|error| error.to_string())?;
        if sandbox.snapshot().source_digest != source_snapshot {
            return cleanup_after_error(
                sandbox,
                "active source snapshot changed before review".to_owned(),
            );
        }
        let blobs = match store.patch_file_blobs(prepared.patch.id) {
            Ok(blobs) => blobs,
            Err(error) => return cleanup_after_error(sandbox, error.to_string()),
        };
        if let Err(error) =
            materialize_patch_artifact(sandbox.checkout_root(), &prepared.patch, &blobs)
        {
            return cleanup_after_error(sandbox, error.to_string());
        }
        let (_, patched_snapshot) = match capture_git_snapshot(sandbox.checkout_root()) {
            Ok(snapshot) => snapshot,
            Err(error) => return cleanup_after_error(sandbox, error.to_string()),
        };
        let reviewer_definition = reviewer_definition_digest(config);
        let mut session = match AppServerSession::start_reviewer(
            config,
            self.codex_home.as_deref(),
            &reviewer_instructions(),
            sandbox.checkout_root(),
            sandbox.target_root(),
            sandbox.temp_root(),
            patched_snapshot.source_digest,
            patched_snapshot.repository_id,
            store,
        ) {
            Ok(session) => session,
            Err(error) => return cleanup_after_error(sandbox, error),
        };
        session.fail_fast_on_pending_approvals();
        let prompt = reviewer_prompt(&prepared.request, &prepared.patch, advisory);
        let output_schema = reviewer_output_schema(advisory);
        let provider_thread_digest = Digest::blake3(session.thread_id().as_bytes());
        let turn = session.run_turn_cancellable(
            &prompt,
            &output_schema,
            Duration::from_secs(config.timeout_seconds),
            self.cancellation.as_deref(),
        );
        let declared = normalize_review_turn(turn, &prepared.request, advisory);
        let session_error = session.cleanup().err();
        let after =
            capture_git_snapshot(sandbox.checkout_root()).map_err(|error| error.to_string());
        let sandbox_error = sandbox.cleanup().err();
        if let Some(error) = session_error {
            return Err(format!("reviewer App Server cleanup failed: {error}").into());
        }
        let (_, after) = after?;
        if after.source_digest != patched_snapshot.source_digest {
            return Err("read-only reviewer modified the patched checkout".to_owned().into());
        }
        if let Some(error) = sandbox_error {
            return Err(format!("review checkout cleanup failed: {error}").into());
        }
        let declared = declared?;

        let created_unix_ms = now_ms();
        let mut provider_observation =
            CanonicalHasher::new(b"needle-codex-review-provider-observation-v1");
        provider_observation.field_digest(config.digest());
        provider_observation.field_digest(source_snapshot);
        provider_observation.field_digest(patch_id.0);
        provider_observation.field_digest(requirements_digest);
        provider_observation.field_digest(patched_snapshot.source_digest);
        provider_observation.field_digest(provider_thread_digest);
        provider_observation.field_digest(Digest::blake3(prompt.as_bytes()));
        provider_observation.field_digest(Digest::blake3(
            serde_json::to_vec(&output_schema)
                .expect("the closed reviewer output schema serializes"),
        ));
        provider_observation.field_digest(declared.response_digest);
        let provider_observation_digest = provider_observation.finish();

        let mut dependency = CanonicalHasher::new(b"needle-review-full-dependency-v1");
        dependency.field_digest(source_snapshot);
        dependency.field_digest(patch_id.0);
        dependency.field_digest(requirements_digest);
        dependency.field_digest(reviewer_definition);
        dependency.field_digest(patched_snapshot.source_digest);
        dependency.field_digest(provider_observation_digest);
        if let Some(advisory) = advisory {
            dependency.field_u8(1);
            dependency.field_digest(advisory.state_delta.digest);
            dependency.field_digest(advisory.prior_manifest.digest());
            dependency.field_digest(advisory.inspection_context_digest);
            dependency.field_u16(advisory.retained_findings.len().try_into().unwrap_or(u16::MAX));
            for finding in &advisory.retained_findings {
                dependency.field_digest(finding.id);
            }
            dependency.field_u16(
                advisory.invalidated_partition_keys.len().try_into().unwrap_or(u16::MAX),
            );
            for key in &advisory.invalidated_partition_keys {
                dependency.field_digest(*key);
            }
            dependency.field_u16(advisory.inspection_targets.len().try_into().unwrap_or(u16::MAX));
            for target in &advisory.inspection_targets {
                dependency.field_digest(target.id);
            }
        } else {
            dependency.field_u8(0);
        }
        for finding in &declared.findings {
            dependency.field_digest(finding.id);
        }
        Ok(ReviewRunOutput {
            verdict: declared.verdict,
            acceptance_coverage: declared.acceptance_coverage,
            findings: declared.findings,
            reviewer_definition,
            dependency_digest: dependency.finish(),
            provider_observation_digest,
            inspection_context_digest: declared.inspection_context_digest,
            inspection_coverage: declared.inspection_coverage,
            created_unix_ms,
            output_tokens: declared.output_tokens,
            worker_turns: 1,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredReview {
    verdict: DeclaredVerdict,
    acceptance_coverage: Vec<DeclaredCoverage>,
    findings: Vec<DeclaredFinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredRefreshReview {
    verdict: DeclaredVerdict,
    acceptance_coverage: Vec<DeclaredCoverage>,
    inspection_results: Vec<DeclaredInspectionResult>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredInspectionResult {
    target_id: Digest,
    outcome: DeclaredInspectionOutcome,
    evidence: String,
    #[serde(default)]
    findings: Vec<DeclaredFinding>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum DeclaredInspectionOutcome {
    StillValid,
    Stale,
    Clean,
    Findings,
    Inconclusive,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DeclaredVerdict {
    Approved,
    Rejected,
    Inconclusive,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredCoverage {
    criterion: String,
    status: DeclaredCoverageStatus,
    evidence: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DeclaredCoverageStatus {
    Addressed,
    Partial,
    Unaddressed,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum DeclaredFinding {
    New {
        rule: String,
        severity: DeclaredSeverity,
        path: String,
        line: Option<u32>,
        message: String,
        evidence: String,
    },
}

struct DeclaredNewFinding {
    rule: String,
    severity: DeclaredSeverity,
    path: String,
    line: Option<u32>,
    message: String,
    evidence: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DeclaredSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

struct NormalizedReview {
    verdict: ReviewReportVerdict,
    acceptance_coverage: Vec<ReviewCoverage>,
    findings: Vec<ReviewFinding>,
    inspection_context_digest: Option<Digest>,
    inspection_coverage: Vec<ReviewInspectionCoverage>,
    output_tokens: Option<u64>,
    response_digest: Digest,
}

fn normalize_review_turn(
    turn: Result<crate::app_server::AppServerTurn, AppServerTurnFailure>,
    request: &ChangeRequest,
    advisory: Option<&ReviewRefreshAdvisory>,
) -> Result<NormalizedReview, ReviewRunError> {
    let turn = turn.map_err(|error| ReviewRunError {
        diagnostic: format!("review worker failed: {}", error.diagnostic),
        full_fallback_required: false,
        output_tokens: error.output_tokens,
        provider_turn_completed: false,
    })?;
    let output_tokens = turn.output_tokens;
    let response_digest = Digest::blake3(
        serde_json::to_vec(&turn.response)
            .map_err(|error| format!("review worker response cannot be hashed: {error}"))?,
    );
    let normalized = match advisory {
        Some(advisory) => normalize_refresh_review(
            turn.response,
            request,
            advisory,
            output_tokens,
            response_digest,
        ),
        None => normalize_full_review(turn.response, request, output_tokens, response_digest),
    };
    normalized.map_err(|mut error| {
        error.provider_turn_completed = true;
        error
    })
}

fn normalize_acceptance_coverage(
    declared: Vec<DeclaredCoverage>,
    request: &ChangeRequest,
) -> Result<Vec<ReviewCoverage>, String> {
    if declared.len() != request.acceptance_criteria.len() {
        return Err("review output exceeded its closed cardinality".to_owned());
    }
    let expected = request
        .acceptance_criteria
        .iter()
        .map(|criterion| (criterion.as_str(), criterion))
        .collect::<BTreeMap<_, _>>();
    let mut coverage = Vec::with_capacity(declared.len());
    for item in declared {
        let criterion = expected
            .get(item.criterion.as_str())
            .ok_or_else(|| "review output contains an unknown acceptance criterion".to_owned())?;
        if coverage.iter().any(|value: &ReviewCoverage| {
            value.criterion_digest == Digest::blake3(criterion.as_bytes())
        }) || item.evidence.trim().is_empty()
            || item.evidence.len() > needle_core::MAX_REVIEW_MESSAGE_BYTES
        {
            return Err("review acceptance coverage is duplicate or out of bounds".to_owned());
        }
        coverage.push(ReviewCoverage {
            criterion_digest: Digest::blake3(criterion.as_bytes()),
            status: match item.status {
                DeclaredCoverageStatus::Addressed => AcceptanceStatus::Addressed,
                DeclaredCoverageStatus::Partial => AcceptanceStatus::Partial,
                DeclaredCoverageStatus::Unaddressed => AcceptanceStatus::Unaddressed,
            },
            evidence_digest: Digest::blake3(item.evidence.as_bytes()),
        });
    }
    coverage.sort_by_key(|item| item.criterion_digest);
    Ok(coverage)
}

fn normalize_full_review(
    response: Value,
    request: &ChangeRequest,
    output_tokens: Option<u64>,
    response_digest: Digest,
) -> Result<NormalizedReview, ReviewRunError> {
    let declared: DeclaredReview = serde_json::from_value(response)
        .map_err(|error| format!("review worker returned invalid output: {error}"))?;
    if declared.findings.len() > needle_core::MAX_REVIEW_FINDINGS {
        return Err("review output exceeded its closed cardinality".to_owned().into());
    }
    let coverage = normalize_acceptance_coverage(declared.acceptance_coverage, request)?;
    let mut findings = Vec::with_capacity(declared.findings.len());
    let mut finding_ids = BTreeSet::new();
    for (index, finding) in declared.findings.into_iter().enumerate() {
        let finding = match finding {
            DeclaredFinding::New { rule, severity, path, line, message, evidence } => {
                normalize_new_finding(
                    index,
                    DeclaredNewFinding { rule, severity, path, line, message, evidence },
                )?
            }
        };
        if !finding_ids.insert(finding.id) {
            continue;
        }
        findings.push(finding);
    }
    let verdict = normalize_verdict(declared.verdict, &coverage, &findings)?;
    Ok(NormalizedReview {
        verdict,
        acceptance_coverage: coverage,
        findings,
        inspection_context_digest: None,
        inspection_coverage: Vec::new(),
        output_tokens,
        response_digest,
    })
}

fn normalize_refresh_review(
    response: Value,
    request: &ChangeRequest,
    advisory: &ReviewRefreshAdvisory,
    output_tokens: Option<u64>,
    response_digest: Digest,
) -> Result<NormalizedReview, ReviewRunError> {
    let declared: DeclaredRefreshReview = serde_json::from_value(response)
        .map_err(|error| format!("review worker returned invalid refresh output: {error}"))?;
    let coverage = normalize_acceptance_coverage(declared.acceptance_coverage, request)?;
    if declared.inspection_results.len() != advisory.inspection_targets.len() {
        return Err(ReviewRunError::fallback(
            "review refresh did not cover every inspection target",
            output_tokens,
        ));
    }
    let expected = advisory
        .inspection_targets
        .iter()
        .map(|target| (target.id, target))
        .collect::<BTreeMap<_, _>>();
    let prior = advisory
        .retained_findings
        .iter()
        .map(|finding| (finding.id, finding))
        .collect::<BTreeMap<_, _>>();
    let mut seen_targets = BTreeSet::new();
    let mut findings_by_id = BTreeMap::new();
    let mut inspection_coverage = Vec::with_capacity(declared.inspection_results.len());
    let mut normalized_finding_count = 0usize;
    for result in declared.inspection_results {
        let Some(target) = expected.get(&result.target_id) else {
            return Err(ReviewRunError::fallback(
                "review refresh returned an unknown inspection target",
                output_tokens,
            ));
        };
        if !seen_targets.insert(result.target_id) {
            return Err(ReviewRunError::fallback(
                "review refresh returned a duplicate inspection target",
                output_tokens,
            ));
        }
        if result.evidence.trim().is_empty()
            || result.evidence.len() > needle_core::MAX_REVIEW_MESSAGE_BYTES
        {
            return Err(ReviewRunError::fallback(
                "review refresh target evidence is empty or out of bounds",
                output_tokens,
            ));
        }
        if result.outcome == DeclaredInspectionOutcome::Inconclusive {
            return Err(ReviewRunError::fallback(
                "review refresh declared an inconclusive inspection target",
                output_tokens,
            ));
        }
        normalized_finding_count =
            normalized_finding_count.checked_add(result.findings.len()).ok_or_else(|| {
                ReviewRunError::fallback("review refresh finding count overflowed", output_tokens)
            })?;
        if normalized_finding_count > needle_core::MAX_REVIEW_FINDINGS {
            return Err(ReviewRunError::fallback(
                "review refresh exceeded the finding bound",
                output_tokens,
            ));
        }
        let mut result_finding_ids = BTreeSet::new();
        for finding in result.findings {
            let finding = match finding {
                DeclaredFinding::New { rule, severity, path, line, message, evidence } => {
                    normalize_new_finding(
                        normalized_finding_count,
                        DeclaredNewFinding { rule, severity, path, line, message, evidence },
                    )
                    .map_err(|error| ReviewRunError::fallback(error, output_tokens))?
                }
            };
            result_finding_ids.insert(finding.id);
            findings_by_id.entry(finding.id).or_insert(finding);
        }
        let (outcome, finding_ids) = match (target.kind, result.outcome) {
            (
                ReviewInspectionTargetKind::RetainedFinding,
                DeclaredInspectionOutcome::StillValid,
            ) if result_finding_ids.is_empty() => {
                let retained_id = target.retained_finding_id.expect("validated retained target");
                let finding = prior.get(&retained_id).ok_or_else(|| {
                    ReviewRunError::fallback(
                        "review refresh retained target has no advisory finding",
                        output_tokens,
                    )
                })?;
                findings_by_id.entry(finding.id).or_insert_with(|| (*finding).clone());
                (ReviewInspectionOutcome::StillValid, vec![retained_id])
            }
            (ReviewInspectionTargetKind::RetainedFinding, DeclaredInspectionOutcome::Stale)
                if result_finding_ids.is_empty() =>
            {
                (ReviewInspectionOutcome::Stale, Vec::new())
            }
            (ReviewInspectionTargetKind::ChangedPath, DeclaredInspectionOutcome::Clean)
                if result_finding_ids.is_empty() =>
            {
                (ReviewInspectionOutcome::Clean, Vec::new())
            }
            (ReviewInspectionTargetKind::ChangedPath, DeclaredInspectionOutcome::Findings)
                if !result_finding_ids.is_empty() =>
            {
                (ReviewInspectionOutcome::Findings, result_finding_ids.into_iter().collect())
            }
            _ => {
                return Err(ReviewRunError::fallback(
                    "review refresh target outcome does not match its target kind or findings",
                    output_tokens,
                ));
            }
        };
        inspection_coverage.push(
            ReviewInspectionCoverage::new(
                advisory.inspection_context_digest,
                (*target).clone(),
                outcome,
                finding_ids,
                Digest::blake3(result.evidence.as_bytes()),
            )
            .map_err(|error| ReviewRunError::fallback(error.to_string(), output_tokens))?,
        );
    }
    if seen_targets.len() != expected.len() {
        return Err(ReviewRunError::fallback(
            "review refresh did not close its inspection target set",
            output_tokens,
        ));
    }
    inspection_coverage.sort_by_key(|item| item.target.id);
    let findings = findings_by_id.into_values().collect::<Vec<_>>();
    let verdict = normalize_verdict(declared.verdict, &coverage, &findings)
        .map_err(|error| ReviewRunError::fallback(error, output_tokens))?;
    Ok(NormalizedReview {
        verdict,
        acceptance_coverage: coverage,
        findings,
        inspection_context_digest: Some(advisory.inspection_context_digest),
        inspection_coverage,
        output_tokens,
        response_digest,
    })
}

fn normalize_verdict(
    declared: DeclaredVerdict,
    coverage: &[ReviewCoverage],
    findings: &[ReviewFinding],
) -> Result<ReviewReportVerdict, String> {
    let verdict = match declared {
        DeclaredVerdict::Approved => ReviewReportVerdict::Approved,
        DeclaredVerdict::Rejected => ReviewReportVerdict::Rejected,
        DeclaredVerdict::Inconclusive => ReviewReportVerdict::Inconclusive,
    };
    if verdict == ReviewReportVerdict::Approved
        && (!findings.is_empty()
            || coverage.iter().any(|item| item.status != AcceptanceStatus::Addressed))
    {
        return Err("approved review contains findings or incomplete coverage".to_owned());
    }
    Ok(verdict)
}

fn normalize_new_finding(
    index: usize,
    finding: DeclaredNewFinding,
) -> Result<ReviewFinding, String> {
    if finding.rule.is_empty()
        || finding.rule.len() > needle_core::MAX_REVIEW_RULE_BYTES
        || !finding
            .rule
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(format!("review finding {index} rule is invalid or out of bounds"));
    }
    if finding.path.is_empty()
        || finding.path.len() > needle_core::MAX_REVIEW_PATH_BYTES
        || finding.path.contains('\\')
        || finding.path.starts_with('/')
        || finding
            .path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(format!("review finding {index} path is invalid or out of bounds"));
    }
    if finding.message.trim().is_empty()
        || finding.message.len() > needle_core::MAX_REVIEW_MESSAGE_BYTES
    {
        return Err(format!("review finding {index} message is invalid or out of bounds"));
    }
    if finding.evidence.trim().is_empty()
        || finding.evidence.len() > needle_core::MAX_REVIEW_MESSAGE_BYTES
    {
        return Err(format!("review finding {index} evidence is invalid or out of bounds"));
    }
    ReviewFinding::new(
        finding.rule,
        match finding.severity {
            DeclaredSeverity::Info => ReviewSeverity::Info,
            DeclaredSeverity::Warning => ReviewSeverity::Warning,
            DeclaredSeverity::Error => ReviewSeverity::Error,
            DeclaredSeverity::Critical => ReviewSeverity::Critical,
        },
        finding.path,
        finding.line,
        finding.message,
        Digest::blake3(finding.evidence.as_bytes()),
    )
    .map_err(|error| error.to_string())
}

fn reviewer_instructions() -> String {
    "You are Needle's independent read-only diff reviewer. Review the actual patched filesystem in the disposable checkout against every supplied acceptance criterion. You have no patcher transcript. Do not modify files, run tests, use network, hooks, plugins, MCP, project instructions, memory, or other agents. Inspect only through the provided bounded repository tools. Report concrete file-and-rule findings with evidence. Return only closed JSON matching the output schema.".to_owned()
}

fn reviewer_prompt(
    request: &ChangeRequest,
    patch: &needle_core::PatchArtifact,
    advisory: Option<&ReviewRefreshAdvisory>,
) -> String {
    serde_json::to_string(&json!({
        "operation": if advisory.is_some() {
            "refresh_aware_full_diff_review"
        } else {
            "full_diff_review"
        },
        "task": request.task,
        "acceptance_criteria": request.acceptance_criteria,
        "constraints": request.constraints,
        "allowed_paths": request.allowed_paths,
        "patch_id": patch.id,
        "changed_files": patch.files.iter().map(|file| &file.path).collect::<Vec<_>>(),
        "finding_format": REVIEW_FINDING_FORMAT_INSTRUCTIONS,
        "prior_partition_advisory": advisory.map(|advisory| json!({
            "state_delta_digest": advisory.state_delta.digest,
            "prior_manifest": advisory.prior_manifest,
            "inspection_context_digest": advisory.inspection_context_digest,
            "changed_locator_count": advisory.state_delta.changed_locators.len(),
            "inspection_targets": advisory.inspection_targets,
            "retained_findings_requiring_revalidation": advisory.retained_findings,
            "invalidated_partition_keys": advisory.invalidated_partition_keys,
            "instructions": REVIEW_REFRESH_INSTRUCTIONS
        }))
    }))
    .expect("bounded review request serializes")
}

fn reviewer_output_schema(advisory: Option<&ReviewRefreshAdvisory>) -> Value {
    match advisory {
        Some(advisory) => refresh_reviewer_output_schema(&advisory.inspection_targets),
        None => full_reviewer_output_schema(),
    }
}

fn full_reviewer_output_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["verdict", "acceptance_coverage", "findings"],
        "properties": {
            "verdict": {"type": "string", "enum": ["approved", "rejected", "inconclusive"]},
            "acceptance_coverage": {
                "type": "array",
                "maxItems": needle_core::MAX_REVIEW_COVERAGE,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["criterion", "status", "evidence"],
                    "properties": {
                        "criterion": {"type": "string"},
                        "status": {"type": "string", "enum": ["addressed", "partial", "unaddressed"]},
                        "evidence": {"type": "string"}
                    }
                }
            },
            "findings": {
                "type": "array",
                "maxItems": needle_core::MAX_REVIEW_FINDINGS,
                "items": new_finding_schema()
            }
        }
    })
}

fn refresh_reviewer_output_schema(targets: &[ReviewInspectionTarget]) -> Value {
    let target_schemas = targets
        .iter()
        .flat_map(|target| match target.kind {
            ReviewInspectionTargetKind::RetainedFinding => vec![inspection_result_schema(
                target.id,
                &["still_valid", "stale", "inconclusive"],
                false,
            )],
            ReviewInspectionTargetKind::ChangedPath => vec![
                inspection_result_schema(target.id, &["clean", "inconclusive"], false),
                inspection_result_schema(target.id, &["findings"], true),
            ],
        })
        .collect::<Vec<_>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["verdict", "acceptance_coverage", "inspection_results"],
        "properties": {
            "verdict": {"type": "string", "enum": ["approved", "rejected", "inconclusive"]},
            "acceptance_coverage": {
                "type": "array",
                "maxItems": needle_core::MAX_REVIEW_COVERAGE,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["criterion", "status", "evidence"],
                    "properties": {
                        "criterion": {"type": "string"},
                        "status": {"type": "string", "enum": ["addressed", "partial", "unaddressed"]},
                        "evidence": {"type": "string"}
                    }
                }
            },
            "inspection_results": {
                "type": "array",
                "minItems": targets.len(),
                "maxItems": targets.len(),
                "items": {"anyOf": target_schemas}
            }
        }
    })
}

fn inspection_result_schema(target_id: Digest, outcomes: &[&str], findings: bool) -> Value {
    let mut required = vec![json!("target_id"), json!("outcome"), json!("evidence")];
    let mut properties = serde_json::Map::from_iter([
        ("target_id".to_owned(), json!({"type": "string", "const": target_id.to_string()})),
        ("outcome".to_owned(), json!({"type": "string", "enum": outcomes})),
        (
            "evidence".to_owned(),
            json!({
                "type": "string",
                "minLength": 1,
                "maxLength": needle_core::MAX_REVIEW_MESSAGE_BYTES
            }),
        ),
    ]);
    if findings {
        required.push(json!("findings"));
        properties.insert(
            "findings".to_owned(),
            json!({
                "type": "array",
                "minItems": 1,
                "maxItems": needle_core::MAX_REVIEW_FINDINGS,
                "items": new_finding_schema()
            }),
        );
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties
    })
}

fn new_finding_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["kind", "rule", "severity", "path", "line", "message", "evidence"],
        "properties": {
            "kind": {"type": "string", "const": "new"},
            "rule": {
                "type": "string",
                "minLength": 1,
                "maxLength": needle_core::MAX_REVIEW_RULE_BYTES
            },
            "severity": {"type": "string", "enum": ["info", "warning", "error", "critical"]},
            "path": {
                "type": "string",
                "minLength": 1,
                "maxLength": needle_core::MAX_REVIEW_PATH_BYTES
            },
            "line": {
                "type": ["integer", "null"],
                "minimum": 1,
                "maximum": u32::MAX
            },
            "message": {
                "type": "string",
                "minLength": 1,
                "maxLength": needle_core::MAX_REVIEW_MESSAGE_BYTES
            },
            "evidence": {
                "type": "string",
                "minLength": 1,
                "maxLength": needle_core::MAX_REVIEW_MESSAGE_BYTES
            }
        }
    })
}

fn reviewer_definition_digest(config: &WorkerConfig) -> Digest {
    let mut hasher = CanonicalHasher::new(b"needle-codex-review-worker-v9");
    hasher.field_digest(codex_change_action_provider_definition());
    hasher.field_digest(config.digest());
    hasher.field_str(&reviewer_instructions());
    hasher.field_bytes(
        &serde_json::to_vec(&full_reviewer_output_schema())
            .expect("the closed reviewer output schema serializes"),
    );
    let placeholder_context = Digest::blake3(b"reviewer-definition-context-placeholder");
    let placeholder_changed_target =
        ReviewInspectionTarget::changed_path(placeholder_context, "src/placeholder.rs", Vec::new())
            .expect("the reviewer definition placeholder is canonical");
    let placeholder_retained_target = ReviewInspectionTarget::retained_finding(
        placeholder_context,
        "src/stable.rs",
        Digest::blake3(b"reviewer-definition-retained-finding-placeholder"),
    )
    .expect("the reviewer retained definition placeholder is canonical");
    let mut placeholder_targets = vec![placeholder_changed_target, placeholder_retained_target];
    placeholder_targets.sort_by_key(|target| target.id);
    hasher.field_bytes(
        &serde_json::to_vec(&refresh_reviewer_output_schema(&placeholder_targets))
            .expect("the refresh reviewer output schema serializes"),
    );
    hasher.field_str(REVIEW_REFRESH_INSTRUCTIONS);
    hasher.field_str(REVIEW_FINDING_FORMAT_INSTRUCTIONS);
    hasher.finish()
}

fn validate_refresh_advisory(
    advisory: &ReviewRefreshAdvisory,
    patch_id: PatchId,
) -> Result<(), ReviewRunError> {
    advisory.state_delta.validate().map_err(|error| error.to_string())?;
    if advisory.inspection_context_digest
        != review_inspection_context_digest(
            advisory.state_delta.digest,
            advisory.prior_manifest,
            patch_id,
        )
        || advisory.inspection_targets.is_empty()
        || advisory.inspection_targets.len() > needle_core::MAX_REVIEW_INSPECTION_TARGETS
        || advisory.inspection_targets.windows(2).any(|pair| pair[0].id >= pair[1].id)
        || advisory.invalidated_partition_keys.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(ReviewRunError::failure("review refresh advisory is not canonical"));
    }
    let retained = advisory
        .retained_findings
        .iter()
        .map(|finding| (finding.id, finding.path.as_str()))
        .collect::<BTreeMap<_, _>>();
    if retained.len() != advisory.retained_findings.len() {
        return Err(ReviewRunError::failure("review refresh retained findings are duplicate"));
    }
    let mut targeted_retained = BTreeSet::new();
    let mut invalidated = BTreeSet::new();
    for target in &advisory.inspection_targets {
        target.validate(advisory.inspection_context_digest).map_err(|error| error.to_string())?;
        match target.kind {
            ReviewInspectionTargetKind::RetainedFinding => {
                let finding_id = target.retained_finding_id.expect("validated retained target");
                if retained.get(&finding_id).copied() != Some(target.path.as_str())
                    || !targeted_retained.insert(finding_id)
                {
                    return Err(ReviewRunError::failure(
                        "review refresh retained target is not bound to its finding",
                    ));
                }
            }
            ReviewInspectionTargetKind::ChangedPath => {
                invalidated.extend(target.invalidated_partition_keys.iter().copied());
            }
        }
    }
    if targeted_retained != retained.keys().copied().collect()
        || invalidated.iter().copied().collect::<Vec<_>>() != advisory.invalidated_partition_keys
    {
        return Err(ReviewRunError::failure(
            "review refresh targets do not close the advisory partitions",
        ));
    }
    Ok(())
}

fn cleanup_after_error<T>(sandbox: IsolatedCheckout, error: String) -> Result<T, ReviewRunError> {
    match sandbox.cleanup() {
        Ok(()) => Err(error.into()),
        Err(cleanup) => Err(format!("{error}; review checkout cleanup failed: {cleanup}").into()),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use needle_core::{
        AllowedPath, AllowedPathScope, ChangeRequest, DependencyLocator, PartitionManifestId,
        PatchArtifact, RepositoryContextId,
    };

    fn request() -> ChangeRequest {
        ChangeRequest {
            task: "Keep the API stable.".to_owned(),
            acceptance_criteria: vec!["The result is deterministic.".to_owned()],
            allowed_paths: vec![AllowedPath {
                path: "src".to_owned(),
                scope: AllowedPathScope::Subtree,
            }],
            constraints: Vec::new(),
            artifact_ids: Vec::new(),
            claim_ids: Vec::new(),
        }
    }

    fn review_turn(response: Value) -> crate::app_server::AppServerTurn {
        crate::app_server::AppServerTurn {
            response,
            input_tokens: None,
            cached_input_tokens: None,
            output_tokens: None,
            approval_wait: Duration::ZERO,
            command_evidence: Vec::new(),
            test_evidence: Vec::new(),
            observation_trace: needle_core::WorkerObservationTrace::default(),
            file_change_approvals_granted: 0,
        }
    }

    fn advisory(retained_findings: Vec<ReviewFinding>) -> ReviewRefreshAdvisory {
        let state_delta = StateDelta::new(
            Digest::blake3(b"repository"),
            RepositoryContextId::new(Digest::blake3(b"review-context")),
            1,
            2,
            vec![DependencyLocator::repository_path("src/changed.rs").unwrap()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            true,
        )
        .unwrap();
        let prior_manifest = PartitionManifestId::new(Digest::blake3(b"manifest"));
        let invalidated_partition_keys = vec![Digest::blake3(b"partition")];
        let inspection_context_digest = review_inspection_context_digest(
            state_delta.digest,
            prior_manifest,
            PatchId(Digest::blake3(b"patch")),
        );
        let mut inspection_targets = retained_findings
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
        inspection_targets.push(
            ReviewInspectionTarget::changed_path(
                inspection_context_digest,
                "src/changed.rs",
                invalidated_partition_keys.clone(),
            )
            .unwrap(),
        );
        inspection_targets.sort_by_key(|target| target.id);
        ReviewRefreshAdvisory {
            state_delta,
            prior_manifest,
            retained_findings,
            invalidated_partition_keys,
            inspection_context_digest,
            inspection_targets,
        }
    }

    #[test]
    fn review_normalization_is_closed_and_criterion_bound() {
        let response = json!({
            "verdict": "approved",
            "acceptance_coverage": [{
                "criterion": "The result is deterministic.",
                "status": "addressed",
                "evidence": "The patched function uses a stable ordering."
            }],
            "findings": []
        });
        let normalized =
            normalize_review_turn(Ok(review_turn(response)), &request(), None).unwrap();
        assert_eq!(normalized.verdict, ReviewReportVerdict::Approved);
        assert_eq!(normalized.acceptance_coverage.len(), 1);
    }

    #[test]
    fn reviewer_schema_matches_core_finding_bounds() {
        let full_schema = reviewer_output_schema(None);
        assert_provider_schema_omits_unsupported_unique_items(&full_schema);
        let full_item = &full_schema["properties"]["findings"]["items"];
        assert!(full_item.get("anyOf").is_none());
        assert_eq!(full_item["properties"]["kind"]["const"], "new");

        let refresh_advisory = advisory(Vec::new());
        let refresh_schema = reviewer_output_schema(Some(&refresh_advisory));
        assert_provider_schema_omits_unsupported_unique_items(&refresh_schema);
        assert_eq!(
            refresh_schema["properties"]["inspection_results"]["minItems"],
            refresh_advisory.inspection_targets.len()
        );
        let variants = &refresh_schema["properties"]["inspection_results"]["items"]["anyOf"];
        let variants = variants.as_array().unwrap();
        assert_eq!(variants.len(), 2);
        let no_findings = variants
            .iter()
            .find(|variant| variant["properties"].get("findings").is_none())
            .unwrap();
        assert_eq!(no_findings["properties"]["outcome"]["enum"], json!(["clean", "inconclusive"]));
        let with_findings = variants
            .iter()
            .find(|variant| variant["properties"].get("findings").is_some())
            .unwrap();
        assert_eq!(with_findings["properties"]["outcome"]["enum"], json!(["findings"]));
        assert_eq!(with_findings["properties"]["findings"]["minItems"], 1);
        let finding = &with_findings["properties"]["findings"]["items"]["properties"];
        assert_eq!(finding["rule"]["maxLength"], needle_core::MAX_REVIEW_RULE_BYTES);
        assert_eq!(finding["path"]["maxLength"], needle_core::MAX_REVIEW_PATH_BYTES);
        assert_eq!(finding["message"]["maxLength"], needle_core::MAX_REVIEW_MESSAGE_BYTES);
        assert_eq!(finding["evidence"]["maxLength"], needle_core::MAX_REVIEW_MESSAGE_BYTES);

        let retained = ReviewFinding::new(
            "stable.rule",
            ReviewSeverity::Warning,
            "src/stable.rs",
            Some(1),
            "The stable defect remains.",
            Digest::blake3(b"stable-evidence"),
        )
        .unwrap();
        let retained_advisory = advisory(vec![retained]);
        let retained_target = retained_advisory
            .inspection_targets
            .iter()
            .find(|target| target.kind == ReviewInspectionTargetKind::RetainedFinding)
            .unwrap();
        let retained_schema = reviewer_output_schema(Some(&retained_advisory));
        let retained_variants =
            retained_schema["properties"]["inspection_results"]["items"]["anyOf"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|variant| {
                    variant["properties"]["target_id"]["const"] == retained_target.id.to_string()
                })
                .collect::<Vec<_>>();
        assert_eq!(retained_variants.len(), 1);
        assert!(retained_variants[0]["properties"].get("findings").is_none());
    }

    fn assert_provider_schema_omits_unsupported_unique_items(value: &Value) {
        match value {
            Value::Object(object) => {
                assert!(
                    !object.contains_key("uniqueItems"),
                    "Codex Structured Outputs rejects uniqueItems"
                );
                for child in object.values() {
                    assert_provider_schema_omits_unsupported_unique_items(child);
                }
            }
            Value::Array(values) => {
                for child in values {
                    assert_provider_schema_omits_unsupported_unique_items(child);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn review_normalization_identifies_invalid_rule_shape() {
        let response = json!({
            "verdict": "rejected",
            "acceptance_coverage": [{
                "criterion": "The result is deterministic.",
                "status": "addressed",
                "evidence": "The relevant source line was inspected."
            }],
            "findings": [{
                "kind": "new",
                "rule": "math/parity",
                "severity": "error",
                "path": "src/lib.rs",
                "line": 1,
                "message": "The implementation returns a constant.",
                "evidence": "The function body returns true for every input."
            }]
        });
        let error = match normalize_review_turn(Ok(review_turn(response)), &request(), None) {
            Ok(_) => panic!("invalid rule unexpectedly normalized"),
            Err(error) => error,
        };
        assert!(error.diagnostic.contains("finding 0 rule"));
    }

    #[test]
    fn refresh_normalization_closes_every_target_and_resolves_retained_payload() {
        let prior = ReviewFinding::new(
            "stable.rule",
            ReviewSeverity::Error,
            "src/lib.rs",
            Some(1),
            "The implementation returns a constant.",
            Digest::blake3(b"stable-evidence"),
        )
        .unwrap();
        let advisory = advisory(vec![prior.clone()]);
        let retained_target = advisory
            .inspection_targets
            .iter()
            .find(|target| target.kind == ReviewInspectionTargetKind::RetainedFinding)
            .unwrap();
        let changed_target = advisory
            .inspection_targets
            .iter()
            .find(|target| target.kind == ReviewInspectionTargetKind::ChangedPath)
            .unwrap();
        let response = json!({
            "verdict": "rejected",
            "acceptance_coverage": [{
                "criterion": "The result is deterministic.",
                "status": "addressed",
                "evidence": "The current source was reviewed independently."
            }],
            "inspection_results": [{
                "target_id": retained_target.id,
                "outcome": "still_valid",
                "evidence": "The retained line still contains the same defect.",
                "findings": []
            }, {
                "target_id": changed_target.id,
                "outcome": "findings",
                "evidence": "The changed path contains a new deterministic defect.",
                "findings": [{
                    "kind": "new",
                    "rule": "new.rule",
                    "severity": "warning",
                    "path": "src/changed.rs",
                    "line": 2,
                    "message": "The changed path introduces a defect.",
                    "evidence": "The new branch returns the wrong value."
                }]
            }]
        });

        let normalized =
            normalize_review_turn(Ok(review_turn(response)), &request(), Some(&advisory)).unwrap();
        assert_eq!(normalized.findings.len(), 2);
        assert!(normalized.findings.contains(&prior));
        assert_eq!(normalized.inspection_coverage.len(), 2);
        assert_eq!(normalized.inspection_context_digest, Some(advisory.inspection_context_digest));
    }

    #[test]
    fn refresh_missing_target_requires_full_fallback() {
        let advisory = advisory(Vec::new());
        let response = json!({
            "verdict": "approved",
            "acceptance_coverage": [{
                "criterion": "The result is deterministic.",
                "status": "addressed",
                "evidence": "The current source was reviewed independently."
            }],
            "inspection_results": []
        });

        let error =
            match normalize_review_turn(Ok(review_turn(response)), &request(), Some(&advisory)) {
                Ok(_) => panic!("incomplete refresh unexpectedly normalized"),
                Err(error) => error,
            };
        assert!(error.full_fallback_required);
        assert!(error.diagnostic.contains("every inspection target"));
    }

    #[test]
    fn refresh_unknown_and_duplicate_targets_require_full_fallback() {
        let acceptance = json!([{
            "criterion": "The result is deterministic.",
            "status": "addressed",
            "evidence": "The current source was reviewed independently."
        }]);
        let single = advisory(Vec::new());
        let unknown = json!({
            "verdict": "approved",
            "acceptance_coverage": acceptance.clone(),
            "inspection_results": [{
                "target_id": Digest::blake3(b"unknown-target"),
                "outcome": "clean",
                "evidence": "An unrelated target was inspected.",
                "findings": []
            }]
        });
        let error = normalize_review_turn(Ok(review_turn(unknown)), &request(), Some(&single))
            .err()
            .unwrap();
        assert!(error.full_fallback_required);
        assert!(error.diagnostic.contains("unknown inspection target"));

        let prior = ReviewFinding::new(
            "stable.rule",
            ReviewSeverity::Error,
            "src/lib.rs",
            Some(1),
            "The implementation returns a constant.",
            Digest::blake3(b"stable-evidence"),
        )
        .unwrap();
        let multiple = advisory(vec![prior]);
        let target = &multiple.inspection_targets[0];
        let duplicate_results = (0..2)
            .map(|_| {
                json!({
                    "target_id": target.id,
                    "outcome": if target.kind == ReviewInspectionTargetKind::ChangedPath {
                        "clean"
                    } else {
                        "stale"
                    },
                    "evidence": "The same target was returned twice.",
                    "findings": []
                })
            })
            .collect::<Vec<_>>();
        let duplicate = json!({
            "verdict": "approved",
            "acceptance_coverage": acceptance,
            "inspection_results": duplicate_results
        });
        let error = normalize_review_turn(Ok(review_turn(duplicate)), &request(), Some(&multiple))
            .err()
            .unwrap();
        assert!(error.full_fallback_required);
        assert!(error.diagnostic.contains("duplicate inspection target"));
    }

    #[test]
    fn refresh_findings_outcome_requires_a_new_finding() {
        let advisory = advisory(Vec::new());
        let target = &advisory.inspection_targets[0];
        let response = json!({
            "verdict": "approved",
            "acceptance_coverage": [{
                "criterion": "The result is deterministic.",
                "status": "addressed",
                "evidence": "The changed source was inspected."
            }],
            "inspection_results": [{
                "target_id": target.id,
                "outcome": "findings",
                "evidence": "A defect was claimed without a finding payload.",
                "findings": []
            }]
        });
        let error = normalize_review_turn(Ok(review_turn(response)), &request(), Some(&advisory))
            .err()
            .unwrap();
        assert!(error.full_fallback_required);
        assert!(error.diagnostic.contains("does not match"));
    }

    #[test]
    fn refresh_inconclusive_target_requires_full_fallback() {
        let advisory = advisory(Vec::new());
        let target = &advisory.inspection_targets[0];
        let response = json!({
            "verdict": "inconclusive",
            "acceptance_coverage": [{
                "criterion": "The result is deterministic.",
                "status": "partial",
                "evidence": "The target could not be fully inspected."
            }],
            "inspection_results": [{
                "target_id": target.id,
                "outcome": "inconclusive",
                "evidence": "The target could not be fully inspected.",
                "findings": []
            }]
        });
        let error = normalize_review_turn(Ok(review_turn(response)), &request(), Some(&advisory))
            .err()
            .unwrap();
        assert!(error.full_fallback_required);
        assert!(error.diagnostic.contains("inconclusive"));
    }

    #[test]
    fn refresh_advisory_is_explicitly_non_authoritative_and_state_bound() {
        let finding = ReviewFinding::new(
            "stale.rule",
            ReviewSeverity::Warning,
            "src/lib.rs",
            Some(7),
            "Revalidate this prior finding.",
            Digest::blake3(b"evidence"),
        )
        .unwrap();
        let delta = StateDelta::new(
            Digest::blake3(b"repository"),
            RepositoryContextId::new(Digest::blake3(b"review-context")),
            1,
            2,
            vec![DependencyLocator::repository_path("src/lib.rs").unwrap()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            true,
        )
        .unwrap();
        let advisory =
            ReviewRefreshAdvisory { state_delta: delta.clone(), ..advisory(vec![finding]) };
        let patch = PatchArtifact {
            id: PatchId(Digest::blake3(b"patch")),
            change_id: ChangeId::from_digest(Digest::blake3(b"change")),
            revision: 2,
            source_snapshot: Digest::blake3(b"source"),
            files: Vec::new(),
            summary: "review fixture".to_owned(),
            acceptance_coverage: Vec::new(),
            residual_risks: Vec::new(),
            declared_output_digest: Digest::blake3(b"output"),
            discrepancies: Vec::new(),
        };
        let prompt: Value =
            serde_json::from_str(&reviewer_prompt(&request(), &patch, Some(&advisory))).unwrap();
        assert_eq!(prompt["operation"], "refresh_aware_full_diff_review");
        assert!(prompt["finding_format"].as_str().unwrap().contains("ASCII letters"));
        assert_eq!(
            prompt["prior_partition_advisory"]["state_delta_digest"],
            delta.digest.to_string()
        );
        assert_eq!(
            prompt["prior_partition_advisory"]["inspection_context_digest"],
            advisory.inspection_context_digest.to_string()
        );
        assert_eq!(
            prompt["prior_partition_advisory"]["inspection_targets"].as_array().unwrap().len(),
            advisory.inspection_targets.len()
        );
        assert_eq!(
            prompt["prior_partition_advisory"]["retained_findings_requiring_revalidation"]
                .as_array()
                .unwrap()
                .len(),
            advisory.retained_findings.len()
        );
        assert!(
            prompt["prior_partition_advisory"]["instructions"]
                .as_str()
                .unwrap()
                .contains("fresh whole-review verdict")
        );
        assert!(
            prompt["prior_partition_advisory"]["instructions"]
                .as_str()
                .unwrap()
                .contains("target_id")
        );
    }
}

#[cfg(test)]
mod live_gate_a6;
