use needle_core::{
    AcceptanceStatus, ChangeRequest, Digest, PatchArtifact, ReviewCoverage, ReviewFinding,
    ReviewReportVerdict, ReviewSeverity,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const REVIEW_FINDING_FORMAT_INSTRUCTIONS: &str = "Every new finding rule must contain only ASCII letters, digits, dot, underscore, or hyphen. Every new finding path must be a repository-relative forward-slash path with no empty, dot, or parent components. Keep all finding and evidence material within the declared schema bounds.";

pub const REVIEWER_INSTRUCTIONS: &str = "You are Needle's independent read-only diff reviewer. Review the actual patched filesystem in the disposable checkout against every supplied acceptance criterion. You have no patcher transcript. Do not modify files, run tests, use network, hooks, plugins, MCP, project instructions, memory, or other agents. Inspect only through the provided bounded repository tools. Report concrete file-and-rule findings with evidence. Return only closed JSON matching the output schema.";

#[derive(Clone, Debug)]
pub struct NormalizedFullReview {
    pub verdict: ReviewReportVerdict,
    pub acceptance_coverage: Vec<ReviewCoverage>,
    pub findings: Vec<ReviewFinding>,
    pub output_tokens: Option<u64>,
    pub response_digest: Digest,
}

pub fn full_reviewer_prompt(request: &ChangeRequest, patch: &PatchArtifact) -> String {
    serde_json::to_string(&json!({
        "operation": "full_diff_review",
        "task": request.task,
        "acceptance_criteria": request.acceptance_criteria,
        "constraints": request.constraints,
        "allowed_paths": request.allowed_paths,
        "patch_id": patch.id,
        "changed_files": patch.files.iter().map(|file| &file.path).collect::<Vec<_>>(),
        "finding_format": REVIEW_FINDING_FORMAT_INSTRUCTIONS,
        "prior_partition_advisory": Value::Null
    }))
    .expect("bounded review request serializes")
}

pub fn full_reviewer_output_schema() -> Value {
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

pub fn normalize_full_review_output(
    response: Value,
    request: &ChangeRequest,
    output_tokens: Option<u64>,
) -> Result<NormalizedFullReview, String> {
    let response_digest = Digest::blake3(
        serde_json::to_vec(&response)
            .map_err(|error| format!("review worker response cannot be hashed: {error}"))?,
    );
    let declared: DeclaredReview = serde_json::from_value(response)
        .map_err(|error| format!("review worker returned invalid output: {error}"))?;
    if declared.findings.len() > needle_core::MAX_REVIEW_FINDINGS {
        return Err("review output exceeded its closed cardinality".to_owned());
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
        if finding_ids.insert(finding.id) {
            findings.push(finding);
        }
    }
    let verdict = normalize_verdict(declared.verdict, &coverage, &findings)?;
    Ok(NormalizedFullReview {
        verdict,
        acceptance_coverage: coverage,
        findings,
        output_tokens,
        response_digest,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredReview {
    verdict: DeclaredVerdict,
    acceptance_coverage: Vec<DeclaredCoverage>,
    findings: Vec<DeclaredFinding>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use needle_core::{AllowedPath, AllowedPathScope};

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

    #[test]
    fn full_review_contract_is_closed_and_criterion_bound() {
        let normalized = normalize_full_review_output(
            json!({
                "verdict": "approved",
                "acceptance_coverage": [{
                    "criterion": "The result is deterministic.",
                    "status": "addressed",
                    "evidence": "The patched function is deterministic."
                }],
                "findings": []
            }),
            &request(),
            Some(7),
        )
        .unwrap();
        assert_eq!(normalized.verdict, ReviewReportVerdict::Approved);
        assert_eq!(normalized.output_tokens, Some(7));
        assert_eq!(full_reviewer_output_schema()["additionalProperties"], false);
        assert!(
            full_reviewer_prompt(
                &request(),
                &PatchArtifact {
                    id: needle_core::PatchId(Digest::blake3(b"patch")),
                    change_id: needle_core::ChangeId::from_digest(Digest::blake3(b"change")),
                    revision: 1,
                    source_snapshot: Digest::blake3(b"source"),
                    files: Vec::new(),
                    summary: "fixture".to_owned(),
                    acceptance_coverage: Vec::new(),
                    residual_risks: Vec::new(),
                    declared_output_digest: Digest::blake3(b"output"),
                    discrepancies: Vec::new(),
                }
            )
            .contains("full_diff_review")
        );
    }

    #[test]
    fn approved_review_rejects_findings_or_incomplete_coverage() {
        for response in [
            json!({
                "verdict": "approved",
                "acceptance_coverage": [{
                    "criterion": "The result is deterministic.",
                    "status": "partial",
                    "evidence": "Only part is covered."
                }],
                "findings": []
            }),
            json!({
                "verdict": "approved",
                "acceptance_coverage": [{
                    "criterion": "The result is deterministic.",
                    "status": "addressed",
                    "evidence": "Covered."
                }],
                "findings": [{
                    "kind": "new",
                    "rule": "fixture.rule",
                    "severity": "error",
                    "path": "src/lib.rs",
                    "line": 1,
                    "message": "A defect remains.",
                    "evidence": "The return value is wrong."
                }]
            }),
        ] {
            assert!(normalize_full_review_output(response, &request(), None).is_err());
        }
    }
}
