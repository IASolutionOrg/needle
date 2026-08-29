use crate::{
    AcceptanceStatus, ArtifactId, ArtifactRequestId, CanonicalHasher, ChangeId, Digest, PatchId,
};
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::marker::PhantomData;
use thiserror::Error;

pub const TEST_EXECUTION_EVIDENCE_SCHEMA_ID: &str = "needle.test-execution-evidence/3";
pub const TEST_EXECUTION_OUTPUT_CONTRACT_ID: &str = "needle.execution.test";
pub const TEST_EXECUTION_OUTPUT_CONTRACT_REVISION: u32 = 3;
pub const MAX_TEST_EXECUTION_COMMAND_EVIDENCE_ID_BYTES: usize = 128;
pub const REVIEW_REPORT_SCHEMA_ID_V1: &str = "needle.review-report/1";
pub const REVIEW_REPORT_SCHEMA_ID: &str = "needle.review-report/2";
pub const REVIEW_REPORT_OUTPUT_CONTRACT_ID: &str = "needle.review.diff";
pub const REVIEW_REPORT_OUTPUT_CONTRACT_REVISION: u32 = 2;
pub const APPLY_RECEIPT_SCHEMA_ID: &str = "needle.apply-receipt/1";
pub const APPLY_RECEIPT_OUTPUT_CONTRACT_ID: &str = "needle.effect.patch-apply";
pub const APPLY_RECEIPT_OUTPUT_CONTRACT_REVISION: u32 = 1;
pub const PATCH_PROPOSAL_SCHEMA_ID: &str = "needle.patch-artifact/1";
pub const PATCH_PROPOSAL_OUTPUT_CONTRACT_ID: &str = "needle.change.patch";
pub const PATCH_PROPOSAL_OUTPUT_CONTRACT_REVISION: u32 = 1;
pub const PATCH_VERIFICATION_SCHEMA_ID: &str = "needle.verification-artifact/2";
pub const PATCH_VERIFICATION_OUTPUT_CONTRACT_ID: &str = "needle.change.verification";
pub const PATCH_VERIFICATION_OUTPUT_CONTRACT_REVISION: u32 = 2;

pub const MAX_REVIEW_FINDINGS: usize = 32;
pub const MAX_REVIEW_COVERAGE: usize = 8;
pub const MAX_REVIEW_RULE_BYTES: usize = 128;
pub const MAX_REVIEW_PATH_BYTES: usize = 512;
pub const MAX_REVIEW_MESSAGE_BYTES: usize = 4 * 1024;
pub const MAX_REVIEW_REPORT_WIRE_BYTES: usize = 256 * 1024;
pub const MAX_REVIEW_INSPECTION_TARGETS: usize = 64;
pub const MAX_REVIEW_INVALIDATED_PARTITIONS_PER_TARGET: usize = MAX_REVIEW_FINDINGS;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestExecutionStatus {
    Passed,
    Failed,
    Unavailable,
    Inconclusive,
}

impl TestExecutionStatus {
    const fn tag(self) -> u8 {
        match self {
            Self::Passed => 0,
            Self::Failed => 1,
            Self::Unavailable => 2,
            Self::Inconclusive => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TestExecutionEvidenceId(pub Digest);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestExecutionEvidence {
    pub schema: String,
    pub id: TestExecutionEvidenceId,
    pub action_request: ArtifactRequestId,
    pub change_id: ChangeId,
    pub patch_id: PatchId,
    pub test_plan_artifact: ArtifactId,
    pub test_plan_digest: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_evidence_id: Option<String>,
    pub source_snapshot: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_snapshot: Option<Digest>,
    pub command_digest: Digest,
    pub toolchain_digest: Digest,
    pub environment_digest: Digest,
    pub execution_policy_digest: Digest,
    pub status: TestExecutionStatus,
    pub exit_status: Option<i32>,
    pub output_digest: Digest,
    pub duration_ms: u64,
    pub executed_unix_ms: u64,
}

impl TestExecutionEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_request: ArtifactRequestId,
        change_id: ChangeId,
        patch_id: PatchId,
        test_plan_artifact: ArtifactId,
        test_plan_digest: Digest,
        command_evidence_id: Option<String>,
        source_snapshot: Digest,
        execution_snapshot: Option<Digest>,
        command_digest: Digest,
        toolchain_digest: Digest,
        environment_digest: Digest,
        execution_policy_digest: Digest,
        status: TestExecutionStatus,
        exit_status: Option<i32>,
        output_digest: Digest,
        duration_ms: u64,
        executed_unix_ms: u64,
    ) -> Result<Self, ChangeActionArtifactError> {
        let mut evidence = Self {
            schema: TEST_EXECUTION_EVIDENCE_SCHEMA_ID.to_owned(),
            id: TestExecutionEvidenceId(Digest([0; 32])),
            action_request,
            change_id,
            patch_id,
            test_plan_artifact,
            test_plan_digest,
            command_evidence_id,
            source_snapshot,
            execution_snapshot,
            command_digest,
            toolchain_digest,
            environment_digest,
            execution_policy_digest,
            status,
            exit_status,
            output_digest,
            duration_ms,
            executed_unix_ms,
        };
        evidence.validate_material()?;
        evidence.id = TestExecutionEvidenceId(evidence.compute_id());
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), ChangeActionArtifactError> {
        self.validate_material()?;
        if self.id.0 != self.compute_id() {
            return Err(ChangeActionArtifactError::Digest);
        }
        Ok(())
    }

    fn validate_material(&self) -> Result<(), ChangeActionArtifactError> {
        if self.schema != TEST_EXECUTION_EVIDENCE_SCHEMA_ID
            || self.action_request.digest() == Digest([0; 32])
            || self.test_plan_digest == Digest([0; 32])
            || self.source_snapshot == Digest([0; 32])
            || self.command_digest == Digest([0; 32])
            || self.toolchain_digest == Digest([0; 32])
            || self.environment_digest == Digest([0; 32])
            || self.execution_policy_digest == Digest([0; 32])
            || self.output_digest == Digest([0; 32])
            || self.execution_snapshot == Some(Digest([0; 32]))
            || self.command_evidence_id.as_deref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > MAX_TEST_EXECUTION_COMMAND_EVIDENCE_ID_BYTES
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
                    })
            })
        {
            return Err(ChangeActionArtifactError::TestExecution);
        }
        let executed =
            matches!(self.status, TestExecutionStatus::Passed | TestExecutionStatus::Failed);
        if executed != self.exit_status.is_some()
            || (self.status == TestExecutionStatus::Passed && self.exit_status != Some(0))
            || (executed && self.command_evidence_id.is_none())
            || (executed && self.execution_snapshot.is_none())
            || (self.status == TestExecutionStatus::Unavailable
                && (self.command_evidence_id.is_some() || self.execution_snapshot.is_some()))
        {
            return Err(ChangeActionArtifactError::TestExecution);
        }
        Ok(())
    }

    fn compute_id(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"needle-test-execution-evidence-v3");
        hasher.field_digest(self.action_request.digest());
        hasher.field_str(self.change_id.as_str());
        hasher.field_digest(self.patch_id.0);
        hasher.field_digest(self.test_plan_artifact.0);
        hasher.field_digest(self.test_plan_digest);
        hasher.field_u8(u8::from(self.command_evidence_id.is_some()));
        if let Some(command_evidence_id) = &self.command_evidence_id {
            hasher.field_str(command_evidence_id);
        }
        hasher.field_digest(self.source_snapshot);
        hasher.field_u8(u8::from(self.execution_snapshot.is_some()));
        if let Some(execution_snapshot) = self.execution_snapshot {
            hasher.field_digest(execution_snapshot);
        }
        hasher.field_digest(self.command_digest);
        hasher.field_digest(self.toolchain_digest);
        hasher.field_digest(self.environment_digest);
        hasher.field_digest(self.execution_policy_digest);
        hasher.field_u8(self.status.tag());
        hasher.field_u8(u8::from(self.exit_status.is_some()));
        if let Some(exit_status) = self.exit_status {
            hasher.field_bytes(&exit_status.to_le_bytes());
        }
        hasher.field_digest(self.output_digest);
        hasher.field_bytes(&self.duration_ms.to_le_bytes());
        hasher.field_bytes(&self.executed_unix_ms.to_le_bytes());
        hasher.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl ReviewSeverity {
    const fn tag(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Warning => 1,
            Self::Error => 2,
            Self::Critical => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewReportVerdict {
    Approved,
    Rejected,
    Inconclusive,
}

impl ReviewReportVerdict {
    const fn tag(self) -> u8 {
        match self {
            Self::Approved => 0,
            Self::Rejected => 1,
            Self::Inconclusive => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewCoverage {
    pub criterion_digest: Digest,
    pub status: AcceptanceStatus,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewFinding {
    pub id: Digest,
    pub rule: String,
    pub severity: ReviewSeverity,
    pub path: String,
    pub line: Option<u32>,
    pub message: String,
    pub evidence_digest: Digest,
}

impl ReviewFinding {
    pub fn new(
        rule: impl Into<String>,
        severity: ReviewSeverity,
        path: impl Into<String>,
        line: Option<u32>,
        message: impl Into<String>,
        evidence_digest: Digest,
    ) -> Result<Self, ChangeActionArtifactError> {
        let mut finding = Self {
            id: Digest([0; 32]),
            rule: rule.into(),
            severity,
            path: path.into(),
            line,
            message: message.into(),
            evidence_digest,
        };
        finding.validate_material()?;
        finding.id = finding.compute_id();
        Ok(finding)
    }

    fn validate_material(&self) -> Result<(), ChangeActionArtifactError> {
        if self.rule.is_empty()
            || self.rule.len() > MAX_REVIEW_RULE_BYTES
            || !self
                .rule
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || !safe_review_path(&self.path)
            || self.message.trim().is_empty()
            || self.message.len() > MAX_REVIEW_MESSAGE_BYTES
            || self.evidence_digest == Digest([0; 32])
        {
            return Err(ChangeActionArtifactError::ReviewFinding);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ChangeActionArtifactError> {
        self.validate_material()?;
        if self.id != self.compute_id() {
            return Err(ChangeActionArtifactError::Digest);
        }
        Ok(())
    }

    fn compute_id(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"needle-review-finding-v1");
        hasher.field_str(&self.rule);
        hasher.field_u8(self.severity.tag());
        hasher.field_str(&self.path);
        hasher.field_u8(u8::from(self.line.is_some()));
        if let Some(line) = self.line {
            hasher.field_u32(line);
        }
        hasher.field_normalized_lines(&self.message);
        hasher.field_digest(self.evidence_digest);
        hasher.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewInspectionTargetKind {
    RetainedFinding,
    ChangedPath,
}

impl ReviewInspectionTargetKind {
    const fn tag(self) -> u8 {
        match self {
            Self::RetainedFinding => 0,
            Self::ChangedPath => 1,
        }
    }
}

pub fn review_inspection_context_digest(
    state_delta_digest: Digest,
    prior_manifest: crate::PartitionManifestId,
    current_patch: PatchId,
) -> Digest {
    let mut hasher = CanonicalHasher::new(b"needle-review-inspection-context-v1");
    hasher.field_digest(state_delta_digest);
    hasher.field_digest(prior_manifest.digest());
    hasher.field_digest(current_patch.0);
    hasher.finish()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewInspectionTarget {
    pub id: Digest,
    pub kind: ReviewInspectionTargetKind,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_finding_id: Option<Digest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde(deserialize_with = "deserialize_review_invalidated_partition_keys")]
    pub invalidated_partition_keys: Vec<Digest>,
}

impl ReviewInspectionTarget {
    pub fn retained_finding(
        context_digest: Digest,
        path: impl Into<String>,
        retained_finding_id: Digest,
    ) -> Result<Self, ChangeActionArtifactError> {
        Self::build(
            context_digest,
            ReviewInspectionTargetKind::RetainedFinding,
            path.into(),
            Some(retained_finding_id),
            Vec::new(),
        )
    }

    pub fn changed_path(
        context_digest: Digest,
        path: impl Into<String>,
        mut invalidated_partition_keys: Vec<Digest>,
    ) -> Result<Self, ChangeActionArtifactError> {
        invalidated_partition_keys.sort_unstable();
        Self::build(
            context_digest,
            ReviewInspectionTargetKind::ChangedPath,
            path.into(),
            None,
            invalidated_partition_keys,
        )
    }

    fn build(
        context_digest: Digest,
        kind: ReviewInspectionTargetKind,
        path: String,
        retained_finding_id: Option<Digest>,
        invalidated_partition_keys: Vec<Digest>,
    ) -> Result<Self, ChangeActionArtifactError> {
        let mut target = Self {
            id: Digest([0; 32]),
            kind,
            path,
            retained_finding_id,
            invalidated_partition_keys,
        };
        target.validate_material(context_digest)?;
        target.id = target.compute_id(context_digest);
        Ok(target)
    }

    pub fn validate(&self, context_digest: Digest) -> Result<(), ChangeActionArtifactError> {
        self.validate_material(context_digest)?;
        if self.id != self.compute_id(context_digest) {
            return Err(ChangeActionArtifactError::Digest);
        }
        Ok(())
    }

    fn validate_material(&self, context_digest: Digest) -> Result<(), ChangeActionArtifactError> {
        if context_digest == Digest([0; 32])
            || !safe_review_path(&self.path)
            || self.invalidated_partition_keys.len() > MAX_REVIEW_INVALIDATED_PARTITIONS_PER_TARGET
            || self.invalidated_partition_keys.contains(&Digest([0; 32]))
            || self.invalidated_partition_keys.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ChangeActionArtifactError::ReviewInspection);
        }
        match self.kind {
            ReviewInspectionTargetKind::RetainedFinding
                if self.retained_finding_id.is_some_and(|finding| finding != Digest([0; 32]))
                    && self.invalidated_partition_keys.is_empty() => {}
            ReviewInspectionTargetKind::ChangedPath if self.retained_finding_id.is_none() => {}
            _ => return Err(ChangeActionArtifactError::ReviewInspection),
        }
        Ok(())
    }

    fn compute_id(&self, context_digest: Digest) -> Digest {
        let mut hasher = CanonicalHasher::new(b"needle-review-inspection-target-v1");
        hasher.field_digest(context_digest);
        hasher.field_u8(self.kind.tag());
        hasher.field_str(&self.path);
        hasher.field_u8(u8::from(self.retained_finding_id.is_some()));
        if let Some(finding) = self.retained_finding_id {
            hasher.field_digest(finding);
        }
        hasher.field_u16(self.invalidated_partition_keys.len().try_into().unwrap_or(u16::MAX));
        for key in &self.invalidated_partition_keys {
            hasher.field_digest(*key);
        }
        hasher.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewInspectionOutcome {
    StillValid,
    Stale,
    Clean,
    Findings,
    Inconclusive,
}

impl ReviewInspectionOutcome {
    const fn tag(self) -> u8 {
        match self {
            Self::StillValid => 0,
            Self::Stale => 1,
            Self::Clean => 2,
            Self::Findings => 3,
            Self::Inconclusive => 4,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewInspectionCoverage {
    pub target: ReviewInspectionTarget,
    pub outcome: ReviewInspectionOutcome,
    #[serde(deserialize_with = "deserialize_review_finding_ids")]
    pub finding_ids: Vec<Digest>,
    pub evidence_digest: Digest,
}

impl ReviewInspectionCoverage {
    pub fn new(
        context_digest: Digest,
        target: ReviewInspectionTarget,
        outcome: ReviewInspectionOutcome,
        mut finding_ids: Vec<Digest>,
        evidence_digest: Digest,
    ) -> Result<Self, ChangeActionArtifactError> {
        finding_ids.sort_unstable();
        let coverage = Self { target, outcome, finding_ids, evidence_digest };
        coverage.validate(context_digest)?;
        Ok(coverage)
    }

    pub fn validate(&self, context_digest: Digest) -> Result<(), ChangeActionArtifactError> {
        self.target.validate(context_digest)?;
        if self.evidence_digest == Digest([0; 32])
            || self.finding_ids.len() > MAX_REVIEW_FINDINGS
            || self.finding_ids.contains(&Digest([0; 32]))
            || self.finding_ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ChangeActionArtifactError::ReviewInspection);
        }
        let valid = match (self.target.kind, self.outcome) {
            (ReviewInspectionTargetKind::RetainedFinding, ReviewInspectionOutcome::StillValid) => {
                self.finding_ids.as_slice()
                    == self.target.retained_finding_id.as_ref().map(std::slice::from_ref).unwrap()
            }
            (ReviewInspectionTargetKind::RetainedFinding, ReviewInspectionOutcome::Stale)
            | (
                ReviewInspectionTargetKind::RetainedFinding,
                ReviewInspectionOutcome::Inconclusive,
            )
            | (ReviewInspectionTargetKind::ChangedPath, ReviewInspectionOutcome::Clean)
            | (ReviewInspectionTargetKind::ChangedPath, ReviewInspectionOutcome::Inconclusive) => {
                self.finding_ids.is_empty()
            }
            (ReviewInspectionTargetKind::ChangedPath, ReviewInspectionOutcome::Findings) => {
                !self.finding_ids.is_empty()
            }
            _ => false,
        };
        if !valid {
            return Err(ChangeActionArtifactError::ReviewInspection);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReport {
    pub schema: String,
    pub id: Digest,
    pub action_request: ArtifactRequestId,
    pub change_id: ChangeId,
    pub patch_id: PatchId,
    pub requirements_digest: Digest,
    pub reviewer_definition: Digest,
    pub verdict: ReviewReportVerdict,
    pub acceptance_coverage: Vec<ReviewCoverage>,
    pub findings: Vec<ReviewFinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspection_context_digest: Option<Digest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde(deserialize_with = "deserialize_review_inspection_coverage")]
    pub inspection_coverage: Vec<ReviewInspectionCoverage>,
    pub manifest: Option<crate::PartitionManifestId>,
    pub created_unix_ms: u64,
}

impl ReviewReport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_request: ArtifactRequestId,
        change_id: ChangeId,
        patch_id: PatchId,
        requirements_digest: Digest,
        reviewer_definition: Digest,
        verdict: ReviewReportVerdict,
        mut acceptance_coverage: Vec<ReviewCoverage>,
        mut findings: Vec<ReviewFinding>,
        manifest: Option<crate::PartitionManifestId>,
        created_unix_ms: u64,
    ) -> Result<Self, ChangeActionArtifactError> {
        acceptance_coverage.sort_by_key(|coverage| coverage.criterion_digest);
        findings.sort_by_key(|finding| finding.id);
        let mut report = Self {
            schema: REVIEW_REPORT_SCHEMA_ID.to_owned(),
            id: Digest([0; 32]),
            action_request,
            change_id,
            patch_id,
            requirements_digest,
            reviewer_definition,
            verdict,
            acceptance_coverage,
            findings,
            inspection_context_digest: None,
            inspection_coverage: Vec::new(),
            manifest,
            created_unix_ms,
        };
        report.validate_material()?;
        report.id = report.compute_id();
        Ok(report)
    }

    pub fn with_inspection_coverage(
        mut self,
        inspection_context_digest: Digest,
        mut inspection_coverage: Vec<ReviewInspectionCoverage>,
    ) -> Result<Self, ChangeActionArtifactError> {
        inspection_coverage.sort_by_key(|coverage| coverage.target.id);
        self.inspection_context_digest = Some(inspection_context_digest);
        self.inspection_coverage = inspection_coverage;
        self.validate_material()?;
        self.id = self.compute_id();
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), ChangeActionArtifactError> {
        self.validate_material()?;
        if self.id != self.compute_id() {
            return Err(ChangeActionArtifactError::Digest);
        }
        Ok(())
    }

    fn validate_material(&self) -> Result<(), ChangeActionArtifactError> {
        let legacy = self.schema == REVIEW_REPORT_SCHEMA_ID_V1;
        if (!legacy && self.schema != REVIEW_REPORT_SCHEMA_ID)
            || self.action_request.digest() == Digest([0; 32])
            || self.requirements_digest == Digest([0; 32])
            || self.reviewer_definition == Digest([0; 32])
            || self.acceptance_coverage.is_empty()
            || self.acceptance_coverage.len() > MAX_REVIEW_COVERAGE
            || self.findings.len() > MAX_REVIEW_FINDINGS
            || self.inspection_coverage.len() > MAX_REVIEW_INSPECTION_TARGETS
            || self.inspection_context_digest == Some(Digest([0; 32]))
            || self.inspection_context_digest.is_some() == self.inspection_coverage.is_empty()
            || (legacy
                && (self.inspection_context_digest.is_some()
                    || !self.inspection_coverage.is_empty()))
        {
            return Err(ChangeActionArtifactError::ReviewReport);
        }
        if self
            .acceptance_coverage
            .windows(2)
            .any(|pair| pair[0].criterion_digest >= pair[1].criterion_digest)
            || self.findings.windows(2).any(|pair| pair[0].id >= pair[1].id)
            || self
                .inspection_coverage
                .windows(2)
                .any(|pair| pair[0].target.id >= pair[1].target.id)
        {
            return Err(ChangeActionArtifactError::CanonicalOrder);
        }
        if self.verdict == ReviewReportVerdict::Approved
            && (self
                .acceptance_coverage
                .iter()
                .any(|coverage| coverage.status != AcceptanceStatus::Addressed)
                || !self.findings.is_empty())
        {
            return Err(ChangeActionArtifactError::ReviewReport);
        }
        for coverage in &self.acceptance_coverage {
            if coverage.criterion_digest == Digest([0; 32])
                || coverage.evidence_digest == Digest([0; 32])
            {
                return Err(ChangeActionArtifactError::ReviewReport);
            }
        }
        for finding in &self.findings {
            finding.validate()?;
        }
        if let Some(context_digest) = self.inspection_context_digest {
            let mut covered_findings = BTreeSet::new();
            for coverage in &self.inspection_coverage {
                coverage.validate(context_digest)?;
                if coverage.outcome == ReviewInspectionOutcome::Inconclusive {
                    return Err(ChangeActionArtifactError::ReviewInspection);
                }
                covered_findings.extend(coverage.finding_ids.iter().copied());
            }
            let report_findings = self.findings.iter().map(|finding| finding.id).collect();
            if covered_findings != report_findings {
                return Err(ChangeActionArtifactError::ReviewInspection);
            }
        }
        Ok(())
    }

    fn compute_id(&self) -> Digest {
        let mut hasher = if self.schema == REVIEW_REPORT_SCHEMA_ID_V1 {
            CanonicalHasher::new(b"needle-review-report-v1")
        } else {
            CanonicalHasher::new(b"needle-review-report-v2")
        };
        hasher.field_digest(self.action_request.digest());
        hasher.field_str(self.change_id.as_str());
        hasher.field_digest(self.patch_id.0);
        hasher.field_digest(self.requirements_digest);
        hasher.field_digest(self.reviewer_definition);
        hasher.field_u8(self.verdict.tag());
        hasher.field_u16(self.acceptance_coverage.len().try_into().unwrap_or(u16::MAX));
        for coverage in &self.acceptance_coverage {
            hasher.field_digest(coverage.criterion_digest);
            hasher.field_u8(match coverage.status {
                AcceptanceStatus::Addressed => 0,
                AcceptanceStatus::Partial => 1,
                AcceptanceStatus::Unaddressed => 2,
            });
            hasher.field_digest(coverage.evidence_digest);
        }
        hasher.field_u16(self.findings.len().try_into().unwrap_or(u16::MAX));
        for finding in &self.findings {
            hasher.field_digest(finding.id);
        }
        if self.schema != REVIEW_REPORT_SCHEMA_ID_V1 {
            hasher.field_u8(u8::from(self.inspection_context_digest.is_some()));
            if let Some(context_digest) = self.inspection_context_digest {
                hasher.field_digest(context_digest);
            }
            hasher.field_u16(self.inspection_coverage.len().try_into().unwrap_or(u16::MAX));
            for coverage in &self.inspection_coverage {
                hasher.field_digest(coverage.target.id);
                hasher.field_u8(coverage.outcome.tag());
                hasher.field_u16(coverage.finding_ids.len().try_into().unwrap_or(u16::MAX));
                for finding in &coverage.finding_ids {
                    hasher.field_digest(*finding);
                }
                hasher.field_digest(coverage.evidence_digest);
            }
        }
        hasher.field_u8(u8::from(self.manifest.is_some()));
        if let Some(manifest) = self.manifest {
            hasher.field_digest(manifest.digest());
        }
        hasher.field_bytes(&self.created_unix_ms.to_le_bytes());
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyReceipt {
    pub schema: String,
    pub id: Digest,
    pub operation_id: Digest,
    pub change_id: ChangeId,
    pub patch_id: PatchId,
    pub expected_state_digest: Digest,
    pub source_before: Digest,
    pub source_after: Digest,
    pub applied_files_digest: Digest,
    pub applied_unix_ms: u64,
}

impl ApplyReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: Digest,
        change_id: ChangeId,
        patch_id: PatchId,
        expected_state_digest: Digest,
        source_before: Digest,
        source_after: Digest,
        applied_files_digest: Digest,
        applied_unix_ms: u64,
    ) -> Result<Self, ChangeActionArtifactError> {
        let mut receipt = Self {
            schema: APPLY_RECEIPT_SCHEMA_ID.to_owned(),
            id: Digest([0; 32]),
            operation_id,
            change_id,
            patch_id,
            expected_state_digest,
            source_before,
            source_after,
            applied_files_digest,
            applied_unix_ms,
        };
        receipt.validate_material()?;
        receipt.id = receipt.compute_id();
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), ChangeActionArtifactError> {
        self.validate_material()?;
        if self.id != self.compute_id() {
            return Err(ChangeActionArtifactError::Digest);
        }
        Ok(())
    }

    fn validate_material(&self) -> Result<(), ChangeActionArtifactError> {
        if self.schema != APPLY_RECEIPT_SCHEMA_ID
            || self.operation_id == Digest([0; 32])
            || self.expected_state_digest == Digest([0; 32])
            || self.source_before == Digest([0; 32])
            || self.source_after == Digest([0; 32])
            || self.applied_files_digest == Digest([0; 32])
            || self.source_before == self.source_after
        {
            return Err(ChangeActionArtifactError::ApplyReceipt);
        }
        Ok(())
    }

    fn compute_id(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"needle-apply-receipt-v1");
        hasher.field_digest(self.operation_id);
        hasher.field_str(self.change_id.as_str());
        hasher.field_digest(self.patch_id.0);
        hasher.field_digest(self.expected_state_digest);
        hasher.field_digest(self.source_before);
        hasher.field_digest(self.source_after);
        hasher.field_digest(self.applied_files_digest);
        hasher.field_bytes(&self.applied_unix_ms.to_le_bytes());
        hasher.finish()
    }
}

pub fn patch_proposal_validator_definition() -> Digest {
    Digest::blake3(b"needle-patch-proposal-validator-v1")
}

pub fn patch_proposal_semantic_definition() -> Digest {
    Digest::blake3(b"needle-patch-proposal-semantics-v1")
}

pub fn test_execution_validator_definition() -> Digest {
    Digest::blake3(b"needle-test-execution-validator-v3")
}

pub fn test_execution_semantic_definition() -> Digest {
    Digest::blake3(b"needle-test-execution-semantics-v2")
}

pub fn review_report_validator_definition() -> Digest {
    Digest::blake3(b"needle-review-report-validator-v2")
}

pub fn patch_verification_validator_definition() -> Digest {
    Digest::blake3(b"needle-patch-verification-validator-v2")
}

pub fn patch_verification_semantic_definition() -> Digest {
    Digest::blake3(b"needle-patch-verification-semantics-v2")
}

pub fn apply_receipt_validator_definition() -> Digest {
    Digest::blake3(b"needle-apply-receipt-validator-v1")
}

pub fn apply_receipt_semantic_definition() -> Digest {
    Digest::blake3(b"needle-apply-receipt-semantics-v1")
}

pub fn review_partition_policy_definition() -> Digest {
    Digest::blake3(b"needle-review-provider-file-rule-partitions-v1")
}

pub fn review_provider_adapter_definition() -> Digest {
    Digest::blake3(b"needle-review-provider-adapter-v3")
}

fn safe_review_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REVIEW_PATH_BYTES
        && !value.contains('\\')
        && !value.starts_with('/')
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ChangeActionArtifactError {
    #[error("test execution evidence is inconsistent or out of bounds")]
    TestExecution,
    #[error("review finding is invalid or out of bounds")]
    ReviewFinding,
    #[error("review report is inconsistent or out of bounds")]
    ReviewReport,
    #[error("review inspection target or coverage is inconsistent or out of bounds")]
    ReviewInspection,
    #[error("change action artifact collection is not strictly ordered and unique")]
    CanonicalOrder,
    #[error("change action artifact digest is invalid")]
    Digest,
    #[error("Apply receipt is inconsistent")]
    ApplyReceipt,
}

struct BoundedReviewVecVisitor<T> {
    maximum: usize,
    label: &'static str,
    marker: PhantomData<T>,
}

impl<'de, T> Visitor<'de> for BoundedReviewVecVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a {} sequence with at most {} entries", self.label, self.maximum)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
        while let Some(value) = sequence.next_element()? {
            if values.len() == self.maximum {
                return Err(A::Error::custom(format!(
                    "{} exceeds its {} entry bound",
                    self.label, self.maximum
                )));
            }
            values.push(value);
        }
        Ok(values)
    }
}

fn deserialize_bounded_review_vec<'de, D, T>(
    deserializer: D,
    maximum: usize,
    label: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(BoundedReviewVecVisitor { maximum, label, marker: PhantomData })
}

fn deserialize_review_invalidated_partition_keys<'de, D>(
    deserializer: D,
) -> Result<Vec<Digest>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_review_vec(
        deserializer,
        MAX_REVIEW_INVALIDATED_PARTITIONS_PER_TARGET,
        "review invalidated partition keys",
    )
}

fn deserialize_review_finding_ids<'de, D>(deserializer: D) -> Result<Vec<Digest>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_review_vec(deserializer, MAX_REVIEW_FINDINGS, "review finding ids")
}

fn deserialize_review_inspection_coverage<'de, D>(
    deserializer: D,
) -> Result<Vec<ReviewInspectionCoverage>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_review_vec(
        deserializer,
        MAX_REVIEW_INSPECTION_TARGETS,
        "review inspection coverage",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_id() -> ArtifactRequestId {
        ArtifactRequestId::new(Digest::blake3("request"))
    }

    #[test]
    fn test_execution_is_exact_environment_bound_and_tamper_evident() {
        let mut evidence = TestExecutionEvidence::new(
            request_id(),
            ChangeId::from_digest(Digest::blake3("change")),
            PatchId(Digest::blake3("patch")),
            ArtifactId::new(Digest::blake3("plan-artifact")),
            Digest::blake3("plan"),
            Some("command-evidence".to_owned()),
            Digest::blake3("source"),
            Some(Digest::blake3("execution-source")),
            Digest::blake3("command"),
            Digest::blake3("toolchain"),
            Digest::blake3("environment"),
            Digest::blake3("policy"),
            TestExecutionStatus::Passed,
            Some(0),
            Digest::blake3("output"),
            20,
            100,
        )
        .unwrap();
        assert!(evidence.validate().is_ok());
        evidence.environment_digest = Digest::blake3("changed");
        assert_eq!(evidence.validate(), Err(ChangeActionArtifactError::Digest));
    }

    #[test]
    fn review_report_is_canonical_and_rejects_approved_findings() {
        let finding = ReviewFinding::new(
            "needle.correctness",
            ReviewSeverity::Error,
            "src/lib.rs",
            Some(10),
            "The state transition is not guarded.",
            Digest::blake3("evidence"),
        )
        .unwrap();
        let coverage = vec![ReviewCoverage {
            criterion_digest: Digest::blake3("criterion"),
            status: AcceptanceStatus::Addressed,
            evidence_digest: Digest::blake3("coverage"),
        }];
        let report = ReviewReport::new(
            request_id(),
            ChangeId::from_digest(Digest::blake3("change")),
            PatchId(Digest::blake3("patch")),
            Digest::blake3("requirements"),
            Digest::blake3("reviewer"),
            ReviewReportVerdict::Rejected,
            coverage.clone(),
            vec![finding.clone()],
            None,
            100,
        )
        .unwrap();
        assert!(report.validate().is_ok());
        assert_eq!(
            ReviewReport::new(
                request_id(),
                ChangeId::from_digest(Digest::blake3("change")),
                PatchId(Digest::blake3("patch")),
                Digest::blake3("requirements"),
                Digest::blake3("reviewer"),
                ReviewReportVerdict::Approved,
                coverage,
                vec![finding],
                None,
                100,
            ),
            Err(ChangeActionArtifactError::ReviewReport)
        );
    }

    #[test]
    fn review_inspection_coverage_is_context_bound_closed_and_tamper_evident() {
        let patch = PatchId(Digest::blake3("patch"));
        let manifest = crate::PartitionManifestId::new(Digest::blake3("manifest"));
        let context = review_inspection_context_digest(Digest::blake3("delta"), manifest, patch);
        let retained = ReviewFinding::new(
            "stable.rule",
            ReviewSeverity::Error,
            "src/stable.rs",
            Some(3),
            "The stable defect remains.",
            Digest::blake3("stable-evidence"),
        )
        .unwrap();
        let added = ReviewFinding::new(
            "new.rule",
            ReviewSeverity::Warning,
            "src/new.rs",
            Some(4),
            "The changed path introduces a defect.",
            Digest::blake3("new-evidence"),
        )
        .unwrap();
        let retained_target =
            ReviewInspectionTarget::retained_finding(context, "src/stable.rs", retained.id)
                .unwrap();
        let changed_target = ReviewInspectionTarget::changed_path(
            context,
            "src/new.rs",
            vec![Digest::blake3("invalidated")],
        )
        .unwrap();
        let coverage = vec![
            ReviewInspectionCoverage::new(
                context,
                retained_target,
                ReviewInspectionOutcome::StillValid,
                vec![retained.id],
                Digest::blake3("stable-inspection"),
            )
            .unwrap(),
            ReviewInspectionCoverage::new(
                context,
                changed_target,
                ReviewInspectionOutcome::Findings,
                vec![added.id],
                Digest::blake3("changed-inspection"),
            )
            .unwrap(),
        ];
        let report = ReviewReport::new(
            request_id(),
            ChangeId::from_digest(Digest::blake3("change")),
            patch,
            Digest::blake3("requirements"),
            Digest::blake3("reviewer"),
            ReviewReportVerdict::Rejected,
            vec![ReviewCoverage {
                criterion_digest: Digest::blake3("criterion"),
                status: AcceptanceStatus::Unaddressed,
                evidence_digest: Digest::blake3("coverage"),
            }],
            vec![retained, added],
            Some(manifest),
            100,
        )
        .unwrap()
        .with_inspection_coverage(context, coverage)
        .unwrap();
        assert!(report.validate().is_ok());
        let encoded = serde_json::to_vec(&report).unwrap();
        assert_eq!(serde_json::from_slice::<ReviewReport>(&encoded).unwrap(), report);

        let mut oversized = serde_json::to_value(&report).unwrap();
        let entry = oversized["inspection_coverage"][0].clone();
        oversized["inspection_coverage"] =
            serde_json::Value::Array(vec![entry; MAX_REVIEW_INSPECTION_TARGETS + 1]);
        assert!(
            serde_json::from_value::<ReviewReport>(oversized)
                .unwrap_err()
                .to_string()
                .contains("review inspection coverage exceeds")
        );

        let mut tampered = report;
        tampered.inspection_coverage[0].evidence_digest = Digest::blake3("tampered");
        assert_eq!(tampered.validate(), Err(ChangeActionArtifactError::Digest));
    }

    #[test]
    fn review_inspection_rejects_inconclusive_duplicate_and_unclosed_coverage() {
        let patch = PatchId(Digest::blake3("patch"));
        let manifest = crate::PartitionManifestId::new(Digest::blake3("manifest"));
        let context = review_inspection_context_digest(Digest::blake3("delta"), manifest, patch);
        let target =
            ReviewInspectionTarget::changed_path(context, "src/changed.rs", Vec::new()).unwrap();
        let inconclusive = ReviewInspectionCoverage::new(
            context,
            target.clone(),
            ReviewInspectionOutcome::Inconclusive,
            Vec::new(),
            Digest::blake3("inspection"),
        )
        .unwrap();
        let base = ReviewReport::new(
            request_id(),
            ChangeId::from_digest(Digest::blake3("change")),
            patch,
            Digest::blake3("requirements"),
            Digest::blake3("reviewer"),
            ReviewReportVerdict::Rejected,
            vec![ReviewCoverage {
                criterion_digest: Digest::blake3("criterion"),
                status: AcceptanceStatus::Unaddressed,
                evidence_digest: Digest::blake3("coverage"),
            }],
            Vec::new(),
            Some(manifest),
            100,
        )
        .unwrap();
        assert_eq!(
            base.clone().with_inspection_coverage(context, vec![inconclusive]),
            Err(ChangeActionArtifactError::ReviewInspection)
        );

        let clean = ReviewInspectionCoverage::new(
            context,
            target,
            ReviewInspectionOutcome::Clean,
            Vec::new(),
            Digest::blake3("clean-inspection"),
        )
        .unwrap();
        assert_eq!(
            base.clone().with_inspection_coverage(context, vec![clean.clone(), clean.clone()]),
            Err(ChangeActionArtifactError::CanonicalOrder)
        );

        let finding = ReviewFinding::new(
            "uncovered.rule",
            ReviewSeverity::Warning,
            "src/changed.rs",
            Some(1),
            "This finding is not linked to inspection coverage.",
            Digest::blake3("uncovered-evidence"),
        )
        .unwrap();
        let mut unclosed = base;
        unclosed.findings = vec![finding];
        unclosed.id = unclosed.compute_id();
        assert_eq!(
            unclosed.with_inspection_coverage(context, vec![clean]),
            Err(ChangeActionArtifactError::ReviewInspection)
        );
    }

    #[test]
    fn legacy_review_report_remains_decodable_and_valid() {
        let mut report = ReviewReport::new(
            request_id(),
            ChangeId::from_digest(Digest::blake3("change")),
            PatchId(Digest::blake3("patch")),
            Digest::blake3("requirements"),
            Digest::blake3("reviewer"),
            ReviewReportVerdict::Rejected,
            vec![ReviewCoverage {
                criterion_digest: Digest::blake3("criterion"),
                status: AcceptanceStatus::Unaddressed,
                evidence_digest: Digest::blake3("coverage"),
            }],
            Vec::new(),
            None,
            100,
        )
        .unwrap();
        report.schema = REVIEW_REPORT_SCHEMA_ID_V1.to_owned();
        report.id = report.compute_id();
        let encoded = serde_json::to_vec(&report).unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains("inspection_coverage"));
        let decoded: ReviewReport = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, report);
        assert!(decoded.validate().is_ok());
    }

    #[test]
    fn apply_receipt_is_operation_and_state_bound() {
        let receipt = ApplyReceipt::new(
            Digest::blake3("operation"),
            ChangeId::from_digest(Digest::blake3("change")),
            PatchId(Digest::blake3("patch")),
            Digest::blake3("state"),
            Digest::blake3("before"),
            Digest::blake3("after"),
            Digest::blake3("files"),
            100,
        )
        .unwrap();
        assert!(receipt.validate().is_ok());
    }
}
