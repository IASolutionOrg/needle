use needle_core::{
    ActionContractId, CanonicalHasher, Digest, ManifestProvenance, ManifestTransition,
    PartitionManifest, ReviewReport, StateDelta,
};
use needle_runtime::{built_in_partition_for_action, review_finding_partition_key};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const REVIEW_CHANGE_IMPACT_GATE_CAMPAIGN_SCHEMA: &str =
    "needle.review-change-impact-gate-a6-campaign/2";
pub const REVIEW_CHANGE_IMPACT_GATE_REPORT_SCHEMA: &str =
    "needle.review-change-impact-gate-a6-report/2";
pub const REVIEW_CHANGE_IMPACT_GATE_FORMAT_REVISION: u16 = 2;
pub const MAX_REVIEW_CHANGE_IMPACT_GATE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_REVIEW_CHANGE_IMPACT_GATE_CASES: usize = 8;
pub const MAX_REVIEW_CHANGE_IMPACT_GATE_FAILURES: usize = 64;
const MAX_GATE_IDENTIFIER_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewChangeImpactEvidenceClass {
    Synthetic,
    ProviderBacked,
}

impl ReviewChangeImpactEvidenceClass {
    const fn gate_eligible(self) -> bool {
        matches!(self, Self::ProviderBacked)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewChangeImpactGateCase {
    pub id: String,
    /// Provider-declared fixture family. The gate treats this as opaque and
    /// only requires two distinct families; it never branches on language.
    pub ecosystem: String,
    pub state_delta: StateDelta,
    pub prior_report: ReviewReport,
    pub refresh_report: ReviewReport,
    pub full_report: ReviewReport,
    pub prior_manifest: PartitionManifest,
    pub refresh_manifest: PartitionManifest,
    pub full_manifest: PartitionManifest,
    pub transition: ManifestTransition,
    pub invalidated_prior_partition_keys: Vec<Digest>,
    pub prior_execution_digest: Digest,
    pub refresh_execution_digest: Digest,
    pub full_execution_digest: Digest,
}

impl ReviewChangeImpactGateCase {
    pub fn definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"review-change-impact-gate-a6-case-v1");
        hasher.field_str(&self.id);
        hasher.field_str(&self.ecosystem);
        hasher.field_digest(self.state_delta.digest);
        hasher.field_digest(self.prior_report.id);
        hasher.field_digest(self.refresh_report.id);
        hasher.field_digest(self.full_report.id);
        hasher.field_digest(self.prior_manifest.definition_digest);
        hasher.field_digest(self.refresh_manifest.definition_digest);
        hasher.field_digest(self.full_manifest.definition_digest);
        hasher.field_digest(self.transition.definition_digest);
        hasher
            .field_u16(self.invalidated_prior_partition_keys.len().try_into().unwrap_or(u16::MAX));
        for key in &self.invalidated_prior_partition_keys {
            hasher.field_digest(*key);
        }
        hasher.field_digest(self.prior_execution_digest);
        hasher.field_digest(self.refresh_execution_digest);
        hasher.field_digest(self.full_execution_digest);
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewChangeImpactGateCampaign {
    pub format_revision: u16,
    pub schema: String,
    pub evidence_class: ReviewChangeImpactEvidenceClass,
    pub cases: Vec<ReviewChangeImpactGateCase>,
    pub campaign_digest: Digest,
}

impl ReviewChangeImpactGateCampaign {
    pub fn new(
        evidence_class: ReviewChangeImpactEvidenceClass,
        mut cases: Vec<ReviewChangeImpactGateCase>,
    ) -> Result<Self, ReviewChangeImpactGateError> {
        cases.sort_by(|left, right| left.id.cmp(&right.id));
        let mut value = Self {
            format_revision: REVIEW_CHANGE_IMPACT_GATE_FORMAT_REVISION,
            schema: REVIEW_CHANGE_IMPACT_GATE_CAMPAIGN_SCHEMA.to_owned(),
            evidence_class,
            cases,
            campaign_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.campaign_digest = value.compute_digest();
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, ReviewChangeImpactGateError> {
        if bytes.len() > MAX_REVIEW_CHANGE_IMPACT_GATE_BYTES {
            return Err(ReviewChangeImpactGateError::Bound("campaign.bytes"));
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ReviewChangeImpactGateError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ReviewChangeImpactGateError> {
        self.validate_shape()?;
        if self.campaign_digest != self.compute_digest() {
            return Err(ReviewChangeImpactGateError::Digest);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ReviewChangeImpactGateError> {
        if self.format_revision != REVIEW_CHANGE_IMPACT_GATE_FORMAT_REVISION {
            return Err(ReviewChangeImpactGateError::FormatRevision(self.format_revision));
        }
        if self.schema != REVIEW_CHANGE_IMPACT_GATE_CAMPAIGN_SCHEMA {
            return Err(ReviewChangeImpactGateError::Schema);
        }
        if self.cases.is_empty()
            || self.cases.len() > MAX_REVIEW_CHANGE_IMPACT_GATE_CASES
            || self.cases.windows(2).any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(ReviewChangeImpactGateError::Bound("campaign.cases"));
        }
        for case in &self.cases {
            validate_identifier("case.id", &case.id)?;
            validate_identifier("case.ecosystem", &case.ecosystem)?;
            if case.invalidated_prior_partition_keys.len()
                > needle_core::MAX_PARTITION_MANIFEST_ENTRIES
                || case.invalidated_prior_partition_keys.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(ReviewChangeImpactGateError::Bound(
                    "case.invalidated_prior_partition_keys",
                ));
            }
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"review-change-impact-gate-a6-campaign-v2");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_u8(match self.evidence_class {
            ReviewChangeImpactEvidenceClass::Synthetic => 0,
            ReviewChangeImpactEvidenceClass::ProviderBacked => 1,
        });
        hasher.field_u16(self.cases.len().try_into().unwrap_or(u16::MAX));
        for case in &self.cases {
            hasher.field_digest(case.definition_digest());
        }
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewChangeImpactGateCaseReport {
    pub id: String,
    pub ecosystem: String,
    pub manifest_and_delta_valid: bool,
    pub stale_findings_removed: bool,
    pub finding_set_equal_to_full: bool,
    pub verdict_equal_to_full: bool,
    pub acceptance_coverage_equal_to_full: bool,
    pub final_conclusion_fresh: bool,
    pub failures: Vec<String>,
    pub passed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewChangeImpactGateReport {
    pub format_revision: u16,
    pub schema: String,
    pub campaign_digest: Digest,
    pub evidence_class: ReviewChangeImpactEvidenceClass,
    pub language_agnostic_fixture_coverage: bool,
    pub gate_eligible: bool,
    pub cases: Vec<ReviewChangeImpactGateCaseReport>,
    pub passed: bool,
}

pub fn evaluate_review_change_impact_gate(
    campaign: &ReviewChangeImpactGateCampaign,
) -> Result<ReviewChangeImpactGateReport, ReviewChangeImpactGateError> {
    campaign.validate()?;
    let ecosystems =
        campaign.cases.iter().map(|case| case.ecosystem.as_str()).collect::<BTreeSet<_>>();
    let language_agnostic_fixture_coverage = ecosystems.len() >= 2;
    let gate_eligible = campaign.evidence_class.gate_eligible();
    let cases = campaign.cases.iter().map(evaluate_case).collect::<Vec<_>>();
    let passed =
        gate_eligible && language_agnostic_fixture_coverage && cases.iter().all(|case| case.passed);
    Ok(ReviewChangeImpactGateReport {
        format_revision: REVIEW_CHANGE_IMPACT_GATE_FORMAT_REVISION,
        schema: REVIEW_CHANGE_IMPACT_GATE_REPORT_SCHEMA.to_owned(),
        campaign_digest: campaign.campaign_digest,
        evidence_class: campaign.evidence_class,
        language_agnostic_fixture_coverage,
        gate_eligible,
        cases,
        passed,
    })
}

fn evaluate_case(case: &ReviewChangeImpactGateCase) -> ReviewChangeImpactGateCaseReport {
    let mut failures = Vec::new();
    let manifest_and_delta_valid = validate_manifest_and_delta(case, &mut failures);
    let finding_projections = [
        defect_locus_projection(&case.prior_report),
        defect_locus_projection(&case.refresh_report),
        defect_locus_projection(&case.full_report),
    ];
    let projections_unambiguous = finding_projections.iter().all(Option::is_some);
    if !projections_unambiguous {
        push_failure(&mut failures, "review contains multiple findings at the same defect locus");
    }
    let empty = BTreeSet::new();
    let prior_findings = finding_projections[0].as_ref().unwrap_or(&empty);
    let refresh_findings = finding_projections[1].as_ref().unwrap_or(&empty);
    let full_findings = finding_projections[2].as_ref().unwrap_or(&empty);
    let stale_findings_removed = projections_unambiguous
        && prior_findings.difference(full_findings).all(|locus| !refresh_findings.contains(locus));
    if !stale_findings_removed {
        push_failure(&mut failures, "refresh review retained a stale prior finding");
    }
    let finding_set_equal_to_full = projections_unambiguous && refresh_findings == full_findings;
    if !finding_set_equal_to_full {
        push_failure(&mut failures, "refresh review finding set differs from the full oracle");
    }
    let verdict_equal_to_full = case.refresh_report.verdict == case.full_report.verdict;
    if !verdict_equal_to_full {
        push_failure(&mut failures, "refresh review verdict differs from the full oracle");
    }
    let acceptance_coverage_equal_to_full =
        acceptance_projection(&case.refresh_report) == acceptance_projection(&case.full_report);
    if !acceptance_coverage_equal_to_full {
        push_failure(
            &mut failures,
            "refresh review acceptance coverage differs from the full oracle",
        );
    }
    let execution_digests =
        [case.prior_execution_digest, case.refresh_execution_digest, case.full_execution_digest];
    let final_conclusion_fresh = execution_digests.iter().all(|digest| *digest != Digest([0; 32]))
        && execution_digests.into_iter().collect::<BTreeSet<_>>().len() == 3
        && case.refresh_report.created_unix_ms > case.prior_report.created_unix_ms
        && case.full_report.created_unix_ms > case.prior_report.created_unix_ms;
    if !final_conclusion_fresh {
        push_failure(&mut failures, "review conclusions lack independent fresh executions");
    }
    let passed = manifest_and_delta_valid
        && stale_findings_removed
        && finding_set_equal_to_full
        && verdict_equal_to_full
        && acceptance_coverage_equal_to_full
        && final_conclusion_fresh;
    ReviewChangeImpactGateCaseReport {
        id: case.id.clone(),
        ecosystem: case.ecosystem.clone(),
        manifest_and_delta_valid,
        stale_findings_removed,
        finding_set_equal_to_full,
        verdict_equal_to_full,
        acceptance_coverage_equal_to_full,
        final_conclusion_fresh,
        failures,
        passed,
    }
}

fn validate_manifest_and_delta(
    case: &ReviewChangeImpactGateCase,
    failures: &mut Vec<String>,
) -> bool {
    let review_action = match ActionContractId::new(needle_core::REVIEW_DIFF_ACTION_CONTRACT) {
        Ok(value) => value,
        Err(_) => {
            push_failure(failures, "review action contract is unavailable");
            return false;
        }
    };
    let Some(definition) = built_in_partition_for_action(&review_action) else {
        push_failure(failures, "review partition definition is unavailable");
        return false;
    };
    let records_valid = case.state_delta.validate().is_ok()
        && case.state_delta.complete
        && case.prior_report.validate().is_ok()
        && case.refresh_report.validate().is_ok()
        && case.full_report.validate().is_ok()
        && case.prior_manifest.validate_against_scheme(&definition.scheme).is_ok()
        && case.refresh_manifest.validate_against_scheme(&definition.scheme).is_ok()
        && case.full_manifest.validate_against_scheme(&definition.scheme).is_ok()
        && case.transition.validate().is_ok();
    if !records_valid {
        push_failure(failures, "gate records are non-canonical or the StateDelta is incomplete");
        return false;
    }
    let reports_bound = manifest_matches_report(&case.prior_manifest, &case.prior_report)
        && manifest_matches_report(&case.refresh_manifest, &case.refresh_report)
        && manifest_matches_report(&case.full_manifest, &case.full_report)
        && case.prior_manifest.binding.repository == case.state_delta.repository_lineage
        && case.refresh_manifest.binding.repository == case.state_delta.repository_lineage
        && case.full_manifest.binding.repository == case.state_delta.repository_lineage
        && case.prior_report.change_id == case.refresh_report.change_id
        && case.refresh_report.change_id == case.full_report.change_id
        && case.prior_report.requirements_digest == case.refresh_report.requirements_digest
        && case.refresh_report.requirements_digest == case.full_report.requirements_digest
        && case.prior_report.patch_id != case.refresh_report.patch_id
        && case.refresh_report.patch_id == case.full_report.patch_id
        && case.refresh_report.reviewer_definition == case.full_report.reviewer_definition;
    if !reports_bound {
        push_failure(failures, "review reports are not exactly bound to their manifests and patch");
        return false;
    }
    let transition_bound = case.transition.prior == case.prior_manifest.id
        && case.transition.current == case.refresh_manifest.id
        && case.transition.state_delta == case.state_delta.digest
        && case.transition.validator == definition.policy.manifest_validator
        && matches!(case.transition.provenance, ManifestProvenance::ProducerAuthored { .. });
    if !transition_bound {
        push_failure(failures, "manifest transition is not provider-owned or state-bound");
        return false;
    }
    let prior_keys =
        case.prior_manifest.entries.iter().map(|entry| entry.key.digest).collect::<BTreeSet<_>>();
    let invalidated =
        case.invalidated_prior_partition_keys.iter().copied().collect::<BTreeSet<_>>();
    let mut mapped_prior = BTreeSet::new();
    let mut mappings_valid = invalidated.is_subset(&prior_keys);
    for mapping in &case.transition.mappings {
        let prior = case
            .prior_manifest
            .entries
            .iter()
            .find(|entry| entry.key.digest == mapping.prior.key_digest);
        let current = case
            .refresh_manifest
            .entries
            .iter()
            .find(|entry| entry.key.digest == mapping.current.key_digest);
        mappings_valid &= prior.zip(current).is_some_and(|(prior, current)| {
            prior.key.value == current.key.value && prior.payload_digest == current.payload_digest
        });
        mapped_prior.insert(mapping.prior.key_digest);
    }
    mappings_valid &= mapped_prior.is_disjoint(&invalidated)
        && mapped_prior.union(&invalidated).copied().collect::<BTreeSet<_>>() == prior_keys;
    if !mappings_valid {
        push_failure(failures, "transition does not completely classify prior partitions");
        return false;
    }
    true
}

fn manifest_matches_report(manifest: &PartitionManifest, report: &ReviewReport) -> bool {
    if report.manifest != Some(manifest.id)
        || report.action_request != manifest.binding.action_request
        || manifest.binding.action_contract.as_str() != needle_core::REVIEW_DIFF_ACTION_CONTRACT
        || manifest.entries.len() != report.findings.len()
    {
        return false;
    }
    report.findings.iter().all(|finding| {
        let raw_key = review_finding_partition_key(finding).bytes();
        manifest.entries.iter().any(|entry| {
            entry.key.value.as_slice() == raw_key && entry.payload_digest == finding.id
        })
    })
}

fn acceptance_projection(report: &ReviewReport) -> BTreeMap<Digest, needle_core::AcceptanceStatus> {
    report
        .acceptance_coverage
        .iter()
        .map(|coverage| (coverage.criterion_digest, coverage.status))
        .collect()
}

type DefectLocus = (String, Option<u32>, u8);

fn defect_locus_projection(report: &ReviewReport) -> Option<BTreeSet<DefectLocus>> {
    let mut loci = BTreeSet::new();
    for finding in &report.findings {
        let severity = match finding.severity {
            needle_core::ReviewSeverity::Info => 0,
            needle_core::ReviewSeverity::Warning => 1,
            needle_core::ReviewSeverity::Error => 2,
            needle_core::ReviewSeverity::Critical => 3,
        };
        if !loci.insert((finding.path.clone(), finding.line, severity)) {
            return None;
        }
    }
    Some(loci)
}

fn push_failure(failures: &mut Vec<String>, message: &str) {
    if failures.len() < MAX_REVIEW_CHANGE_IMPACT_GATE_FAILURES {
        failures.push(message.to_owned());
    }
}

fn validate_identifier(
    field: &'static str,
    value: &str,
) -> Result<(), ReviewChangeImpactGateError> {
    if value.is_empty()
        || value.len() > MAX_GATE_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ReviewChangeImpactGateError::Identifier(field));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ReviewChangeImpactGateError {
    #[error("unsupported review ChangeImpact gate format revision {0}")]
    FormatRevision(u16),
    #[error("unsupported review ChangeImpact gate schema")]
    Schema,
    #[error("review ChangeImpact gate bound failed for {0}")]
    Bound(&'static str),
    #[error("review ChangeImpact gate identifier failed for {0}")]
    Identifier(&'static str),
    #[error("review ChangeImpact gate campaign digest changed")]
    Digest,
    #[error("invalid review ChangeImpact gate JSON: {0}")]
    Json(String),
}

#[cfg(test)]
mod tests;
