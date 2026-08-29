use super::{
    LIVE_TEST_TARGET_REFRESH_FORMAT_REVISION, LiveTestTargetRefreshCalibrationReport,
    MAX_LIVE_TEST_TARGET_REFRESH_SOURCE_BYTES, hash_bool, hash_u64, repository_identity_digest,
    valid_git_sha,
};
use needle_core::{CanonicalHasher, Digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_SCHEMA: &str =
    "needle.test-target-refresh-live-acceptance/1";
pub const MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_BYTES: usize = 64 * 1024;
pub const MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTED_REPORTS: usize = 8;
pub const MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_LIMITATIONS: usize = 16;
pub const MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_TEXT_BYTES: usize = 1_024;
pub const MAX_LIVE_TEST_TARGET_REFRESH_REVIEWER_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveRefreshGateDecisionBasis {
    LatencyPrimary,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedLiveRefreshObservation {
    pub report_digest: Digest,
    pub repository_identity_digest: Digest,
    pub source_repository: String,
    pub source_sha: String,
    pub latency_value_accepted: bool,
    pub bounded_p95_accepted: bool,
    pub exact_oracle_agreement_accepted: bool,
    pub zero_stale_retained_accepted: bool,
    pub provider_cost_included_accepted: bool,
    pub monetary_provenance_present: bool,
}

impl AcceptedLiveRefreshObservation {
    fn from_report(
        report: &LiveTestTargetRefreshCalibrationReport,
    ) -> Result<Self, LiveRefreshAcceptanceError> {
        report
            .validate()
            .map_err(|error| LiveRefreshAcceptanceError::ReportValidation(error.to_string()))?;
        if !report.gate_a4_observation_eligible {
            return Err(LiveRefreshAcceptanceError::IneligibleReport(report.report_digest));
        }
        Ok(Self {
            report_digest: report.report_digest,
            repository_identity_digest: report.repository_identity_digest,
            source_repository: report.source_repository.clone(),
            source_sha: report.source_sha.clone(),
            latency_value_accepted: true,
            bounded_p95_accepted: true,
            exact_oracle_agreement_accepted: true,
            zero_stale_retained_accepted: true,
            provider_cost_included_accepted: true,
            monetary_provenance_present: report.cost_provenance.is_some(),
        })
    }

    fn validate(&self) -> Result<(), LiveRefreshAcceptanceError> {
        if self.report_digest == Digest([0; 32])
            || self.repository_identity_digest == Digest([0; 32])
            || self.source_repository.is_empty()
            || self.source_repository.len() > MAX_LIVE_TEST_TARGET_REFRESH_SOURCE_BYTES
            || self.source_repository.chars().any(char::is_control)
            || !valid_git_sha(&self.source_sha)
            || self.repository_identity_digest
                != repository_identity_digest(&self.source_repository, &self.source_sha)
            || !self.latency_value_accepted
            || !self.bounded_p95_accepted
            || !self.exact_oracle_agreement_accepted
            || !self.zero_stale_retained_accepted
            || !self.provider_cost_included_accepted
        {
            return Err(LiveRefreshAcceptanceError::Shape("acceptance.accepted_reports"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveTestTargetRefreshGateAcceptance {
    pub format_revision: u16,
    pub schema: String,
    pub report_set_digest: Digest,
    pub accepted_reports: Vec<AcceptedLiveRefreshObservation>,
    pub reviewer_id: String,
    pub reviewed_unix_ms: u64,
    pub decision_basis: LiveRefreshGateDecisionBasis,
    pub limitations: Vec<String>,
    pub local_shadow_evidence_accepted: bool,
    pub authority_promotion_approved: bool,
    pub statistical_claim: bool,
    pub gate_a4_closed: bool,
    pub acceptance_digest: Digest,
}

impl LiveTestTargetRefreshGateAcceptance {
    pub fn new(
        reports: &[LiveTestTargetRefreshCalibrationReport],
        reviewer_id: impl Into<String>,
        reviewed_unix_ms: u64,
        mut limitations: Vec<String>,
    ) -> Result<Self, LiveRefreshAcceptanceError> {
        if reports.is_empty() || reports.len() > MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTED_REPORTS {
            return Err(LiveRefreshAcceptanceError::ReportCount(reports.len()));
        }
        let mut accepted_reports = reports
            .iter()
            .map(AcceptedLiveRefreshObservation::from_report)
            .collect::<Result<Vec<_>, _>>()?;
        accepted_reports.sort();
        limitations.sort();
        let report_set_digest = compute_report_set_digest(&accepted_reports);
        let mut value = Self {
            format_revision: LIVE_TEST_TARGET_REFRESH_FORMAT_REVISION,
            schema: LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_SCHEMA.to_owned(),
            report_set_digest,
            accepted_reports,
            reviewer_id: reviewer_id.into(),
            reviewed_unix_ms,
            decision_basis: LiveRefreshGateDecisionBasis::LatencyPrimary,
            limitations,
            local_shadow_evidence_accepted: true,
            authority_promotion_approved: false,
            statistical_claim: false,
            gate_a4_closed: false,
            acceptance_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.acceptance_digest = value.compute_digest();
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, LiveRefreshAcceptanceError> {
        if bytes.len() > MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_BYTES {
            return Err(LiveRefreshAcceptanceError::WireBound {
                actual: bytes.len(),
                maximum: MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| LiveRefreshAcceptanceError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), LiveRefreshAcceptanceError> {
        self.validate_shape()?;
        if self.acceptance_digest != self.compute_digest() {
            return Err(LiveRefreshAcceptanceError::AcceptanceDigest);
        }
        Ok(())
    }

    pub fn validate_for_reports(
        &self,
        reports: &[LiveTestTargetRefreshCalibrationReport],
    ) -> Result<(), LiveRefreshAcceptanceError> {
        self.validate()?;
        if reports.is_empty() || reports.len() > MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTED_REPORTS {
            return Err(LiveRefreshAcceptanceError::ReportCount(reports.len()));
        }
        let mut expected = reports
            .iter()
            .map(AcceptedLiveRefreshObservation::from_report)
            .collect::<Result<Vec<_>, _>>()?;
        expected.sort();
        if self.accepted_reports != expected
            || self.report_set_digest != compute_report_set_digest(&expected)
        {
            return Err(LiveRefreshAcceptanceError::ReportBinding);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), LiveRefreshAcceptanceError> {
        if self.format_revision != LIVE_TEST_TARGET_REFRESH_FORMAT_REVISION {
            return Err(LiveRefreshAcceptanceError::FormatRevision(self.format_revision));
        }
        if self.schema != LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_SCHEMA {
            return Err(LiveRefreshAcceptanceError::Shape("acceptance.schema"));
        }
        if self.accepted_reports.is_empty()
            || self.accepted_reports.len() > MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTED_REPORTS
        {
            return Err(LiveRefreshAcceptanceError::ReportCount(self.accepted_reports.len()));
        }
        if self.accepted_reports.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(LiveRefreshAcceptanceError::Canonical("acceptance.accepted_reports"));
        }
        for report in &self.accepted_reports {
            report.validate()?;
        }
        if self.report_set_digest != compute_report_set_digest(&self.accepted_reports) {
            return Err(LiveRefreshAcceptanceError::ReportSetDigest);
        }
        validate_reviewer(&self.reviewer_id)?;
        if self.reviewed_unix_ms == 0 {
            return Err(LiveRefreshAcceptanceError::Shape("acceptance.reviewed_unix_ms"));
        }
        validate_limitations(&self.limitations)?;
        if self.decision_basis != LiveRefreshGateDecisionBasis::LatencyPrimary
            || !self.local_shadow_evidence_accepted
            || self.authority_promotion_approved
            || self.statistical_claim
            || self.gate_a4_closed
        {
            return Err(LiveRefreshAcceptanceError::AuthorityBoundary);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"test-target-refresh-live-acceptance-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_digest(self.report_set_digest);
        hasher.field_u16(self.accepted_reports.len().try_into().unwrap_or(u16::MAX));
        for report in &self.accepted_reports {
            hash_observation(&mut hasher, report);
        }
        hasher.field_str(&self.reviewer_id);
        hash_u64(&mut hasher, self.reviewed_unix_ms);
        hasher.field_u8(0);
        hasher.field_u16(self.limitations.len().try_into().unwrap_or(u16::MAX));
        for limitation in &self.limitations {
            hasher.field_str(limitation);
        }
        hash_bool(&mut hasher, self.local_shadow_evidence_accepted);
        hash_bool(&mut hasher, self.authority_promotion_approved);
        hash_bool(&mut hasher, self.statistical_claim);
        hash_bool(&mut hasher, self.gate_a4_closed);
        hasher.finish()
    }
}

fn compute_report_set_digest(reports: &[AcceptedLiveRefreshObservation]) -> Digest {
    let mut hasher = CanonicalHasher::new(b"test-target-refresh-live-report-set-v1");
    hasher.field_u16(reports.len().try_into().unwrap_or(u16::MAX));
    for report in reports {
        hash_observation(&mut hasher, report);
    }
    hasher.finish()
}

fn hash_observation(hasher: &mut CanonicalHasher, report: &AcceptedLiveRefreshObservation) {
    hasher.field_digest(report.report_digest);
    hasher.field_digest(report.repository_identity_digest);
    hasher.field_str(&report.source_repository);
    hasher.field_str(&report.source_sha);
    hash_bool(hasher, report.latency_value_accepted);
    hash_bool(hasher, report.bounded_p95_accepted);
    hash_bool(hasher, report.exact_oracle_agreement_accepted);
    hash_bool(hasher, report.zero_stale_retained_accepted);
    hash_bool(hasher, report.provider_cost_included_accepted);
    hash_bool(hasher, report.monetary_provenance_present);
}

fn validate_reviewer(value: &str) -> Result<(), LiveRefreshAcceptanceError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_LIVE_TEST_TARGET_REFRESH_REVIEWER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(LiveRefreshAcceptanceError::Shape("acceptance.reviewer_id"));
    }
    Ok(())
}

fn validate_limitations(values: &[String]) -> Result<(), LiveRefreshAcceptanceError> {
    if values.is_empty() || values.len() > MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_LIMITATIONS {
        return Err(LiveRefreshAcceptanceError::Shape("acceptance.limitations"));
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(LiveRefreshAcceptanceError::Canonical("acceptance.limitations"));
    }
    if values.iter().any(|value| {
        value.is_empty()
            || value.trim() != value
            || value.len() > MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_TEXT_BYTES
            || value.chars().any(char::is_control)
    }) {
        return Err(LiveRefreshAcceptanceError::Shape("acceptance.limitations"));
    }
    Ok(())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LiveRefreshAcceptanceError {
    #[error("live refresh acceptance wire has {actual} bytes; maximum is {maximum}")]
    WireBound { actual: usize, maximum: usize },
    #[error("live refresh acceptance contains {0} reports outside its bound")]
    ReportCount(usize),
    #[error("live refresh report is invalid: {0}")]
    ReportValidation(String),
    #[error("live refresh report {0} is not eligible for acceptance")]
    IneligibleReport(Digest),
    #[error("live refresh acceptance format revision {0} is unsupported")]
    FormatRevision(u16),
    #[error("live refresh acceptance JSON is invalid: {0}")]
    Json(String),
    #[error("live refresh acceptance field {0} is invalid")]
    Shape(&'static str),
    #[error("live refresh acceptance field {0} is not canonical")]
    Canonical(&'static str),
    #[error("live refresh acceptance report-set digest is inconsistent")]
    ReportSetDigest,
    #[error("live refresh acceptance digest is inconsistent")]
    AcceptanceDigest,
    #[error("live refresh acceptance does not bind the supplied report set")]
    ReportBinding,
    #[error("live refresh acceptance cannot promote authority, claim statistics, or close Gate A4")]
    AuthorityBoundary,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        LIVE_TEST_TARGET_REFRESH_REPORT_SCHEMA, LiveRefreshCostProvenance,
        MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_BYTES,
    };
    use needle_core::CapabilityMode;

    fn report(source: &str, sha: &str, label: &[u8]) -> LiveTestTargetRefreshCalibrationReport {
        let mut value = LiveTestTargetRefreshCalibrationReport {
            format_revision: LIVE_TEST_TARGET_REFRESH_FORMAT_REVISION,
            schema: LIVE_TEST_TARGET_REFRESH_REPORT_SCHEMA.to_owned(),
            authority: CapabilityMode::Shadow,
            source_repository: source.to_owned(),
            source_sha: sha.to_owned(),
            repository_identity_digest: super::super::repository_identity_digest(source, sha),
            cargo_version: "cargo 1.97.0".to_owned(),
            platform: "windows".to_owned(),
            changed_paths: vec!["crate/Cargo.toml".to_owned()],
            mutation_definition_digest: Digest::blake3(b"append-comment-v1"),
            prior_source_digest: Digest::blake3([label, b"-prior"].concat()),
            current_source_digest: Digest::blake3([label, b"-current"].concat()),
            provider_timeout_seconds: 30,
            provider_process_transport_included: true,
            full_current_oracle_outside_refresh_timing: true,
            arm_order_alternated: true,
            fresh_samples_micros: vec![100, 101, 102, 103, 104],
            refresh_samples_micros: vec![40, 41, 42, 43, 44],
            fresh_p95_micros: 104,
            refresh_p95_micros: 44,
            p95_budget_micros: 1_000,
            positive_latency_value: true,
            bounded_refresh_p95: true,
            exact_oracle_agreement: true,
            stale_retained_partitions: 0,
            acquisition_retained_partitions: 2,
            retained_partitions: 2,
            recomputed_partitions: 1,
            refreshed_partitions: 1,
            added_partitions: 0,
            removed_partitions: 0,
            cost_provenance: None::<LiveRefreshCostProvenance>,
            gate_a4_observation_eligible: true,
            gate_a4_closed: false,
            report_digest: Digest([0; 32]),
        };
        value.report_digest = value.compute_digest();
        value
    }

    fn reports() -> Vec<LiveTestTargetRefreshCalibrationReport> {
        vec![
            report(
                "https://github.com/dtolnay/thiserror",
                "485c2b7eed2702c4a109be3cf42bb4be27fe16bd",
                b"thiserror",
            ),
            report(
                "https://github.com/tokio-rs/tracing",
                "d9d4c542de10f5d3a711b7a45ffe450fd0666437",
                b"tracing",
            ),
        ]
    }

    #[test]
    fn acceptance_is_canonical_digest_bound_and_report_bound() {
        let reports = reports();
        let acceptance = LiveTestTargetRefreshGateAcceptance::new(
            &reports,
            "local-owner",
            1_754_000_000_000,
            vec!["not a statistical claim".to_owned(), "Shadow evidence only".to_owned()],
        )
        .unwrap();
        acceptance.validate_for_reports(&reports).unwrap();
        assert_eq!(acceptance.limitations, vec!["Shadow evidence only", "not a statistical claim"]);
        assert!(!acceptance.authority_promotion_approved);
        assert!(!acceptance.statistical_claim);
        assert!(!acceptance.gate_a4_closed);
        let bytes = serde_json::to_vec(&acceptance).unwrap();
        assert_eq!(LiveTestTargetRefreshGateAcceptance::decode_json(&bytes).unwrap(), acceptance);
    }

    #[test]
    fn acceptance_rejects_tamper_ineligible_and_different_report_set() {
        let reports = reports();
        let mut acceptance = LiveTestTargetRefreshGateAcceptance::new(
            &reports,
            "local-owner",
            1_754_000_000_000,
            vec!["bounded local calibration".to_owned()],
        )
        .unwrap();
        acceptance.accepted_reports[0].source_sha =
            "0000000000000000000000000000000000000000".to_owned();
        assert_eq!(
            acceptance.validate(),
            Err(LiveRefreshAcceptanceError::Shape("acceptance.accepted_reports"))
        );

        let mut ineligible = reports[0].clone();
        ineligible.positive_latency_value = false;
        ineligible.refresh_p95_micros = ineligible.fresh_p95_micros;
        ineligible.refresh_samples_micros = ineligible.fresh_samples_micros.clone();
        ineligible.gate_a4_observation_eligible = false;
        ineligible.report_digest = ineligible.compute_digest();
        assert!(matches!(
            LiveTestTargetRefreshGateAcceptance::new(
                &[ineligible],
                "local-owner",
                1,
                vec!["bounded".to_owned()]
            ),
            Err(LiveRefreshAcceptanceError::IneligibleReport(_))
        ));

        let acceptance = LiveTestTargetRefreshGateAcceptance::new(
            &reports,
            "local-owner",
            1_754_000_000_000,
            vec!["bounded local calibration".to_owned()],
        )
        .unwrap();
        assert_eq!(
            acceptance.validate_for_reports(&reports[..1]),
            Err(LiveRefreshAcceptanceError::ReportBinding)
        );
    }

    #[test]
    fn acceptance_decode_and_collections_are_bounded() {
        let oversized = vec![b' '; MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_BYTES + 1];
        assert!(matches!(
            LiveTestTargetRefreshGateAcceptance::decode_json(&oversized),
            Err(LiveRefreshAcceptanceError::WireBound { .. })
        ));
        let reports = reports();
        assert!(matches!(
            LiveTestTargetRefreshGateAcceptance::new(
                &reports,
                "local-owner",
                1,
                vec!["x".repeat(MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_TEXT_BYTES + 1)]
            ),
            Err(LiveRefreshAcceptanceError::Shape("acceptance.limitations"))
        ));
    }
}
