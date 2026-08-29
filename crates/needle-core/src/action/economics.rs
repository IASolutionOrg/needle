use super::ActionContractId;
use crate::{ArtifactRequestId, CanonicalHasher, CapabilityMode, Digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const REFRESH_ECONOMIC_FORMAT_REVISION: u16 = 1;
pub const MAX_REFRESH_ECONOMIC_WIRE_BYTES: usize = 16 * 1024;
pub const MAX_REFRESH_ECONOMIC_COST_MICROUSD: u64 = i64::MAX as u64;
pub const MAX_REFRESH_ECONOMIC_LATENCY_MICROS: u64 = u32::MAX as u64 * 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshCostEvidenceBasis {
    PairedObserved,
    BenchmarkDerived,
    HistoricalEstimate,
    ConfiguredStatic,
}

impl RefreshCostEvidenceBasis {
    const fn tag(self) -> u8 {
        match self {
            Self::PairedObserved => 0,
            Self::BenchmarkDerived => 1,
            Self::HistoricalEstimate => 2,
            Self::ConfiguredStatic => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshEconomicPolicyInput {
    pub action_operational_policy_digest: Digest,
    pub refresh_policy_definition_digest: Digest,
    pub minimum_expected_net_microusd: u64,
    pub maximum_refresh_latency_micros: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshEconomicPolicy {
    pub format_revision: u16,
    pub action_operational_policy_digest: Digest,
    pub refresh_policy_definition_digest: Digest,
    pub minimum_expected_net_microusd: u64,
    pub maximum_refresh_latency_micros: Option<u64>,
    pub definition_digest: Digest,
}

impl RefreshEconomicPolicy {
    pub fn new(input: RefreshEconomicPolicyInput) -> Result<Self, RefreshEconomicError> {
        let mut value = Self {
            format_revision: REFRESH_ECONOMIC_FORMAT_REVISION,
            action_operational_policy_digest: input.action_operational_policy_digest,
            refresh_policy_definition_digest: input.refresh_policy_definition_digest,
            minimum_expected_net_microusd: input.minimum_expected_net_microusd,
            maximum_refresh_latency_micros: input.maximum_refresh_latency_micros,
            definition_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.definition_digest = value.compute_definition_digest();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), RefreshEconomicError> {
        self.validate_shape()?;
        validate_digest(
            "refresh_economic_policy.definition_digest",
            self.compute_definition_digest(),
            self.definition_digest,
        )
    }

    fn validate_shape(&self) -> Result<(), RefreshEconomicError> {
        validate_revision("refresh_economic_policy", self.format_revision)?;
        validate_cost(
            "refresh_economic_policy.minimum_expected_net_microusd",
            self.minimum_expected_net_microusd,
        )?;
        if let Some(latency) = self.maximum_refresh_latency_micros {
            validate_latency("refresh_economic_policy.maximum_refresh_latency_micros", latency)?;
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"refresh-economic-policy-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.action_operational_policy_digest);
        hasher.field_digest(self.refresh_policy_definition_digest);
        hash_u64(&mut hasher, self.minimum_expected_net_microusd);
        hash_optional_u64(&mut hasher, self.maximum_refresh_latency_micros);
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshCostEvidenceInput {
    pub request: ArtifactRequestId,
    pub action_contract: ActionContractId,
    pub candidate_definition_digest: Digest,
    pub operator_definition_digest: Digest,
    pub execution_scope_digest: Digest,
    pub basis: RefreshCostEvidenceBasis,
    pub evidence_digest: Digest,
    pub pricing_revision: Option<Digest>,
    pub estimated_fresh_total_microusd: u64,
    pub estimated_refresh_total_microusd: u64,
    pub estimated_refresh_latency_micros: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshCostEvidence {
    pub format_revision: u16,
    pub request: ArtifactRequestId,
    pub action_contract: ActionContractId,
    pub candidate_definition_digest: Digest,
    pub operator_definition_digest: Digest,
    pub execution_scope_digest: Digest,
    pub basis: RefreshCostEvidenceBasis,
    pub evidence_digest: Digest,
    pub pricing_revision: Option<Digest>,
    pub estimated_fresh_total_microusd: u64,
    pub estimated_refresh_total_microusd: u64,
    pub estimated_refresh_latency_micros: Option<u64>,
    pub definition_digest: Digest,
}

impl RefreshCostEvidence {
    pub fn new(input: RefreshCostEvidenceInput) -> Result<Self, RefreshEconomicError> {
        let mut value = Self {
            format_revision: REFRESH_ECONOMIC_FORMAT_REVISION,
            request: input.request,
            action_contract: input.action_contract,
            candidate_definition_digest: input.candidate_definition_digest,
            operator_definition_digest: input.operator_definition_digest,
            execution_scope_digest: input.execution_scope_digest,
            basis: input.basis,
            evidence_digest: input.evidence_digest,
            pricing_revision: input.pricing_revision,
            estimated_fresh_total_microusd: input.estimated_fresh_total_microusd,
            estimated_refresh_total_microusd: input.estimated_refresh_total_microusd,
            estimated_refresh_latency_micros: input.estimated_refresh_latency_micros,
            definition_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.definition_digest = value.compute_definition_digest();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), RefreshEconomicError> {
        self.validate_shape()?;
        validate_digest(
            "refresh_cost_evidence.definition_digest",
            self.compute_definition_digest(),
            self.definition_digest,
        )
    }

    fn validate_shape(&self) -> Result<(), RefreshEconomicError> {
        validate_revision("refresh_cost_evidence", self.format_revision)?;
        validate_cost(
            "refresh_cost_evidence.estimated_fresh_total_microusd",
            self.estimated_fresh_total_microusd,
        )?;
        validate_cost(
            "refresh_cost_evidence.estimated_refresh_total_microusd",
            self.estimated_refresh_total_microusd,
        )?;
        if let Some(latency) = self.estimated_refresh_latency_micros {
            validate_latency("refresh_cost_evidence.estimated_refresh_latency_micros", latency)?;
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"refresh-cost-evidence-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.request.digest());
        hasher.field_str(self.action_contract.as_str());
        hasher.field_digest(self.candidate_definition_digest);
        hasher.field_digest(self.operator_definition_digest);
        hasher.field_digest(self.execution_scope_digest);
        hasher.field_u8(self.basis.tag());
        hasher.field_digest(self.evidence_digest);
        hash_optional_digest(&mut hasher, self.pricing_revision);
        hash_u64(&mut hasher, self.estimated_fresh_total_microusd);
        hash_u64(&mut hasher, self.estimated_refresh_total_microusd);
        hash_optional_u64(&mut hasher, self.estimated_refresh_latency_micros);
        hasher.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshEconomicFallback {
    MissingCostEvidence,
    BelowMinimumNetValue,
    MissingLatencyEvidence,
    RefreshLatencyBudgetExceeded,
}

impl RefreshEconomicFallback {
    const fn tag(self) -> u8 {
        match self {
            Self::MissingCostEvidence => 0,
            Self::BelowMinimumNetValue => 1,
            Self::MissingLatencyEvidence => 2,
            Self::RefreshLatencyBudgetExceeded => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "selection", rename_all = "snake_case", deny_unknown_fields)]
pub enum RefreshEconomicDecision {
    Refresh,
    FullCompute { reason: RefreshEconomicFallback },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshEconomicAssessmentInput {
    pub request: ArtifactRequestId,
    pub action_contract: ActionContractId,
    pub candidate_definition_digest: Digest,
    pub operator_definition_digest: Digest,
    pub execution_scope_digest: Digest,
    pub policy: RefreshEconomicPolicy,
    pub evidence: Option<RefreshCostEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshEconomicAssessment {
    pub format_revision: u16,
    pub definition_digest: Digest,
    pub request: ArtifactRequestId,
    pub action_contract: ActionContractId,
    pub candidate_definition_digest: Digest,
    pub operator_definition_digest: Digest,
    pub execution_scope_digest: Digest,
    pub policy: RefreshEconomicPolicy,
    pub evidence: Option<RefreshCostEvidence>,
    pub expected_net_microusd: Option<i64>,
    pub decision: RefreshEconomicDecision,
    pub authority: CapabilityMode,
}

impl RefreshEconomicAssessment {
    pub fn new(input: RefreshEconomicAssessmentInput) -> Result<Self, RefreshEconomicError> {
        let (expected_net_microusd, decision) = evaluate(&input.policy, input.evidence.as_ref())?;
        let mut value = Self {
            format_revision: REFRESH_ECONOMIC_FORMAT_REVISION,
            definition_digest: Digest([0; 32]),
            request: input.request,
            action_contract: input.action_contract,
            candidate_definition_digest: input.candidate_definition_digest,
            operator_definition_digest: input.operator_definition_digest,
            execution_scope_digest: input.execution_scope_digest,
            policy: input.policy,
            evidence: input.evidence,
            expected_net_microusd,
            decision,
            authority: CapabilityMode::Shadow,
        };
        value.validate_shape()?;
        value.definition_digest = value.compute_definition_digest();
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, RefreshEconomicError> {
        if bytes.len() > MAX_REFRESH_ECONOMIC_WIRE_BYTES {
            return Err(RefreshEconomicError::WireBound {
                actual: bytes.len(),
                maximum: MAX_REFRESH_ECONOMIC_WIRE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| RefreshEconomicError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), RefreshEconomicError> {
        self.validate_shape()?;
        validate_digest(
            "refresh_economic_assessment.definition_digest",
            self.compute_definition_digest(),
            self.definition_digest,
        )
    }

    fn validate_shape(&self) -> Result<(), RefreshEconomicError> {
        validate_revision("refresh_economic_assessment", self.format_revision)?;
        if self.authority != CapabilityMode::Shadow {
            return Err(RefreshEconomicError::Authority);
        }
        self.policy.validate()?;
        if let Some(evidence) = &self.evidence {
            evidence.validate()?;
            if evidence.request != self.request
                || evidence.action_contract != self.action_contract
                || evidence.candidate_definition_digest != self.candidate_definition_digest
                || evidence.operator_definition_digest != self.operator_definition_digest
                || evidence.execution_scope_digest != self.execution_scope_digest
            {
                return Err(RefreshEconomicError::EvidenceBinding);
            }
        }
        let (expected_net_microusd, decision) = evaluate(&self.policy, self.evidence.as_ref())?;
        if self.expected_net_microusd != expected_net_microusd || self.decision != decision {
            return Err(RefreshEconomicError::Decision);
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"refresh-economic-assessment-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.request.digest());
        hasher.field_str(self.action_contract.as_str());
        hasher.field_digest(self.candidate_definition_digest);
        hasher.field_digest(self.operator_definition_digest);
        hasher.field_digest(self.execution_scope_digest);
        hasher.field_digest(self.policy.definition_digest);
        hash_optional_digest(
            &mut hasher,
            self.evidence.as_ref().map(|evidence| evidence.definition_digest),
        );
        match self.expected_net_microusd {
            Some(value) => {
                hasher.field_u8(1);
                hasher.field_bytes(&value.to_le_bytes());
            }
            None => hasher.field_u8(0),
        }
        match self.decision {
            RefreshEconomicDecision::Refresh => hasher.field_u8(0),
            RefreshEconomicDecision::FullCompute { reason } => {
                hasher.field_u8(1);
                hasher.field_u8(reason.tag());
            }
        }
        hasher.field_u8(0);
        hasher.finish()
    }
}

fn evaluate(
    policy: &RefreshEconomicPolicy,
    evidence: Option<&RefreshCostEvidence>,
) -> Result<(Option<i64>, RefreshEconomicDecision), RefreshEconomicError> {
    policy.validate()?;
    let Some(evidence) = evidence else {
        return Ok((
            None,
            RefreshEconomicDecision::FullCompute {
                reason: RefreshEconomicFallback::MissingCostEvidence,
            },
        ));
    };
    evidence.validate()?;
    let fresh = i64::try_from(evidence.estimated_fresh_total_microusd)
        .map_err(|_| RefreshEconomicError::CostBound("estimated_fresh_total_microusd"))?;
    let refresh = i64::try_from(evidence.estimated_refresh_total_microusd)
        .map_err(|_| RefreshEconomicError::CostBound("estimated_refresh_total_microusd"))?;
    let expected_net = fresh - refresh;
    let minimum = i64::try_from(policy.minimum_expected_net_microusd)
        .map_err(|_| RefreshEconomicError::CostBound("minimum_expected_net_microusd"))?
        .max(1);
    if expected_net < minimum {
        return Ok((
            Some(expected_net),
            RefreshEconomicDecision::FullCompute {
                reason: RefreshEconomicFallback::BelowMinimumNetValue,
            },
        ));
    }
    if let Some(maximum) = policy.maximum_refresh_latency_micros {
        let Some(actual) = evidence.estimated_refresh_latency_micros else {
            return Ok((
                Some(expected_net),
                RefreshEconomicDecision::FullCompute {
                    reason: RefreshEconomicFallback::MissingLatencyEvidence,
                },
            ));
        };
        if actual > maximum {
            return Ok((
                Some(expected_net),
                RefreshEconomicDecision::FullCompute {
                    reason: RefreshEconomicFallback::RefreshLatencyBudgetExceeded,
                },
            ));
        }
    }
    Ok((Some(expected_net), RefreshEconomicDecision::Refresh))
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RefreshEconomicError {
    #[error("{record} format revision {actual} is unsupported")]
    FormatRevision { record: &'static str, actual: u16 },
    #[error("refresh economic record contains {actual} bytes; the maximum is {maximum}")]
    WireBound { actual: usize, maximum: usize },
    #[error("refresh economic JSON is invalid: {0}")]
    Json(String),
    #[error("refresh economic field `{0}` exceeds its canonical cost bound")]
    CostBound(&'static str),
    #[error("refresh economic field `{0}` exceeds its canonical latency bound")]
    LatencyBound(&'static str),
    #[error("refresh economic cost evidence does not bind the assessed candidate")]
    EvidenceBinding,
    #[error("refresh economic decision is not canonical")]
    Decision,
    #[error("refresh economic assessment authority must remain Shadow")]
    Authority,
    #[error("{field} digest mismatch: expected {expected}, got {actual}")]
    Digest { field: &'static str, expected: Digest, actual: Digest },
}

fn validate_revision(record: &'static str, actual: u16) -> Result<(), RefreshEconomicError> {
    if actual == REFRESH_ECONOMIC_FORMAT_REVISION {
        Ok(())
    } else {
        Err(RefreshEconomicError::FormatRevision { record, actual })
    }
}

fn validate_cost(field: &'static str, value: u64) -> Result<(), RefreshEconomicError> {
    if value <= MAX_REFRESH_ECONOMIC_COST_MICROUSD {
        Ok(())
    } else {
        Err(RefreshEconomicError::CostBound(field))
    }
}

fn validate_latency(field: &'static str, value: u64) -> Result<(), RefreshEconomicError> {
    if value <= MAX_REFRESH_ECONOMIC_LATENCY_MICROS {
        Ok(())
    } else {
        Err(RefreshEconomicError::LatencyBound(field))
    }
}

fn validate_digest(
    field: &'static str,
    expected: Digest,
    actual: Digest,
) -> Result<(), RefreshEconomicError> {
    if expected == actual {
        Ok(())
    } else {
        Err(RefreshEconomicError::Digest { field, expected, actual })
    }
}

fn hash_u64(hasher: &mut CanonicalHasher, value: u64) {
    hasher.field_bytes(&value.to_le_bytes());
}

fn hash_optional_u64(hasher: &mut CanonicalHasher, value: Option<u64>) {
    match value {
        Some(value) => {
            hasher.field_u8(1);
            hash_u64(hasher, value);
        }
        None => hasher.field_u8(0),
    }
}

fn hash_optional_digest(hasher: &mut CanonicalHasher, value: Option<Digest>) {
    match value {
        Some(value) => {
            hasher.field_u8(1);
            hasher.field_digest(value);
        }
        None => hasher.field_u8(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> Digest {
        Digest::blake3(label.as_bytes())
    }

    fn policy(maximum_latency: Option<u64>) -> RefreshEconomicPolicy {
        RefreshEconomicPolicy::new(RefreshEconomicPolicyInput {
            action_operational_policy_digest: digest("action-operational"),
            refresh_policy_definition_digest: digest("refresh-policy"),
            minimum_expected_net_microusd: 100,
            maximum_refresh_latency_micros: maximum_latency,
        })
        .unwrap()
    }

    fn evidence(candidate: Digest, refresh_cost: u64, latency: Option<u64>) -> RefreshCostEvidence {
        RefreshCostEvidence::new(RefreshCostEvidenceInput {
            request: ArtifactRequestId::new(digest("request")),
            action_contract: ActionContractId::new("needle.tests.inventory").unwrap(),
            candidate_definition_digest: candidate,
            operator_definition_digest: digest("operator"),
            execution_scope_digest: digest("scope"),
            basis: RefreshCostEvidenceBasis::BenchmarkDerived,
            evidence_digest: digest("evidence"),
            pricing_revision: Some(digest("pricing")),
            estimated_fresh_total_microusd: 1_000,
            estimated_refresh_total_microusd: refresh_cost,
            estimated_refresh_latency_micros: latency,
        })
        .unwrap()
    }

    fn assessment(
        policy: RefreshEconomicPolicy,
        evidence: Option<RefreshCostEvidence>,
    ) -> RefreshEconomicAssessment {
        let candidate = digest("candidate");
        RefreshEconomicAssessment::new(RefreshEconomicAssessmentInput {
            request: ArtifactRequestId::new(digest("request")),
            action_contract: ActionContractId::new("needle.tests.inventory").unwrap(),
            candidate_definition_digest: candidate,
            operator_definition_digest: digest("operator"),
            execution_scope_digest: digest("scope"),
            policy,
            evidence,
        })
        .unwrap()
    }

    #[test]
    fn positive_economics_are_canonical_shadow_and_round_trip() {
        let value =
            assessment(policy(Some(500)), Some(evidence(digest("candidate"), 400, Some(250))));
        assert_eq!(value.expected_net_microusd, Some(600));
        assert_eq!(value.decision, RefreshEconomicDecision::Refresh);
        assert_eq!(value.authority, CapabilityMode::Shadow);
        let json = serde_json::to_vec(&value).unwrap();
        assert_eq!(RefreshEconomicAssessment::decode_json(&json).unwrap(), value);
        let mut unknown = serde_json::to_value(&value).unwrap();
        unknown.as_object_mut().unwrap().insert("unknown".to_owned(), true.into());
        assert!(
            RefreshEconomicAssessment::decode_json(&serde_json::to_vec(&unknown).unwrap()).is_err()
        );
    }

    #[test]
    fn missing_dominated_and_slow_evidence_fail_closed() {
        let missing = assessment(policy(None), None);
        assert_eq!(
            missing.decision,
            RefreshEconomicDecision::FullCompute {
                reason: RefreshEconomicFallback::MissingCostEvidence
            }
        );
        let dominated =
            assessment(policy(None), Some(evidence(digest("candidate"), 950, Some(10))));
        assert_eq!(
            dominated.decision,
            RefreshEconomicDecision::FullCompute {
                reason: RefreshEconomicFallback::BelowMinimumNetValue
            }
        );
        let missing_latency =
            assessment(policy(Some(500)), Some(evidence(digest("candidate"), 400, None)));
        assert_eq!(
            missing_latency.decision,
            RefreshEconomicDecision::FullCompute {
                reason: RefreshEconomicFallback::MissingLatencyEvidence
            }
        );
        let slow =
            assessment(policy(Some(500)), Some(evidence(digest("candidate"), 400, Some(501))));
        assert_eq!(
            slow.decision,
            RefreshEconomicDecision::FullCompute {
                reason: RefreshEconomicFallback::RefreshLatencyBudgetExceeded
            }
        );
    }

    #[test]
    fn evidence_binding_tamper_and_wire_bounds_are_rejected() {
        let mut mismatched = evidence(digest("other-candidate"), 400, Some(250));
        let input = RefreshEconomicAssessmentInput {
            request: ArtifactRequestId::new(digest("request")),
            action_contract: ActionContractId::new("needle.tests.inventory").unwrap(),
            candidate_definition_digest: digest("candidate"),
            operator_definition_digest: digest("operator"),
            execution_scope_digest: digest("scope"),
            policy: policy(Some(500)),
            evidence: Some(mismatched.clone()),
        };
        assert_eq!(
            RefreshEconomicAssessment::new(input),
            Err(RefreshEconomicError::EvidenceBinding)
        );
        mismatched.candidate_definition_digest = digest("candidate");
        assert!(mismatched.validate().is_err());

        let mut value =
            assessment(policy(Some(500)), Some(evidence(digest("candidate"), 400, Some(250))));
        value.definition_digest = digest("tampered");
        assert!(value.validate().is_err());
        let mut decision =
            assessment(policy(Some(500)), Some(evidence(digest("candidate"), 400, Some(250))));
        decision.decision = RefreshEconomicDecision::FullCompute {
            reason: RefreshEconomicFallback::BelowMinimumNetValue,
        };
        assert_eq!(decision.validate(), Err(RefreshEconomicError::Decision));
        assert!(
            RefreshEconomicAssessment::decode_json(&vec![
                b' ';
                MAX_REFRESH_ECONOMIC_WIRE_BYTES + 1
            ])
            .is_err()
        );
    }
}
