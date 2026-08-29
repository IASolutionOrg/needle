use needle_core::{
    ActionContract, ActionRequest, CapabilityMode, Digest, MAX_NEED_IR_BYTES, RefreshCostEvidence,
    RefreshEconomicAssessment, RefreshEconomicAssessmentInput, RefreshEconomicDecision,
    RefreshEconomicError, RefreshEconomicFallback, RefreshEconomicPolicy,
};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShadowRefreshCandidate<T> {
    Ready { definition_digest: Digest, result: T },
    FullCompute { reason_digest: Digest },
    RefreshFailed { failure_evidence_digest: Digest },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShadowRefreshFallbackTrigger {
    CandidateRejected { reason_digest: Digest },
    RefreshFailed { failure_evidence_digest: Digest },
    Economic { reason: RefreshEconomicFallback },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShadowRefreshResolution<RefreshResult, FullComputeResult> {
    Refresh {
        result: RefreshResult,
        assessment: RefreshEconomicAssessment,
    },
    FullCompute {
        result: FullComputeResult,
        trigger: ShadowRefreshFallbackTrigger,
        assessment: Option<RefreshEconomicAssessment>,
    },
}

impl<RefreshResult, FullComputeResult> ShadowRefreshResolution<RefreshResult, FullComputeResult> {
    pub const fn authority(&self) -> CapabilityMode {
        CapabilityMode::Shadow
    }
}

#[derive(Clone, Copy)]
pub struct ShadowRefreshResolverInput<'a> {
    pub request: &'a ActionRequest,
    pub contract: &'a ActionContract,
    pub operator_definition_digest: Digest,
    pub execution_scope_digest: Digest,
    pub policy: &'a RefreshEconomicPolicy,
    pub evidence: Option<&'a RefreshCostEvidence>,
}

pub fn resolve_shadow_refresh_or_full_compute<RefreshResult, FullComputeResult, FullComputeError>(
    input: ShadowRefreshResolverInput<'_>,
    candidate: ShadowRefreshCandidate<RefreshResult>,
    full_compute: impl FnOnce() -> Result<FullComputeResult, FullComputeError>,
) -> Result<
    ShadowRefreshResolution<RefreshResult, FullComputeResult>,
    ShadowRefreshResolverError<FullComputeError>,
>
where
    FullComputeError: std::error::Error + Send + Sync + 'static,
{
    if input.request.artifact_request.normalized_request.len() > MAX_NEED_IR_BYTES {
        return Err(ShadowRefreshResolverError::RequestTextBound);
    }
    input
        .request
        .validate(input.contract)
        .map_err(|error| ShadowRefreshResolverError::Request(error.to_string()))?;

    match candidate {
        ShadowRefreshCandidate::FullCompute { reason_digest } => {
            let result = full_compute().map_err(ShadowRefreshResolverError::FullCompute)?;
            Ok(ShadowRefreshResolution::FullCompute {
                result,
                trigger: ShadowRefreshFallbackTrigger::CandidateRejected { reason_digest },
                assessment: None,
            })
        }
        ShadowRefreshCandidate::RefreshFailed { failure_evidence_digest } => {
            let result = full_compute().map_err(ShadowRefreshResolverError::FullCompute)?;
            Ok(ShadowRefreshResolution::FullCompute {
                result,
                trigger: ShadowRefreshFallbackTrigger::RefreshFailed { failure_evidence_digest },
                assessment: None,
            })
        }
        ShadowRefreshCandidate::Ready { definition_digest, result } => {
            if input.policy.action_operational_policy_digest
                != input.contract.operational_policy_digest
            {
                return Err(ShadowRefreshResolverError::PolicyBinding);
            }
            let assessment = RefreshEconomicAssessment::new(RefreshEconomicAssessmentInput {
                request: input.request.semantic_id(),
                action_contract: input.contract.id.clone(),
                candidate_definition_digest: definition_digest,
                operator_definition_digest: input.operator_definition_digest,
                execution_scope_digest: input.execution_scope_digest,
                policy: input.policy.clone(),
                evidence: input.evidence.cloned(),
            })?;
            match assessment.decision {
                RefreshEconomicDecision::Refresh => {
                    Ok(ShadowRefreshResolution::Refresh { result, assessment })
                }
                RefreshEconomicDecision::FullCompute { reason } => {
                    let result = full_compute().map_err(ShadowRefreshResolverError::FullCompute)?;
                    Ok(ShadowRefreshResolution::FullCompute {
                        result,
                        trigger: ShadowRefreshFallbackTrigger::Economic { reason },
                        assessment: Some(assessment),
                    })
                }
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum ShadowRefreshResolverError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    #[error("Shadow refresh action request is invalid: {0}")]
    Request(String),
    #[error("Shadow refresh request text exceeds the canonical bound")]
    RequestTextBound,
    #[error("Shadow refresh candidate is invalid: {0}")]
    Candidate(String),
    #[error("Shadow refresh economic policy does not bind the action operational policy")]
    PolicyBinding,
    #[error(transparent)]
    Economics(#[from] RefreshEconomicError),
    #[error("full-compute fallback failed: {0}")]
    FullCompute(E),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{built_in_action_for_artifact_kind, partitioned_action_artifact::tests::fixture};
    use needle_core::{
        ArtifactKind, RefreshCostEvidenceBasis, RefreshCostEvidenceInput,
        RefreshEconomicPolicyInput,
    };
    use std::cell::Cell;
    use std::convert::Infallible;

    fn digest(label: &str) -> Digest {
        Digest::blake3(label.as_bytes())
    }

    fn setup(
        refresh_cost: u64,
    ) -> (ActionRequest, &'static ActionContract, RefreshEconomicPolicy, RefreshCostEvidence) {
        let (request, _, _, _, _) = fixture();
        let contract = &built_in_action_for_artifact_kind(&ArtifactKind::test_target_inventory())
            .unwrap()
            .contract;
        let policy = RefreshEconomicPolicy::new(RefreshEconomicPolicyInput {
            action_operational_policy_digest: contract.operational_policy_digest,
            refresh_policy_definition_digest: digest("refresh-policy"),
            minimum_expected_net_microusd: 100,
            maximum_refresh_latency_micros: Some(500),
        })
        .unwrap();
        let evidence = RefreshCostEvidence::new(RefreshCostEvidenceInput {
            request: request.semantic_id(),
            action_contract: contract.id.clone(),
            candidate_definition_digest: digest("candidate"),
            operator_definition_digest: digest("operator"),
            execution_scope_digest: digest("scope"),
            basis: RefreshCostEvidenceBasis::ConfiguredStatic,
            evidence_digest: digest("evidence"),
            pricing_revision: Some(digest("pricing")),
            estimated_fresh_total_microusd: 1_000,
            estimated_refresh_total_microusd: refresh_cost,
            estimated_refresh_latency_micros: Some(250),
        })
        .unwrap();
        (request, contract, policy, evidence)
    }

    fn input<'a>(
        request: &'a ActionRequest,
        contract: &'a ActionContract,
        policy: &'a RefreshEconomicPolicy,
        evidence: Option<&'a RefreshCostEvidence>,
    ) -> ShadowRefreshResolverInput<'a> {
        ShadowRefreshResolverInput {
            request,
            contract,
            operator_definition_digest: digest("operator"),
            execution_scope_digest: digest("scope"),
            policy,
            evidence,
        }
    }

    #[test]
    fn positive_economics_select_refresh_without_running_fallback() {
        let (request, contract, policy, evidence) = setup(400);
        let fallback_calls = Cell::new(0);
        let resolution = resolve_shadow_refresh_or_full_compute(
            input(&request, contract, &policy, Some(&evidence)),
            ShadowRefreshCandidate::Ready {
                definition_digest: digest("candidate"),
                result: "refreshed",
            },
            || {
                fallback_calls.set(fallback_calls.get() + 1);
                Ok::<_, Infallible>("fresh")
            },
        )
        .unwrap();
        assert_eq!(fallback_calls.get(), 0);
        assert_eq!(resolution.authority(), CapabilityMode::Shadow);
        assert!(matches!(resolution, ShadowRefreshResolution::Refresh { result: "refreshed", .. }));
    }

    #[test]
    fn missing_or_dominated_economics_runs_full_compute_once() {
        let (request, contract, policy, evidence) = setup(950);
        for evidence in [None, Some(&evidence)] {
            let fallback_calls = Cell::new(0);
            let resolution = resolve_shadow_refresh_or_full_compute(
                input(&request, contract, &policy, evidence),
                ShadowRefreshCandidate::Ready {
                    definition_digest: digest("candidate"),
                    result: "refreshed",
                },
                || {
                    fallback_calls.set(fallback_calls.get() + 1);
                    Ok::<_, Infallible>("fresh")
                },
            )
            .unwrap();
            assert_eq!(fallback_calls.get(), 1);
            assert!(matches!(
                resolution,
                ShadowRefreshResolution::FullCompute { result: "fresh", .. }
            ));
        }
    }

    #[test]
    fn rejected_and_failed_candidates_skip_economics_and_fallback() {
        let (request, contract, policy, _) = setup(400);
        for candidate in [
            ShadowRefreshCandidate::<&str>::FullCompute { reason_digest: digest("reason") },
            ShadowRefreshCandidate::RefreshFailed { failure_evidence_digest: digest("failure") },
        ] {
            let resolution = resolve_shadow_refresh_or_full_compute(
                input(&request, contract, &policy, None),
                candidate,
                || Ok::<_, Infallible>("fresh"),
            )
            .unwrap();
            assert!(matches!(
                resolution,
                ShadowRefreshResolution::FullCompute { assessment: None, .. }
            ));
        }
    }

    #[test]
    fn forged_policy_or_evidence_never_runs_full_compute() {
        let (request, contract, mut policy, mut evidence) = setup(400);
        policy.action_operational_policy_digest = digest("other-policy");
        let fallback_calls = Cell::new(0);
        let result = resolve_shadow_refresh_or_full_compute(
            input(&request, contract, &policy, Some(&evidence)),
            ShadowRefreshCandidate::Ready {
                definition_digest: digest("candidate"),
                result: "refreshed",
            },
            || {
                fallback_calls.set(fallback_calls.get() + 1);
                Ok::<_, Infallible>("fresh")
            },
        );
        assert!(matches!(result, Err(ShadowRefreshResolverError::PolicyBinding)));
        assert_eq!(fallback_calls.get(), 0);

        let (_, _, policy, _) = setup(400);
        evidence.candidate_definition_digest = digest("other-candidate");
        let result = resolve_shadow_refresh_or_full_compute(
            input(&request, contract, &policy, Some(&evidence)),
            ShadowRefreshCandidate::Ready {
                definition_digest: digest("candidate"),
                result: "refreshed",
            },
            || Ok::<_, Infallible>("fresh"),
        );
        assert!(matches!(result, Err(ShadowRefreshResolverError::Economics(_))));
    }

    #[test]
    fn full_compute_failure_is_returned_without_a_false_resolution() {
        let (request, contract, policy, _) = setup(400);
        let result = resolve_shadow_refresh_or_full_compute(
            input(&request, contract, &policy, None),
            ShadowRefreshCandidate::<&str>::FullCompute { reason_digest: digest("reason") },
            || Err::<&str, _>(std::io::Error::other("fresh failed")),
        );
        assert!(matches!(result, Err(ShadowRefreshResolverError::FullCompute(_))));
    }
}
