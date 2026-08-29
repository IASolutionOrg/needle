use crate::{CodexChangeActionProvider, lifecycle_test_plan};
use needle_core::{
    ActionContractId, ArtifactId, CanonicalHasher, ChangeActionInput, Digest,
    LifecycleAcceptanceReview, LifecycleActionPhasePlan, LifecycleActionPhasePlans,
    LifecyclePatchRef, LifecyclePhase, LifecycleReason, LifecycleReviewVerdict,
    LifecycleTestResult, LifecycleTransition, LifecycleUsage, LifecycleVerificationRef,
    LifecycleWorkerCompletion, NeedExecution, NeedExecutionEnvelopeV1,
    PATCH_PROPOSE_ACTION_CONTRACT, PATCH_VERIFY_ACTION_CONTRACT, PatchActionInputRef,
    REVIEW_DIFF_ACTION_CONTRACT, ReviewArtifact, ReviewReportVerdict,
    TESTS_EXECUTE_ACTION_CONTRACT, TestExecutionStatus, VerificationActionInputRef,
};
use needle_runtime::{
    ActionExecutionResult, ActionExecutionService, ChangeActionOutput, LifecycleAdapterCleanup,
    LifecycleAdapterFailure, LifecycleAdapterInvocationClaim, LifecycleAdapterInvocationState,
    LifecycleAdapterResult, LifecyclePhaseAdapter, LifecyclePhaseAdapterOutcome,
    LifecyclePhaseAdapterRequest, RuntimeStore,
};
use std::fs;
use std::path::{Path, PathBuf};

const CODEX_LIFECYCLE_ACTION_ADAPTER_REVISION: u16 = 2;
const MAX_ADAPTER_FAILURE_DETAIL_BYTES: usize = 2 * 1024;

/// One phase-specific lifecycle adapter backed by the same action execution
/// service used by standalone actions. Apply is deliberately not supported.
pub struct CodexLifecycleActionAdapter {
    store: RuntimeStore,
    data_directory: PathBuf,
    repository_root: PathBuf,
    codex_home: Option<PathBuf>,
    phase: LifecyclePhase,
    definition_digest: Digest,
}

impl CodexLifecycleActionAdapter {
    pub fn new(
        store: RuntimeStore,
        data_directory: impl Into<PathBuf>,
        repository_root: impl AsRef<Path>,
        phase: LifecyclePhase,
    ) -> Result<Self, String> {
        if matches!(phase, LifecyclePhase::Explore | LifecyclePhase::Apply) {
            return Err(
                "action-native lifecycle adapters support Implement, Test, Review, or Verify"
                    .to_owned(),
            );
        }
        let repository_root = fs::canonicalize(repository_root.as_ref()).map_err(|error| {
            format!(
                "cannot resolve lifecycle action repository {}: {error}",
                repository_root.as_ref().display()
            )
        })?;
        let definition_digest = adapter_definition_digest(phase);
        Ok(Self {
            store,
            data_directory: data_directory.into(),
            repository_root,
            codex_home: None,
            phase,
            definition_digest,
        })
    }

    pub fn definition_digest(&self) -> Digest {
        self.definition_digest
    }

    pub fn with_codex_home(mut self, codex_home: impl Into<PathBuf>) -> Self {
        self.codex_home = Some(codex_home.into());
        self
    }

    pub fn phase_plans() -> Result<LifecycleActionPhasePlans, String> {
        LifecycleActionPhasePlans::new(
            action_phase_plan(LifecyclePhase::Implement, PATCH_PROPOSE_ACTION_CONTRACT)?,
            action_phase_plan(LifecyclePhase::Test, TESTS_EXECUTE_ACTION_CONTRACT)?,
            action_phase_plan(LifecyclePhase::Review, REVIEW_DIFF_ACTION_CONTRACT)?,
            action_phase_plan(LifecyclePhase::Verify, PATCH_VERIFY_ACTION_CONTRACT)?,
        )
        .map_err(|error| error.to_string())
    }

    fn execute(
        &self,
        request: &LifecyclePhaseAdapterRequest,
    ) -> Result<LifecyclePhaseAdapterOutcome, String> {
        let action_plan =
            request.lifecycle.spec.explore_action_plan.as_ref().ok_or_else(|| {
                "legacy lifecycle has no frozen action-native Need plan".to_owned()
            })?;
        let phase_plans = request
            .lifecycle
            .spec
            .action_phase_plans
            .as_ref()
            .ok_or_else(|| "legacy lifecycle has no frozen action phase plans".to_owned())?;
        let frozen = phase_plans
            .for_phase(request.phase)
            .ok_or_else(|| "lifecycle phase has no frozen action plan".to_owned())?;
        let expected_contract = action_contract_for_phase(request.phase)
            .ok_or_else(|| "lifecycle phase is not action-native".to_owned())?;
        let live = needle_runtime::built_in_action_contracts()
            .iter()
            .find(|definition| definition.contract.id.as_str() == expected_contract)
            .ok_or_else(|| "frozen lifecycle action contract is not registered".to_owned())?;
        if frozen.action_contract.as_str() != expected_contract
            || frozen.action_definition_digest != live.contract.definition_digest
            || frozen.adapter_definition_digest != self.definition_digest
        {
            return Err("frozen lifecycle action phase plan drifted".to_owned());
        }
        let shadow = self
            .store
            .need_shadow(&action_plan.fragment.root_need)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "frozen lifecycle Need is unavailable".to_owned())?;
        if shadow.need.id != action_plan.fragment.root_need
            || shadow.need.world.repository_lineage != request.change.repository_id
            || request.change.source_snapshot != request.lifecycle.source_snapshot
        {
            return Err("lifecycle Need, repository, or source binding changed".to_owned());
        }
        if request.phase == LifecyclePhase::Test
            && request.lifecycle.spec.test_plans.is_empty()
            && request.lifecycle.resolved_test_plans.is_empty()
        {
            let discovery = lifecycle_test_plan::discover(
                &self.store,
                &self.data_directory,
                &self.repository_root,
                self.codex_home.as_deref(),
                request,
            )?;
            return Ok(LifecyclePhaseAdapterOutcome {
                schema: needle_runtime::LIFECYCLE_ADAPTER_OUTCOME_SCHEMA.to_owned(),
                invocation_id: request.invocation_id,
                expected_state_digest: request.expected_state_digest,
                phase: request.phase,
                usage: discovery.usage.clone(),
                result: LifecycleAdapterResult::Completed {
                    transition: Box::new(LifecycleTransition::BindTestPlans {
                        worker: Some(worker(request, discovery.usage)),
                        plans: discovery.plans,
                    }),
                },
                cleanup: LifecycleAdapterCleanup::succeeded(),
            });
        }
        let settings = self.store.settings().map_err(|error| error.to_string())?;
        let config = self
            .store
            .worker_config_for_provenance(&request.profile, settings.codex_executable)
            .map_err(|error| error.to_string())?;
        let provider = self.codex_home.as_ref().map_or_else(
            || {
                CodexChangeActionProvider::new(
                    &self.data_directory,
                    &self.repository_root,
                    config.clone(),
                )
            },
            |codex_home| {
                CodexChangeActionProvider::new(
                    &self.data_directory,
                    &self.repository_root,
                    config.clone(),
                )
                .with_codex_home(codex_home)
            },
        );
        let service = ActionExecutionService::new(self.store.clone(), provider);
        let (transition, usage) = match request.phase {
            LifecyclePhase::Implement => {
                let (prior_patch, repair_verification) = self.repair_inputs(request)?;
                let input = ChangeActionInput::PatchPropose {
                    change: request.change.request.clone(),
                    prior_patch,
                    repair_verification,
                };
                let result = self.execute_action(
                    &service,
                    request,
                    shadow.need_ir.clone(),
                    input,
                    Digest::blake3(b"implement"),
                )?;
                let ChangeActionOutput::PatchProposal(patch) = result.output else {
                    return Err("Implement action returned a different output contract".to_owned());
                };
                if patch.source_snapshot != request.change.source_snapshot
                    || patch.change_id != action_change_id(request)
                {
                    return Err("Implement patch is not bound to the lifecycle request".to_owned());
                }
                let usage = result.usage;
                (
                    LifecycleTransition::CompleteImplement {
                        worker: worker(request, usage.clone()),
                        patch: LifecyclePatchRef { patch_id: patch.id, revision: patch.revision },
                    },
                    usage,
                )
            }
            LifecyclePhase::Test => {
                let resolved_test_plans = self.test_plan_inputs(request)?;
                let patch = self.patch_input(request)?;
                let action_change_id = action_change_id(request);
                let mut results = Vec::with_capacity(resolved_test_plans.len());
                let mut usage = LifecycleUsage::default();
                for resolved in &resolved_test_plans {
                    let input = ChangeActionInput::TestsExecute {
                        change_id: action_change_id.clone(),
                        requirements_digest: request.change.request_digest,
                        patch,
                        test_plan_artifact: resolved.artifact,
                    };
                    let result = self.execute_action(
                        &service,
                        request,
                        shadow.need_ir.clone(),
                        input,
                        resolved.artifact.digest(),
                    )?;
                    let ChangeActionOutput::TestExecution(evidence) = result.output else {
                        return Err("Test action returned a different output contract".to_owned());
                    };
                    usage = checked_usage_add(&usage, &result.usage)?;
                    let (available, executed, passed, failure_code) = match evidence.status {
                        TestExecutionStatus::Passed => (true, true, true, None),
                        TestExecutionStatus::Failed => {
                            (true, true, false, Some("test_failed".to_owned()))
                        }
                        TestExecutionStatus::Unavailable => {
                            (false, false, false, Some("test_execution_unavailable".to_owned()))
                        }
                        TestExecutionStatus::Inconclusive => {
                            (true, false, false, Some("test_execution_inconclusive".to_owned()))
                        }
                    };
                    results.push(LifecycleTestResult {
                        plan_digest: resolved.binding.plan_digest(),
                        certificate_digest: resolved.binding.certificate_digest,
                        available,
                        executed,
                        passed,
                        evidence_id: evidence.command_evidence_id.clone(),
                        action_evidence_artifact: Some(ArtifactId::new(result.artifact.id)),
                        failure_code,
                    });
                }
                (
                    LifecycleTransition::CompleteTest {
                        worker: worker(request, usage.clone()),
                        results,
                    },
                    usage,
                )
            }
            LifecyclePhase::Review => {
                let patch = self.patch_input(request)?;
                let input = ChangeActionInput::ReviewDiff {
                    change_id: action_change_id(request),
                    requirements_digest: request.change.request_digest,
                    patch,
                    prior_review_artifacts: request.lifecycle.review_report_artifacts.clone(),
                };
                let result = self.execute_action(
                    &service,
                    request,
                    shadow.need_ir.clone(),
                    input,
                    Digest::blake3(b"review"),
                )?;
                let ChangeActionOutput::Review(report) = result.output else {
                    return Err("Review action returned a different output contract".to_owned());
                };
                let verdict = match report.verdict {
                    ReviewReportVerdict::Approved => LifecycleReviewVerdict::Approved,
                    ReviewReportVerdict::Rejected => LifecycleReviewVerdict::Rejected,
                    ReviewReportVerdict::Inconclusive => LifecycleReviewVerdict::Inconclusive,
                };
                let coverage = report
                    .acceptance_coverage
                    .iter()
                    .map(|entry| LifecycleAcceptanceReview {
                        criterion_digest: entry.criterion_digest,
                        status: entry.status,
                        evidence_digest: entry.evidence_digest,
                    })
                    .collect();
                let findings = report
                    .findings
                    .iter()
                    .map(|finding| LifecycleReason::new(&finding.rule, finding.message.as_bytes()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())?;
                let review = ReviewArtifact::new(
                    request.lifecycle.change_id.clone(),
                    report.patch_id,
                    verdict,
                    coverage,
                    findings,
                    request.profile.definition_digest,
                    report.created_unix_ms,
                )
                .map_err(|error| error.to_string())?;
                let usage = result.usage;
                (
                    LifecycleTransition::CompleteReview {
                        worker: worker(request, usage.clone()),
                        review,
                        report_artifact: Some(ArtifactId::new(result.artifact.id)),
                    },
                    usage,
                )
            }
            LifecyclePhase::Verify => {
                let patch = self.patch_input(request)?;
                let mut evidence = request
                    .lifecycle
                    .test_results
                    .iter()
                    .map(|result| {
                        result.action_evidence_artifact.ok_or_else(|| {
                            "Verify requires action-native certified test evidence".to_owned()
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                evidence.sort_unstable();
                if evidence.windows(2).any(|pair| pair[0] >= pair[1]) {
                    return Err("Verify test evidence is not unique".to_owned());
                }
                let input = ChangeActionInput::PatchVerify {
                    change_id: action_change_id(request),
                    requirements_digest: request.change.request_digest,
                    patch,
                    test_evidence_artifacts: evidence,
                };
                let result = self.execute_action(
                    &service,
                    request,
                    shadow.need_ir,
                    input,
                    Digest::blake3(b"verify"),
                )?;
                let ChangeActionOutput::PatchVerification(verification) = result.output else {
                    return Err("Verify action returned a different output contract".to_owned());
                };
                let usage = result.usage;
                (
                    LifecycleTransition::CompleteVerify {
                        worker: worker(request, usage.clone()),
                        verification: LifecycleVerificationRef {
                            verification_id: verification.id,
                            patch_id: verification.patch_id,
                            verdict: verification.verdict,
                        },
                    },
                    usage,
                )
            }
            LifecyclePhase::Explore | LifecyclePhase::Apply => {
                return Err("unsupported lifecycle action phase".to_owned());
            }
        };
        Ok(LifecyclePhaseAdapterOutcome {
            schema: needle_runtime::LIFECYCLE_ADAPTER_OUTCOME_SCHEMA.to_owned(),
            invocation_id: request.invocation_id,
            expected_state_digest: request.expected_state_digest,
            phase: request.phase,
            usage,
            result: LifecycleAdapterResult::Completed { transition: Box::new(transition) },
            cleanup: LifecycleAdapterCleanup::succeeded(),
        })
    }

    fn execute_action(
        &self,
        service: &ActionExecutionService<CodexChangeActionProvider>,
        request: &LifecyclePhaseAdapterRequest,
        need: needle_core::NeedIr,
        input: ChangeActionInput,
        discriminator: Digest,
    ) -> Result<ActionExecutionResult, String> {
        let contract =
            ActionContractId::new(input.contract_id()).map_err(|error| error.to_string())?;
        let operation_id =
            lifecycle_action_operation_id(request.invocation_id, &contract, discriminator);
        let envelope = NeedExecutionEnvelopeV1::new(
            operation_id,
            need,
            NeedExecution::Action {
                action: needle_core::ChangeActionInvocation { contract, input },
            },
        );
        service
            .execute_action(&envelope, request.change.repository_id, request.change.source_snapshot)
            .map_err(|error| error.to_string())
    }

    fn patch_input(
        &self,
        request: &LifecyclePhaseAdapterRequest,
    ) -> Result<PatchActionInputRef, String> {
        let patch = request
            .lifecycle
            .patch
            .as_ref()
            .ok_or_else(|| "lifecycle patch is unavailable".to_owned())?;
        let contract = ActionContractId::new(PATCH_PROPOSE_ACTION_CONTRACT)
            .map_err(|error| error.to_string())?;
        let artifact = self
            .store
            .opaque_action_artifact_by_payload(&contract, patch.patch_id.0)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "lifecycle patch has no certified action artifact".to_owned())?;
        Ok(PatchActionInputRef { artifact: ArtifactId::new(artifact.id), patch: patch.patch_id })
    }

    fn test_plan_inputs(
        &self,
        request: &LifecyclePhaseAdapterRequest,
    ) -> Result<Vec<needle_core::LifecycleResolvedTestPlan>, String> {
        if !request.lifecycle.resolved_test_plans.is_empty() {
            if !request.lifecycle.spec.test_plans.is_empty() {
                return Err("lifecycle contains both frozen and resolved TestPlans".to_owned());
            }
            return Ok(request.lifecycle.resolved_test_plans.clone());
        }
        if request.lifecycle.spec.test_plans.is_empty() {
            return Err("action-native Test requires certified TestPlans".to_owned());
        }
        let candidates = self
            .store
            .lifecycle_start_test_plan_candidates(request.change.source_snapshot)
            .map_err(|error| error.to_string())?;
        let mut by_binding = std::collections::BTreeMap::new();
        for candidate in candidates {
            let key = (candidate.binding.plan_digest(), candidate.binding.certificate_digest);
            if by_binding.insert(key, candidate).is_some() {
                return Err("current source has duplicate certified TestPlan bindings".to_owned());
            }
        }
        request
            .lifecycle
            .spec
            .test_plans
            .iter()
            .map(|binding| {
                let key = (binding.plan_digest(), binding.certificate_digest);
                let candidate = by_binding.get(&key).ok_or_else(|| {
                    "frozen lifecycle TestPlan has no current certified artifact".to_owned()
                })?;
                if candidate.binding != *binding {
                    return Err("frozen lifecycle TestPlan binding changed".to_owned());
                }
                Ok(needle_core::LifecycleResolvedTestPlan {
                    artifact: candidate.artifact_id,
                    binding: binding.clone(),
                })
            })
            .collect()
    }

    fn repair_inputs(
        &self,
        request: &LifecyclePhaseAdapterRequest,
    ) -> Result<(Option<PatchActionInputRef>, Option<VerificationActionInputRef>), String> {
        let Some(verification) = request.repair_verification.as_ref() else {
            return Ok((None, None));
        };
        let patch_contract = ActionContractId::new(PATCH_PROPOSE_ACTION_CONTRACT)
            .map_err(|error| error.to_string())?;
        let patch_artifact = self
            .store
            .opaque_action_artifact_by_payload(&patch_contract, verification.patch_id.0)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "repair patch action artifact is unavailable".to_owned())?;
        let verification_contract = ActionContractId::new(PATCH_VERIFY_ACTION_CONTRACT)
            .map_err(|error| error.to_string())?;
        let verification_artifact = self
            .store
            .opaque_action_artifact_by_payload(&verification_contract, verification.id.0)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "repair verification action artifact is unavailable".to_owned())?;
        Ok((
            Some(PatchActionInputRef {
                artifact: ArtifactId::new(patch_artifact.id),
                patch: verification.patch_id,
            }),
            Some(VerificationActionInputRef {
                artifact: ArtifactId::new(verification_artifact.id),
                verification: verification.id,
            }),
        ))
    }

    fn rejected_implement_usage(
        &self,
        request: &LifecyclePhaseAdapterRequest,
    ) -> Result<LifecycleUsage, String> {
        if request.phase != LifecyclePhase::Implement {
            return Ok(LifecycleUsage::default());
        }
        let contract = ActionContractId::new(PATCH_PROPOSE_ACTION_CONTRACT)
            .map_err(|error| error.to_string())?;
        let operation_id = lifecycle_action_operation_id(
            request.invocation_id,
            &contract,
            Digest::blake3(b"implement"),
        );
        let operation_id = operation_id.to_string();
        let change_id = action_change_id(request);
        let attempts = self.store.change_attempts(&change_id).map_err(|error| error.to_string())?;
        let profile = self
            .store
            .read_role_profile_revision(&request.profile.profile_id, request.profile.revision)
            .map_err(|error| error.to_string())?;
        if profile.definition.definition_digest != request.profile.definition_digest {
            return Err("rejected attempt role-profile definition binding changed".to_owned());
        }
        Ok(rejected_patch_attempt_usage(
            &attempts,
            &operation_id,
            profile.definition.budget.max_output_tokens,
            profile.definition.budget.max_cost_microusd,
        ))
    }
}

fn checked_usage_add(
    current: &LifecycleUsage,
    delta: &LifecycleUsage,
) -> Result<LifecycleUsage, String> {
    Ok(LifecycleUsage {
        worker_turns: current
            .worker_turns
            .checked_add(delta.worker_turns)
            .ok_or_else(|| "action worker-turn usage overflowed".to_owned())?,
        output_tokens: current
            .output_tokens
            .checked_add(delta.output_tokens)
            .ok_or_else(|| "action output-token usage overflowed".to_owned())?,
        cost_microusd: current
            .cost_microusd
            .checked_add(delta.cost_microusd)
            .ok_or_else(|| "action cost usage overflowed".to_owned())?,
    })
}

fn rejected_patch_attempt_usage(
    attempts: &[needle_runtime::ChangeAttemptRecord],
    operation_id: &str,
    max_output_tokens: u32,
    max_cost_microusd: u64,
) -> LifecycleUsage {
    let Some(attempt) = attempts.iter().rev().find(|attempt| {
        attempt.role == "patcher"
            && attempt.patch_id.is_none()
            && attempt.attempt.get("outcome").and_then(serde_json::Value::as_str)
                == Some("rejected")
            && attempt.attempt.get("operation_id").and_then(serde_json::Value::as_str)
                == Some(operation_id)
    }) else {
        return LifecycleUsage::default();
    };
    LifecycleUsage {
        worker_turns: 1,
        output_tokens: attempt
            .usage
            .get("output_tokens")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(u64::from(max_output_tokens)),
        cost_microusd: max_cost_microusd,
    }
}

impl LifecyclePhaseAdapter for CodexLifecycleActionAdapter {
    fn invoke(&self, request: &LifecyclePhaseAdapterRequest) -> LifecyclePhaseAdapterOutcome {
        if request.phase != self.phase {
            return failure_outcome(
                request,
                "unsupported_phase",
                "the lifecycle adapter was invoked for a different frozen phase",
            );
        }
        match self.store.claim_lifecycle_adapter_invocation(request, self.definition_digest) {
            Ok(LifecycleAdapterInvocationClaim::Existing(
                LifecycleAdapterInvocationState::Completed { outcome, .. },
            )) => return *outcome,
            Ok(LifecycleAdapterInvocationClaim::Existing(
                LifecycleAdapterInvocationState::InProgress { .. },
            )) => {
                return failure_outcome(
                    request,
                    "adapter_in_progress",
                    "the durable adapter invocation is already in progress",
                );
            }
            Ok(LifecycleAdapterInvocationClaim::Existing(
                LifecycleAdapterInvocationState::Aborted { .. },
            )) => {
                return failure_outcome(
                    request,
                    "adapter_invocation_aborted",
                    "the durable adapter invocation was explicitly aborted",
                );
            }
            Ok(LifecycleAdapterInvocationClaim::Claimed) => {}
            Err(error) => {
                return failure_outcome(request, "adapter_claim_failed", &error.to_string());
            }
        }
        let outcome = match self.execute(request) {
            Ok(outcome) => outcome,
            Err(error) => {
                let usage = self.rejected_implement_usage(request).unwrap_or_default();
                failure_outcome_with_usage(request, "action_execution_failed", &error, usage)
            }
        };
        if let Err(error) = self.store.complete_lifecycle_adapter_invocation(
            request,
            self.definition_digest,
            &outcome,
        ) {
            return failure_outcome(
                request,
                "adapter_outcome_persistence_failed",
                &error.to_string(),
            );
        }
        outcome
    }
}

fn action_change_id(request: &LifecyclePhaseAdapterRequest) -> needle_core::ChangeId {
    needle_core::ChangeId::from_digest(request.change.request_digest)
}

fn worker(
    request: &LifecyclePhaseAdapterRequest,
    usage: LifecycleUsage,
) -> LifecycleWorkerCompletion {
    LifecycleWorkerCompletion {
        profile: request.profile.clone(),
        worker_depth: 1,
        logical_worker_spawns: 1,
        usage,
    }
}

fn lifecycle_action_operation_id(
    invocation_id: Digest,
    contract: &ActionContractId,
    discriminator: Digest,
) -> Digest {
    let mut hasher = CanonicalHasher::new(b"needle-lifecycle-action-operation-v1");
    hasher.field_digest(invocation_id);
    hasher.field_str(contract.as_str());
    hasher.field_digest(discriminator);
    hasher.finish()
}

fn adapter_definition_digest(phase: LifecyclePhase) -> Digest {
    let mut hasher = CanonicalHasher::new(b"needle-codex-lifecycle-action-adapter-v1");
    hasher.field_u16(CODEX_LIFECYCLE_ACTION_ADAPTER_REVISION);
    hasher.field_str(phase.as_str());
    hasher.field_str(match phase {
        LifecyclePhase::Implement => PATCH_PROPOSE_ACTION_CONTRACT,
        LifecyclePhase::Test => TESTS_EXECUTE_ACTION_CONTRACT,
        LifecyclePhase::Review => REVIEW_DIFF_ACTION_CONTRACT,
        LifecyclePhase::Verify => PATCH_VERIFY_ACTION_CONTRACT,
        LifecyclePhase::Explore | LifecyclePhase::Apply => "unsupported",
    });
    if phase == LifecyclePhase::Test {
        hasher.field_digest(Digest::blake3(lifecycle_test_plan::TEST_PLAN_DISCOVERY_DEFINITION));
    }
    hasher.field_digest(needle_runtime::active_definition_set().audit_digest);
    hasher.finish()
}

fn action_contract_for_phase(phase: LifecyclePhase) -> Option<&'static str> {
    match phase {
        LifecyclePhase::Implement => Some(PATCH_PROPOSE_ACTION_CONTRACT),
        LifecyclePhase::Test => Some(TESTS_EXECUTE_ACTION_CONTRACT),
        LifecyclePhase::Review => Some(REVIEW_DIFF_ACTION_CONTRACT),
        LifecyclePhase::Verify => Some(PATCH_VERIFY_ACTION_CONTRACT),
        LifecyclePhase::Explore | LifecyclePhase::Apply => None,
    }
}

fn action_phase_plan(
    phase: LifecyclePhase,
    contract: &'static str,
) -> Result<LifecycleActionPhasePlan, String> {
    let definition = needle_runtime::built_in_action_contracts()
        .iter()
        .find(|definition| definition.contract.id.as_str() == contract)
        .ok_or_else(|| format!("action contract `{contract}` is not registered"))?;
    LifecycleActionPhasePlan::new(
        phase,
        definition.contract.id.clone(),
        definition.contract.definition_digest,
        adapter_definition_digest(phase),
    )
    .map_err(|error| error.to_string())
}

fn failure_outcome(
    request: &LifecyclePhaseAdapterRequest,
    code: &str,
    detail: &str,
) -> LifecyclePhaseAdapterOutcome {
    failure_outcome_with_usage(request, code, detail, LifecycleUsage::default())
}

fn failure_outcome_with_usage(
    request: &LifecyclePhaseAdapterRequest,
    code: &str,
    detail: &str,
    usage: LifecycleUsage,
) -> LifecyclePhaseAdapterOutcome {
    let detail = bounded_detail(detail);
    LifecyclePhaseAdapterOutcome {
        schema: needle_runtime::LIFECYCLE_ADAPTER_OUTCOME_SCHEMA.to_owned(),
        invocation_id: request.invocation_id,
        expected_state_digest: request.expected_state_digest,
        phase: request.phase,
        usage,
        result: LifecycleAdapterResult::Failed {
            failure: LifecycleAdapterFailure { code: code.to_owned(), detail },
        },
        cleanup: LifecycleAdapterCleanup::succeeded(),
    }
}

fn bounded_detail(value: &str) -> String {
    if value.len() <= MAX_ADAPTER_FAILURE_DETAIL_BYTES {
        return value.to_owned();
    }
    let end = value
        .char_indices()
        .take_while(|(index, _)| *index <= MAX_ADAPTER_FAILURE_DETAIL_BYTES)
        .map(|(index, character)| index + character.len_utf8())
        .last()
        .unwrap_or(0)
        .min(MAX_ADAPTER_FAILURE_DETAIL_BYTES);
    value[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(
        operation_id: &str,
        output_tokens: serde_json::Value,
    ) -> needle_runtime::ChangeAttemptRecord {
        needle_runtime::ChangeAttemptRecord {
            role: "patcher".to_owned(),
            patch_id: None,
            attempt: serde_json::json!({
                "operation_id": operation_id,
                "outcome": "rejected"
            }),
            usage: serde_json::json!({"output_tokens": output_tokens}),
            cost_microusd: None,
            created_unix_ms: 1,
            role_profile_provenance: None,
        }
    }

    #[test]
    fn rejected_attempt_usage_is_operation_bound_and_uses_observed_tokens() {
        let attempts =
            vec![attempt("old", serde_json::json!(90)), attempt("current", serde_json::json!(40))];
        assert_eq!(
            rejected_patch_attempt_usage(&attempts, "current", 500, 100_000),
            LifecycleUsage { worker_turns: 1, output_tokens: 40, cost_microusd: 100_000 }
        );
        assert_eq!(
            rejected_patch_attempt_usage(&attempts, "missing", 500, 100_000),
            LifecycleUsage::default()
        );
    }

    #[test]
    fn rejected_attempt_usage_falls_back_to_the_frozen_output_budget() {
        let attempts = vec![attempt("current", serde_json::Value::Null)];
        assert_eq!(
            rejected_patch_attempt_usage(&attempts, "current", 500, 100_000),
            LifecycleUsage { worker_turns: 1, output_tokens: 500, cost_microusd: 100_000 }
        );
    }
}
