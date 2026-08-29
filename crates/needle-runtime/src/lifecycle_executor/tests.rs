use super::*;
use crate::{ShadowActionResolutionAuthority, compile_lifecycle_explore_action_plan};
use needle_core::{
    AcceptanceCoverage, AcceptanceStatus, ActionAssuranceEvidenceId, ActionCapabilityClassId,
    ActionCapabilityDecisionId, ArtifactId, ArtifactValidationCertificateId, ChangeRequest,
    CoverageEntry, CoverageManifest, Facet, LifecycleAcceptanceReview, LifecycleArtifactKind,
    LifecycleArtifactRef, LifecycleBudget, LifecycleExploreActionPlan,
    LifecycleExploreReuseAuthority, LifecycleExploreReuseCompletion, LifecyclePatchRef,
    LifecycleReviewVerdict, LifecycleSpec, LifecycleTestPlanBinding, LifecycleTestResult,
    LifecycleVerificationRef, LifecycleWorkerCompletion, LifecycleWorkerProfiles, Need, NeedId,
    NeedRequest, Obligation, PredicateKind, ReuseDescriptor, ReuseDescriptorInput,
    ReuseSufficiencyCertificateId, ReviewArtifact, RoleProfileId, SelectedPlanId, SemanticWorld,
    Subject, SubjectKind, TestPlan, need_fragment,
};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
};

fn profile(name: &str) -> RoleProfileProvenance {
    RoleProfileProvenance::new(
        RoleProfileId::new(name).unwrap(),
        1,
        Digest::blake3(name.as_bytes()),
    )
    .unwrap()
}

fn lifecycle_spec(max_worker_turns: u32) -> LifecycleSpec {
    LifecycleSpec {
        worker_depth_limit: 1,
        profiles: LifecycleWorkerProfiles {
            explore: profile("kernel.explore"),
            implement: profile("kernel.implement"),
            test: profile("kernel.test"),
            review: profile("kernel.review"),
            verify: profile("kernel.verify"),
        },
        budget: LifecycleBudget {
            max_worker_turns,
            max_output_tokens: 100,
            max_cost_microusd: 100,
            max_concurrent_workers: 1,
        },
        explore_action_plan: None,
        action_phase_plans: None,
        test_plans: vec![LifecycleTestPlanBinding {
            plan: TestPlan {
                runner: "cargo".to_owned(),
                argv: vec!["cargo".to_owned(), "test".to_owned(), "kernel".to_owned()],
                cwd_relative: ".".to_owned(),
                test_identifier: "kernel".to_owned(),
                requires_approval: true,
                execution_evidence_id: None,
            },
            certificate_digest: Digest::blake3(b"kernel-test-certificate"),
        }],
    }
}

fn context(change_id: &ChangeId, source_snapshot: Digest) -> LifecycleChangeContext {
    let request = ChangeRequest {
        task: format!("Execute {change_id} through the lifecycle kernel."),
        acceptance_criteria: vec!["the bounded lifecycle completes".to_owned()],
        allowed_paths: Vec::new(),
        artifact_ids: Vec::new(),
        claim_ids: Vec::new(),
        constraints: Vec::new(),
    };
    LifecycleChangeContext {
        request_digest: request.digest(source_snapshot),
        request,
        repository_id: Digest::blake3(b"kernel-repository"),
        source_snapshot,
    }
}

fn projection(lifecycle: DevelopmentLifecycle) -> LifecycleProjection {
    LifecycleProjection { state_digest: lifecycle.state_digest(), lifecycle }
}

struct FakeStore {
    projection: RefCell<LifecycleProjection>,
    context: LifecycleChangeContext,
    latest_verification: RefCell<Option<VerificationArtifact>>,
    repair_calls: Cell<u32>,
    fail_next_parent_commit: Cell<bool>,
    concurrent_transition: RefCell<Option<LifecycleTransition>>,
    corrupt_replay: Cell<bool>,
    explore_action_observations: RefCell<Vec<LifecycleExploreShadowObservation>>,
    fail_explore_action_observation: Cell<bool>,
    explore_reuse_authority: RefCell<Option<(LifecycleExploreReuseAuthority, bool)>>,
    explore_reuse_attempts: Cell<u32>,
}

impl FakeStore {
    fn new(max_worker_turns: u32) -> (Self, ChangeId) {
        let change_id = ChangeId::from_digest(Digest::blake3(b"kernel-change"));
        let source_snapshot = Digest::blake3(b"kernel-source");
        let lifecycle = DevelopmentLifecycle::new(
            change_id.clone(),
            source_snapshot,
            lifecycle_spec(max_worker_turns),
            1,
        )
        .unwrap();
        (
            Self {
                projection: RefCell::new(projection(lifecycle)),
                context: context(&change_id, source_snapshot),
                latest_verification: RefCell::new(None),
                repair_calls: Cell::new(0),
                fail_next_parent_commit: Cell::new(false),
                concurrent_transition: RefCell::new(None),
                corrupt_replay: Cell::new(false),
                explore_action_observations: RefCell::new(Vec::new()),
                fail_explore_action_observation: Cell::new(false),
                explore_reuse_authority: RefCell::new(None),
                explore_reuse_attempts: Cell::new(0),
            },
            change_id,
        )
    }

    fn apply(&self, transition: LifecycleTransition) -> Result<LifecycleProjection, StoreError> {
        let current = self.projection.borrow().clone();
        let (next, _) =
            current.lifecycle.transition(transition, current.lifecycle.updated_unix_ms + 1)?;
        let next = projection(next);
        *self.projection.borrow_mut() = next.clone();
        Ok(next)
    }

    fn install_explore_action_plan(&self, plan: LifecycleExploreActionPlan) {
        let mut current = self.projection.borrow().clone();
        current.lifecycle.spec.explore_action_plan = Some(plan);
        current.lifecycle.validate().unwrap();
        current.state_digest = current.lifecycle.state_digest();
        *self.projection.borrow_mut() = current;
    }

    fn authorize_explore_reuse(&self, lifecycle_consumption: bool) {
        self.explore_reuse_authority.replace(Some((
            LifecycleExploreReuseAuthority {
                capability_class: ActionCapabilityClassId::new(Digest::blake3(b"capability")),
                capability_definition_digest: Digest::blake3(b"capability-definition"),
                evidence: ActionAssuranceEvidenceId::new(Digest::blake3(b"evidence")),
                decision: ActionCapabilityDecisionId::new(Digest::blake3(b"decision")),
            },
            lifecycle_consumption,
        )));
    }
}

impl LifecycleKernelStore for FakeStore {
    fn replay(&self, change_id: &ChangeId) -> Result<LifecycleProjection, StoreError> {
        if self.corrupt_replay.get() {
            return Err(StoreError::LifecycleCorruption(format!(
                "{change_id}: injected replay corruption"
            )));
        }
        Ok(self.projection.borrow().clone())
    }

    fn change_context(
        &self,
        _change_id: &ChangeId,
    ) -> Result<Option<LifecycleChangeContext>, StoreError> {
        Ok(Some(self.context.clone()))
    }

    fn latest_verification(
        &self,
        _change_id: &ChangeId,
    ) -> Result<Option<VerificationArtifact>, StoreError> {
        Ok(self.latest_verification.borrow().clone())
    }

    fn parent_transition(
        &self,
        change_id: &ChangeId,
        expected_state_digest: Digest,
        transition: LifecycleTransition,
    ) -> Result<LifecycleProjection, StoreError> {
        let current = self.projection.borrow().clone();
        if current.state_digest != expected_state_digest {
            return Err(StoreError::LifecycleConflict(format!(
                "{change_id}: stale injected state"
            )));
        }
        if self.fail_next_parent_commit.replace(false) {
            return Err(StoreError::ConnectionLock);
        }
        if let Some(concurrent) = self.concurrent_transition.borrow_mut().take() {
            self.apply(concurrent)?;
            return Err(StoreError::LifecycleConflict(format!(
                "{change_id}: injected concurrent transition"
            )));
        }

        let verification_artifact = match &transition {
            LifecycleTransition::CompleteVerify { verification, .. } => {
                let artifact = verification_artifact(
                    &current.lifecycle,
                    &self.context.request,
                    verification.verdict,
                );
                if artifact.id != verification.verification_id {
                    return Err(StoreError::LifecycleCorruption(format!(
                        "{change_id}: fake verification identity"
                    )));
                }
                Some(artifact)
            }
            _ => None,
        };
        let next = self.apply(transition)?;
        if let Some(artifact) = verification_artifact {
            *self.latest_verification.borrow_mut() = Some(artifact);
        }
        Ok(next)
    }

    fn test_plan_candidates(
        &self,
        _source_snapshot: Digest,
    ) -> Result<Vec<crate::LifecycleStartTestPlanCandidate>, StoreError> {
        Ok(Vec::new())
    }

    fn bind_test_plans(
        &self,
        change_id: &ChangeId,
        expected_state_digest: Digest,
        worker: Option<LifecycleWorkerCompletion>,
        plans: Vec<needle_core::LifecycleResolvedTestPlan>,
    ) -> Result<LifecycleProjection, StoreError> {
        self.parent_transition(
            change_id,
            expected_state_digest,
            LifecycleTransition::BindTestPlans { worker, plans },
        )
    }

    fn begin_repair(
        &self,
        change_id: &ChangeId,
        action_change_id: &ChangeId,
        patch_id: PatchId,
    ) -> Result<(), StoreError> {
        self.repair_calls.set(self.repair_calls.get() + 1);
        let current = self.projection.borrow().clone();
        if current.lifecycle.patch.as_ref().map(|patch| patch.patch_id) != Some(patch_id)
            || *action_change_id != ChangeId::from_digest(self.context.request_digest)
        {
            return Err(StoreError::ChangeConflict(format!(
                "{change_id}: injected repair patch mismatch"
            )));
        }
        self.apply(LifecycleTransition::ConsumeRepair)?;
        Ok(())
    }

    fn record_explore_action_observation(
        &self,
        observation: &LifecycleExploreShadowObservation,
    ) -> Result<(), StoreError> {
        if self.fail_explore_action_observation.get() {
            return Err(StoreError::ConnectionLock);
        }
        let mut observations = self.explore_action_observations.borrow_mut();
        if !observations.contains(observation) {
            observations.push(observation.clone());
        }
        Ok(())
    }

    fn try_complete_explore_from_reuse(
        &self,
        _change_id: &ChangeId,
        expected_state_digest: Digest,
        summary: &crate::ShadowActionResolutionSummary,
    ) -> Result<LifecycleExploreReuseCommit, StoreError> {
        self.explore_reuse_attempts.set(self.explore_reuse_attempts.get() + 1);
        let Some((authority, lifecycle_consumption)) =
            self.explore_reuse_authority.borrow().clone()
        else {
            return Ok(LifecycleExploreReuseCommit::Ineligible);
        };
        if !lifecycle_consumption {
            return Ok(LifecycleExploreReuseCommit::ResolverAuthorized(authority));
        }
        let current = self.projection.borrow().clone();
        if current.state_digest != expected_state_digest {
            return Err(StoreError::LifecycleConflict("injected reuse state conflict".to_owned()));
        }
        let completion = LifecycleExploreReuseCompletion {
            authority,
            action_request: summary.request,
            origin_request: summary.artifact_origin_requests[0],
            artifact: summary.artifacts[0],
            validation_certificate: summary.validation_certificates[0],
            selected_plan: summary.selected_plan,
            sufficiency_certificate: summary.sufficiency_certificate.unwrap(),
            repository_id: self.context.repository_id,
            source_snapshot: self.context.source_snapshot,
            resolution_definition_digest: summary.definition_digest,
        };
        let artifacts = vec![LifecycleArtifactRef {
            kind: LifecycleArtifactKind::Exploration,
            id: completion.artifact.digest(),
            source_snapshot: completion.source_snapshot,
        }];
        let projection = self.apply(LifecycleTransition::CompleteExploreFromReuse {
            reuse: completion.clone(),
            artifacts,
        })?;
        Ok(LifecycleExploreReuseCommit::Committed {
            projection: Box::new(projection),
            completion: Box::new(completion),
        })
    }
}

#[derive(Clone, Copy)]
enum FakeAdapterMode {
    Success,
    RepairOnce,
    RejectVerification,
    WrongPhase,
    WrongProfile,
    BadWorkerDepth,
    Failure,
    CleanupFailure,
    OversizedFailure,
}

struct FakeAdapter {
    mode: FakeAdapterMode,
    calls: Cell<u32>,
    side_effects: RefCell<BTreeSet<Digest>>,
    cached: RefCell<BTreeMap<Digest, LifecyclePhaseAdapterOutcome>>,
    phases: RefCell<Vec<LifecyclePhase>>,
    repair_contexts: Cell<u32>,
}

impl FakeAdapter {
    fn new(mode: FakeAdapterMode) -> Self {
        Self {
            mode,
            calls: Cell::new(0),
            side_effects: RefCell::new(BTreeSet::new()),
            cached: RefCell::new(BTreeMap::new()),
            phases: RefCell::new(Vec::new()),
            repair_contexts: Cell::new(0),
        }
    }
}

impl LifecyclePhaseAdapter for FakeAdapter {
    fn invoke(&self, request: &LifecyclePhaseAdapterRequest) -> LifecyclePhaseAdapterOutcome {
        self.calls.set(self.calls.get() + 1);
        self.phases.borrow_mut().push(request.phase);
        if request.repair_verification.is_some() {
            self.repair_contexts.set(self.repair_contexts.get() + 1);
        }
        if let Some(outcome) = self.cached.borrow().get(&request.invocation_id) {
            return outcome.clone();
        }
        self.side_effects.borrow_mut().insert(request.invocation_id);

        let usage = LifecycleUsage { worker_turns: 1, output_tokens: 1, cost_microusd: 1 };
        let cleanup = match self.mode {
            FakeAdapterMode::CleanupFailure => LifecycleAdapterCleanup {
                succeeded: false,
                failure: Some(LifecycleAdapterFailure {
                    code: "cleanup_failed".to_owned(),
                    detail: "the fake adapter could not clean up".to_owned(),
                }),
            },
            _ => LifecycleAdapterCleanup::succeeded(),
        };
        let result = match self.mode {
            FakeAdapterMode::Failure => LifecycleAdapterResult::Failed {
                failure: LifecycleAdapterFailure {
                    code: "adapter_failed".to_owned(),
                    detail: "the fake adapter failed".to_owned(),
                },
            },
            FakeAdapterMode::OversizedFailure => LifecycleAdapterResult::Failed {
                failure: LifecycleAdapterFailure {
                    code: "adapter_failed".to_owned(),
                    detail: "x".repeat(MAX_LIFECYCLE_ADAPTER_DETAIL_BYTES + 1),
                },
            },
            FakeAdapterMode::WrongPhase => LifecycleAdapterResult::Completed {
                transition: Box::new(LifecycleTransition::CompleteImplement {
                    worker: worker(request, usage.clone(), 1, false),
                    patch: LifecyclePatchRef {
                        patch_id: PatchId(Digest::blake3(b"wrong-phase-patch")),
                        revision: 1,
                    },
                }),
            },
            mode => {
                let verify_status = match mode {
                    FakeAdapterMode::RepairOnce
                        if request.phase == LifecyclePhase::Verify
                            && !request.lifecycle.repair_consumed =>
                    {
                        VerificationStatus::Repairable
                    }
                    FakeAdapterMode::RejectVerification
                        if request.phase == LifecyclePhase::Verify =>
                    {
                        VerificationStatus::Rejected
                    }
                    _ => VerificationStatus::Verified,
                };
                LifecycleAdapterResult::Completed {
                    transition: Box::new(completion_transition(
                        request,
                        usage.clone(),
                        if matches!(mode, FakeAdapterMode::BadWorkerDepth) { 2 } else { 1 },
                        matches!(mode, FakeAdapterMode::WrongProfile),
                        verify_status,
                    )),
                }
            }
        };
        let outcome = LifecyclePhaseAdapterOutcome {
            schema: LIFECYCLE_ADAPTER_OUTCOME_SCHEMA.to_owned(),
            invocation_id: request.invocation_id,
            expected_state_digest: request.expected_state_digest,
            phase: request.phase,
            usage,
            result,
            cleanup,
        };
        self.cached.borrow_mut().insert(request.invocation_id, outcome.clone());
        outcome
    }
}

fn worker(
    request: &LifecyclePhaseAdapterRequest,
    usage: LifecycleUsage,
    worker_depth: u8,
    wrong_profile: bool,
) -> LifecycleWorkerCompletion {
    LifecycleWorkerCompletion {
        profile: if wrong_profile {
            profile("kernel.wrong-profile")
        } else {
            request.profile.clone()
        },
        worker_depth,
        logical_worker_spawns: 1,
        usage,
    }
}

fn completion_transition(
    request: &LifecyclePhaseAdapterRequest,
    usage: LifecycleUsage,
    worker_depth: u8,
    wrong_profile: bool,
    verify_status: VerificationStatus,
) -> LifecycleTransition {
    let worker = worker(request, usage, worker_depth, wrong_profile);
    match request.phase {
        LifecyclePhase::Explore => LifecycleTransition::CompleteExplore {
            worker,
            artifacts: vec![LifecycleArtifactRef {
                kind: LifecycleArtifactKind::Exploration,
                id: Digest::blake3(b"kernel-exploration"),
                source_snapshot: request.lifecycle.source_snapshot,
            }],
        },
        LifecyclePhase::Implement => LifecycleTransition::CompleteImplement {
            worker,
            patch: LifecyclePatchRef {
                patch_id: PatchId(Digest::blake3(if request.lifecycle.repair_consumed {
                    b"kernel-patch-2"
                } else {
                    b"kernel-patch-1"
                })),
                revision: if request.lifecycle.repair_consumed { 2 } else { 1 },
            },
        },
        LifecyclePhase::Test => {
            let binding = &request.lifecycle.spec.test_plans[0];
            LifecycleTransition::CompleteTest {
                worker,
                results: vec![LifecycleTestResult {
                    plan_digest: binding.plan_digest(),
                    certificate_digest: binding.certificate_digest,
                    available: true,
                    executed: true,
                    passed: true,
                    evidence_id: Some("fake:test-evidence".to_owned()),
                    action_evidence_artifact: None,
                    failure_code: None,
                }],
            }
        }
        LifecyclePhase::Review => {
            let patch_id = request.lifecycle.patch.as_ref().unwrap().patch_id;
            let review = ReviewArtifact::new(
                request.lifecycle.change_id.clone(),
                patch_id,
                LifecycleReviewVerdict::Approved,
                vec![LifecycleAcceptanceReview::new(
                    request.change.request.acceptance_criteria[0].as_bytes(),
                    AcceptanceStatus::Addressed,
                    b"fake review evidence",
                )],
                Vec::new(),
                request.profile.definition_digest,
                request.lifecycle.updated_unix_ms,
            )
            .unwrap();
            LifecycleTransition::CompleteReview { worker, review, report_artifact: None }
        }
        LifecyclePhase::Verify => {
            let verification =
                verification_artifact(&request.lifecycle, &request.change.request, verify_status);
            LifecycleTransition::CompleteVerify {
                worker,
                verification: LifecycleVerificationRef {
                    verification_id: verification.id,
                    patch_id: verification.patch_id,
                    verdict: verification.verdict,
                },
            }
        }
        LifecyclePhase::Apply => unreachable!("the kernel never invokes an apply adapter"),
    }
}

fn verification_artifact(
    lifecycle: &DevelopmentLifecycle,
    request: &ChangeRequest,
    verdict: VerificationStatus,
) -> VerificationArtifact {
    let action_change_id = ChangeId::from_digest(request.digest(lifecycle.source_snapshot));
    let patch_id = lifecycle.patch.as_ref().unwrap().patch_id;
    let acceptance_coverage = vec![AcceptanceCoverage {
        criterion: request.acceptance_criteria[0].clone(),
        status: AcceptanceStatus::Addressed,
        evidence: "fake verification evidence".to_owned(),
    }];
    let findings = if verdict == VerificationStatus::Repairable {
        vec!["one bounded repair is required".to_owned()]
    } else {
        Vec::new()
    };
    let test_evidence_ids = Vec::new();
    let verifier_definition = lifecycle.spec.profiles.verify.definition_digest;
    let id = VerificationArtifact::compute_id(
        &action_change_id,
        patch_id,
        verdict,
        &acceptance_coverage,
        &findings,
        &test_evidence_ids,
        verifier_definition,
    );
    let artifact = VerificationArtifact {
        id,
        change_id: action_change_id,
        patch_id,
        action_request: None,
        requirements_digest: None,
        input_test_evidence_artifacts: Vec::new(),
        verdict,
        acceptance_coverage,
        findings,
        test_evidence_ids,
        test_plan_results: Vec::new(),
        test_plans_over_cap: false,
        verifier_definition,
        created_unix_ms: lifecycle.updated_unix_ms,
    };
    assert!(artifact.is_canonical());
    artifact
}

fn adapters(adapter: &FakeAdapter) -> LifecyclePhaseAdapters<'_> {
    LifecyclePhaseAdapters {
        explore: adapter,
        implement: adapter,
        test: adapter,
        review: adapter,
        verify: adapter,
    }
}

fn step(
    store: &FakeStore,
    adapter: &FakeAdapter,
    cancellation: &dyn LifecycleCancellation,
    change_id: &ChangeId,
) -> Result<LifecycleExecutionOutcome, LifecycleExecutionError> {
    execute_step(
        store,
        &adapters(adapter),
        cancellation,
        &NOOP_LIFECYCLE_EXPLORE_ACTION_RESOLVER,
        change_id,
    )
}

fn explore_action_plan(change: &LifecycleChangeContext) -> LifecycleExploreActionPlan {
    let subject = Subject::exact(change.repository_id, SubjectKind::CliOption, "--kernel");
    let required = vec![Obligation::new(
        PredicateKind::ImplementationLocation,
        subject.id,
        vec![Facet { key: "selection".to_owned(), value: "primary".to_owned() }],
    )];
    let request = NeedRequest {
        key: needle_core::NeedKey::new("locate.implementation").unwrap(),
        body: "Locate the lifecycle kernel implementation.".to_owned(),
    };
    let need = Need {
        id: NeedId::new(Digest::blake3(b"kernel-explore-need")),
        subjects: vec![subject],
        required,
        preferred: Vec::new(),
        semantic_constraints: Vec::new(),
        world: SemanticWorld {
            repository_lineage: change.repository_id,
            source_selector: "worktree".to_owned(),
            platform: "windows".to_owned(),
            features: "default".to_owned(),
            configuration: None,
            toolchain: None,
        },
        input_artifacts: Vec::new(),
        residual: None,
        body_digest: Digest::blake3(request.body.as_bytes()),
        format_revision: needle_core::NEED_IR_FORMAT_REVISION,
    };
    let fragment = need_fragment(&need, need.required.clone(), Vec::new());
    compile_lifecycle_explore_action_plan(
        &request,
        &need,
        &fragment,
        change.repository_id,
        change.source_snapshot,
    )
    .unwrap()
}

struct RecordingExploreResolver {
    calls: Cell<u32>,
    empty_resolved: bool,
}

struct ExactExploreResolver {
    summary: crate::ShadowActionResolutionSummary,
    calls: Cell<u32>,
}

impl LifecycleExploreActionResolver for ExactExploreResolver {
    fn resolve(
        &self,
        _plan: &LifecycleExploreActionPlan,
        _change: &LifecycleChangeContext,
    ) -> LifecycleExploreActionResolverOutcome {
        self.calls.set(self.calls.get() + 1);
        LifecycleExploreActionResolverOutcome::Resolved(vec![self.summary.clone()])
    }
}

fn exact_action_summary(plan: &LifecycleExploreActionPlan) -> crate::ShadowActionResolutionSummary {
    let request = &plan.actions[0];
    let action = crate::built_in_action_contracts()
        .iter()
        .find(|definition| definition.contract.id == request.contract)
        .unwrap();
    let descriptor = ReuseDescriptor::new(ReuseDescriptorInput {
        artifact: ArtifactId::new(Digest::blake3(b"reuse-artifact")),
        exact_request: request.semantic_id(),
        action_contract: action.contract.id.clone(),
        action_semantic_definition_digest: action.contract.semantic_definition_digest,
        action_validation_definition_digest: action.contract.validation_definition_digest,
        output_contract_definition_digest: action.output_contract_definition_digest,
        validator_definition_digest: action.validator_definition_digest,
        validation_certificate: ArtifactValidationCertificateId::new(Digest::blake3(
            b"reuse-certificate",
        )),
        coverage: CoverageManifest {
            entries: plan
                .fragment
                .obligations
                .iter()
                .cloned()
                .map(|obligation| CoverageEntry {
                    obligation,
                    evidence: vec!["src/lib.rs:item".to_owned()],
                })
                .collect(),
            world: plan.fragment.world.clone(),
            dependency_manifest_digest: Digest::blake3(b"reuse-manifest"),
        },
    })
    .unwrap();
    crate::ShadowActionResolutionSummary::new(crate::ShadowActionResolutionInput {
        request,
        action,
        resolution: crate::ShadowActionResolutionKind::Exact,
        descriptors: &[descriptor],
        selected_plan: SelectedPlanId::new(Digest::blake3(b"reuse-plan")),
        sufficiency_certificate: Some(ReuseSufficiencyCertificateId::new(Digest::blake3(
            b"reuse-sufficiency",
        ))),
        covered_mask: 1,
        missing_mask: 0,
    })
    .unwrap()
}

impl LifecycleExploreActionResolver for RecordingExploreResolver {
    fn resolve(
        &self,
        _plan: &LifecycleExploreActionPlan,
        _change: &LifecycleChangeContext,
    ) -> LifecycleExploreActionResolverOutcome {
        self.calls.set(self.calls.get() + 1);
        if self.empty_resolved {
            LifecycleExploreActionResolverOutcome::Resolved(Vec::new())
        } else {
            LifecycleExploreActionResolverOutcome::Miss
        }
    }
}

struct PreflightAwareAdapter<'a> {
    inner: &'a FakeAdapter,
    resolver_calls: &'a Cell<u32>,
    observations: &'a RefCell<Vec<LifecycleExploreShadowObservation>>,
}

impl LifecyclePhaseAdapter for PreflightAwareAdapter<'_> {
    fn invoke(&self, request: &LifecyclePhaseAdapterRequest) -> LifecyclePhaseAdapterOutcome {
        assert_eq!(self.resolver_calls.get(), 1, "Explore preflight must precede the adapter");
        assert_eq!(self.observations.borrow().len(), 1, "Shadow persistence must precede adapter");
        self.inner.invoke(request)
    }
}

struct CancelOnCheck {
    cancel_on: u32,
    checks: Cell<u32>,
}

impl LifecycleCancellation for CancelOnCheck {
    fn is_cancelled(&self, _change_id: &ChangeId, _expected_state_digest: Digest) -> bool {
        let check = self.checks.get() + 1;
        self.checks.set(check);
        check == self.cancel_on
    }
}

#[test]
fn success_invokes_one_adapter_per_phase_and_stops_at_approval() {
    let (store, change_id) = FakeStore::new(10);
    let adapter = FakeAdapter::new(FakeAdapterMode::Success);
    let mut last = None;

    for _ in 0..5 {
        last = Some(step(&store, &adapter, &NeverCancel, &change_id).unwrap());
    }

    let last = last.unwrap();
    assert_eq!(last.disposition, LifecycleExecutionDisposition::AwaitingApproval);
    assert_eq!(last.projection.lifecycle.phase, LifecyclePhase::Apply);
    assert_eq!(last.projection.lifecycle.status, LifecycleStatus::AwaitingApproval);
    assert_eq!(last.projection.lifecycle.usage.worker_turns, 5);
    assert_eq!(adapter.calls.get(), 5);
    assert_eq!(adapter.side_effects.borrow().len(), 5);
    assert_eq!(
        adapter.phases.borrow().as_slice(),
        &[
            LifecyclePhase::Explore,
            LifecyclePhase::Implement,
            LifecyclePhase::Test,
            LifecyclePhase::Review,
            LifecyclePhase::Verify,
        ]
    );

    let stopped = step(&store, &adapter, &NeverCancel, &change_id).unwrap();
    assert_eq!(stopped.disposition, LifecycleExecutionDisposition::AwaitingApproval);
    assert_eq!(adapter.calls.get(), 5);
}

#[test]
fn explore_shadow_preflight_runs_before_adapter_without_bypassing_it() {
    let (store, change_id) = FakeStore::new(10);
    let plan = explore_action_plan(&store.context);
    store.install_explore_action_plan(plan.clone());
    let adapter = FakeAdapter::new(FakeAdapterMode::Success);
    let resolver = RecordingExploreResolver { calls: Cell::new(0), empty_resolved: false };
    let guarded_adapter = PreflightAwareAdapter {
        inner: &adapter,
        resolver_calls: &resolver.calls,
        observations: &store.explore_action_observations,
    };
    let phase_adapters = LifecyclePhaseAdapters {
        explore: &guarded_adapter,
        implement: &guarded_adapter,
        test: &guarded_adapter,
        review: &guarded_adapter,
        verify: &guarded_adapter,
    };

    let outcome =
        execute_step(&store, &phase_adapters, &NeverCancel, &resolver, &change_id).unwrap();

    assert_eq!(resolver.calls.get(), 1);
    assert_eq!(adapter.calls.get(), 1);
    assert_eq!(outcome.disposition, LifecycleExecutionDisposition::Advanced);
    assert_eq!(outcome.projection.lifecycle.phase, LifecyclePhase::Implement);
    assert_eq!(
        outcome.explore_action_observation_persistence,
        Some(LifecycleExploreShadowObservationPersistence::Stored)
    );
    let observation = outcome.explore_action_observation.as_ref().unwrap();
    assert_eq!(observation.resolution, LifecycleExploreShadowResolutionKind::Miss);
    assert_eq!(observation.authority, ShadowActionResolutionAuthority::Shadow);
    assert!(observation.adapter_invocation_required);
    observation
        .validate_for_execution(
            observation.lifecycle,
            Digest::blake3(b"wrong-expected-state"),
            &plan,
        )
        .unwrap_err();
    observation
        .validate_for_execution(observation.lifecycle, observation.expected_state_digest, &plan)
        .unwrap();
}

#[test]
fn exact_resolution_without_authority_falls_back_to_fresh_adapter() {
    let (store, change_id) = FakeStore::new(10);
    let plan = explore_action_plan(&store.context);
    let summary = exact_action_summary(&plan);
    store.install_explore_action_plan(plan);
    let adapter = FakeAdapter::new(FakeAdapterMode::Success);
    let resolver = ExactExploreResolver { summary, calls: Cell::new(0) };

    let outcome =
        execute_step(&store, &adapters(&adapter), &NeverCancel, &resolver, &change_id).unwrap();

    assert_eq!(resolver.calls.get(), 1);
    assert_eq!(store.explore_reuse_attempts.get(), 1);
    assert_eq!(adapter.calls.get(), 1);
    assert!(outcome.explore_reuse.is_none());
    assert_eq!(outcome.projection.lifecycle.usage.worker_turns, 1);
    assert!(outcome.projection.lifecycle.explore_reuse.is_none());
}

#[test]
fn resolver_only_authority_is_visible_but_still_invokes_fresh_adapter() {
    let (store, change_id) = FakeStore::new(10);
    let plan = explore_action_plan(&store.context);
    let summary = exact_action_summary(&plan);
    store.install_explore_action_plan(plan);
    store.authorize_explore_reuse(false);
    let adapter = FakeAdapter::new(FakeAdapterMode::Success);
    let resolver = ExactExploreResolver { summary, calls: Cell::new(0) };

    let outcome =
        execute_step(&store, &adapters(&adapter), &NeverCancel, &resolver, &change_id).unwrap();

    assert_eq!(adapter.calls.get(), 1);
    assert!(matches!(
        outcome.explore_reuse,
        Some(LifecycleExploreReuseOutcome::ResolverAuthorized { .. })
    ));
    assert_eq!(outcome.projection.lifecycle.usage.worker_turns, 1);
    assert!(outcome.projection.lifecycle.explore_reuse.is_none());
}

#[test]
fn lifecycle_authority_commits_exact_reuse_without_adapter_or_worker_accounting() {
    let (store, change_id) = FakeStore::new(10);
    let plan = explore_action_plan(&store.context);
    let summary = exact_action_summary(&plan);
    store.install_explore_action_plan(plan);
    store.authorize_explore_reuse(true);
    let adapter = FakeAdapter::new(FakeAdapterMode::Success);
    let resolver = ExactExploreResolver { summary: summary.clone(), calls: Cell::new(0) };

    let outcome =
        execute_step(&store, &adapters(&adapter), &NeverCancel, &resolver, &change_id).unwrap();

    assert_eq!(adapter.calls.get(), 0);
    assert!(adapter.side_effects.borrow().is_empty());
    assert_eq!(outcome.disposition, LifecycleExecutionDisposition::Advanced);
    assert_eq!(outcome.projection.lifecycle.phase, LifecyclePhase::Implement);
    assert_eq!(outcome.projection.lifecycle.usage, LifecycleUsage::default());
    assert!(outcome.invocation_id.is_none());
    assert!(outcome.cleanup.is_none());
    assert!(matches!(
        outcome.explore_reuse,
        Some(LifecycleExploreReuseOutcome::Consumed { ref completion })
            if completion.resolution_definition_digest == summary.definition_digest
    ));
    let persisted = outcome.projection.lifecycle.explore_reuse.as_ref().unwrap();
    assert_eq!(persisted.resolution_definition_digest, summary.definition_digest);
    assert_eq!(persisted.artifact, summary.artifacts[0]);
    let encoded = serde_json::to_vec(&outcome).unwrap();
    assert_eq!(serde_json::from_slice::<LifecycleExecutionOutcome>(&encoded).unwrap(), outcome);
}

#[test]
fn invalid_shadow_resolution_is_diagnostic_and_adapter_still_advances() {
    let (store, change_id) = FakeStore::new(10);
    store.install_explore_action_plan(explore_action_plan(&store.context));
    let adapter = FakeAdapter::new(FakeAdapterMode::Success);
    let resolver = RecordingExploreResolver { calls: Cell::new(0), empty_resolved: true };

    let outcome =
        execute_step(&store, &adapters(&adapter), &NeverCancel, &resolver, &change_id).unwrap();

    assert_eq!(resolver.calls.get(), 1);
    assert_eq!(adapter.calls.get(), 1);
    assert_eq!(outcome.disposition, LifecycleExecutionDisposition::Advanced);
    assert_eq!(
        outcome.explore_action_observation.as_ref().unwrap().resolution,
        LifecycleExploreShadowResolutionKind::Invalid
    );
    assert_eq!(
        outcome.explore_action_observation_persistence,
        Some(LifecycleExploreShadowObservationPersistence::Stored)
    );
}

#[test]
fn shadow_persistence_failure_is_reported_without_blocking_adapter() {
    let (store, change_id) = FakeStore::new(10);
    store.install_explore_action_plan(explore_action_plan(&store.context));
    store.fail_explore_action_observation.set(true);
    let adapter = FakeAdapter::new(FakeAdapterMode::Success);
    let resolver = RecordingExploreResolver { calls: Cell::new(0), empty_resolved: false };

    let outcome =
        execute_step(&store, &adapters(&adapter), &NeverCancel, &resolver, &change_id).unwrap();

    assert_eq!(resolver.calls.get(), 1);
    assert_eq!(adapter.calls.get(), 1);
    assert_eq!(outcome.disposition, LifecycleExecutionDisposition::Advanced);
    assert!(outcome.explore_action_observation.is_some());
    assert_eq!(
        outcome.explore_action_observation_persistence,
        Some(LifecycleExploreShadowObservationPersistence::Failed)
    );
    assert!(store.explore_action_observations.borrow().is_empty());
}

#[test]
fn lifecycle_without_typed_plan_does_not_call_shadow_resolver() {
    let (store, change_id) = FakeStore::new(10);
    let adapter = FakeAdapter::new(FakeAdapterMode::Success);
    let resolver = RecordingExploreResolver { calls: Cell::new(0), empty_resolved: false };

    let outcome =
        execute_step(&store, &adapters(&adapter), &NeverCancel, &resolver, &change_id).unwrap();

    assert_eq!(resolver.calls.get(), 0);
    assert_eq!(adapter.calls.get(), 1);
    assert!(outcome.explore_action_observation.is_none());
    assert!(outcome.explore_action_observation_persistence.is_none());

    let outcome_json = serde_json::to_value(&outcome).unwrap();
    assert!(outcome_json.get("explore_action_observation").is_none());
    assert_eq!(serde_json::from_value::<LifecycleExecutionOutcome>(outcome_json).unwrap(), outcome);

    let spec = lifecycle_spec(10);
    let spec_json = serde_json::to_value(&spec).unwrap();
    assert!(spec_json.get("explore_action_plan").is_none());
    assert_eq!(serde_json::from_value::<LifecycleSpec>(spec_json).unwrap(), spec);
}

#[test]
fn repair_is_consumed_transactionally_once_then_resumes_implement() {
    let (store, change_id) = FakeStore::new(12);
    let adapter = FakeAdapter::new(FakeAdapterMode::RepairOnce);
    for _ in 0..5 {
        step(&store, &adapter, &NeverCancel, &change_id).unwrap();
    }
    assert_eq!(store.projection.borrow().lifecycle.status, LifecycleStatus::RepairReserved);

    let resumed = step(&store, &adapter, &NeverCancel, &change_id).unwrap();
    assert_eq!(resumed.disposition, LifecycleExecutionDisposition::RepairResumed);
    assert_eq!(resumed.projection.lifecycle.phase, LifecyclePhase::Implement);
    assert!(resumed.projection.lifecycle.repair_consumed);
    assert_eq!(store.repair_calls.get(), 1);
    assert_eq!(adapter.calls.get(), 5);

    for _ in 0..4 {
        step(&store, &adapter, &NeverCancel, &change_id).unwrap();
    }
    let finished = store.projection.borrow().clone();
    assert_eq!(finished.lifecycle.status, LifecycleStatus::AwaitingApproval);
    assert_eq!(finished.lifecycle.patch.as_ref().unwrap().revision, 2);
    assert_eq!(finished.lifecycle.usage.worker_turns, 9);
    assert_eq!(store.repair_calls.get(), 1);
    assert_eq!(adapter.calls.get(), 9);
    assert_eq!(adapter.repair_contexts.get(), 4);
}

#[test]
fn cancellation_wins_before_a_reserved_repair_is_consumed() {
    let (store, change_id) = FakeStore::new(12);
    let adapter = FakeAdapter::new(FakeAdapterMode::RepairOnce);
    for _ in 0..5 {
        step(&store, &adapter, &NeverCancel, &change_id).unwrap();
    }
    assert_eq!(store.projection.borrow().lifecycle.status, LifecycleStatus::RepairReserved);
    let cancellation = CancelOnCheck { cancel_on: 1, checks: Cell::new(0) };

    let outcome = step(&store, &adapter, &cancellation, &change_id).unwrap();

    assert_eq!(outcome.disposition, LifecycleExecutionDisposition::Cancelled);
    assert_eq!(outcome.projection.lifecycle.status, LifecycleStatus::Cancelled);
    assert_eq!(store.repair_calls.get(), 0);
    assert_eq!(adapter.calls.get(), 5);
}

#[test]
fn rejection_is_a_typed_terminal_completion() {
    let (store, change_id) = FakeStore::new(10);
    let adapter = FakeAdapter::new(FakeAdapterMode::RejectVerification);
    let mut outcome = None;
    for _ in 0..5 {
        outcome = Some(step(&store, &adapter, &NeverCancel, &change_id).unwrap());
    }
    let outcome = outcome.unwrap();
    assert_eq!(outcome.disposition, LifecycleExecutionDisposition::Terminal);
    assert_eq!(outcome.projection.lifecycle.status, LifecycleStatus::Failed);
    assert_eq!(
        outcome.projection.lifecycle.terminal_reason.as_ref().unwrap().code,
        "verification_rejected"
    );
}

#[test]
fn phase_profile_mismatch_and_bad_depth_fail_closed_as_invalid_output() {
    for mode in [
        FakeAdapterMode::WrongPhase,
        FakeAdapterMode::WrongProfile,
        FakeAdapterMode::BadWorkerDepth,
    ] {
        let (store, change_id) = FakeStore::new(10);
        let adapter = FakeAdapter::new(mode);
        let outcome = step(&store, &adapter, &NeverCancel, &change_id).unwrap();
        assert_eq!(outcome.disposition, LifecycleExecutionDisposition::InvalidAdapterOutput);
        assert_eq!(outcome.projection.lifecycle.status, LifecycleStatus::Failed);
        assert_eq!(
            outcome.projection.lifecycle.terminal_reason.as_ref().unwrap().code,
            "adapter_invalid_output"
        );
    }
}

#[test]
fn cancellation_before_and_after_adapter_is_fail_closed() {
    let (before_store, before_id) = FakeStore::new(10);
    let before_adapter = FakeAdapter::new(FakeAdapterMode::Success);
    let before = CancelOnCheck { cancel_on: 1, checks: Cell::new(0) };
    let outcome = step(&before_store, &before_adapter, &before, &before_id).unwrap();
    assert_eq!(outcome.disposition, LifecycleExecutionDisposition::Cancelled);
    assert_eq!(outcome.projection.lifecycle.status, LifecycleStatus::Cancelled);
    assert_eq!(before_adapter.calls.get(), 0);

    let (after_store, after_id) = FakeStore::new(10);
    let after_adapter = FakeAdapter::new(FakeAdapterMode::Success);
    let after = CancelOnCheck { cancel_on: 2, checks: Cell::new(0) };
    let outcome = step(&after_store, &after_adapter, &after, &after_id).unwrap();
    assert_eq!(outcome.disposition, LifecycleExecutionDisposition::Cancelled);
    assert_eq!(outcome.projection.lifecycle.status, LifecycleStatus::Cancelled);
    assert_eq!(outcome.adapter_usage.worker_turns, 1);
    assert_eq!(after_adapter.calls.get(), 1);
}

#[test]
fn exhausted_aggregate_budget_stops_before_another_adapter() {
    let (store, change_id) = FakeStore::new(1);
    let adapter = FakeAdapter::new(FakeAdapterMode::Success);
    step(&store, &adapter, &NeverCancel, &change_id).unwrap();

    let outcome = step(&store, &adapter, &NeverCancel, &change_id).unwrap();
    assert_eq!(outcome.disposition, LifecycleExecutionDisposition::BudgetExhausted);
    assert_eq!(outcome.projection.lifecycle.status, LifecycleStatus::Failed);
    assert_eq!(
        outcome.projection.lifecycle.terminal_reason.as_ref().unwrap().code,
        "budget_exhausted"
    );
    assert_eq!(adapter.calls.get(), 1);
}

#[test]
fn adapter_and_cleanup_failures_are_distinct_terminal_outcomes() {
    let (failed_store, failed_id) = FakeStore::new(10);
    let failed_adapter = FakeAdapter::new(FakeAdapterMode::Failure);
    let failed = step(&failed_store, &failed_adapter, &NeverCancel, &failed_id).unwrap();
    assert_eq!(failed.disposition, LifecycleExecutionDisposition::AdapterFailed);
    assert_eq!(
        failed.projection.lifecycle.terminal_reason.as_ref().unwrap().code,
        "adapter_failed"
    );

    let (cleanup_store, cleanup_id) = FakeStore::new(10);
    let cleanup_adapter = FakeAdapter::new(FakeAdapterMode::CleanupFailure);
    let cleanup = step(&cleanup_store, &cleanup_adapter, &NeverCancel, &cleanup_id).unwrap();
    assert_eq!(cleanup.disposition, LifecycleExecutionDisposition::CleanupFailed);
    assert_eq!(
        cleanup.projection.lifecycle.terminal_reason.as_ref().unwrap().code,
        "adapter_cleanup_failed"
    );
    assert!(!cleanup.cleanup.unwrap().succeeded);
}

#[test]
fn oversized_adapter_failure_is_bounded_and_rejected() {
    let (store, change_id) = FakeStore::new(10);
    let adapter = FakeAdapter::new(FakeAdapterMode::OversizedFailure);
    let outcome = step(&store, &adapter, &NeverCancel, &change_id).unwrap();
    assert_eq!(outcome.disposition, LifecycleExecutionDisposition::InvalidAdapterOutput);
    assert_eq!(
        outcome.projection.lifecycle.terminal_reason.as_ref().unwrap().code,
        "adapter_invalid_output"
    );
}

#[test]
fn stale_cas_does_not_overwrite_a_concurrent_parent_transition() {
    let (store, change_id) = FakeStore::new(10);
    let adapter = FakeAdapter::new(FakeAdapterMode::Success);
    store.concurrent_transition.replace(Some(LifecycleTransition::Cancel {
        reason: LifecycleReason::new("concurrent_cancel", b"concurrent parent won").unwrap(),
    }));

    let outcome = step(&store, &adapter, &NeverCancel, &change_id).unwrap();
    assert_eq!(outcome.disposition, LifecycleExecutionDisposition::StaleState);
    assert_eq!(outcome.projection.lifecycle.status, LifecycleStatus::Cancelled);
    assert!(outcome.projection.lifecycle.exploration_artifacts.is_empty());
}

#[test]
fn retry_reuses_invocation_identity_without_repeating_adapter_side_effect() {
    let (store, change_id) = FakeStore::new(10);
    let adapter = FakeAdapter::new(FakeAdapterMode::Success);
    let initial_digest = store.projection.borrow().state_digest;
    store.fail_next_parent_commit.set(true);

    let first = step(&store, &adapter, &NeverCancel, &change_id);
    assert!(matches!(first, Err(LifecycleExecutionError::Store(StoreError::ConnectionLock))));
    assert_eq!(store.projection.borrow().state_digest, initial_digest);

    let second = step(&store, &adapter, &NeverCancel, &change_id).unwrap();
    assert_eq!(second.disposition, LifecycleExecutionDisposition::Advanced);
    assert_eq!(second.projection.lifecycle.phase, LifecyclePhase::Implement);
    assert_eq!(adapter.calls.get(), 2);
    assert_eq!(adapter.side_effects.borrow().len(), 1);
    assert_eq!(
        adapter.phases.borrow().as_slice(),
        &[LifecyclePhase::Explore, LifecyclePhase::Explore]
    );
}

#[test]
fn replay_corruption_is_rejected_before_adapter_invocation() {
    let (store, change_id) = FakeStore::new(10);
    let adapter = FakeAdapter::new(FakeAdapterMode::Success);
    store.corrupt_replay.set(true);

    let outcome = step(&store, &adapter, &NeverCancel, &change_id);
    assert!(matches!(
        outcome,
        Err(LifecycleExecutionError::Store(StoreError::LifecycleCorruption(_)))
    ));
    assert_eq!(adapter.calls.get(), 0);
}
