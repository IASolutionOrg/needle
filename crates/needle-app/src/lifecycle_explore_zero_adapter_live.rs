use super::{AppError, canonical_child_path, repository_status_clean};
use crate::lifecycle_explore_authority::{
    AUTHORITY_PREFLIGHT_FILE, DATABASE_FILE, LIVE_REPORT_FILE, LifecycleExploreAuthorityPreflight,
    MAX_AUTHORITY_PREFLIGHT_BYTES,
};
use crate::lifecycle_explore_authority_acceptance::{
    ACCEPTANCE_FILE, LifecycleExploreAuthorityAcceptance, MAX_ACCEPTANCE_BYTES,
};
use crate::lifecycle_explore_lifecycle_authority::{
    LIFECYCLE_AUTHORITY_PREFLIGHT_FILE, LifecycleExploreLifecycleAuthorityPreflight,
    MAX_LIFECYCLE_AUTHORITY_PREFLIGHT_BYTES,
};
use crate::lifecycle_explore_lifecycle_authority_acceptance::{
    LIFECYCLE_AUTHORITY_ACCEPTANCE_FILE, LifecycleExploreLifecycleAuthorityAcceptance,
    MAX_LIFECYCLE_AUTHORITY_ACCEPTANCE_BYTES,
};
use crate::lifecycle_explore_live::{
    MAX_LIFECYCLE_EXPLORE_LIVE_REPORT_BYTES, decode_authority_source,
};
use needle_bench::read_bounded_file;
use needle_core::{
    ActionCapabilityDecisionId, CanonicalHasher, ChangeId, Digest, LifecycleEventKind,
    LifecycleExploreReuseCompletion, LifecyclePhase, LifecycleStatus, LifecycleTransition,
    LifecycleUsage,
};
use needle_runtime::{
    LIFECYCLE_ADAPTER_OUTCOME_SCHEMA, LifecycleAdapterCleanup, LifecycleAdapterFailure,
    LifecycleAdapterResult, LifecycleExecutionDisposition, LifecycleExecutionKernel,
    LifecycleExecutionOutcome, LifecycleExploreReuseOutcome,
    LifecycleExploreShadowObservationPersistence, LifecycleExploreShadowResolutionKind,
    LifecyclePhaseAdapter, LifecyclePhaseAdapterOutcome, LifecyclePhaseAdapterRequest,
    LifecyclePhaseAdapters, NeverCancel, ProviderBackedActionAssuranceInput, RuntimeStore,
    SemanticLifecycleExploreActionResolver, ShadowActionResolutionAuthority, capture_git_snapshot,
    implementation_location_exact_capability,
};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

const REPORT_FORMAT_REVISION: u16 = 1;
const REPORT_SCHEMA: &str = "needle.lifecycle-explore-zero-adapter-live-report/1";
const REPORT_FILE: &str = "lifecycle-explore-zero-adapter-live-report.json";
const MAX_REPORT_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleExploreZeroAdapterLiveReport {
    format_revision: u16,
    schema: String,
    source_report_digest: Digest,
    lifecycle_authority_acceptance_digest: Digest,
    authority_decision: ActionCapabilityDecisionId,
    repository_id: Digest,
    source_snapshot: Digest,
    source_lifecycle: needle_core::LifecycleId,
    target_change: ChangeId,
    target_lifecycle: needle_core::LifecycleId,
    action_plan_definition_digest: Digest,
    lifecycle_created: bool,
    outcome: LifecycleExecutionOutcome,
    worker_run_count_before: u64,
    worker_run_count_after: u64,
    adapter_calls: u32,
    adapter_invocation_recorded: bool,
    transition_persisted: bool,
    source_unchanged: bool,
    checkout_clean: bool,
    provider_call_performed: bool,
    passed: bool,
    failures: Vec<String>,
    report_digest: Digest,
}

impl LifecycleExploreZeroAdapterLiveReport {
    fn new(input: ReportInput) -> Result<Self, AppError> {
        let mut value = Self {
            format_revision: REPORT_FORMAT_REVISION,
            schema: REPORT_SCHEMA.to_owned(),
            source_report_digest: input.source_report_digest,
            lifecycle_authority_acceptance_digest: input.lifecycle_authority_acceptance_digest,
            authority_decision: input.authority_decision,
            repository_id: input.repository_id,
            source_snapshot: input.source_snapshot,
            source_lifecycle: input.source_lifecycle,
            target_change: input.target_change,
            target_lifecycle: input.target_lifecycle,
            action_plan_definition_digest: input.action_plan_definition_digest,
            lifecycle_created: input.lifecycle_created,
            outcome: input.outcome,
            worker_run_count_before: input.worker_run_count_before,
            worker_run_count_after: input.worker_run_count_after,
            adapter_calls: input.adapter_calls,
            adapter_invocation_recorded: input.adapter_invocation_recorded,
            transition_persisted: input.transition_persisted,
            source_unchanged: input.source_unchanged,
            checkout_clean: input.checkout_clean,
            provider_call_performed: false,
            passed: true,
            failures: Vec::new(),
            report_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.report_digest = value.compute_digest();
        Ok(value)
    }

    fn decode_json(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() > MAX_REPORT_BYTES {
            return Err(AppError::Experiment(format!(
                "zero-adapter report has {} bytes; maximum is {}",
                bytes.len(),
                MAX_REPORT_BYTES
            )));
        }
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), AppError> {
        self.validate_shape()?;
        if self.report_digest != self.compute_digest() {
            return Err(AppError::Experiment("zero-adapter report digest is inconsistent".into()));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), AppError> {
        self.outcome
            .projection
            .lifecycle
            .validate()
            .map_err(|error| AppError::Experiment(error.to_string()))?;
        let observation = self.outcome.explore_action_observation.as_ref().ok_or_else(|| {
            AppError::Experiment("zero-adapter outcome has no action observation".into())
        })?;
        observation.validate().map_err(|error| AppError::Experiment(error.to_string()))?;
        let completion = consumed_completion(&self.outcome)?;
        completion.validate().map_err(|error| AppError::Experiment(error.to_string()))?;
        let lifecycle = &self.outcome.projection.lifecycle;
        if self.format_revision != REPORT_FORMAT_REVISION
            || self.schema != REPORT_SCHEMA
            || self.source_report_digest == Digest([0; 32])
            || self.lifecycle_authority_acceptance_digest == Digest([0; 32])
            || self.repository_id == Digest([0; 32])
            || self.source_snapshot == Digest([0; 32])
            || self.action_plan_definition_digest == Digest([0; 32])
            || !self.lifecycle_created
            || self.outcome.disposition != LifecycleExecutionDisposition::Advanced
            || self.outcome.invocation_id.is_some()
            || self.outcome.adapter_usage != LifecycleUsage::default()
            || self.outcome.cleanup.is_some()
            || self.outcome.explore_action_observation_persistence
                != Some(LifecycleExploreShadowObservationPersistence::Stored)
            || observation.lifecycle != self.target_lifecycle
            || observation.plan_definition_digest != self.action_plan_definition_digest
            || observation.resolution != LifecycleExploreShadowResolutionKind::Resolved
            || observation.actions.len() != 1
            || observation.authority != ShadowActionResolutionAuthority::Shadow
            || !observation.adapter_invocation_required
            || lifecycle.id != self.target_lifecycle
            || lifecycle.change_id != self.target_change
            || lifecycle.source_snapshot != self.source_snapshot
            || lifecycle.phase != LifecyclePhase::Implement
            || lifecycle.status != LifecycleStatus::Active
            || lifecycle.usage != LifecycleUsage::default()
            || lifecycle.exploration_artifacts.len() != 1
            || lifecycle.explore_reuse.as_ref() != Some(completion)
            || self.outcome.projection.state_digest != lifecycle.state_digest()
            || completion.authority.decision != self.authority_decision
            || completion.repository_id != self.repository_id
            || completion.source_snapshot != self.source_snapshot
            || completion.artifact.digest() != lifecycle.exploration_artifacts[0].id
            || self.worker_run_count_before != self.worker_run_count_after
            || self.adapter_calls != 0
            || self.adapter_invocation_recorded
            || !self.transition_persisted
            || !self.source_unchanged
            || !self.checkout_clean
            || self.provider_call_performed
            || !self.passed
            || !self.failures.is_empty()
        {
            return Err(AppError::Experiment("zero-adapter report shape is invalid".into()));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let completion = consumed_completion(&self.outcome)
            .expect("validated zero-adapter reports always contain a reuse completion");
        let observation = self
            .outcome
            .explore_action_observation
            .as_ref()
            .expect("validated zero-adapter reports always contain an observation");
        let mut hasher = CanonicalHasher::new(b"needle-lifecycle-explore-zero-adapter-live-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_digest(self.source_report_digest);
        hasher.field_digest(self.lifecycle_authority_acceptance_digest);
        hasher.field_digest(self.authority_decision.digest());
        hasher.field_digest(self.repository_id);
        hasher.field_digest(self.source_snapshot);
        hasher.field_digest(self.source_lifecycle.0);
        hasher.field_str(&self.target_change.to_string());
        hasher.field_digest(self.target_lifecycle.0);
        hasher.field_digest(self.action_plan_definition_digest);
        hasher.field_digest(self.outcome.projection.state_digest);
        hasher.field_digest(observation.definition_digest);
        hasher.field_digest(completion.action_request.digest());
        hasher.field_digest(completion.origin_request.digest());
        hasher.field_digest(completion.artifact.digest());
        hasher.field_digest(completion.validation_certificate.digest());
        hasher.field_digest(completion.selected_plan.digest());
        hasher.field_digest(completion.sufficiency_certificate.digest());
        hasher.field_bytes(&self.worker_run_count_before.to_le_bytes());
        hasher.field_bytes(&self.worker_run_count_after.to_le_bytes());
        hasher.field_u32(self.adapter_calls);
        for value in [
            self.lifecycle_created,
            self.adapter_invocation_recorded,
            self.transition_persisted,
            self.source_unchanged,
            self.checkout_clean,
            self.provider_call_performed,
            self.passed,
        ] {
            hasher.field_u8(u8::from(value));
        }
        hasher.finish()
    }
}

struct ReportInput {
    source_report_digest: Digest,
    lifecycle_authority_acceptance_digest: Digest,
    authority_decision: ActionCapabilityDecisionId,
    repository_id: Digest,
    source_snapshot: Digest,
    source_lifecycle: needle_core::LifecycleId,
    target_change: ChangeId,
    target_lifecycle: needle_core::LifecycleId,
    action_plan_definition_digest: Digest,
    lifecycle_created: bool,
    outcome: LifecycleExecutionOutcome,
    worker_run_count_before: u64,
    worker_run_count_after: u64,
    adapter_calls: u32,
    adapter_invocation_recorded: bool,
    transition_persisted: bool,
    source_unchanged: bool,
    checkout_clean: bool,
}

#[derive(Default)]
struct ForbiddenProviderAdapter {
    calls: AtomicU32,
}

impl ForbiddenProviderAdapter {
    fn calls(&self) -> u32 {
        self.calls.load(Ordering::Relaxed)
    }
}

impl LifecyclePhaseAdapter for ForbiddenProviderAdapter {
    fn invoke(&self, request: &LifecyclePhaseAdapterRequest) -> LifecyclePhaseAdapterOutcome {
        self.calls.fetch_add(1, Ordering::Relaxed);
        LifecyclePhaseAdapterOutcome {
            schema: LIFECYCLE_ADAPTER_OUTCOME_SCHEMA.to_owned(),
            invocation_id: request.invocation_id,
            expected_state_digest: request.expected_state_digest,
            phase: request.phase,
            usage: LifecycleUsage::default(),
            result: LifecycleAdapterResult::Failed {
                failure: LifecycleAdapterFailure {
                    code: "provider_forbidden".to_owned(),
                    detail: "provider-free Gate A5 runner reached the Fresh adapter boundary"
                        .to_owned(),
                },
            },
            cleanup: LifecycleAdapterCleanup::succeeded(),
        }
    }
}

pub(super) fn run(arguments: &[String]) -> Result<(), AppError> {
    let parsed = Arguments::parse(arguments)?;
    parsed.validate()?;
    let artifact_root =
        canonical_child_path(Path::new(parsed.artifact_root.as_deref().expect("validated")))?;
    let paths = EvidencePaths::new(&artifact_root);
    paths.validate()?;

    let source_report_bytes = read(&paths.live_report, MAX_LIFECYCLE_EXPLORE_LIVE_REPORT_BYTES)?;
    let source_report_digest = Digest::blake3(&source_report_bytes);
    let source = decode_authority_source(&source_report_bytes)?;
    let source_preflight = LifecycleExploreAuthorityPreflight::decode_json(&read(
        &paths.authority_preflight,
        MAX_AUTHORITY_PREFLIGHT_BYTES,
    )?)?;
    let source_acceptance = LifecycleExploreAuthorityAcceptance::decode_json(
        &read(&paths.authority_acceptance, MAX_ACCEPTANCE_BYTES)?,
        &source_preflight,
    )?;
    let lifecycle_preflight = LifecycleExploreLifecycleAuthorityPreflight::decode_json(&read(
        &paths.lifecycle_preflight,
        MAX_LIFECYCLE_AUTHORITY_PREFLIGHT_BYTES,
    )?)?;
    let lifecycle_acceptance = LifecycleExploreLifecycleAuthorityAcceptance::decode_json(
        &read(&paths.lifecycle_acceptance, MAX_LIFECYCLE_AUTHORITY_ACCEPTANCE_BYTES)?,
        &lifecycle_preflight,
    )?;
    verify_explicit_identity(&parsed, source_report_digest, &lifecycle_acceptance)?;

    let assurance_input = ProviderBackedActionAssuranceInput {
        repository: source.repository,
        source_snapshot: source.source_snapshot,
        lifecycle: source.lifecycle,
        adapter_invocation: source.adapter_invocation,
        artifact: source.artifact,
        execution_evidence_digest: source_report_digest,
    };
    let immutable_store = RuntimeStore::new(&paths.database);
    let assurance = immutable_store
        .preflight_provider_backed_action_assurance(assurance_input)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let capability = implementation_location_exact_capability();
    if !lifecycle_preflight.validate_acceptance_source(
        &source_preflight,
        &source_acceptance,
        &assurance,
        capability,
    )? {
        return Err(AppError::Experiment(
            "zero-adapter run requires the accepted lifecycle-authority head".into(),
        ));
    }
    let effective = assurance.effective_decision.as_ref().ok_or_else(|| {
        AppError::Experiment("zero-adapter run has no effective authority head".into())
    })?;
    if effective.decision.id != lifecycle_acceptance.decision
        || effective.recorded_unix_ms != lifecycle_acceptance.decision_recorded_unix_ms
    {
        return Err(AppError::Experiment(
            "zero-adapter authority receipt differs from the effective decision head".into(),
        ));
    }
    drop(immutable_store);

    let target_change =
        target_change_id(source_report_digest, lifecycle_acceptance.acceptance_digest);
    if paths.output.is_file() {
        let report = LifecycleExploreZeroAdapterLiveReport::decode_json(&read(
            &paths.output,
            MAX_REPORT_BYTES,
        )?)?;
        verify_existing_report(
            &report,
            ExistingReportBindings {
                source_report_digest,
                acceptance: &lifecycle_acceptance,
                repository_id: source.repository,
                source_snapshot: source.source_snapshot,
                source_lifecycle: source.lifecycle,
                target_change,
                database: &paths.database,
            },
        )?;
        print_report("verified at", &paths.output, &report);
        return Ok(());
    }

    let store = RuntimeStore::new(&paths.database);
    if store
        .lifecycle(&target_change)
        .map_err(|error| AppError::Experiment(error.to_string()))?
        .is_some()
    {
        return Err(AppError::Experiment(
            "zero-adapter target lifecycle exists without its canonical report".into(),
        ));
    }
    let source_projection = store
        .lifecycle(&source.change)
        .map_err(|error| AppError::Experiment(error.to_string()))?
        .ok_or_else(|| AppError::Experiment("assured source lifecycle is unavailable".into()))?;
    let source_context = store
        .lifecycle_change_context(&source.change)
        .map_err(|error| AppError::Experiment(error.to_string()))?
        .ok_or_else(|| AppError::Experiment("assured source request is unavailable".into()))?;
    if source_projection.lifecycle.id != source.lifecycle
        || source_projection.lifecycle.phase != LifecyclePhase::Implement
        || source_projection.lifecycle.status != LifecycleStatus::Active
        || source_context.repository_id != source.repository
        || source_context.source_snapshot != source.source_snapshot
    {
        return Err(AppError::Experiment(
            "assured source lifecycle differs from the retained Fresh evidence".into(),
        ));
    }
    let plan =
        source_projection.lifecycle.spec.explore_action_plan.as_ref().ok_or_else(|| {
            AppError::Experiment("assured source has no Explore action plan".into())
        })?;
    let repository_root = store
        .repository_root_for_need(&plan.fragment.root_need.to_string())
        .map_err(|error| AppError::Experiment(error.to_string()))?
        .ok_or_else(|| AppError::Experiment("assured Need has no repository root".into()))?;
    let repository_root = canonical_child_path(&repository_root)?;
    let (_, initial_snapshot) = capture_git_snapshot(&repository_root)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    if initial_snapshot.repository_id != source.repository
        || initial_snapshot.source_digest != source.source_snapshot
        || !repository_status_clean(&repository_root)?
    {
        return Err(AppError::Experiment(
            "retained source repository is no longer the exact clean snapshot".into(),
        ));
    }

    let worker_run_count_before =
        store.worker_run_count().map_err(|error| AppError::Experiment(error.to_string()))?;
    let creation = store
        .create_lifecycle_with_request(
            &target_change,
            source.repository,
            source.source_snapshot,
            &source_context.request,
            source_projection.lifecycle.spec.clone(),
        )
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    if !creation.created
        || creation.projection.lifecycle.phase != LifecyclePhase::Explore
        || creation.projection.lifecycle.usage != LifecycleUsage::default()
    {
        return Err(AppError::Experiment(
            "zero-adapter lifecycle was not created at a fresh Explore boundary".into(),
        ));
    }

    let adapter = ForbiddenProviderAdapter::default();
    let resolver = SemanticLifecycleExploreActionResolver::new(store.clone());
    let adapters = LifecyclePhaseAdapters {
        explore: &adapter,
        implement: &adapter,
        test: &adapter,
        review: &adapter,
        verify: &adapter,
    };
    let outcome = LifecycleExecutionKernel::new_with_explore_resolver(
        &store,
        adapters,
        &NeverCancel,
        &resolver,
    )
    .step(&target_change)
    .map_err(|error| AppError::Experiment(error.to_string()))?;
    let adapter_calls = adapter.calls();
    let worker_run_count_after =
        store.worker_run_count().map_err(|error| AppError::Experiment(error.to_string()))?;
    let adapter_invocation_recorded = store
        .latest_lifecycle_adapter_invocation(creation.projection.lifecycle.id)
        .map_err(|error| AppError::Experiment(error.to_string()))?
        .is_some();
    let completion = consumed_completion(&outcome)?.clone();
    let transition_persisted = store
        .replay_lifecycle_events(&target_change)
        .map_err(|error| AppError::Experiment(error.to_string()))?
        .last()
        .is_some_and(|event| {
            matches!(
                &event.kind,
                LifecycleEventKind::Transitioned { transition }
                    if matches!(transition.as_ref(), LifecycleTransition::CompleteExploreFromReuse {
                        reuse,
                        artifacts,
                    } if reuse == &completion && artifacts == &outcome.projection.lifecycle.exploration_artifacts)
            )
        });
    let (_, final_snapshot) = capture_git_snapshot(&repository_root)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let source_unchanged = final_snapshot.source_digest == initial_snapshot.source_digest;
    let checkout_clean = repository_status_clean(&repository_root)?;
    let report = LifecycleExploreZeroAdapterLiveReport::new(ReportInput {
        source_report_digest,
        lifecycle_authority_acceptance_digest: lifecycle_acceptance.acceptance_digest,
        authority_decision: lifecycle_acceptance.decision,
        repository_id: source.repository,
        source_snapshot: source.source_snapshot,
        source_lifecycle: source.lifecycle,
        target_change: target_change.clone(),
        target_lifecycle: creation.projection.lifecycle.id,
        action_plan_definition_digest: plan.definition_digest,
        lifecycle_created: creation.created,
        outcome,
        worker_run_count_before,
        worker_run_count_after,
        adapter_calls,
        adapter_invocation_recorded,
        transition_persisted,
        source_unchanged,
        checkout_clean,
    })?;
    drop(store);
    verify_existing_report(
        &report,
        ExistingReportBindings {
            source_report_digest,
            acceptance: &lifecycle_acceptance,
            repository_id: source.repository,
            source_snapshot: source.source_snapshot,
            source_lifecycle: source.lifecycle,
            target_change,
            database: &paths.database,
        },
    )?;
    write_create_new(&paths.output, &report)?;
    print_report("written to", &paths.output, &report);
    Ok(())
}

fn consumed_completion(
    outcome: &LifecycleExecutionOutcome,
) -> Result<&LifecycleExploreReuseCompletion, AppError> {
    match outcome.explore_reuse.as_ref() {
        Some(LifecycleExploreReuseOutcome::Consumed { completion }) => Ok(completion),
        _ => Err(AppError::Experiment("lifecycle Explore did not consume exact reuse".into())),
    }
}

struct ExistingReportBindings<'a> {
    source_report_digest: Digest,
    repository_id: Digest,
    source_snapshot: Digest,
    source_lifecycle: needle_core::LifecycleId,
    target_change: ChangeId,
    acceptance: &'a LifecycleExploreLifecycleAuthorityAcceptance,
    database: &'a Path,
}

fn verify_existing_report(
    report: &LifecycleExploreZeroAdapterLiveReport,
    expected: ExistingReportBindings<'_>,
) -> Result<(), AppError> {
    report.validate()?;
    if report.source_report_digest != expected.source_report_digest
        || report.lifecycle_authority_acceptance_digest != expected.acceptance.acceptance_digest
        || report.authority_decision != expected.acceptance.decision
        || report.repository_id != expected.repository_id
        || report.source_snapshot != expected.source_snapshot
        || report.source_lifecycle != expected.source_lifecycle
        || report.target_change != expected.target_change
    {
        return Err(AppError::Experiment(
            "existing zero-adapter report differs from the accepted evidence chain".into(),
        ));
    }
    let store = RuntimeStore::new(expected.database);
    let projection = store
        .lifecycle(&expected.target_change)
        .map_err(|error| AppError::Experiment(error.to_string()))?
        .ok_or_else(|| AppError::Experiment("zero-adapter lifecycle is unavailable".into()))?;
    let worker_run_count =
        store.worker_run_count().map_err(|error| AppError::Experiment(error.to_string()))?;
    let invocation = store
        .latest_lifecycle_adapter_invocation(report.target_lifecycle)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let effective = store
        .effective_action_capability_decision(implementation_location_exact_capability().id)
        .map_err(|error| AppError::Experiment(error.to_string()))?
        .ok_or_else(|| AppError::Experiment("zero-adapter authority head is unavailable".into()))?;
    if projection != report.outcome.projection
        || worker_run_count != report.worker_run_count_after
        || invocation.is_some()
        || effective.decision.id != report.authority_decision
        || effective.recorded_unix_ms != expected.acceptance.decision_recorded_unix_ms
    {
        return Err(AppError::Experiment(
            "persisted zero-adapter state differs from the canonical report".into(),
        ));
    }
    let events = store
        .replay_lifecycle_events(&expected.target_change)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let completion = consumed_completion(&report.outcome)?;
    if !events.last().is_some_and(|event| {
        matches!(
            &event.kind,
            LifecycleEventKind::Transitioned { transition }
                if matches!(transition.as_ref(), LifecycleTransition::CompleteExploreFromReuse {
                    reuse,
                    artifacts,
                } if reuse == completion && artifacts == &projection.lifecycle.exploration_artifacts)
        )
    }) {
        return Err(AppError::Experiment(
            "persisted zero-adapter transition provenance is unavailable".into(),
        ));
    }
    Ok(())
}

fn target_change_id(source_report_digest: Digest, acceptance_digest: Digest) -> ChangeId {
    let mut hasher = CanonicalHasher::new(b"needle-lifecycle-explore-zero-adapter-target-v1");
    hasher.field_digest(source_report_digest);
    hasher.field_digest(acceptance_digest);
    ChangeId::from_digest(hasher.finish())
}

fn verify_explicit_identity(
    arguments: &Arguments,
    source_report_digest: Digest,
    acceptance: &LifecycleExploreLifecycleAuthorityAcceptance,
) -> Result<(), AppError> {
    let requested_source = parse_digest(
        arguments.source_report_digest.as_deref().expect("validated"),
        "--source-report-digest",
    )?;
    let requested_acceptance = parse_digest(
        arguments.authority_acceptance_digest.as_deref().expect("validated"),
        "--authority-acceptance-digest",
    )?;
    let requested_decision = ActionCapabilityDecisionId::new(parse_digest(
        arguments.decision_id.as_deref().expect("validated"),
        "--decision-id",
    )?);
    if requested_source != source_report_digest
        || requested_acceptance != acceptance.acceptance_digest
        || requested_decision != acceptance.decision
    {
        return Err(AppError::Experiment(
            "zero-adapter execution identity differs from the explicit operator confirmation"
                .into(),
        ));
    }
    Ok(())
}

fn parse_digest(value: &str, argument: &str) -> Result<Digest, AppError> {
    Digest::parse(value).map_err(|error| AppError::Usage(format!("invalid {argument}: {error}")))
}

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>, AppError> {
    read_bounded_file(path, maximum).map_err(|error| AppError::Experiment(error.to_string()))
}

fn write_create_new(
    path: &Path,
    report: &LifecycleExploreZeroAdapterLiveReport,
) -> Result<(), AppError> {
    let mut bytes = serde_json::to_vec_pretty(report)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(AppError::Experiment(format!(
            "zero-adapter report has {} bytes; maximum is {}",
            bytes.len(),
            MAX_REPORT_BYTES
        )));
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn print_report(verb: &str, path: &Path, report: &LifecycleExploreZeroAdapterLiveReport) {
    let completion = consumed_completion(&report.outcome)
        .expect("validated zero-adapter report has a completion");
    println!("lifecycle Explore zero-adapter live report {verb} {}", path.display());
    println!("report_digest={}", report.report_digest);
    println!("target_change_id={}", report.target_change);
    println!("target_lifecycle_id={}", report.target_lifecycle);
    println!("authority_decision_id={}", report.authority_decision);
    println!("artifact_id={}", completion.artifact);
    println!("transition=complete_explore_from_reuse");
    println!("adapter_calls=0");
    println!("worker_run_delta=0");
    println!("worker_turns=0");
    println!("output_tokens=0");
    println!("cost_microusd=0");
    println!("provider_call_performed=false");
    println!("passed=true");
}

struct EvidencePaths<'a> {
    live_report: std::path::PathBuf,
    authority_preflight: std::path::PathBuf,
    authority_acceptance: std::path::PathBuf,
    lifecycle_preflight: std::path::PathBuf,
    lifecycle_acceptance: std::path::PathBuf,
    database: std::path::PathBuf,
    output: std::path::PathBuf,
    _root: &'a Path,
}

impl<'a> EvidencePaths<'a> {
    fn new(root: &'a Path) -> Self {
        Self {
            live_report: root.join(LIVE_REPORT_FILE),
            authority_preflight: root.join(AUTHORITY_PREFLIGHT_FILE),
            authority_acceptance: root.join(ACCEPTANCE_FILE),
            lifecycle_preflight: root.join(LIFECYCLE_AUTHORITY_PREFLIGHT_FILE),
            lifecycle_acceptance: root.join(LIFECYCLE_AUTHORITY_ACCEPTANCE_FILE),
            database: root.join(DATABASE_FILE),
            output: root.join(REPORT_FILE),
            _root: root,
        }
    }

    fn validate(&self) -> Result<(), AppError> {
        if [
            &self.live_report,
            &self.authority_preflight,
            &self.authority_acceptance,
            &self.lifecycle_preflight,
            &self.lifecycle_acceptance,
            &self.database,
        ]
        .into_iter()
        .any(|path| !path.is_file())
        {
            return Err(AppError::Experiment(
                "zero-adapter execution requires the complete retained authority chain and database"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[derive(Default)]
struct Arguments {
    artifact_root: Option<String>,
    source_report_digest: Option<String>,
    authority_acceptance_digest: Option<String>,
    decision_id: Option<String>,
    confirm_provider_free_zero_adapter: bool,
    confirm_retained_exact_artifact: bool,
}

impl Arguments {
    fn parse(arguments: &[String]) -> Result<Self, AppError> {
        let mut parsed = Self::default();
        let mut index = 0;
        while index < arguments.len() {
            match arguments[index].as_str() {
                "--artifact-root"
                | "--source-report-digest"
                | "--authority-acceptance-digest"
                | "--decision-id" => {
                    let value = arguments.get(index + 1).ok_or_else(|| {
                        AppError::Usage(format!("{} requires a value", arguments[index]))
                    })?;
                    match arguments[index].as_str() {
                        "--artifact-root" => parsed.artifact_root = Some(value.clone()),
                        "--source-report-digest" => {
                            parsed.source_report_digest = Some(value.clone());
                        }
                        "--authority-acceptance-digest" => {
                            parsed.authority_acceptance_digest = Some(value.clone());
                        }
                        "--decision-id" => parsed.decision_id = Some(value.clone()),
                        _ => unreachable!(),
                    }
                    index += 2;
                }
                "--confirm-provider-free-zero-adapter" => {
                    parsed.confirm_provider_free_zero_adapter = true;
                    index += 1;
                }
                "--confirm-retained-exact-artifact" => {
                    parsed.confirm_retained_exact_artifact = true;
                    index += 1;
                }
                argument => {
                    return Err(AppError::Usage(format!(
                        "unknown lifecycle-explore-zero-adapter-live argument `{argument}`"
                    )));
                }
            }
        }
        Ok(parsed)
    }

    fn validate(&self) -> Result<(), AppError> {
        if self.artifact_root.is_none()
            || self.source_report_digest.is_none()
            || self.authority_acceptance_digest.is_none()
            || self.decision_id.is_none()
            || !self.confirm_provider_free_zero_adapter
            || !self.confirm_retained_exact_artifact
        {
            return Err(AppError::Usage(
                "zero-adapter execution requires exact identities and both confirmation flags"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_require_exact_authority_and_provider_free_confirmations() {
        let arguments = Arguments::parse(&[
            "--artifact-root".into(),
            "target/live".into(),
            "--source-report-digest".into(),
            Digest::blake3(b"report").to_string(),
            "--authority-acceptance-digest".into(),
            Digest::blake3(b"acceptance").to_string(),
            "--decision-id".into(),
            Digest::blake3(b"decision").to_string(),
            "--confirm-provider-free-zero-adapter".into(),
            "--confirm-retained-exact-artifact".into(),
        ])
        .unwrap();
        arguments.validate().unwrap();

        let missing = Arguments::parse(&[
            "--artifact-root".into(),
            "target/live".into(),
            "--source-report-digest".into(),
            Digest::blake3(b"report").to_string(),
            "--authority-acceptance-digest".into(),
            Digest::blake3(b"acceptance").to_string(),
            "--decision-id".into(),
            Digest::blake3(b"decision").to_string(),
        ])
        .unwrap();
        assert!(missing.validate().is_err());
        assert!(Arguments::parse(&["--provider".into()]).is_err());
    }

    #[test]
    fn target_change_identity_binds_report_and_acceptance() {
        let report = Digest::blake3(b"report");
        let acceptance = Digest::blake3(b"acceptance");
        assert_eq!(target_change_id(report, acceptance), target_change_id(report, acceptance));
        assert_ne!(
            target_change_id(report, acceptance),
            target_change_id(report, Digest::blake3(b"other"))
        );
    }

    #[test]
    fn forbidden_adapter_is_a_bounded_tripwire() {
        let adapter = ForbiddenProviderAdapter::default();
        assert_eq!(adapter.calls(), 0);
        assert_eq!(
            adapter.calls.fetch_add(1, Ordering::Relaxed),
            0,
            "the counter must observe the first forbidden boundary crossing"
        );
        assert_eq!(adapter.calls(), 1);
    }
}
