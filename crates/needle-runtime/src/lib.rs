//! Local, on-demand Needle product runtime.

mod action_capabilities;
mod action_contracts;
mod action_execution;
mod action_resolution;
mod approval;
mod architecture_brief;
mod artifact_cache;
mod awcp;
mod change_impact;
mod changes;
mod claim_proof;
mod definition_registry;
mod dependency_validity;
mod input_artifact_state;
mod lifecycle_action_plan;
mod lifecycle_executor;
mod lifecycle_explore_adapter;
mod model_ladder;
mod opaque_action_artifact;
mod orchestrator;
mod partition_manifests;
mod partitioned_action_artifact;
mod proof;
mod refresh_planner;
mod repository_observer;
mod repository_watcher;
mod reuse_descriptor;
mod router;
mod sandbox;
mod semantic_action_request;
mod semantic_claim_projection;
mod semantic_resolver;
mod semantic_validation;
mod snapshot;
mod store;
mod test_target_inventory;

pub use orchestrator::{
    ResolveOutcome, ResolveRequest, RuntimeEngine, RuntimeError, WorkerExecutor,
};
pub use router::{RouteError, select_route};
pub use sandbox::{IsolatedCheckout, SandboxError};
pub use snapshot::{
    SnapshotError, bind_evidence_digests, capture_git_snapshot, validate_cached_need_result,
    validate_need_result,
};
pub use store::{
    ActionAssuranceEvidenceRecord, ActionAssurancePreflight, ActionCapabilityDecisionRecord,
    ActionSafetyMetrics, ActivationRecord, ActivationScope, ActivationStatus, CacheRecord,
    ChangeAttemptRecord, ConfigExport, LifecycleAdapterInvocationClaim,
    LifecycleAdapterInvocationRecord, LifecycleAdapterInvocationState,
    LifecycleAdapterRecoveryRecord, LifecycleAdapterRecoveryResult, LifecycleAdapterRecoverySource,
    LifecycleChangeContext, LifecycleExploreShadowObservationRecord, LifecycleProjection,
    LifecycleStartCreation, LifecycleStartTestPlanCandidate, LifecycleSummaryRecord,
    MAX_LIFECYCLE_EXPLORE_OBSERVATION_LIST_LIMIT, MAX_LIFECYCLE_LIST_LIMIT,
    MAX_LIFECYCLE_START_TEST_PLAN_CANDIDATES, MAX_PARTITION_MANIFEST_LIST_LIMIT,
    MAX_PARTITION_SOURCE_VALIDATION_WIRE_BYTES, MAX_REFRESH_ECONOMIC_ASSESSMENT_LIST_LIMIT,
    MainTurnObservationRecord, NeedShadowRecord, NeedShadowWrite, NeedStepEventRecord,
    NeedStepRequestRecord, NegativeAttemptRecord, OperatorCostKey, OperatorCostObservation,
    PARTITIONED_ACTION_HEAD_FORMAT_REVISION, PartitionManifestSummaryRecord,
    PartitionedActionHeadKey, PartitionedActionHeadRecord, PatchFileBlob, PreparedChangeRecord,
    ProofAccountingRecord, ProviderBackedActionAssuranceInput, RefreshEconomicAssessmentRecord,
    RoleProfileAuditOperation, RoleProfileAuditRecord, RoleProfileStateRecord,
    RouteCostObservation, RoutePromotionRecord, RuntimeSettings, RuntimeStore, SessionRecord,
    ShadowEconomicallyAssessedPartitionedActionArtifactPublication,
    ShadowEconomicallySelectedRefreshedActionArtifactPublication,
    ShadowPartitionedActionHeadAdvance, ShadowPartitionedActionHeadBase,
    ShadowRefreshedActionArtifactPublication, StoreError, WorkerRunRecord,
};

use needle_core::{NeedKey, Preset, Route, RouteMatcher};

pub fn built_in_presets() -> Vec<Preset> {
    vec![
        Preset::new(
            "locate.implementation",
            "Locate implementation",
            "Locate the exact implementation bodies and focused supporting tests for the requested anchors. Return only claims backed by exact repository-relative evidence.",
        ),
        Preset::new(
            "trace.state-flow",
            "Trace state flow",
            "Complete all discovery needed to trace producer, carrier, transformation, consumer, precedence, and focused tests. Return the minimum sufficient snapshot-bound claims and exact repository-relative evidence so the main model can answer without repository access. Do not investigate edit loci or modification constraints unless the root task explicitly requests a change.",
        ),
        Preset::new(
            "tests.relevant",
            "Relevant tests",
            "Identify the exact relevant test cases and focused commands without executing them. Cite the test definitions and the implementation behavior they constrain.",
        ),
    ]
}

pub fn built_in_routes() -> Vec<Route> {
    ["locate.implementation", "trace.state-flow", "tests.relevant"]
        .into_iter()
        .enumerate()
        .map(|(index, key)| {
            Route::new(
                key,
                100 - index as i32,
                RouteMatcher {
                    platform: "codex".to_owned(),
                    main_model: "*".to_owned(),
                    need_key: NeedKey::new(key).expect("built-in need keys are valid"),
                    repository: "*".to_owned(),
                },
                key,
            )
        })
        .collect()
}
pub use action_capabilities::{
    implementation_location_exact_capability, test_target_inventory_refresh_capability,
};
pub use action_contracts::{
    BUILT_IN_ACTION_COUNT, BuiltInActionCoverage, BuiltInActionDefinition,
    built_in_action_contracts, built_in_action_for_artifact_kind, built_in_action_for_predicate,
};
pub use action_execution::{
    ActionExecutionError, ActionExecutionResult, ActionExecutionService, ChangeActionProvider,
    ChangeActionProviderContext, ChangeActionProviderError, ChangeActionProviderOutput,
};
pub use action_resolution::{
    SHADOW_ACTION_RESOLUTION_FORMAT_REVISION, ShadowActionResolutionAuthority,
    ShadowActionResolutionError, ShadowActionResolutionInput, ShadowActionResolutionKind,
    ShadowActionResolutionSummary,
};
pub use approval::{
    ApprovalBroker, ApprovalContext, ApprovalError, command_evidence_from_output,
    parse_direct_argv, parse_read_only_command_argv, parse_test_command_argv,
    validate_test_evidence,
};
pub use architecture_brief::{
    ARCHITECTURE_BRIEF_ANALYSIS_REVISION, ArchitectureBriefRuntimeError,
    ArchitectureBriefValidationCertificate, ArchitectureBriefValidationInput,
    MAX_ARCHITECTURE_EVIDENCE_FILE_BYTES, MAX_ARCHITECTURE_EVIDENCE_TOTAL_BYTES,
    architecture_brief_analysis_definition, architecture_brief_partition_policy_definition,
    architecture_brief_validator_definition, assemble_architecture_briefs,
    project_architecture_brief, validate_architecture_brief,
};
pub use artifact_cache::{ArtifactCache, ArtifactCacheError, PlanCacheResult};
pub use awcp::{
    AuthenticatedAwcpContext, MAX_OFFLINE_AWCP_ARTIFACTS, MAX_OFFLINE_AWCP_GRANTS,
    MAX_OFFLINE_AWCP_REPORTS, MAX_OFFLINE_AWCP_RESOLUTIONS, MAX_OFFLINE_AWCP_TICKETS,
    OfflineActionResolution, OfflineArtifactProjection, OfflineAwcpError, OfflineAwcpSimulator,
};
pub use change_impact::{
    CHANGE_IMPACT_ANALYSIS_REVISION, ChangeImpactRuntimeError, ChangeImpactValidationCertificate,
    ChangeImpactValidationInput, MAX_CHANGE_IMPACT_BLOB_FILE_BYTES,
    MAX_CHANGE_IMPACT_BLOB_TOTAL_BYTES, assemble_change_impacts, change_impact_analysis_definition,
    change_impact_partition_policy_definition, change_impact_validator_definition,
    derive_change_impact_change_set, project_change_impact, validate_change_impact,
};
pub use changes::{
    ChangeApplyError, ChangeMaterializationError, apply_lifecycle_change,
    apply_lifecycle_change_for_operation, apply_verified_change,
    apply_verified_change_for_operation, materialize_patch_artifact,
    recover_pending_change_applies, validate_patch_artifact_base,
};
pub use claim_proof::{
    ClaimProofError, ClaimProofMaterial, build_claim_component_certificate,
    build_claim_set_certificate, claim_proof_engine_definition,
    claim_validation_certificate_is_fresh, replay_claim_set_certificate,
};
pub use definition_registry::active_definition_set;
pub use dependency_validity::{
    DEPENDENCY_INTERSECTION_FORMAT_REVISION, DependencyDeltaIntersection,
    DependencyIntersectionError, DependencyLocatorSet, DependencyRevalidationReason,
    FAST_VALIDITY_FORMAT_REVISION, MAX_DEPENDENCY_MANIFEST_ENTRIES,
    MAX_DEPENDENCY_MANIFEST_TEXT_BYTES, MAX_FAST_VALIDITY_DELTAS, classify_dependency_delta,
    dependency_intersection_definition_digest, fast_validity_definition_digest,
};
pub use input_artifact_state::{
    ArtifactGraphRevalidationReason, ArtifactGraphValidity, ArtifactGraphValidityState,
    INPUT_ARTIFACT_STATE_FORMAT_REVISION, MAX_INPUT_ARTIFACT_STATE_NODES,
    empty_input_artifact_state_digest, input_artifact_state_definition_digest,
};
pub use lifecycle_action_plan::{
    LifecycleExploreActionPlanError, compile_lifecycle_explore_action_plan,
    validate_lifecycle_explore_action_plan,
};
pub use lifecycle_executor::{
    LIFECYCLE_ADAPTER_OUTCOME_SCHEMA, LIFECYCLE_ADAPTER_REQUEST_SCHEMA,
    LIFECYCLE_EXPLORE_SHADOW_OBSERVATION_FORMAT_REVISION, LifecycleAdapterCleanup,
    LifecycleAdapterFailure, LifecycleAdapterResult, LifecycleCancellation,
    LifecycleExecutionDisposition, LifecycleExecutionError, LifecycleExecutionKernel,
    LifecycleExecutionOutcome, LifecycleExploreActionResolver,
    LifecycleExploreActionResolverOutcome, LifecycleExploreReuseOutcome,
    LifecycleExploreShadowObservation, LifecycleExploreShadowObservationError,
    LifecycleExploreShadowObservationPersistence, LifecycleExploreShadowResolutionKind,
    LifecyclePhaseAdapter, LifecyclePhaseAdapterOutcome, LifecyclePhaseAdapterRequest,
    LifecyclePhaseAdapters, LifecycleRemainingBudget, MAX_LIFECYCLE_ADAPTER_DETAIL_BYTES,
    MAX_LIFECYCLE_ADAPTER_OUTCOME_BYTES, MAX_LIFECYCLE_ADAPTER_REQUEST_BYTES,
    MAX_LIFECYCLE_EXPLORE_SHADOW_OBSERVATION_BYTES, NeverCancel,
    NoopLifecycleExploreActionResolver, SemanticLifecycleExploreActionResolver,
    lifecycle_adapter_invocation_id,
};
pub use lifecycle_explore_adapter::{
    FRESH_LIFECYCLE_EXPLORE_ADAPTER_REVISION, FreshLifecycleExploreAdapter,
    fresh_lifecycle_explore_adapter_definition_digest,
};
pub use model_ladder::{
    LadderAttempt, LadderAttemptRecord, ModelLadder, ModelLadderError, ModelLadderOutcome,
};
pub use opaque_action_artifact::{
    ChangeActionOutput, OpaqueActionArtifactError, OpaqueActionCertificationInput,
    ShadowOpaqueActionArtifactPublication, certify_shadow_opaque_action_artifact,
};
pub use partition_manifests::{
    BUILT_IN_PARTITION_DEFINITION_COUNT, BuiltInPartitionDefinition,
    BuiltInPartitionDefinitionError, ShadowManifestContext, ShadowPartitionManifestError,
    ShadowPartitionManifestPublication, built_in_partition_definitions,
    built_in_partition_for_action, built_in_partition_for_scheme,
    certify_architecture_brief_shadow_manifest, certify_change_impact_shadow_manifest,
    certify_review_shadow_manifest, certify_test_target_inventory_shadow_manifest,
    derive_architecture_brief_shadow_manifest, derive_change_impact_shadow_manifest,
    derive_review_shadow_manifest, derive_test_target_inventory_shadow_manifest,
    review_finding_partition_key,
};
pub use partitioned_action_artifact::{
    PartitionedActionArtifactError, ShadowPartitionedActionArtifactPublication,
    certify_review_action_artifact, certify_test_target_inventory_action_artifact,
};
pub use proof::{
    ClaimAdvisoryPlan, ClaimAdvisoryResolutionKind, ProofCandidate, ProofError, ProofPlan,
    ProofPlanner, ProofResolutionKind, SemanticCostEstimates, ValiditySelection,
};
pub use refresh_planner::{
    ShadowRefreshCandidate, ShadowRefreshFallbackTrigger, ShadowRefreshResolution,
    ShadowRefreshResolverError, ShadowRefreshResolverInput, resolve_shadow_refresh_or_full_compute,
};
pub use repository_observer::{
    GIT_REPOSITORY_OBSERVER_REVISION, MAX_REPOSITORY_SOURCE_VERSION_BYTES,
    RepositoryReconciliation, RepositoryReconciliationError, RepositoryReconciliationStatus,
    git_repository_observer_definition_digest, reconcile_git_repository,
};
pub use repository_watcher::{
    REPOSITORY_WATCHER_DEBOUNCE, REPOSITORY_WATCHER_RECONCILIATION_INTERVAL,
    REPOSITORY_WATCHER_REVISION, RepositoryWatcher, RepositoryWatcherError,
    RepositoryWatcherHealth, RepositoryWatcherHealthHandle, repository_watcher_definition_digest,
};
pub use reuse_descriptor::{
    MAX_REUSE_DESCRIPTOR_CERTIFICATE_EVIDENCE, ReuseDescriptorDerivationError,
    derive_shadow_reuse_descriptor,
};
pub use semantic_resolver::{
    CLAIM_PROOF_RESOLUTION_FORMAT_REVISION, PROOF_RESOLUTION_FORMAT_REVISION, SemanticResolver,
    SemanticResolverError, SemanticReuseDecision,
};
pub use semantic_validation::{
    SEMANTIC_VALIDATOR_REVISION, SemanticValidationError, ValidatedClaimSet,
    ValidatedSemanticArtifact, artifact_and_certificate_are_fresh, manifest_digest,
    validate_semantic_artifact, validate_semantic_artifact_with_trace, validate_semantic_result,
    validate_semantic_test_plan, validate_semantic_test_plan_with_evidence, validator_definition,
};
pub use test_target_inventory::{
    CARGO_TEST_TARGET_ADAPTER_REVISION, CargoTestTargetInventoryInput,
    CargoTestTargetRefreshAcquisition, CargoTestTargetRefreshCandidate,
    CargoTestTargetRefreshFallback, CargoTestTargetRefreshInput, MAX_CARGO_METADATA_INPUT_BYTES,
    MAX_CARGO_VERSION_BYTES, MAX_TEST_TARGET_MANIFEST_BYTES, ShadowCargoTestTargetHostError,
    ShadowCargoTestTargetHostExecution, ShadowCargoTestTargetHostInput,
    ShadowCargoTestTargetHostRebaseline, ShadowCargoTestTargetRefreshExecutionInput,
    ShadowRefreshCostEstimate, ShadowTestTargetHeadExecutionContext,
    ShadowTestTargetInventoryRefresh, ShadowTestTargetPublicationReceipt,
    ShadowTestTargetRefreshExecution, ShadowTestTargetRefreshExecutionError,
    ShadowTestTargetRefreshExecutionFallback, TestTargetInventoryRefreshDecision,
    TestTargetInventoryRefreshError, TestTargetInventoryRefreshFallback,
    TestTargetInventoryRefreshInput, TestTargetInventoryRefreshPlan,
    TestTargetInventoryRuntimeError, TestTargetInventoryValidationCertificate,
    acquire_cargo_test_target_refresh_candidate, assemble_test_target_inventories,
    cargo_test_target_adapter_definition, cargo_test_target_partition_opaque_key,
    cargo_test_target_provider_context_digest, cargo_test_target_refresh_acquisition_definition,
    enumerate_cargo_test_targets, evaluate_test_target_inventory_refresh,
    execute_shadow_cargo_test_target_host, execute_shadow_cargo_test_target_refresh,
    project_test_target_inventory, resolve_test_target_inventory_refresh_or_full_compute,
    test_target_inventory_partition_policy_definition, test_target_inventory_refresh_definition,
    test_target_inventory_validator_definition, validate_cargo_test_target_inventory,
};
