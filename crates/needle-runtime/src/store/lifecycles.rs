use super::*;
use crate::{
    LifecycleExploreShadowObservation, LifecycleExploreShadowResolutionKind,
    ShadowActionResolutionKind, ShadowActionResolutionSummary,
    implementation_location_exact_capability,
};
use needle_core::{
    ActionOutputValidationCertificate, ActionRequest, ApprovalDecisionSource, Artifact, ArtifactId,
    ArtifactValidationCertificate, CapabilityMode, ChangeApplyId, ChangeApplyStatus, ChangeId,
    ChangeRequest, CodexRole, CommandExecutionEvidence, DevelopmentLifecycle, Digest,
    LifecycleApplyApproval, LifecycleError, LifecycleEvent, LifecycleExploreReuseAuthority,
    LifecycleExploreReuseCompletion, LifecyclePhase, LifecycleReason, LifecycleSpec,
    LifecycleStatus, LifecycleTerminalOutcome, LifecycleTestPlanBinding, LifecycleTestResult,
    LifecycleTransition, LifecycleUsage, LifecycleWorkerProfiles, PATCH_PROPOSE_ACTION_CONTRACT,
    PATCH_VERIFY_ACTION_CONTRACT, PatchId, ReviewArtifact, RoleProfileProvenance,
    SemanticWorkerArtifact, TESTS_EXECUTE_ACTION_CONTRACT, TestExecutionStatus, TestPlan,
    VerificationArtifact, VerificationArtifactId,
};
use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

type LifecycleChangeAnchors =
    (String, String, String, u64, bool, Option<String>, Option<u64>, Option<String>);
type LifecycleProjectionRow = (String, String, String, String, u64);

pub const MAX_LIFECYCLE_LIST_LIMIT: usize = 100;
pub const MAX_LIFECYCLE_START_TEST_PLAN_CANDIDATES: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleStartTestPlanCandidate {
    pub artifact_id: ArtifactId,
    pub binding: LifecycleTestPlanBinding,
    pub issued_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleStartCreation {
    pub projection: LifecycleProjection,
    pub created: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleProjection {
    pub lifecycle: DevelopmentLifecycle,
    pub state_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LifecycleExploreReuseCommit {
    Ineligible,
    ResolverAuthorized(LifecycleExploreReuseAuthority),
    Committed {
        projection: Box<LifecycleProjection>,
        completion: Box<LifecycleExploreReuseCompletion>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleSummaryRecord {
    pub lifecycle_id: needle_core::LifecycleId,
    pub change_id: ChangeId,
    pub source_snapshot: Digest,
    pub phase: LifecyclePhase,
    pub status: LifecycleStatus,
    pub state_digest: Digest,
    pub generation: u64,
    pub usage: LifecycleUsage,
    pub terminal_outcome: Option<LifecycleTerminalOutcome>,
    pub terminal_reason: Option<LifecycleReason>,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
}

impl LifecycleSummaryRecord {
    fn from_projection(projection: LifecycleProjection) -> Self {
        let lifecycle = projection.lifecycle;
        Self {
            lifecycle_id: lifecycle.id,
            change_id: lifecycle.change_id,
            source_snapshot: lifecycle.source_snapshot,
            phase: lifecycle.phase,
            status: lifecycle.status,
            state_digest: projection.state_digest,
            generation: lifecycle.generation,
            usage: lifecycle.usage,
            terminal_outcome: lifecycle.terminal_outcome,
            terminal_reason: lifecycle.terminal_reason,
            created_unix_ms: lifecycle.created_unix_ms,
            updated_unix_ms: lifecycle.updated_unix_ms,
        }
    }
}

impl LifecycleProjection {
    fn new(lifecycle: DevelopmentLifecycle) -> Result<Self, StoreError> {
        lifecycle.validate()?;
        let state_digest = lifecycle.state_digest();
        Ok(Self { lifecycle, state_digest })
    }
}

fn validate_action_native_lifecycle_test_plan(
    request_json: &str,
    source_snapshot: Digest,
    artifact: &needle_core::Artifact,
    certificate: &needle_core::ArtifactValidationCertificate,
) -> Result<(), StoreError> {
    let request: needle_core::ActionRequest = serde_json::from_str(request_json)?;
    let action =
        crate::built_in_action_for_artifact_kind(&artifact.contract.kind).ok_or_else(|| {
            StoreError::LifecycleCorruption(
                "stored lifecycle action TestPlan has an unknown action contract".to_owned(),
            )
        })?;
    request.validate(&action.contract).map_err(|_| {
        StoreError::LifecycleCorruption(
            "stored lifecycle action TestPlan request is not canonical".to_owned(),
        )
    })?;
    if request.semantic_id().digest() != artifact.request_id
        || request.artifact_request.source_snapshot_digest != source_snapshot
        || request.artifact_request.contract_id != action.output_contract_id
        || request.artifact_request.contract_revision != action.output_contract_revision
        || artifact.contract.id != action.output_contract_id
        || artifact.contract.revision != action.output_contract_revision
        || artifact.contract.schema_id != action.output_schema_id
        || artifact.contract.kind != action.artifact_kind
        || artifact.contract.definition_digest != action.output_contract_definition_digest
        || certificate.validator_definition != action.validator_definition_digest
        || certificate.coverage.world.repository_lineage != request.artifact_request.repository_id
    {
        return Err(StoreError::LifecycleCorruption(
            "stored lifecycle action TestPlan bindings are inconsistent".to_owned(),
        ));
    }
    crate::reuse_descriptor::derive_shadow_reuse_descriptor_from_validated_pair(
        artifact,
        certificate,
    )
    .map(|_| ())
    .map_err(|_| {
        StoreError::LifecycleCorruption(
            "stored lifecycle action TestPlan certificate is invalid".to_owned(),
        )
    })
}

impl RuntimeStore {
    /// Atomically freeze a new immutable change request and its lifecycle.
    ///
    /// Repeating the exact same `change_id` and inputs is idempotent. A reused
    /// identity with different material fails closed before either aggregate is
    /// changed.
    #[allow(clippy::too_many_arguments)]
    pub fn create_lifecycle_with_request(
        &self,
        change_id: &ChangeId,
        repository_id: Digest,
        source_snapshot: Digest,
        request: &ChangeRequest,
        spec: LifecycleSpec,
    ) -> Result<LifecycleStartCreation, StoreError> {
        self.create_lifecycle_with_optional_operation(
            change_id,
            repository_id,
            source_snapshot,
            request,
            spec,
            None,
        )
    }

    /// Atomically bind a public idempotency key to the exact structured
    /// lifecycle invocation while freezing or resuming its lifecycle.
    #[allow(clippy::too_many_arguments)]
    pub fn create_lifecycle_for_operation(
        &self,
        operation_id: Digest,
        operational_request_digest: Digest,
        change_id: &ChangeId,
        repository_id: Digest,
        source_snapshot: Digest,
        request: &ChangeRequest,
        spec: LifecycleSpec,
    ) -> Result<LifecycleStartCreation, StoreError> {
        self.create_lifecycle_with_optional_operation(
            change_id,
            repository_id,
            source_snapshot,
            request,
            spec,
            Some((operation_id, operational_request_digest)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_lifecycle_with_optional_operation(
        &self,
        change_id: &ChangeId,
        repository_id: Digest,
        source_snapshot: Digest,
        request: &ChangeRequest,
        spec: LifecycleSpec,
        operation: Option<(Digest, Digest)>,
    ) -> Result<LifecycleStartCreation, StoreError> {
        self.initialize()?;
        spec.validate()?;
        if repository_id == Digest([0; 32])
            || source_snapshot == Digest([0; 32])
            || operation
                .is_some_and(|(id, digest)| id == Digest([0; 32]) || digest == Digest([0; 32]))
        {
            return Err(StoreError::LifecycleConflict(
                "lifecycle start requires non-zero repository, source and operation identities"
                    .to_owned(),
            ));
        }
        let now = now_ms();
        let mut connection = self.connection()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        validate_profile_set(&transaction, &spec.profiles)?;
        let request_digest = request.digest(source_snapshot);
        super::changes::record_change_request_in_transaction(
            &transaction,
            change_id,
            repository_id,
            source_snapshot,
            request_digest,
            request,
            Some(&spec.profiles.implement),
            now,
        )?;
        let creation = if let Some(projection) =
            lifecycle_projection_in_transaction(&transaction, change_id)?
        {
            if projection.lifecycle.source_snapshot != source_snapshot
                || projection.lifecycle.spec != spec
            {
                return Err(StoreError::LifecycleConflict(format!(
                    "{change_id}: lifecycle start identity was reused with different material"
                )));
            }
            LifecycleStartCreation { projection, created: false }
        } else {
            let projection = create_lifecycle_in_transaction(&transaction, change_id, spec, now)?;
            LifecycleStartCreation { projection, created: true }
        };
        if let Some((operation_id, operational_request_digest)) = operation {
            super::lifecycle_execution_operations::bind_lifecycle_execution_operation_in_transaction(
                &transaction,
                operation_id,
                operational_request_digest,
                change_id,
            )?;
        }
        transaction.commit()?;
        Ok(creation)
    }

    pub fn create_lifecycle(
        &self,
        change_id: &ChangeId,
        spec: LifecycleSpec,
    ) -> Result<LifecycleProjection, StoreError> {
        self.initialize()?;
        spec.validate()?;
        let now = now_ms();
        let mut connection = self.connection()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        validate_profile_set(&transaction, &spec.profiles)?;
        if lifecycle_projection_in_transaction(&transaction, change_id)?.is_some() {
            return Err(StoreError::LifecycleConflict(format!(
                "{change_id}: lifecycle already exists"
            )));
        }
        let projection = create_lifecycle_in_transaction(&transaction, change_id, spec, now)?;
        transaction.commit()?;
        Ok(projection)
    }

    pub fn lifecycle(
        &self,
        change_id: &ChangeId,
    ) -> Result<Option<LifecycleProjection>, StoreError> {
        let connection = self.connection()?;
        lifecycle_projection_in_transaction(&*connection, change_id)
    }

    /// Return a bounded, deterministic set of validated TestPlan bindings for
    /// the exact current source snapshot. Commands remain inside the runtime;
    /// HTTP/UI projections expose only their identities.
    pub fn lifecycle_start_test_plan_candidates(
        &self,
        source_snapshot: Digest,
    ) -> Result<Vec<LifecycleStartTestPlanCandidate>, StoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT a.artifact_id, a.request_id, a.artifact_json,
                    c.certificate_json, c.issued_unix_ms,
                    a.format_revision, r.request_json
             FROM artifact_validation_certificates c
             JOIN artifacts a ON a.artifact_id=c.artifact_id
             JOIN artifact_requests r ON r.request_id=a.request_id
             WHERE a.format_revision IN (2, ?2) AND r.source_digest=?1
             ORDER BY c.issued_unix_ms DESC, c.certificate_id ASC
             LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                source_snapshot.to_string(),
                super::ACTION_REQUEST_STORAGE_FORMAT_REVISION,
                MAX_LIFECYCLE_START_TEST_PLAN_CANDIDATES as u64
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, u16>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )?;
        let mut candidates = BTreeMap::new();
        for row in rows {
            let (
                artifact_id,
                request_id,
                artifact_json,
                certificate_json,
                issued_unix_ms,
                storage_revision,
                request_json,
            ) = row?;
            let (artifact, worker_artifact) =
                parse_semantic_artifact(&artifact_id, &request_id, &artifact_json)?;
            let SemanticWorkerArtifact::TestPlan {
                runner, argv, cwd_relative, identifiers, ..
            } = &worker_artifact
            else {
                continue;
            };
            let Some(test_identifier) = identifiers.first().filter(|_| identifiers.len() == 1)
            else {
                continue;
            };
            let certificate: needle_core::ArtifactValidationCertificate =
                serde_json::from_str(&certificate_json)?;
            let typed_artifact_id = ArtifactId::new(artifact.id);
            if certificate.artifact != typed_artifact_id
                || certificate.test_plan_evidence.is_none()
                || !validation_certificate_is_structurally_canonical(&certificate)
            {
                return Err(StoreError::LifecycleCorruption(
                    "stored lifecycle TestPlan certificate is not canonical".to_owned(),
                ));
            }
            if storage_revision == super::ACTION_REQUEST_STORAGE_FORMAT_REVISION {
                validate_action_native_lifecycle_test_plan(
                    &request_json,
                    source_snapshot,
                    &artifact,
                    &certificate,
                )?;
            }
            let plan = TestPlan {
                runner: runner.clone(),
                argv: argv.clone(),
                cwd_relative: cwd_relative.clone(),
                test_identifier: test_identifier.clone(),
                requires_approval: true,
                execution_evidence_id: None,
            };
            crate::semantic_validation::validate_parent_owned_test_plan_binding(
                &worker_artifact,
                &plan,
            )
            .map_err(|_| {
                StoreError::LifecycleCorruption(
                    "stored lifecycle TestPlan command is not canonical".to_owned(),
                )
            })?;
            let binding =
                LifecycleTestPlanBinding { plan, certificate_digest: certificate.id.digest() };
            candidates.entry(binding.plan_digest()).or_insert(LifecycleStartTestPlanCandidate {
                artifact_id: typed_artifact_id,
                binding,
                issued_unix_ms,
            });
        }
        Ok(candidates.into_values().collect())
    }

    /// Return validated lifecycle summaries ordered by canonical change identity.
    ///
    /// Every selected lifecycle is replayed against its bounded journal before
    /// projection, so corruption is returned instead of hidden by a partial list.
    pub fn list_lifecycle_summaries(
        &self,
        limit: usize,
    ) -> Result<Vec<LifecycleSummaryRecord>, StoreError> {
        if limit == 0 || limit > MAX_LIFECYCLE_LIST_LIMIT {
            return Err(StoreError::LifecycleQuery(format!(
                "limit must be between 1 and {MAX_LIFECYCLE_LIST_LIMIT}"
            )));
        }
        let mut connection = self.connection()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        let ids = {
            let mut statement = transaction.prepare(
                "SELECT change_id FROM change_lifecycles ORDER BY change_id ASC LIMIT ?1",
            )?;
            statement
                .query_map([limit as u64], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut summaries = Vec::with_capacity(ids.len());
        for raw_id in ids {
            let change_id = ChangeId::parse(&raw_id).map_err(|_| {
                StoreError::LifecycleCorruption("lifecycle list change identity".to_owned())
            })?;
            let projection = replay_lifecycle_in_transaction(&transaction, &change_id)?;
            summaries.push(LifecycleSummaryRecord::from_projection(projection));
        }
        transaction.commit()?;
        Ok(summaries)
    }

    pub fn lifecycle_events(
        &self,
        change_id: &ChangeId,
    ) -> Result<Vec<LifecycleEvent>, StoreError> {
        let connection = self.connection()?;
        lifecycle_events_in_connection(&connection, change_id)
    }

    pub fn replay_lifecycle(
        &self,
        change_id: &ChangeId,
    ) -> Result<LifecycleProjection, StoreError> {
        let mut connection = self.connection()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        let projection = replay_lifecycle_in_transaction(&transaction, change_id)?;
        transaction.commit()?;
        Ok(projection)
    }

    /// Return the canonical ordered journal after replaying it against the
    /// persisted lifecycle projection in one read transaction.
    pub fn replay_lifecycle_events(
        &self,
        change_id: &ChangeId,
    ) -> Result<Vec<LifecycleEvent>, StoreError> {
        let mut connection = self.connection()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        let (_, events) = replay_lifecycle_and_events_in_transaction(&transaction, change_id)?;
        transaction.commit()?;
        Ok(events)
    }

    /// Parent-owned transition boundary. Worker outputs are data carried by a
    /// transition; workers do not receive this store capability.
    pub fn parent_transition_lifecycle(
        &self,
        change_id: &ChangeId,
        expected_state_digest: Digest,
        transition: LifecycleTransition,
    ) -> Result<LifecycleProjection, StoreError> {
        if matches!(
            transition,
            LifecycleTransition::CompleteExploreFromReuse { .. }
                | LifecycleTransition::BindTestPlans { .. }
                | LifecycleTransition::ConsumeRepair
                | LifecycleTransition::ApproveApply { .. }
                | LifecycleTransition::StartApply { .. }
                | LifecycleTransition::FinishApply { .. }
        ) {
            return Err(StoreError::LifecycleConflict(format!(
                "{change_id}: transition is reserved for a typed parent operation"
            )));
        }
        let now = now_ms();
        let mut connection = self.connection()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let projection = lifecycle_projection_in_transaction(&transaction, change_id)?
            .ok_or_else(|| StoreError::LifecycleNotFound(change_id.to_string()))?;
        if projection.state_digest != expected_state_digest {
            return Err(StoreError::LifecycleConflict(format!(
                "{change_id}: state digest changed"
            )));
        }
        validate_transition_artifacts(&transaction, &projection.lifecycle, &transition)?;
        let result =
            persist_transition(&transaction, &projection, expected_state_digest, transition, now)?;
        transaction.commit()?;
        Ok(result)
    }

    pub fn bind_lifecycle_test_plans(
        &self,
        change_id: &ChangeId,
        expected_state_digest: Digest,
        worker: Option<needle_core::LifecycleWorkerCompletion>,
        plans: Vec<needle_core::LifecycleResolvedTestPlan>,
    ) -> Result<LifecycleProjection, StoreError> {
        let now = now_ms();
        let mut connection = self.connection()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let projection = lifecycle_projection_in_transaction(&transaction, change_id)?
            .ok_or_else(|| StoreError::LifecycleNotFound(change_id.to_string()))?;
        if projection.state_digest != expected_state_digest {
            return Err(StoreError::LifecycleConflict(format!(
                "{change_id}: state digest changed"
            )));
        }
        let transition = LifecycleTransition::BindTestPlans { worker, plans };
        validate_transition_artifacts(&transaction, &projection.lifecycle, &transition)?;
        let result =
            persist_transition(&transaction, &projection, expected_state_digest, transition, now)?;
        transaction.commit()?;
        Ok(result)
    }

    /// Parent-owned, atomic Explore reuse boundary.
    ///
    /// An exact Shadow projection is only a candidate. This method replays its
    /// durable observation, the current action material, and the effective
    /// assurance decision under the same write lock as the lifecycle CAS.
    pub(crate) fn try_complete_lifecycle_explore_from_reuse(
        &self,
        change_id: &ChangeId,
        expected_state_digest: Digest,
        summary: &ShadowActionResolutionSummary,
    ) -> Result<LifecycleExploreReuseCommit, StoreError> {
        let mut connection = self.connection()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let projection = lifecycle_projection_in_transaction(&transaction, change_id)?
            .ok_or_else(|| StoreError::LifecycleNotFound(change_id.to_string()))?;
        if projection.state_digest != expected_state_digest {
            return Err(StoreError::LifecycleConflict(format!(
                "{change_id}: state digest changed"
            )));
        }
        let candidate = lifecycle_explore_reuse_candidate(&transaction, &projection, summary)?;
        let completion = match candidate {
            LifecycleExploreReuseCandidate::Ineligible => {
                transaction.commit()?;
                return Ok(LifecycleExploreReuseCommit::Ineligible);
            }
            LifecycleExploreReuseCandidate::ResolverAuthorized(authority) => {
                transaction.commit()?;
                return Ok(LifecycleExploreReuseCommit::ResolverAuthorized(authority));
            }
            LifecycleExploreReuseCandidate::LifecycleAuthorized(completion) => completion,
        };
        let artifacts = vec![needle_core::LifecycleArtifactRef {
            kind: needle_core::LifecycleArtifactKind::Exploration,
            id: completion.artifact.digest(),
            source_snapshot: completion.source_snapshot,
        }];
        let transition = LifecycleTransition::CompleteExploreFromReuse {
            reuse: completion.as_ref().clone(),
            artifacts,
        };
        let next = persist_transition(
            &transaction,
            &projection,
            expected_state_digest,
            transition,
            now_ms(),
        )?;
        transaction.commit()?;
        Ok(LifecycleExploreReuseCommit::Committed { projection: Box::new(next), completion })
    }

    /// Record an explicit user approval against the exact verified lifecycle
    /// projection. The state digest prevents an approval from floating to a
    /// later patch or verification revision.
    pub fn approve_lifecycle_apply(
        &self,
        change_id: &ChangeId,
        expected_state_digest: Digest,
        source: ApprovalDecisionSource,
    ) -> Result<LifecycleProjection, StoreError> {
        if source != ApprovalDecisionSource::WebUser {
            return Err(StoreError::LifecycleConflict(format!(
                "{change_id}: apply approval must come from an explicit web user decision"
            )));
        }
        let projection = self
            .lifecycle(change_id)?
            .ok_or_else(|| StoreError::LifecycleNotFound(change_id.to_string()))?;
        if projection.state_digest != expected_state_digest
            || projection.lifecycle.phase != LifecyclePhase::Apply
            || projection.lifecycle.status != LifecycleStatus::AwaitingApproval
        {
            return Err(StoreError::LifecycleConflict(format!(
                "{change_id}: lifecycle is not awaiting approval at this digest"
            )));
        }
        let patch = projection.lifecycle.patch.as_ref().ok_or(LifecycleError::MissingArtifact)?;
        let verification =
            projection.lifecycle.verification.as_ref().ok_or(LifecycleError::MissingArtifact)?;
        let approval = LifecycleApplyApproval::new(
            expected_state_digest,
            patch.patch_id,
            verification.verification_id,
            source,
            now_ms(),
        );
        let mut connection = self.connection()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current = lifecycle_projection_in_transaction(&transaction, change_id)?
            .ok_or_else(|| StoreError::LifecycleNotFound(change_id.to_string()))?;
        let result = persist_transition(
            &transaction,
            &current,
            expected_state_digest,
            LifecycleTransition::ApproveApply { approval },
            now_ms(),
        )?;
        transaction.commit()?;
        Ok(result)
    }
}

fn create_lifecycle_in_transaction(
    transaction: &Transaction<'_>,
    change_id: &ChangeId,
    spec: LifecycleSpec,
    now: u64,
) -> Result<LifecycleProjection, StoreError> {
    let anchors: Option<LifecycleChangeAnchors> = transaction
        .query_row(
            "SELECT source_snapshot_digest, repository_id, state, latest_patch_revision,
                    repair_attempted, role_profile_id, role_profile_revision,
                    role_profile_definition_digest
             FROM change_requests WHERE change_id=?1",
            [change_id.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    let Some((
        source,
        repository,
        state,
        latest_patch_revision,
        repair_attempted,
        profile_id,
        profile_revision,
        profile_digest,
    )) = anchors
    else {
        return Err(StoreError::LifecycleNotFound(format!(
            "{change_id}: immutable change request"
        )));
    };
    if state != "requested" || latest_patch_revision != 0 || repair_attempted {
        return Err(StoreError::LifecycleConflict(format!(
            "{change_id}: lifecycle must be created before implementation"
        )));
    }
    let source_snapshot = Digest::parse(&source)
        .map_err(|_| StoreError::LifecycleCorruption(format!("{change_id}: source digest")))?;
    let repository_id = Digest::parse(&repository)
        .map_err(|_| StoreError::LifecycleCorruption(format!("{change_id}: repository digest")))?;
    if spec.explore_action_plan.as_ref().is_some_and(|plan| {
        plan.repository_id() != repository_id || plan.source_snapshot() != Some(source_snapshot)
    }) {
        return Err(StoreError::LifecycleConflict(format!(
            "{change_id}: lifecycle Explore plan source differs from change request"
        )));
    }
    validate_test_plan_certificates(transaction, &spec, source_snapshot)?;
    let request_profile = parse_profile_anchor(profile_id, profile_revision, profile_digest)?;
    if request_profile.as_ref() != Some(&spec.profiles.implement) {
        return Err(StoreError::LifecycleConflict(format!(
            "{change_id}: request implementer profile differs from lifecycle"
        )));
    }
    let lifecycle = DevelopmentLifecycle::new(change_id.clone(), source_snapshot, spec, now)?;
    let projection = LifecycleProjection::new(lifecycle)?;
    let state_json = serde_json::to_string(&projection.lifecycle)?;
    transaction.execute(
        "INSERT INTO change_lifecycles(
            lifecycle_id, change_id, source_snapshot_digest, state_digest,
            generation, state_json, created_unix_ms, updated_unix_ms
         ) VALUES(?1, ?2, ?3, ?4, 0, ?5, ?6, ?6)",
        params![
            projection.lifecycle.id.to_string(),
            change_id.to_string(),
            source_snapshot.to_string(),
            projection.state_digest.to_string(),
            state_json,
            now,
        ],
    )?;
    let event = LifecycleEvent::created(&projection.lifecycle)?;
    insert_lifecycle_event(transaction, &event, "lifecycle_created")?;
    Ok(projection)
}

fn validate_profile_set(
    transaction: &Transaction<'_>,
    profiles: &LifecycleWorkerProfiles,
) -> Result<(), StoreError> {
    for (phase, role) in [
        (LifecyclePhase::Explore, CodexRole::Explorer),
        (LifecyclePhase::Implement, CodexRole::Implementer),
        (LifecyclePhase::Test, CodexRole::TestRunner),
        (LifecyclePhase::Review, CodexRole::Reviewer),
        (LifecyclePhase::Verify, CodexRole::Verifier),
    ] {
        let provenance = profiles.for_phase(phase).ok_or(LifecycleError::ProfileMismatch)?;
        let matches: u64 = transaction.query_row(
            "SELECT COUNT(*)
             FROM role_profiles p
             JOIN role_profile_state s ON s.profile_id=p.profile_id
             JOIN role_profile_revisions r
               ON r.profile_id=p.profile_id AND r.revision=s.active_revision
             WHERE p.profile_id=?1 AND p.role=?2 AND s.active_revision=?3
               AND r.definition_digest=?4 AND r.activated_unix_ms IS NOT NULL",
            params![
                provenance.profile_id.as_str(),
                role.as_str(),
                provenance.revision,
                provenance.definition_digest.to_string(),
            ],
            |row| row.get(0),
        )?;
        if matches != 1 {
            return Err(StoreError::LifecycleConflict(format!(
                "{}: profile is not bound to {}",
                provenance.profile_id,
                phase.as_str()
            )));
        }
    }
    Ok(())
}

fn validate_test_plan_certificates(
    transaction: &Transaction<'_>,
    spec: &LifecycleSpec,
    source_snapshot: Digest,
) -> Result<(), StoreError> {
    for binding in &spec.test_plans {
        let row: Option<(String, String, String, String, u16, String)> = transaction
            .query_row(
                "SELECT a.artifact_id, a.request_id, a.artifact_json, c.certificate_json,
                        a.format_revision, r.request_json
                 FROM artifact_validation_certificates c
                 JOIN artifacts a ON a.artifact_id=c.artifact_id
                 JOIN artifact_requests r ON r.request_id=a.request_id
                 WHERE c.certificate_id=?1 AND a.format_revision IN (2, ?3)
                   AND r.source_digest=?2",
                params![
                    binding.certificate_digest.to_string(),
                    source_snapshot.to_string(),
                    super::ACTION_REQUEST_STORAGE_FORMAT_REVISION,
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            artifact_id,
            request_id,
            artifact_json,
            certificate_json,
            storage_revision,
            request_json,
        )) = row
        else {
            return Err(StoreError::LifecycleConflict(
                "lifecycle test plan has no persisted validation certificate".to_owned(),
            ));
        };
        let (artifact, worker_artifact) =
            parse_semantic_artifact(&artifact_id, &request_id, &artifact_json)?;
        crate::semantic_validation::validate_parent_owned_test_plan_binding(
            &worker_artifact,
            &binding.plan,
        )
        .map_err(|_| {
            StoreError::LifecycleConflict(
                "lifecycle test plan differs from its certified artifact".to_owned(),
            )
        })?;
        let certificate: needle_core::ArtifactValidationCertificate =
            serde_json::from_str(&certificate_json)?;
        if storage_revision == super::ACTION_REQUEST_STORAGE_FORMAT_REVISION {
            validate_action_native_lifecycle_test_plan(
                &request_json,
                source_snapshot,
                &artifact,
                &certificate,
            )?;
        }
        if certificate.id.digest() != binding.certificate_digest
            || certificate.artifact.to_string() != artifact_id
            || certificate.test_plan_evidence.is_none()
            || !validation_certificate_is_structurally_canonical(&certificate)
        {
            return Err(StoreError::LifecycleConflict(
                "lifecycle test-plan certificate identity or evidence status is invalid".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validation_certificate_is_structurally_canonical(
    certificate: &needle_core::ArtifactValidationCertificate,
) -> bool {
    certificate.dependency_checks_digest == certificate.coverage.dependency_manifest_digest
        && certificate.id
            == crate::semantic_validation::validation_certificate_id(
                certificate.artifact,
                &certificate.input_artifacts,
                &certificate.evidence_ids,
                &certificate.coverage,
                certificate.validator_definition,
                certificate.test_plan_evidence,
            )
}

fn parse_semantic_artifact(
    stored_artifact_id: &str,
    stored_request_id: &str,
    artifact_json: &str,
) -> Result<(needle_core::Artifact, needle_core::SemanticWorkerArtifact), StoreError> {
    let artifact: needle_core::Artifact = serde_json::from_str(artifact_json)?;
    let worker_artifact: needle_core::SemanticWorkerArtifact =
        serde_json::from_value(artifact.payload.clone())?;
    let canonical_id =
        worker_artifact
            .canonical_artifact_id(artifact.contract.definition_digest)
            .ok_or_else(|| StoreError::LifecycleCorruption("semantic artifact bound".to_owned()))?;
    if artifact.id.to_string() != stored_artifact_id
        || artifact.request_id.to_string() != stored_request_id
        || artifact.contract.schema_id != needle_core::SEMANTIC_ARTIFACT_RESULT_SCHEMA_ID
        || artifact.contract.kind != worker_artifact.kind()
        || artifact.contract.cache_scope != artifact.dependency_manifest.scope
        || canonical_id.digest() != artifact.id
    {
        return Err(StoreError::LifecycleCorruption("semantic artifact identity".to_owned()));
    }
    Ok((artifact, worker_artifact))
}

fn parse_profile_anchor(
    profile_id: Option<String>,
    revision: Option<u64>,
    digest: Option<String>,
) -> Result<Option<RoleProfileProvenance>, StoreError> {
    match (profile_id, revision, digest) {
        (None, None, None) => Ok(None),
        (Some(profile_id), Some(revision), Some(digest)) => Ok(Some(
            RoleProfileProvenance::new(
                needle_core::RoleProfileId::new(profile_id)
                    .map_err(|_| StoreError::LifecycleCorruption("profile id".to_owned()))?,
                revision,
                Digest::parse(&digest)
                    .map_err(|_| StoreError::LifecycleCorruption("profile digest".to_owned()))?,
            )
            .map_err(|_| StoreError::LifecycleCorruption("profile anchor".to_owned()))?,
        )),
        _ => Err(StoreError::LifecycleCorruption("partial role-profile anchor".to_owned())),
    }
}

pub(super) trait LifecycleConnection {
    fn query_projection_row(
        &self,
        change_id: &ChangeId,
    ) -> rusqlite::Result<Option<LifecycleProjectionRow>>;
}

impl LifecycleConnection for rusqlite::Connection {
    fn query_projection_row(
        &self,
        change_id: &ChangeId,
    ) -> rusqlite::Result<Option<LifecycleProjectionRow>> {
        self.query_row(
            "SELECT lifecycle_id, source_snapshot_digest, state_digest, state_json, generation
             FROM change_lifecycles WHERE change_id=?1",
            [change_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()
    }
}

impl LifecycleConnection for Transaction<'_> {
    fn query_projection_row(
        &self,
        change_id: &ChangeId,
    ) -> rusqlite::Result<Option<LifecycleProjectionRow>> {
        self.query_row(
            "SELECT lifecycle_id, source_snapshot_digest, state_digest, state_json, generation
             FROM change_lifecycles WHERE change_id=?1",
            [change_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()
    }
}

pub(super) fn lifecycle_projection_in_transaction<C: LifecycleConnection>(
    connection: &C,
    change_id: &ChangeId,
) -> Result<Option<LifecycleProjection>, StoreError> {
    let Some((lifecycle_id, source_snapshot, stored_state_digest, state_json, generation)) =
        connection.query_projection_row(change_id)?
    else {
        return Ok(None);
    };
    let lifecycle: DevelopmentLifecycle = serde_json::from_str(&state_json)?;
    lifecycle.validate().map_err(StoreError::from)?;
    let state_digest = lifecycle.state_digest();
    if lifecycle.change_id != *change_id
        || lifecycle.id.to_string() != lifecycle_id
        || lifecycle.source_snapshot.to_string() != source_snapshot
        || state_digest.to_string() != stored_state_digest
        || lifecycle.generation != generation
    {
        return Err(StoreError::LifecycleCorruption(change_id.to_string()));
    }
    Ok(Some(LifecycleProjection { lifecycle, state_digest }))
}

fn lifecycle_events_in_connection(
    connection: &rusqlite::Connection,
    change_id: &ChangeId,
) -> Result<Vec<LifecycleEvent>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT payload_json, payload_digest FROM change_events
         WHERE change_id=?1 AND lifecycle_sequence IS NOT NULL
         ORDER BY lifecycle_sequence LIMIT ?2",
    )?;
    let events = statement
        .query_map(params![change_id.to_string(), needle_core::MAX_LIFECYCLE_EVENTS + 1], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .map(|row| {
            let (json, stored_digest) = row?;
            if Digest::blake3(json.as_bytes()).to_string() != stored_digest {
                return Err(StoreError::LifecycleCorruption(format!(
                    "{change_id}: lifecycle event payload digest"
                )));
            }
            let event: LifecycleEvent = serde_json::from_str(&json).map_err(|_| {
                StoreError::LifecycleCorruption(format!("{change_id}: lifecycle event JSON"))
            })?;
            if event.change_id != *change_id {
                return Err(StoreError::LifecycleCorruption(format!(
                    "{change_id}: lifecycle event change identity"
                )));
            }
            Ok(event)
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    if events.len() > needle_core::MAX_LIFECYCLE_EVENTS {
        return Err(StoreError::LifecycleCorruption(format!("{change_id}: lifecycle event count")));
    }
    Ok(events)
}

fn replay_lifecycle_in_transaction(
    transaction: &Transaction<'_>,
    change_id: &ChangeId,
) -> Result<LifecycleProjection, StoreError> {
    replay_lifecycle_and_events_in_transaction(transaction, change_id)
        .map(|(projection, _)| projection)
}

fn replay_lifecycle_and_events_in_transaction(
    transaction: &Transaction<'_>,
    change_id: &ChangeId,
) -> Result<(LifecycleProjection, Vec<LifecycleEvent>), StoreError> {
    let persisted = lifecycle_projection_in_transaction(transaction, change_id)?
        .ok_or_else(|| StoreError::LifecycleNotFound(change_id.to_string()))?;
    let events = lifecycle_events_in_connection(transaction, change_id)?;
    let replayed = DevelopmentLifecycle::replay(&events)?;
    let replayed = LifecycleProjection::new(replayed)?;
    if replayed != persisted {
        return Err(StoreError::LifecycleCorruption(format!(
            "{change_id}: event replay differs from current projection"
        )));
    }
    Ok((replayed, events))
}

pub(super) fn persist_transition(
    transaction: &Transaction<'_>,
    projection: &LifecycleProjection,
    expected_state_digest: Digest,
    transition: LifecycleTransition,
    created_unix_ms: u64,
) -> Result<LifecycleProjection, StoreError> {
    if projection.state_digest != expected_state_digest {
        return Err(StoreError::LifecycleConflict(format!(
            "{}: state digest changed",
            projection.lifecycle.change_id
        )));
    }
    let (next, event) = projection.lifecycle.transition(transition, created_unix_ms)?;
    let next = LifecycleProjection::new(next)?;
    let changed = transaction.execute(
        "UPDATE change_lifecycles
         SET state_digest=?2, generation=?3, state_json=?4, updated_unix_ms=?5
         WHERE change_id=?1 AND state_digest=?6 AND generation=?7",
        params![
            projection.lifecycle.change_id.to_string(),
            next.state_digest.to_string(),
            next.lifecycle.generation,
            serde_json::to_string(&next.lifecycle)?,
            created_unix_ms,
            expected_state_digest.to_string(),
            projection.lifecycle.generation,
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::LifecycleConflict(format!(
            "{}: concurrent transition",
            projection.lifecycle.change_id
        )));
    }
    insert_lifecycle_event(transaction, &event, "lifecycle_transitioned")?;
    Ok(next)
}

fn insert_lifecycle_event(
    transaction: &Transaction<'_>,
    event: &LifecycleEvent,
    event_type: &str,
) -> Result<(), StoreError> {
    let payload_json = serde_json::to_string(event)?;
    let payload_digest = Digest::blake3(payload_json.as_bytes());
    transaction.execute(
        "INSERT INTO change_events(
            change_id, event_type, payload_digest, payload_json,
            created_unix_ms, lifecycle_sequence
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            event.change_id.to_string(),
            event_type,
            payload_digest.to_string(),
            payload_json,
            event.created_unix_ms,
            event.sequence,
        ],
    )?;
    Ok(())
}

enum LifecycleExploreReuseCandidate {
    Ineligible,
    ResolverAuthorized(LifecycleExploreReuseAuthority),
    LifecycleAuthorized(Box<LifecycleExploreReuseCompletion>),
}

fn lifecycle_explore_reuse_candidate(
    transaction: &Transaction<'_>,
    projection: &LifecycleProjection,
    summary: &ShadowActionResolutionSummary,
) -> Result<LifecycleExploreReuseCandidate, StoreError> {
    let lifecycle = &projection.lifecycle;
    let Some(plan) = lifecycle.spec.explore_action_plan.as_ref() else {
        return Ok(LifecycleExploreReuseCandidate::Ineligible);
    };
    if lifecycle.phase != LifecyclePhase::Explore
        || lifecycle.status != LifecycleStatus::Active
        || plan.actions.len() != 1
        || plan.repository_id() == Digest([0; 32])
        || plan.source_snapshot() != Some(lifecycle.source_snapshot)
        || summary.resolution != ShadowActionResolutionKind::Exact
        || summary.artifacts.len() != 1
        || summary.artifact_origin_requests.len() != 1
        || summary.validation_certificates.len() != 1
    {
        return Ok(LifecycleExploreReuseCandidate::Ineligible);
    }
    let request = &plan.actions[0];
    let Some(action) = crate::built_in_action_contracts()
        .iter()
        .find(|definition| definition.contract.id == request.contract)
    else {
        return Ok(LifecycleExploreReuseCandidate::Ineligible);
    };
    if summary.validate_for_request_and_action(request, action).is_err() {
        return Ok(LifecycleExploreReuseCandidate::Ineligible);
    }
    let capability = implementation_location_exact_capability();
    if capability.action_contract != action.contract.id
        || capability.definition_digest == Digest([0; 32])
    {
        return Ok(LifecycleExploreReuseCandidate::Ineligible);
    }

    let observation_json: Option<String> = transaction
        .query_row(
            "SELECT observation_json
             FROM lifecycle_explore_action_observations
             WHERE lifecycle_id=?1 AND expected_state_digest=?2",
            params![lifecycle.id.to_string(), projection.state_digest.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(observation_json) = observation_json else {
        return Ok(LifecycleExploreReuseCandidate::Ineligible);
    };
    let observation: LifecycleExploreShadowObservation = serde_json::from_str(&observation_json)
        .map_err(|error| StoreError::LifecycleExploreObservationCorruption(error.to_string()))?;
    if observation.validate_for_execution(lifecycle.id, projection.state_digest, plan).is_err()
        || observation.resolution != LifecycleExploreShadowResolutionKind::Resolved
        || observation.actions.as_slice() != std::slice::from_ref(summary)
    {
        return Ok(LifecycleExploreReuseCandidate::Ineligible);
    }

    let effective = match super::action_assurance::read_effective_decision(transaction, capability)
    {
        Ok(value) => value,
        Err(
            StoreError::ActionAssuranceValidation(_) | StoreError::ActionAssuranceCorruption(_),
        ) => {
            return Ok(LifecycleExploreReuseCandidate::Ineligible);
        }
        Err(error) => return Err(error),
    };
    let Some(effective) = effective else {
        return Ok(LifecycleExploreReuseCandidate::Ineligible);
    };
    let decision = &effective.decision;
    if decision.selected_mode != CapabilityMode::Authoritative
        || !decision.automatic_resolver_consumption_approved
    {
        return Ok(LifecycleExploreReuseCandidate::Ineligible);
    }
    let authority = LifecycleExploreReuseAuthority {
        capability_class: capability.id,
        capability_definition_digest: capability.definition_digest,
        evidence: effective.evidence.id,
        decision: decision.id,
    };
    authority.validate()?;
    if !decision.automatic_lifecycle_consumption_approved {
        return Ok(LifecycleExploreReuseCandidate::ResolverAuthorized(authority));
    }

    let Some(sufficiency_certificate) = summary.sufficiency_certificate else {
        return Ok(LifecycleExploreReuseCandidate::Ineligible);
    };
    let material: Option<(String, u16, String, u16, String)> = transaction
        .query_row(
            "SELECT r.request_json, r.format_revision,
                    a.artifact_json, a.format_revision, c.certificate_json
             FROM artifact_requests r
             JOIN artifacts a ON a.artifact_id=?2
             JOIN artifact_validation_certificates c
               ON c.artifact_id=a.artifact_id AND c.certificate_id=?3
             WHERE r.request_id=?1",
            params![
                summary.request.to_string(),
                summary.artifacts[0].to_string(),
                summary.validation_certificates[0].to_string(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()?;
    let Some((request_json, request_revision, artifact_json, artifact_revision, certificate_json)) =
        material
    else {
        return Ok(LifecycleExploreReuseCandidate::Ineligible);
    };
    if request_revision != super::ACTION_REQUEST_STORAGE_FORMAT_REVISION
        || !matches!(artifact_revision, 2 | 3)
    {
        return Ok(LifecycleExploreReuseCandidate::Ineligible);
    }
    let stored_request: ActionRequest = serde_json::from_str(&request_json)
        .map_err(|error| StoreError::LifecycleCorruption(error.to_string()))?;
    let artifact: Artifact = serde_json::from_str(&artifact_json)
        .map_err(|error| StoreError::LifecycleCorruption(error.to_string()))?;
    let certificate: ArtifactValidationCertificate = serde_json::from_str(&certificate_json)
        .map_err(|error| StoreError::LifecycleCorruption(error.to_string()))?;
    let descriptor =
        match crate::reuse_descriptor::derive_shadow_reuse_descriptor_from_validated_pair(
            &artifact,
            &certificate,
        ) {
            Ok(descriptor) => descriptor,
            Err(_) => return Ok(LifecycleExploreReuseCandidate::Ineligible),
        };
    let origin_request = summary.artifact_origin_requests[0];
    if stored_request != *request
        || stored_request.semantic_id() != summary.request
        || stored_request.artifact_request.repository_id != plan.repository_id()
        || stored_request.artifact_request.source_snapshot_digest != lifecycle.source_snapshot
        || artifact.id != summary.artifacts[0].digest()
        || artifact.request_id != origin_request.digest()
        || certificate.id != summary.validation_certificates[0]
        || !validation_certificate_is_structurally_canonical(&certificate)
        || descriptor.artifact != summary.artifacts[0]
        || descriptor.exact_request != origin_request
        || descriptor.origin_request != origin_request
        || descriptor.validation_certificate != summary.validation_certificates[0]
        || descriptor.action_contract != action.contract.id
        || descriptor.semantic_world_digest != summary.semantic_world_digest
    {
        return Ok(LifecycleExploreReuseCandidate::Ineligible);
    }
    let mapping_exists = if summary.request == origin_request {
        transaction
            .query_row(
                "SELECT 1 FROM artifact_origins WHERE artifact_id=?1 AND request_id=?2 LIMIT 1",
                params![summary.artifacts[0].to_string(), origin_request.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
    } else {
        transaction
            .query_row(
                "SELECT 1 FROM action_request_identity_mappings
                 WHERE action_request_id=?1 AND legacy_request_id=?2
                   AND artifact_id=?3 AND validation_certificate_id=?4
                   AND action_semantic_definition_digest=?5 LIMIT 1",
                params![
                    summary.request.to_string(),
                    origin_request.to_string(),
                    summary.artifacts[0].to_string(),
                    summary.validation_certificates[0].to_string(),
                    action.contract.semantic_definition_digest.to_string(),
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
    };
    if !mapping_exists {
        return Ok(LifecycleExploreReuseCandidate::Ineligible);
    }

    let completion = LifecycleExploreReuseCompletion {
        authority,
        action_request: summary.request,
        origin_request,
        artifact: summary.artifacts[0],
        validation_certificate: summary.validation_certificates[0],
        selected_plan: summary.selected_plan,
        sufficiency_certificate,
        repository_id: plan.repository_id(),
        source_snapshot: lifecycle.source_snapshot,
        resolution_definition_digest: summary.definition_digest,
    };
    completion.validate()?;
    Ok(LifecycleExploreReuseCandidate::LifecycleAuthorized(Box::new(completion)))
}

fn validate_transition_artifacts(
    transaction: &Transaction<'_>,
    lifecycle: &DevelopmentLifecycle,
    transition: &LifecycleTransition,
) -> Result<(), StoreError> {
    match transition {
        LifecycleTransition::CompleteExplore { artifacts, .. } => {
            for artifact in artifacts {
                let row: Option<(String, String, String, String)> = transaction
                    .query_row(
                        "SELECT a.artifact_id, a.request_id, a.artifact_json, c.certificate_json
                         FROM artifacts a
                         JOIN artifact_requests r ON r.request_id=a.request_id
                         JOIN artifact_validation_certificates c ON c.artifact_id=a.artifact_id
                         WHERE a.artifact_id=?1 AND a.format_revision IN (2, 3)
                           AND r.source_digest=?2
                         ORDER BY c.issued_unix_ms DESC, c.certificate_id LIMIT 1",
                        params![artifact.id.to_string(), lifecycle.source_snapshot.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .optional()?;
                let Some((artifact_id, request_id, json, certificate_json)) = row else {
                    return Err(StoreError::LifecycleConflict(format!(
                        "{}: exploration artifact is unavailable",
                        lifecycle.change_id
                    )));
                };
                let (_, worker_artifact) =
                    parse_semantic_artifact(&artifact_id, &request_id, &json)?;
                if matches!(worker_artifact, needle_core::SemanticWorkerArtifact::TestPlan { .. }) {
                    return Err(StoreError::LifecycleConflict(format!(
                        "{}: test-plan artifact cannot satisfy exploration",
                        lifecycle.change_id
                    )));
                }
                let certificate: needle_core::ArtifactValidationCertificate =
                    serde_json::from_str(&certificate_json)?;
                if certificate.artifact.to_string() != artifact.id.to_string()
                    || !validation_certificate_is_structurally_canonical(&certificate)
                {
                    return Err(StoreError::LifecycleConflict(format!(
                        "{}: exploration certificate identity is invalid",
                        lifecycle.change_id
                    )));
                }
            }
        }
        LifecycleTransition::CompleteExploreFromReuse { .. } => {
            return Err(StoreError::LifecycleConflict(format!(
                "{}: Explore reuse requires the typed authority boundary",
                lifecycle.change_id
            )));
        }
        LifecycleTransition::CompleteImplement { patch, .. } => {
            let row: Option<(u32, String)> = transaction
                .query_row(
                    "SELECT p.revision, p.source_snapshot_digest
                     FROM patch_artifacts p
                     JOIN change_requests c
                       ON c.change_id=p.change_id AND c.latest_patch_revision=p.revision
                     WHERE p.change_id=?1 AND p.patch_id=?2",
                    params![lifecycle.change_id.to_string(), patch.patch_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if row != Some((patch.revision, lifecycle.source_snapshot.to_string())) {
                return Err(StoreError::LifecycleConflict(format!(
                    "{}: patch is not the latest source-bound revision",
                    lifecycle.change_id
                )));
            }
        }
        LifecycleTransition::BindTestPlans { plans, .. } => {
            for resolved in plans {
                validate_resolved_test_plan(transaction, lifecycle, resolved)?;
            }
        }
        LifecycleTransition::CompleteTest { results, .. } => {
            for (index, (binding, result)) in
                lifecycle.active_test_plans()?.into_iter().zip(results).enumerate()
            {
                let Some(evidence_id) = result.evidence_id.as_deref() else {
                    if result.action_evidence_artifact.is_some() {
                        return Err(StoreError::LifecycleConflict(format!(
                            "{}: action test evidence has no command evidence",
                            lifecycle.change_id
                        )));
                    }
                    continue;
                };
                let evidence_json: Option<String> = transaction
                    .query_row(
                        "SELECT evidence_json FROM command_evidence WHERE evidence_id=?1",
                        [evidence_id],
                        |row| row.get(0),
                    )
                    .optional()?;
                let Some(evidence_json) = evidence_json else {
                    return Err(StoreError::LifecycleConflict(format!(
                        "{}: test evidence is unavailable",
                        lifecycle.change_id
                    )));
                };
                let command_evidence: CommandExecutionEvidence =
                    serde_json::from_str(&evidence_json)?;
                if (result.action_evidence_artifact.is_none()
                    && command_evidence.source_snapshot_digest != lifecycle.source_snapshot)
                    || command_evidence.runner != binding.plan.runner
                    || command_evidence.argv != binding.plan.argv
                    || command_evidence.test_identifier.as_deref()
                        != Some(binding.plan.test_identifier.as_str())
                {
                    return Err(StoreError::LifecycleConflict(format!(
                        "{}: test evidence differs from the frozen plan",
                        lifecycle.change_id
                    )));
                }
                if result.passed {
                    crate::validate_test_evidence(&binding.plan, &command_evidence).map_err(
                        |_| {
                            StoreError::LifecycleConflict(format!(
                                "{}: passing test evidence is invalid",
                                lifecycle.change_id
                            ))
                        },
                    )?;
                } else if result.executed
                    && command_evidence.exit_status == Some(0)
                    && command_evidence.infrastructure_failure.is_none()
                {
                    return Err(StoreError::LifecycleConflict(format!(
                        "{}: failed test result contradicts evidence",
                        lifecycle.change_id
                    )));
                }
                if let Some(action_artifact) = result.action_evidence_artifact {
                    validate_action_native_test_evidence(
                        transaction,
                        lifecycle,
                        index,
                        binding,
                        result,
                        action_artifact,
                        &command_evidence,
                    )?;
                }
            }
        }
        LifecycleTransition::CompleteReview { review, .. } => {
            validate_review_artifact(transaction, lifecycle, review)?;
        }
        LifecycleTransition::CompleteVerify { worker, verification } => {
            let json: Option<String> = transaction
                .query_row(
                    "SELECT artifact_json FROM verification_artifacts
                     WHERE verification_id=?1 AND change_id=?2 AND patch_id=?3",
                    params![
                        verification.verification_id.to_string(),
                        lifecycle.change_id.to_string(),
                        verification.patch_id.to_string(),
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(json) = json else {
                return Err(StoreError::LifecycleConflict(format!(
                    "{}: verification artifact is unavailable",
                    lifecycle.change_id
                )));
            };
            let artifact: VerificationArtifact = serde_json::from_str(&json)?;
            if !artifact.is_canonical()
                || artifact.id != verification.verification_id
                || artifact.verdict != verification.verdict
                || lifecycle.patch.as_ref().map(|patch| patch.patch_id) != Some(artifact.patch_id)
            {
                return Err(StoreError::LifecycleConflict(format!(
                    "{}: verification artifact is not current and canonical",
                    lifecycle.change_id
                )));
            }
            if artifact.action_request.is_some() {
                validate_action_native_verification(transaction, lifecycle, &artifact)?;
            } else if artifact.verifier_definition != worker.profile.definition_digest {
                return Err(StoreError::LifecycleConflict(format!(
                    "{}: verification artifact does not match the frozen verifier profile",
                    lifecycle.change_id
                )));
            }
        }
        LifecycleTransition::Cancel { .. } | LifecycleTransition::Fail { .. } => {}
        LifecycleTransition::ConsumeRepair
        | LifecycleTransition::ApproveApply { .. }
        | LifecycleTransition::StartApply { .. }
        | LifecycleTransition::FinishApply { .. } => {
            return Err(StoreError::LifecycleConflict(format!(
                "{}: reserved lifecycle transition",
                lifecycle.change_id
            )));
        }
    }
    Ok(())
}

fn validate_action_native_test_evidence(
    transaction: &Transaction<'_>,
    lifecycle: &DevelopmentLifecycle,
    index: usize,
    binding: &LifecycleTestPlanBinding,
    result: &LifecycleTestResult,
    action_artifact_id: ArtifactId,
    command_evidence: &CommandExecutionEvidence,
) -> Result<(), StoreError> {
    let resolved = lifecycle.resolved_test_plans.get(index).ok_or_else(|| {
        StoreError::LifecycleConflict(format!(
            "{}: action test evidence requires a parent-resolved TestPlan",
            lifecycle.change_id
        ))
    })?;
    let row: Option<(String, String)> = transaction
        .query_row(
            "SELECT a.artifact_json, c.certificate_json
             FROM artifacts a
             JOIN opaque_action_validation_certificates c ON c.artifact_id=a.artifact_id
             WHERE a.artifact_id=?1 AND c.action_contract_id=?2
             ORDER BY c.issued_unix_ms DESC, c.certificate_id
             LIMIT 1",
            params![action_artifact_id.to_string(), TESTS_EXECUTE_ACTION_CONTRACT],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((artifact_json, certificate_json)) = row else {
        return Err(StoreError::LifecycleConflict(format!(
            "{}: action-native test evidence artifact is unavailable",
            lifecycle.change_id
        )));
    };
    let artifact: Artifact = serde_json::from_str(&artifact_json)?;
    let certificate: ActionOutputValidationCertificate = serde_json::from_str(&certificate_json)?;
    certificate.validate().map_err(|error| {
        StoreError::LifecycleConflict(format!(
            "{}: action-native test certificate is invalid: {error}",
            lifecycle.change_id
        ))
    })?;
    let crate::ChangeActionOutput::TestExecution(action_evidence) =
        crate::ChangeActionOutput::from_artifact(&artifact).map_err(|error| {
            StoreError::LifecycleConflict(format!(
                "{}: action-native test payload is invalid: {error}",
                lifecycle.change_id
            ))
        })?
    else {
        return Err(StoreError::LifecycleConflict(format!(
            "{}: action-native test artifact has the wrong output kind",
            lifecycle.change_id
        )));
    };
    let definition = crate::built_in_action_contracts()
        .iter()
        .find(|definition| definition.contract.id.as_str() == TESTS_EXECUTE_ACTION_CONTRACT)
        .expect("built-in test execution action is registered");
    let expected_status = match action_evidence.status {
        TestExecutionStatus::Passed => (true, true, true),
        TestExecutionStatus::Failed => (true, true, false),
        TestExecutionStatus::Unavailable => (false, false, false),
        TestExecutionStatus::Inconclusive => (true, false, false),
    };
    let current_patch = lifecycle.patch.as_ref().ok_or_else(|| {
        StoreError::LifecycleConflict(format!(
            "{}: action-native test evidence has no lifecycle patch",
            lifecycle.change_id
        ))
    })?;
    if artifact.id != action_artifact_id.digest()
        || artifact.request_id != action_evidence.action_request.digest()
        || artifact.contract.id != definition.output_contract_id
        || artifact.contract.revision != definition.output_contract_revision
        || artifact.contract.definition_digest != definition.output_contract_definition_digest
        || certificate.artifact != action_artifact_id
        || certificate.action_contract != definition.contract.id
        || certificate.action_semantic_definition_digest
            != definition.contract.semantic_definition_digest
        || certificate.action_validation_definition_digest
            != definition.contract.validation_definition_digest
        || certificate.output_contract_definition_digest
            != definition.output_contract_definition_digest
        || certificate.validator_definition_digest != definition.validator_definition_digest
        || action_evidence.change_id != lifecycle.change_id
        || action_evidence.patch_id != current_patch.patch_id
        || action_evidence.test_plan_artifact != resolved.artifact
        || action_evidence.test_plan_digest != binding.plan_digest()
        || action_evidence.command_evidence_id.as_deref() != result.evidence_id.as_deref()
        || action_evidence.source_snapshot != lifecycle.source_snapshot
        || action_evidence.execution_snapshot != Some(command_evidence.source_snapshot_digest)
        || action_evidence.command_digest != binding.plan.identity_digest()
        || action_evidence.exit_status != command_evidence.exit_status
        || action_evidence.output_digest != command_evidence.output_digest
        || action_evidence.duration_ms != command_evidence.duration_ms
        || expected_status != (result.available, result.executed, result.passed)
    {
        return Err(StoreError::LifecycleConflict(format!(
            "{}: action-native test evidence differs from the lifecycle result",
            lifecycle.change_id
        )));
    }
    Ok(())
}

fn validate_action_native_verification(
    transaction: &Transaction<'_>,
    lifecycle: &DevelopmentLifecycle,
    verification: &VerificationArtifact,
) -> Result<(), StoreError> {
    let row: Option<(String, String)> = transaction
        .query_row(
            "SELECT a.artifact_json, c.certificate_json
             FROM artifacts a
             JOIN opaque_action_validation_certificates c ON c.artifact_id=a.artifact_id
             WHERE c.action_contract_id=?1 AND c.source_payload_digest=?2
             ORDER BY c.issued_unix_ms DESC, c.certificate_id DESC
             LIMIT 1",
            params![PATCH_VERIFY_ACTION_CONTRACT, verification.id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((artifact_json, certificate_json)) = row else {
        return Err(StoreError::LifecycleConflict(format!(
            "{}: action-native verification artifact is unavailable",
            lifecycle.change_id
        )));
    };
    let artifact: Artifact = serde_json::from_str(&artifact_json)?;
    let certificate: ActionOutputValidationCertificate = serde_json::from_str(&certificate_json)?;
    certificate.validate().map_err(|error| {
        StoreError::LifecycleConflict(format!(
            "{}: action-native verification certificate is invalid: {error}",
            lifecycle.change_id
        ))
    })?;
    let crate::ChangeActionOutput::PatchVerification(action_verification) =
        crate::ChangeActionOutput::from_artifact(&artifact).map_err(|error| {
            StoreError::LifecycleConflict(format!(
                "{}: action-native verification payload is invalid: {error}",
                lifecycle.change_id
            ))
        })?
    else {
        return Err(StoreError::LifecycleConflict(format!(
            "{}: action-native verification artifact has the wrong output kind",
            lifecycle.change_id
        )));
    };
    let definition = crate::built_in_action_contracts()
        .iter()
        .find(|definition| definition.contract.id.as_str() == PATCH_VERIFY_ACTION_CONTRACT)
        .expect("built-in patch verification action is registered");
    let patch_id = lifecycle.patch.as_ref().map(|patch| patch.patch_id).ok_or_else(|| {
        StoreError::LifecycleConflict(format!(
            "{}: action-native verification has no lifecycle patch",
            lifecycle.change_id
        ))
    })?;
    let patch_artifact_id: Option<String> = transaction
        .query_row(
            "SELECT artifact_id
             FROM opaque_action_validation_certificates
             WHERE action_contract_id=?1 AND source_payload_digest=?2
             ORDER BY issued_unix_ms DESC, certificate_id DESC
             LIMIT 1",
            params![PATCH_PROPOSE_ACTION_CONTRACT, patch_id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(patch_artifact_id) = patch_artifact_id else {
        return Err(StoreError::LifecycleConflict(format!(
            "{}: action-native verification patch artifact is unavailable",
            lifecycle.change_id
        )));
    };
    let patch_artifact_id = Digest::parse(&patch_artifact_id)
        .map(ArtifactId::new)
        .map_err(|_| StoreError::Digest(patch_artifact_id))?;
    let request_digest: String = transaction.query_row(
        "SELECT request_digest FROM change_requests WHERE change_id=?1",
        params![lifecycle.change_id.to_string()],
        |row| row.get(0),
    )?;
    let request_digest =
        Digest::parse(&request_digest).map_err(|_| StoreError::Digest(request_digest))?;
    let mut expected_test_evidence = lifecycle
        .test_results
        .iter()
        .map(|result| {
            result.action_evidence_artifact.ok_or_else(|| {
                StoreError::LifecycleConflict(format!(
                    "{}: action-native verification requires certified test evidence",
                    lifecycle.change_id
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    expected_test_evidence.sort_unstable();
    if expected_test_evidence.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(StoreError::LifecycleConflict(format!(
            "{}: action-native test evidence is not unique",
            lifecycle.change_id
        )));
    }
    let mut expected_inputs = Vec::with_capacity(lifecycle.test_results.len().saturating_add(1));
    expected_inputs.push(patch_artifact_id);
    expected_inputs.extend(expected_test_evidence.iter().copied());
    expected_inputs.sort_unstable();
    if expected_inputs.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(StoreError::LifecycleConflict(format!(
            "{}: action-native verification inputs are not unique",
            lifecycle.change_id
        )));
    }
    let request_id = verification.action_request.expect("action-native branch checked");
    if action_verification != *verification
        || verification.requirements_digest != Some(request_digest)
        || verification.input_test_evidence_artifacts != expected_test_evidence
        || artifact.request_id != request_id.digest()
        || artifact.contract.id != definition.output_contract_id
        || artifact.contract.revision != definition.output_contract_revision
        || artifact.contract.definition_digest != definition.output_contract_definition_digest
        || Artifact::compute_content_id(&artifact.contract, &artifact.payload)
            .map_err(StoreError::from)?
            .digest()
            != artifact.id
        || certificate.artifact.digest() != artifact.id
        || certificate.input_artifacts != expected_inputs
        || certificate.action_contract != definition.contract.id
        || certificate.action_semantic_definition_digest
            != definition.contract.semantic_definition_digest
        || certificate.action_validation_definition_digest
            != definition.contract.validation_definition_digest
        || certificate.output_contract_definition_digest
            != definition.output_contract_definition_digest
        || certificate.source_payload_digest != verification.id.0
        || certificate.dependency_manifest_digest
            != crate::semantic_validation::manifest_digest(&artifact.dependency_manifest)
        || certificate.validator_definition_digest != definition.validator_definition_digest
        || certificate.issued_unix_ms != artifact.created_unix_ms
    {
        return Err(StoreError::LifecycleConflict(format!(
            "{}: action-native verification differs from its certified action output",
            lifecycle.change_id
        )));
    }
    Ok(())
}

fn validate_resolved_test_plan(
    transaction: &Transaction<'_>,
    lifecycle: &DevelopmentLifecycle,
    resolved: &needle_core::LifecycleResolvedTestPlan,
) -> Result<(), StoreError> {
    resolved.validate()?;
    let row: Option<(String, String, String, String, u16)> = transaction
        .query_row(
            "SELECT a.artifact_id, a.request_id, a.artifact_json, c.certificate_json,
                    a.format_revision
             FROM artifacts a
             JOIN artifact_requests r ON r.request_id=a.request_id
             JOIN artifact_validation_certificates c ON c.artifact_id=a.artifact_id
             WHERE a.artifact_id=?1 AND c.certificate_id=?2 AND r.source_digest=?3
             LIMIT 1",
            params![
                resolved.artifact.to_string(),
                resolved.binding.certificate_digest.to_string(),
                lifecycle.source_snapshot.to_string(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()?;
    let Some((artifact_id, request_id, artifact_json, certificate_json, storage_revision)) = row
    else {
        return Err(StoreError::LifecycleConflict(format!(
            "{}: resolved TestPlan is unavailable or stale",
            lifecycle.change_id
        )));
    };
    let (artifact, worker_artifact) =
        parse_semantic_artifact(&artifact_id, &request_id, &artifact_json)?;
    if !matches!(worker_artifact, SemanticWorkerArtifact::TestPlan { .. }) {
        return Err(StoreError::LifecycleConflict(format!(
            "{}: resolved artifact is not a TestPlan",
            lifecycle.change_id
        )));
    }
    let certificate: needle_core::ArtifactValidationCertificate =
        serde_json::from_str(&certificate_json)?;
    if certificate.artifact != resolved.artifact
        || !validation_certificate_is_structurally_canonical(&certificate)
    {
        return Err(StoreError::LifecycleConflict(format!(
            "{}: resolved TestPlan certificate is invalid",
            lifecycle.change_id
        )));
    }
    if storage_revision == super::ACTION_REQUEST_STORAGE_FORMAT_REVISION {
        let request_json: String = transaction.query_row(
            "SELECT request_json FROM artifact_requests WHERE request_id=?1",
            [request_id],
            |row| row.get(0),
        )?;
        validate_action_native_lifecycle_test_plan(
            &request_json,
            lifecycle.source_snapshot,
            &artifact,
            &certificate,
        )?;
    }
    crate::semantic_validation::validate_parent_owned_test_plan_binding(
        &worker_artifact,
        &resolved.binding.plan,
    )
    .map_err(|_| {
        StoreError::LifecycleConflict(format!(
            "{}: resolved TestPlan command differs from its artifact",
            lifecycle.change_id
        ))
    })?;
    Ok(())
}

fn validate_review_artifact(
    transaction: &Transaction<'_>,
    lifecycle: &DevelopmentLifecycle,
    review: &ReviewArtifact,
) -> Result<(), StoreError> {
    let request_json: String = transaction.query_row(
        "SELECT request_json FROM change_requests WHERE change_id=?1",
        [lifecycle.change_id.to_string()],
        |row| row.get(0),
    )?;
    let request: ChangeRequest = serde_json::from_str(&request_json)?;
    let expected = request.acceptance_criteria.iter().map(Digest::blake3).collect::<BTreeSet<_>>();
    let observed = review
        .acceptance_coverage
        .iter()
        .map(|coverage| coverage.criterion_digest)
        .collect::<BTreeSet<_>>();
    if expected != observed {
        return Err(StoreError::LifecycleConflict(format!(
            "{}: review coverage differs from acceptance criteria",
            lifecycle.change_id
        )));
    }
    Ok(())
}

pub(super) fn require_lifecycle_worker_phase(
    transaction: &Transaction<'_>,
    change_id: &ChangeId,
    phase: LifecyclePhase,
    provenance: Option<&RoleProfileProvenance>,
) -> Result<bool, StoreError> {
    let Some(projection) = lifecycle_projection_in_transaction(transaction, change_id)? else {
        return Ok(false);
    };
    if projection.lifecycle.phase != phase
        || projection.lifecycle.status != LifecycleStatus::Active
        || projection.lifecycle.spec.profiles.for_phase(phase) != provenance
    {
        return Err(StoreError::LifecycleConflict(format!(
            "{change_id}: worker write is outside the active lifecycle phase"
        )));
    }
    Ok(true)
}

pub(super) fn consume_lifecycle_repair(
    transaction: &Transaction<'_>,
    change_id: &ChangeId,
    patch_id: PatchId,
    verification_id: VerificationArtifactId,
    created_unix_ms: u64,
) -> Result<(), StoreError> {
    let Some(projection) = lifecycle_projection_in_transaction(transaction, change_id)? else {
        return Ok(());
    };
    if projection.lifecycle.patch.as_ref().map(|patch| patch.patch_id) != Some(patch_id)
        || projection
            .lifecycle
            .verification
            .as_ref()
            .map(|verification| verification.verification_id)
            != Some(verification_id)
    {
        return Err(StoreError::LifecycleConflict(format!(
            "{change_id}: repair artifacts differ from lifecycle"
        )));
    }
    persist_transition(
        transaction,
        &projection,
        projection.state_digest,
        LifecycleTransition::ConsumeRepair,
        created_unix_ms,
    )?;
    Ok(())
}

pub(super) fn fail_lifecycle(
    transaction: &Transaction<'_>,
    change_id: &ChangeId,
    reason: LifecycleReason,
    created_unix_ms: u64,
) -> Result<(), StoreError> {
    let Some(projection) = lifecycle_projection_in_transaction(transaction, change_id)? else {
        return Ok(());
    };
    if projection.lifecycle.status != LifecycleStatus::Active
        || !matches!(
            projection.lifecycle.phase,
            LifecyclePhase::Explore | LifecyclePhase::Implement
        )
    {
        return Err(StoreError::LifecycleConflict(format!(
            "{change_id}: preparation failure is outside an active preparation phase"
        )));
    }
    persist_transition(
        transaction,
        &projection,
        projection.state_digest,
        LifecycleTransition::Fail { reason },
        created_unix_ms,
    )?;
    Ok(())
}

pub(super) fn begin_lifecycle_apply(
    transaction: &Transaction<'_>,
    change_id: &ChangeId,
    expected_state_digest: Option<Digest>,
    apply_id: ChangeApplyId,
    patch_id: PatchId,
    verification_id: VerificationArtifactId,
    created_unix_ms: u64,
) -> Result<(), StoreError> {
    let lifecycle = lifecycle_projection_in_transaction(transaction, change_id)?;
    match (lifecycle, expected_state_digest) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(StoreError::LifecycleNotFound(change_id.to_string())),
        (Some(_), None) => Err(StoreError::LifecycleConflict(format!(
            "{change_id}: lifecycle apply requires its current state digest"
        ))),
        (Some(projection), Some(expected)) => {
            if projection.lifecycle.patch.as_ref().map(|patch| patch.patch_id) != Some(patch_id)
                || projection
                    .lifecycle
                    .verification
                    .as_ref()
                    .map(|verification| verification.verification_id)
                    != Some(verification_id)
            {
                return Err(StoreError::LifecycleConflict(format!(
                    "{change_id}: apply artifacts differ from approved lifecycle"
                )));
            }
            persist_transition(
                transaction,
                &projection,
                expected,
                LifecycleTransition::StartApply { apply_id },
                created_unix_ms,
            )?;
            Ok(())
        }
    }
}

pub(super) fn finish_lifecycle_apply(
    transaction: &Transaction<'_>,
    change_id: &ChangeId,
    apply_id: ChangeApplyId,
    status: ChangeApplyStatus,
    completed_unix_ms: u64,
) -> Result<(), StoreError> {
    let Some(projection) = lifecycle_projection_in_transaction(transaction, change_id)? else {
        return Ok(());
    };
    persist_transition(
        transaction,
        &projection,
        projection.state_digest,
        LifecycleTransition::FinishApply { apply_id, status },
        completed_unix_ms,
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "lifecycles/tests.rs"]
pub(crate) mod tests;
