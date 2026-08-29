use crate::reviewer::{CodexReviewWorker, ReviewActionRequest, ReviewRefreshAdvisory};
use crate::test_executor::{CodexTestExecutor, TestExecutionBinding};
use crate::verifier::{CertifiedTestExecutionInput, CodexVerifier, FreshVerificationRequest};
use crate::{CodexPatchWorker, PatchContextItem, ProposeActionBinding};
use needle_core::{
    ActionContractId, ApplyReceipt, ApprovalDecisionSource, CacheScope, CanonicalHasher,
    ChangeActionInput, DependencyLocator, DependencyManifest, Digest, LifecycleStatus,
    LifecycleUsage, ManifestProvenance, ManifestTransition, PartitionKeyMapping, PartitionRef,
    PatchArtifact, RepositoryContextId, ReviewInspectionTarget, ReviewReport, StateDelta,
    VerificationStatus, WorkerConfig, review_inspection_context_digest,
};
use needle_runtime::{
    ChangeActionOutput, ChangeActionProvider, ChangeActionProviderContext,
    ChangeActionProviderError, ChangeActionProviderOutput, RuntimeStore, ShadowManifestContext,
    StoreError, apply_lifecycle_change_for_operation, apply_verified_change_for_operation,
    artifact_and_certificate_are_fresh, built_in_partition_for_action, capture_git_snapshot,
    certify_review_shadow_manifest, claim_validation_certificate_is_fresh,
    derive_review_shadow_manifest, review_finding_partition_key,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

#[derive(Clone, Debug)]
pub struct CodexChangeActionProvider {
    data_directory: PathBuf,
    repository_root: PathBuf,
    config: WorkerConfig,
    codex_home: Option<PathBuf>,
    cancellation: Option<Arc<AtomicBool>>,
}

impl CodexChangeActionProvider {
    pub fn new(
        data_directory: impl Into<PathBuf>,
        repository_root: impl Into<PathBuf>,
        config: WorkerConfig,
    ) -> Self {
        Self {
            data_directory: data_directory.into(),
            repository_root: repository_root.into(),
            config,
            codex_home: None,
            cancellation: None,
        }
    }

    pub fn with_codex_home(mut self, codex_home: impl Into<PathBuf>) -> Self {
        self.codex_home = Some(codex_home.into());
        self
    }

    pub fn with_cancellation(mut self, cancellation: Arc<AtomicBool>) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    pub fn repository_root(&self) -> &Path {
        &self.repository_root
    }

    fn worker_usage(
        &self,
        output_tokens: Option<u64>,
    ) -> Result<LifecycleUsage, ChangeActionProviderError> {
        self.worker_usage_for_turns(output_tokens, 1)
    }

    fn worker_usage_for_turns(
        &self,
        output_tokens: Option<u64>,
        worker_turns: u32,
    ) -> Result<LifecycleUsage, ChangeActionProviderError> {
        if worker_turns == 0 {
            return Err(ChangeActionProviderError::new("action usage has no worker turn"));
        }
        let provenance = self.config.role_profile_provenance.as_ref().ok_or_else(|| {
            ChangeActionProviderError::new("action worker has no frozen role-profile provenance")
        })?;
        let store = RuntimeStore::new(self.data_directory.join("needle.sqlite3"));
        let revision = store
            .read_role_profile_revision(&provenance.profile_id, provenance.revision)
            .map_err(|error| ChangeActionProviderError::new(error.to_string()))?;
        if revision.definition.definition_digest != provenance.definition_digest {
            return Err(ChangeActionProviderError::new(
                "action role-profile definition binding changed",
            ));
        }
        let turns = u64::from(worker_turns);
        Ok(LifecycleUsage {
            worker_turns,
            output_tokens: output_tokens.unwrap_or_else(|| {
                u64::from(revision.definition.budget.max_output_tokens).saturating_mul(turns)
            }),
            cost_microusd: revision.definition.budget.max_cost_microusd.saturating_mul(turns),
        })
    }

    fn patch_context(
        &self,
        change: &needle_core::ChangeRequest,
    ) -> Result<Vec<PatchContextItem>, ChangeActionProviderError> {
        let store = RuntimeStore::new(self.data_directory.join("needle.sqlite3"));
        let (_, snapshot) = capture_git_snapshot(&self.repository_root)
            .map_err(|error| ChangeActionProviderError::new(error.to_string()))?;
        let mut context = Vec::with_capacity(change.artifact_ids.len() + change.claim_ids.len());
        for id in &change.artifact_ids {
            let artifact = store
                .semantic_artifact(&id.to_string())
                .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
                .ok_or_else(|| {
                    ChangeActionProviderError::new(format!("artifact `{id}` is missing"))
                })?;
            let certificate = store
                .validation_certificate_for_artifact(&id.to_string())
                .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
                .ok_or_else(|| {
                    ChangeActionProviderError::new(format!(
                        "artifact `{id}` has no validation certificate"
                    ))
                })?;
            if !artifact_and_certificate_are_fresh(&artifact, &certificate, &self.repository_root)
                || (artifact.contract.cache_scope == CacheScope::SnapshotExact
                    && store
                        .semantic_artifact_source_digest(*id)
                        .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
                        != Some(snapshot.source_digest))
            {
                return Err(ChangeActionProviderError::new(format!(
                    "artifact `{id}` is stale or belongs to another snapshot"
                )));
            }
            for entry in &certificate.coverage.entries {
                let subject = store
                    .subject(entry.obligation.subject)
                    .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
                    .ok_or_else(|| {
                        ChangeActionProviderError::new(format!(
                            "artifact `{id}` subject is missing"
                        ))
                    })?;
                if subject.repository_lineage != snapshot.repository_id {
                    return Err(ChangeActionProviderError::new(format!(
                        "artifact `{id}` belongs to another repository"
                    )));
                }
            }
            let content = serde_json::to_string(&serde_json::json!({
                "artifact_id": id,
                "kind": artifact.contract.kind,
                "payload": artifact.payload,
            }))
            .map_err(|error| ChangeActionProviderError::new(error.to_string()))?;
            if content.len() > 8 * 1024 {
                return Err(ChangeActionProviderError::new(format!(
                    "artifact `{id}` exceeds the bounded patch context"
                )));
            }
            context.push(PatchContextItem { label: format!("artifact:{id}"), content });
        }
        for id in &change.claim_ids {
            let claim = store
                .semantic_claim(*id)
                .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
                .ok_or_else(|| {
                    ChangeActionProviderError::new(format!("claim `{id}` is missing"))
                })?;
            let certificate = store
                .claim_validation_certificate_for_claim(*id)
                .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
                .ok_or_else(|| {
                    ChangeActionProviderError::new(format!(
                        "claim `{id}` has no validation certificate"
                    ))
                })?;
            let subject = store
                .subject(certificate.subject)
                .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
                .ok_or_else(|| {
                    ChangeActionProviderError::new(format!("claim `{id}` subject is missing"))
                })?;
            if certificate.claim != *id
                || !claim.is_canonical()
                || !certificate.is_canonical()
                || !claim_validation_certificate_is_fresh(&certificate, &self.repository_root)
                || subject.repository_lineage != snapshot.repository_id
            {
                return Err(ChangeActionProviderError::new(format!(
                    "claim `{id}` is stale or belongs to another repository"
                )));
            }
            let content = serde_json::to_string(&serde_json::json!({
                "claim_id": id,
                "kind": claim.kind,
                "payload": claim.payload,
            }))
            .map_err(|error| ChangeActionProviderError::new(error.to_string()))?;
            if content.len() > 8 * 1024 {
                return Err(ChangeActionProviderError::new(format!(
                    "claim `{id}` exceeds the bounded patch context"
                )));
            }
            context.push(PatchContextItem { label: format!("claim:{id}"), content });
        }
        Ok(context)
    }

    fn review_refresh_advisory(
        &self,
        store: &RuntimeStore,
        change_id: &needle_core::ChangeId,
        requirements_digest: Digest,
        current_patch: &PatchArtifact,
        prior_review_artifacts: &[needle_core::ArtifactId],
        repository_lineage: Digest,
    ) -> Result<Option<ReviewRefreshAdvisory>, ChangeActionProviderError> {
        if prior_review_artifacts.is_empty() {
            return Ok(None);
        }
        let mut candidates = Vec::with_capacity(prior_review_artifacts.len());
        for artifact_id in prior_review_artifacts {
            let Some(artifact) = store
                .semantic_artifact(&artifact_id.to_string())
                .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
            else {
                return Ok(None);
            };
            if artifact.id != artifact_id.digest() {
                return Ok(None);
            }
            let ChangeActionOutput::Review(report) =
                ChangeActionOutput::from_artifact(&artifact)
                    .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
            else {
                return Ok(None);
            };
            if report.change_id != *change_id
                || report.requirements_digest != requirements_digest
                || report.patch_id == current_patch.id
            {
                return Ok(None);
            }
            candidates.push(report);
        }
        let Some(prior_report) = candidates.into_iter().max_by_key(|report| report.created_unix_ms)
        else {
            return Ok(None);
        };
        let Some(manifest_id) = prior_report.manifest else {
            return Ok(None);
        };
        let Some(publication) = store
            .partition_manifest_publication(manifest_id)
            .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
        else {
            return Ok(None);
        };
        if publication.manifest.binding.action_request != prior_report.action_request
            || publication.manifest.entries.len() != prior_report.findings.len()
        {
            return Ok(None);
        }
        for finding in &prior_report.findings {
            let raw_key = review_finding_partition_key(finding).bytes();
            if !publication.manifest.entries.iter().any(|entry| {
                entry.key.value.as_slice() == raw_key && entry.payload_digest == finding.id
            }) {
                return Ok(None);
            }
        }
        let patch_contract = ActionContractId::new(needle_core::PATCH_PROPOSE_ACTION_CONTRACT)
            .map_err(|error| ChangeActionProviderError::new(error.to_string()))?;
        let Some(prior_patch_artifact) = store
            .opaque_action_artifact_by_payload(&patch_contract, prior_report.patch_id.0)
            .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
        else {
            return Ok(None);
        };
        let ChangeActionOutput::PatchProposal(prior_patch) =
            ChangeActionOutput::from_artifact(&prior_patch_artifact)
                .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
        else {
            return Ok(None);
        };
        if prior_patch.revision.checked_add(1) != Some(current_patch.revision)
            || prior_patch.source_snapshot != current_patch.source_snapshot
            || prior_patch.change_id != current_patch.change_id
        {
            return Ok(None);
        }
        let prior_files = prior_patch
            .files
            .iter()
            .map(|file| (file.path.as_str(), file))
            .collect::<BTreeMap<_, _>>();
        let current_files = current_patch
            .files
            .iter()
            .map(|file| (file.path.as_str(), file))
            .collect::<BTreeMap<_, _>>();
        let mut paths =
            prior_files.keys().chain(current_files.keys()).copied().collect::<BTreeSet<_>>();
        paths.retain(|path| prior_files.get(path) != current_files.get(path));
        let changed_locators = paths
            .iter()
            .map(|path| DependencyLocator::repository_path(path))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| ChangeActionProviderError::new(error.to_string()))?;
        let mut context = CanonicalHasher::new(b"needle-review-patch-context-v1");
        context.field_str(change_id.as_str());
        context.field_digest(current_patch.source_snapshot);
        let state_delta = StateDelta::new(
            repository_lineage,
            RepositoryContextId::new(context.finish()),
            u64::from(prior_patch.revision),
            u64::from(current_patch.revision),
            changed_locators,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            true,
        )
        .map_err(|error| ChangeActionProviderError::new(error.to_string()))?;
        let mut manifest_keys = BTreeMap::new();
        for entry in &publication.manifest.entries {
            let raw: [u8; 32] = entry
                .key
                .value
                .as_slice()
                .try_into()
                .map_err(|_| ChangeActionProviderError::new("review manifest key changed"))?;
            if manifest_keys.insert(Digest(raw), entry.key.digest).is_some() {
                return Ok(None);
            }
        }
        let changed_paths = paths.into_iter().map(str::to_owned).collect::<BTreeSet<_>>();
        let ReviewPartitionClassification {
            retained_findings,
            invalidated_partition_keys,
            mut invalidated_by_path,
        } = classify_review_partitions(&prior_report.findings, &manifest_keys, &changed_paths)?;
        let inspection_context_digest =
            review_inspection_context_digest(state_delta.digest, manifest_id, current_patch.id);
        let mut inspection_targets =
            Vec::with_capacity(retained_findings.len().saturating_add(changed_paths.len()));
        for finding in &retained_findings {
            inspection_targets.push(
                ReviewInspectionTarget::retained_finding(
                    inspection_context_digest,
                    finding.path.clone(),
                    finding.id,
                )
                .map_err(|error| ChangeActionProviderError::new(error.to_string()))?,
            );
        }
        for path in changed_paths {
            inspection_targets.push(
                ReviewInspectionTarget::changed_path(
                    inspection_context_digest,
                    path.clone(),
                    invalidated_by_path.remove(&path).unwrap_or_default(),
                )
                .map_err(|error| ChangeActionProviderError::new(error.to_string()))?,
            );
        }
        if !invalidated_by_path.is_empty()
            || inspection_targets.is_empty()
            || inspection_targets.len() > needle_core::MAX_REVIEW_INSPECTION_TARGETS
        {
            return Ok(None);
        }
        inspection_targets.sort_by_key(|target| target.id);
        Ok(Some(ReviewRefreshAdvisory {
            state_delta,
            prior_manifest: manifest_id,
            retained_findings,
            invalidated_partition_keys,
            inspection_context_digest,
            inspection_targets,
        }))
    }
}

struct ReviewPartitionClassification {
    retained_findings: Vec<needle_core::ReviewFinding>,
    invalidated_partition_keys: Vec<Digest>,
    invalidated_by_path: BTreeMap<String, Vec<Digest>>,
}

fn classify_review_partitions(
    findings: &[needle_core::ReviewFinding],
    manifest_keys: &BTreeMap<Digest, Digest>,
    changed_paths: &BTreeSet<String>,
) -> Result<ReviewPartitionClassification, ChangeActionProviderError> {
    let mut retained = Vec::new();
    let mut invalidated = Vec::new();
    let mut invalidated_by_path = BTreeMap::<String, Vec<Digest>>::new();
    for finding in findings {
        let raw = review_finding_partition_key(finding);
        let key = manifest_keys
            .get(&raw)
            .copied()
            .ok_or_else(|| ChangeActionProviderError::new("review manifest changed"))?;
        if changed_paths.contains(&finding.path) {
            invalidated.push(key);
            invalidated_by_path.entry(finding.path.clone()).or_default().push(key);
        } else {
            retained.push(finding.clone());
        }
    }
    retained.sort_by_key(|finding| finding.id);
    invalidated.sort_unstable();
    for keys in invalidated_by_path.values_mut() {
        keys.sort_unstable();
    }
    Ok(ReviewPartitionClassification {
        retained_findings: retained,
        invalidated_partition_keys: invalidated,
        invalidated_by_path,
    })
}

fn derive_review_manifest_transition(
    store: &RuntimeStore,
    advisory: &ReviewRefreshAdvisory,
    current: &needle_core::PartitionManifest,
    current_findings: &[needle_core::ReviewFinding],
    operation_id: Digest,
) -> Result<ManifestTransition, ChangeActionProviderError> {
    let prior = store
        .partition_manifest_publication(advisory.prior_manifest)
        .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
        .ok_or_else(|| ChangeActionProviderError::new("review prior manifest disappeared"))?;
    let review_action = ActionContractId::new(needle_core::REVIEW_DIFF_ACTION_CONTRACT)
        .map_err(|error| ChangeActionProviderError::new(error.to_string()))?;
    let definition = built_in_partition_for_action(&review_action)
        .ok_or_else(|| ChangeActionProviderError::new("review partition definition is missing"))?;
    let current_by_id =
        current_findings.iter().map(|finding| (finding.id, finding)).collect::<BTreeMap<_, _>>();
    let mut mappings = Vec::with_capacity(advisory.retained_findings.len());
    for finding in &advisory.retained_findings {
        if !current_by_id.contains_key(&finding.id) {
            continue;
        }
        let raw_key = review_finding_partition_key(finding).bytes();
        let prior_entry = prior
            .manifest
            .entries
            .iter()
            .find(|entry| entry.key.value.as_slice() == raw_key)
            .ok_or_else(|| ChangeActionProviderError::new("review prior partition changed"))?;
        let current_entry =
            current.entries.iter().find(|entry| entry.key.value.as_slice() == raw_key).ok_or_else(
                || ChangeActionProviderError::new("review current partition changed"),
            )?;
        mappings.push(PartitionKeyMapping {
            prior: PartitionRef::new(prior.manifest.id, prior_entry.key.digest),
            current: PartitionRef::new(current.id, current_entry.key.digest),
        });
    }
    ManifestTransition::new(
        prior.manifest.id,
        current.id,
        advisory.state_delta.digest,
        mappings,
        ManifestProvenance::ProducerAuthored { attempt: operation_id },
        definition.policy.manifest_validator.clone(),
    )
    .map_err(|error| ChangeActionProviderError::new(error.to_string()))
}

impl ChangeActionProvider for CodexChangeActionProvider {
    fn execute(
        &self,
        context: ChangeActionProviderContext<'_>,
    ) -> Result<ChangeActionProviderOutput, ChangeActionProviderError> {
        match context.input {
            ChangeActionInput::PatchPropose { change, prior_patch, repair_verification } => {
                let change_id = context
                    .input
                    .change_id(context.request.artifact_request.source_snapshot_digest);
                let mut patcher = self.codex_home.as_ref().map_or_else(
                    || CodexPatchWorker::new(&self.data_directory),
                    |codex_home| {
                        CodexPatchWorker::with_codex_home(&self.data_directory, codex_home)
                    },
                );
                if let Some(cancellation) = self.cancellation.as_ref() {
                    patcher = patcher.with_cancellation(Arc::clone(cancellation));
                }
                let patch_context = self.patch_context(change)?;
                let (patch, worker_output_tokens) =
                    if prior_patch.is_none() && repair_verification.is_none() {
                        let outcome = patcher
                            .propose_action(
                                &self.config,
                                &self.repository_root,
                                &ProposeActionBinding {
                                    operation_id: context.operation_id,
                                    change_id: change_id.clone(),
                                    source_snapshot: context
                                        .request
                                        .artifact_request
                                        .source_snapshot_digest,
                                },
                                change,
                                &patch_context,
                            )
                            .map_err(ChangeActionProviderError::new)?;
                        (outcome.patch, outcome.usage.output_tokens)
                    } else {
                        let outcome = patcher
                            .repair_action(
                                &self.config,
                                &self.repository_root,
                                &change_id,
                                context.operation_id,
                            )
                            .map_err(ChangeActionProviderError::new)?;
                        let store = RuntimeStore::new(self.data_directory.join("needle.sqlite3"));
                        let prepared = store
                            .prepared_change(&change_id)
                            .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
                            .ok_or_else(|| {
                                ChangeActionProviderError::new("repaired patch is missing")
                            })?;
                        if prepared.patch.id != outcome.patch_id {
                            return Err(ChangeActionProviderError::new(
                                "repaired patch does not match the worker outcome",
                            ));
                        }
                        (prepared.patch, outcome.output_tokens)
                    };
                Ok(ChangeActionProviderOutput {
                    output: ChangeActionOutput::PatchProposal(patch),
                    world: context.need.world.clone(),
                    dependency_manifest: DependencyManifest {
                        scope: CacheScope::SnapshotExact,
                        observed_files_complete: false,
                        dependencies: Vec::new(),
                        gaps: vec!["provider-owned-patch-observation".to_owned()],
                    },
                    review_manifest: None,
                    review_transition: None,
                    usage: self.worker_usage(worker_output_tokens)?,
                })
            }
            ChangeActionInput::TestsExecute {
                change_id,
                requirements_digest,
                patch,
                test_plan_artifact,
            } => {
                let mut executor = CodexTestExecutor::new(&self.data_directory);
                if let Some(codex_home) = self.codex_home.as_ref() {
                    executor = executor.with_codex_home(codex_home);
                }
                let evidence = executor
                    .execute(
                        &self.config,
                        &self.repository_root,
                        TestExecutionBinding {
                            action_request: context.request.semantic_id(),
                            change_id: change_id.clone(),
                            requirements_digest: *requirements_digest,
                            patch_id: patch.patch,
                            test_plan_artifact: *test_plan_artifact,
                            source_snapshot: context
                                .request
                                .artifact_request
                                .source_snapshot_digest,
                        },
                    )
                    .map_err(ChangeActionProviderError::new)?;
                Ok(ChangeActionProviderOutput {
                    output: ChangeActionOutput::TestExecution(evidence),
                    world: context.need.world.clone(),
                    dependency_manifest: DependencyManifest {
                        scope: CacheScope::SnapshotExact,
                        observed_files_complete: true,
                        dependencies: Vec::new(),
                        gaps: Vec::new(),
                    },
                    review_manifest: None,
                    review_transition: None,
                    usage: LifecycleUsage { worker_turns: 1, output_tokens: 0, cost_microusd: 0 },
                })
            }
            ChangeActionInput::ReviewDiff {
                change_id,
                requirements_digest,
                patch,
                prior_review_artifacts,
            } => {
                // Gate A6 keeps the final conclusion fresh. Valid prior
                // partitions are supplied only as provider-owned advisory;
                // absent or mismatched manifests fall back to a full review.
                let store = RuntimeStore::new(self.data_directory.join("needle.sqlite3"));
                let prepared = store
                    .prepared_change(change_id)
                    .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
                    .ok_or_else(|| ChangeActionProviderError::new("review patch is missing"))?;
                if prepared.patch.id != patch.patch {
                    return Err(ChangeActionProviderError::new("review patch binding changed"));
                }
                let advisory = self.review_refresh_advisory(
                    &store,
                    change_id,
                    *requirements_digest,
                    &prepared.patch,
                    prior_review_artifacts,
                    context.need.world.repository_lineage,
                )?;
                let mut reviewer = CodexReviewWorker::new(&self.data_directory);
                if let Some(codex_home) = self.codex_home.as_ref() {
                    reviewer = reviewer.with_codex_home(codex_home);
                }
                if let Some(cancellation) = self.cancellation.as_ref() {
                    reviewer = reviewer.with_cancellation(Arc::clone(cancellation));
                }
                let review_request = ReviewActionRequest {
                    config: &self.config,
                    repository_root: &self.repository_root,
                    change_id,
                    requirements_digest: *requirements_digest,
                    patch_id: patch.patch,
                    source_snapshot: context.request.artifact_request.source_snapshot_digest,
                    advisory: advisory.as_ref(),
                };
                let (mut review, effective_advisory) = match reviewer.review(review_request) {
                    Ok(review) => (review, advisory.as_ref()),
                    Err(error) if advisory.is_some() && error.full_fallback_required => {
                        let refresh_output_tokens = error.output_tokens;
                        let mut full = reviewer
                            .review(ReviewActionRequest { advisory: None, ..review_request })
                            .map_err(|error| ChangeActionProviderError::new(error.diagnostic))?;
                        full.output_tokens = match (refresh_output_tokens, full.output_tokens) {
                            (Some(refresh), Some(full)) => refresh.checked_add(full),
                            _ => None,
                        };
                        full.worker_turns = 2;
                        (full, None)
                    }
                    Err(error) => return Err(ChangeActionProviderError::new(error.diagnostic)),
                };
                let usage =
                    self.worker_usage_for_turns(review.output_tokens, review.worker_turns)?;
                let manifest = derive_review_shadow_manifest(
                    ShadowManifestContext {
                        request: context.request,
                        world: &context.need.world,
                        definition_set_digest: context.definition_set_digest,
                    },
                    &review.findings,
                    review.dependency_digest,
                )
                .map_err(|error| ChangeActionProviderError::new(error.to_string()))?;
                let inspection_context_digest = review.inspection_context_digest;
                let inspection_coverage = std::mem::take(&mut review.inspection_coverage);
                let report = ReviewReport::new(
                    context.request.semantic_id(),
                    change_id.clone(),
                    patch.patch,
                    *requirements_digest,
                    review.reviewer_definition,
                    review.verdict,
                    review.acceptance_coverage,
                    review.findings,
                    Some(manifest.id),
                    review.created_unix_ms,
                )
                .map_err(|error| ChangeActionProviderError::new(error.to_string()))?;
                let report = match inspection_context_digest {
                    Some(context_digest) => report
                        .with_inspection_coverage(context_digest, inspection_coverage)
                        .map_err(|error| ChangeActionProviderError::new(error.to_string()))?,
                    None if inspection_coverage.is_empty() => report,
                    None => {
                        return Err(ChangeActionProviderError::new(
                            "review inspection coverage has no context",
                        ));
                    }
                };
                let mut source_validation =
                    CanonicalHasher::new(b"needle-review-source-validation-v1");
                source_validation.field_digest(report.id);
                source_validation.field_digest(review.reviewer_definition);
                source_validation.field_digest(review.dependency_digest);
                source_validation.field_digest(review.provider_observation_digest);
                let publication = certify_review_shadow_manifest(
                    manifest,
                    &report,
                    source_validation.finish(),
                    review.created_unix_ms,
                )
                .map_err(|error| ChangeActionProviderError::new(error.to_string()))?;
                let transition = effective_advisory
                    .map(|advisory| {
                        derive_review_manifest_transition(
                            &store,
                            advisory,
                            &publication.manifest,
                            &report.findings,
                            context.operation_id,
                        )
                    })
                    .transpose()?;
                Ok(ChangeActionProviderOutput {
                    output: ChangeActionOutput::Review(report),
                    world: context.need.world.clone(),
                    dependency_manifest: DependencyManifest {
                        scope: CacheScope::SnapshotExact,
                        observed_files_complete: true,
                        dependencies: Vec::new(),
                        gaps: Vec::new(),
                    },
                    review_manifest: Some(publication),
                    review_transition: transition,
                    usage,
                })
            }
            ChangeActionInput::PatchVerify {
                change_id,
                requirements_digest,
                patch,
                test_evidence_artifacts,
            } => {
                let store = RuntimeStore::new(self.data_directory.join("needle.sqlite3"));
                let plans = store
                    .lifecycle_start_test_plan_candidates(
                        context.request.artifact_request.source_snapshot_digest,
                    )
                    .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
                    .into_iter()
                    .map(|candidate| (candidate.artifact_id, candidate.binding.plan))
                    .collect::<BTreeMap<_, _>>();
                let mut inputs = Vec::with_capacity(test_evidence_artifacts.len());
                for artifact_id in test_evidence_artifacts {
                    let artifact = store
                        .semantic_artifact(&artifact_id.to_string())
                        .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
                        .ok_or_else(|| {
                            ChangeActionProviderError::new(
                                "certified test execution artifact is missing",
                            )
                        })?;
                    if artifact.id != artifact_id.digest() {
                        return Err(ChangeActionProviderError::new(
                            "test execution artifact identity changed",
                        ));
                    }
                    let ChangeActionOutput::TestExecution(evidence) =
                        ChangeActionOutput::from_artifact(&artifact)
                            .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
                    else {
                        return Err(ChangeActionProviderError::new(
                            "Verify accepts only TestExecutionEvidence inputs",
                        ));
                    };
                    let plan =
                        plans.get(&evidence.test_plan_artifact).cloned().ok_or_else(|| {
                            ChangeActionProviderError::new(
                                "test execution plan is unavailable for the exact source",
                            )
                        })?;
                    inputs.push(CertifiedTestExecutionInput {
                        artifact: *artifact_id,
                        evidence,
                        plan,
                    });
                }
                let mut verifier = CodexVerifier::new(&self.data_directory);
                if let Some(codex_home) = self.codex_home.as_ref() {
                    verifier = CodexVerifier::with_codex_home(&self.data_directory, codex_home);
                }
                if let Some(cancellation) = self.cancellation.as_ref() {
                    verifier = verifier.with_cancellation(Arc::clone(cancellation));
                }
                let outcome = verifier
                    .verify_action_fresh(FreshVerificationRequest {
                        config: &self.config,
                        repository_root: &self.repository_root,
                        change_id,
                        action_request: context.request.semantic_id(),
                        requirements_digest: *requirements_digest,
                        patch_id: patch.patch,
                        test_inputs: &inputs,
                    })
                    .map_err(ChangeActionProviderError::new)?;
                let usage = self.worker_usage(outcome.output_tokens)?;
                Ok(ChangeActionProviderOutput {
                    output: ChangeActionOutput::PatchVerification(outcome.artifact),
                    world: context.need.world.clone(),
                    dependency_manifest: DependencyManifest {
                        scope: CacheScope::SnapshotExact,
                        observed_files_complete: true,
                        dependencies: Vec::new(),
                        gaps: Vec::new(),
                    },
                    review_manifest: None,
                    review_transition: None,
                    usage,
                })
            }
            ChangeActionInput::PatchApply {
                change_id,
                requirements_digest,
                patch,
                verification,
                expected_state_digest,
                confirm,
            } => {
                if !confirm {
                    return Err(ChangeActionProviderError::new(
                        "Apply requires explicit parent confirmation",
                    ));
                }
                let store = RuntimeStore::new(self.data_directory.join("needle.sqlite3"));
                let verification_artifact = store
                    .semantic_artifact(&verification.artifact.to_string())
                    .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
                    .ok_or_else(|| {
                        ChangeActionProviderError::new("verified patch artifact is missing")
                    })?;
                let ChangeActionOutput::PatchVerification(verified) =
                    ChangeActionOutput::from_artifact(&verification_artifact)
                        .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
                else {
                    return Err(ChangeActionProviderError::new(
                        "Apply accepts only a VerificationArtifact",
                    ));
                };
                if verified.id != verification.verification
                    || verified.change_id != *change_id
                    || verified.patch_id != patch.patch
                    || verified.requirements_digest != Some(*requirements_digest)
                    || verified.verdict != VerificationStatus::Verified
                {
                    return Err(ChangeActionProviderError::new(
                        "Apply verification binding is stale or not successful",
                    ));
                }
                let change_state = store
                    .change_digest(change_id)
                    .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
                    .ok_or_else(|| ChangeActionProviderError::new("change is missing"))?;
                let record = match store.replay_lifecycle(change_id) {
                    Ok(projection) => {
                        let approved_state = match projection.lifecycle.status {
                            LifecycleStatus::AwaitingApproval => {
                                if projection.state_digest != *expected_state_digest {
                                    return Err(ChangeActionProviderError::new(
                                        "Apply approval state changed",
                                    ));
                                }
                                store
                                    .approve_lifecycle_apply(
                                        change_id,
                                        *expected_state_digest,
                                        ApprovalDecisionSource::WebUser,
                                    )
                                    .map_err(|error| {
                                        ChangeActionProviderError::new(error.to_string())
                                    })?
                                    .state_digest
                            }
                            LifecycleStatus::Approved
                            | LifecycleStatus::Applying
                            | LifecycleStatus::Completed => {
                                if projection.lifecycle.approval.as_ref().is_none_or(|approval| {
                                    approval.approved_state_digest != *expected_state_digest
                                }) {
                                    return Err(ChangeActionProviderError::new(
                                        "Apply approval binding changed",
                                    ));
                                }
                                projection.state_digest
                            }
                            _ => {
                                return Err(ChangeActionProviderError::new(
                                    "lifecycle is not awaiting or executing Apply",
                                ));
                            }
                        };
                        apply_lifecycle_change_for_operation(
                            &store,
                            &self.repository_root,
                            change_id,
                            change_state,
                            approved_state,
                            context.operation_id,
                        )
                    }
                    Err(StoreError::LifecycleNotFound(_)) => {
                        if change_state != *expected_state_digest {
                            return Err(ChangeActionProviderError::new(
                                "Apply expected state digest changed",
                            ));
                        }
                        apply_verified_change_for_operation(
                            &store,
                            &self.repository_root,
                            change_id,
                            *expected_state_digest,
                            context.operation_id,
                        )
                    }
                    Err(error) => {
                        return Err(ChangeActionProviderError::new(error.to_string()));
                    }
                }
                .map_err(|error| ChangeActionProviderError::new(error.to_string()))?;
                let prepared = store
                    .prepared_change(change_id)
                    .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
                    .ok_or_else(|| ChangeActionProviderError::new("applied change is missing"))?;
                if prepared.patch.id != patch.patch
                    || prepared.request_digest != *requirements_digest
                {
                    return Err(ChangeActionProviderError::new("applied change binding changed"));
                }
                let mut applied_files = CanonicalHasher::new(b"needle-applied-files-v1");
                applied_files.field_u16(prepared.patch.files.len().try_into().unwrap_or(u16::MAX));
                for file in &prepared.patch.files {
                    applied_files.field_str(&file.path);
                    applied_files.field_u8(match file.operation {
                        needle_core::PatchOperation::Create => 0,
                        needle_core::PatchOperation::Update => 1,
                        needle_core::PatchOperation::Delete => 2,
                    });
                    if let Some(digest) = file.after_digest {
                        applied_files.field_digest(digest);
                    }
                }
                let receipt = ApplyReceipt::new(
                    context.operation_id,
                    change_id.clone(),
                    patch.patch,
                    *expected_state_digest,
                    record.pre_snapshot,
                    record.post_snapshot.ok_or_else(|| {
                        ChangeActionProviderError::new("Apply completed without a post snapshot")
                    })?,
                    applied_files.finish(),
                    record.completed_unix_ms.unwrap_or(record.created_unix_ms),
                )
                .map_err(|error| ChangeActionProviderError::new(error.to_string()))?;
                Ok(ChangeActionProviderOutput {
                    output: ChangeActionOutput::ApplyReceipt(receipt),
                    world: context.need.world.clone(),
                    dependency_manifest: DependencyManifest {
                        scope: CacheScope::SnapshotExact,
                        observed_files_complete: true,
                        dependencies: Vec::new(),
                        gaps: Vec::new(),
                    },
                    review_manifest: None,
                    review_transition: None,
                    usage: LifecycleUsage::default(),
                })
            }
        }
    }
}

pub fn codex_change_action_provider_definition() -> Digest {
    Digest::blake3(b"needle-codex-change-action-provider-v4")
}

#[cfg(test)]
mod tests {
    use super::*;
    use needle_core::{ReviewFinding, ReviewSeverity};

    fn finding(path: &str, rule: &str) -> ReviewFinding {
        ReviewFinding::new(
            rule,
            ReviewSeverity::Warning,
            path,
            Some(1),
            format!("{rule} finding"),
            Digest::blake3(format!("{path}:{rule}:evidence")),
        )
        .unwrap()
    }

    #[test]
    fn changed_review_partitions_are_invalidated_instead_of_retained() {
        let stale = finding("src/changed.rs", "stale.rule");
        let retained = finding("src/stable.rs", "stable.rule");
        let stale_key = Digest::blake3(b"stale-partition");
        let retained_key = Digest::blake3(b"retained-partition");
        let manifest_keys = BTreeMap::from([
            (review_finding_partition_key(&stale), stale_key),
            (review_finding_partition_key(&retained), retained_key),
        ]);
        let changed_paths = BTreeSet::from(["src/changed.rs".to_owned()]);

        let classification =
            classify_review_partitions(&[stale, retained.clone()], &manifest_keys, &changed_paths)
                .unwrap();
        assert_eq!(classification.retained_findings, vec![retained]);
        assert_eq!(classification.invalidated_partition_keys, vec![stale_key]);
        assert_eq!(
            classification.invalidated_by_path,
            BTreeMap::from([("src/changed.rs".to_owned(), vec![stale_key])])
        );
    }
}
