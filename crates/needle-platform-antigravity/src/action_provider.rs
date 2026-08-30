use crate::reviewer::{AntigravityReviewWorker, ReviewActionRequest};
use needle_core::{
    CacheScope, CanonicalHasher, ChangeActionInput, DependencyManifest, LifecycleUsage,
    ReviewReport, WorkerConfig,
};
use needle_runtime::{
    ChangeActionOutput, ChangeActionProvider, ChangeActionProviderContext,
    ChangeActionProviderError, ChangeActionProviderOutput, RuntimeStore, ShadowManifestContext,
    certify_review_shadow_manifest, derive_review_shadow_manifest,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

const UNATTESTED_HOST_OBSERVATION_GAP: &str =
    "antigravity_tool_paths_not_attested_by_host_protocol";

#[derive(Clone, Debug)]
pub struct AntigravityChangeActionProvider {
    data_directory: PathBuf,
    repository_root: PathBuf,
    config: WorkerConfig,
    cancellation: Option<Arc<AtomicBool>>,
}

impl AntigravityChangeActionProvider {
    pub fn new(
        data_directory: impl Into<PathBuf>,
        repository_root: impl Into<PathBuf>,
        config: WorkerConfig,
    ) -> Self {
        Self {
            data_directory: data_directory.into(),
            repository_root: repository_root.into(),
            config,
            cancellation: None,
        }
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
        output_tokens: u64,
    ) -> Result<LifecycleUsage, ChangeActionProviderError> {
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
        if output_tokens > u64::from(revision.definition.budget.max_output_tokens) {
            return Err(ChangeActionProviderError::new(
                "action worker output tokens exceeded the frozen role-profile budget",
            ));
        }
        Ok(LifecycleUsage {
            worker_turns: 1,
            output_tokens,
            cost_microusd: revision.definition.budget.max_cost_microusd,
        })
    }
}

impl ChangeActionProvider for AntigravityChangeActionProvider {
    fn execute(
        &self,
        context: ChangeActionProviderContext<'_>,
    ) -> Result<ChangeActionProviderOutput, ChangeActionProviderError> {
        let ChangeActionInput::ReviewDiff {
            change_id,
            requirements_digest,
            patch,
            prior_review_artifacts: _,
        } = context.input
        else {
            return Err(ChangeActionProviderError::new(
                "Antigravity supports only needle.review.diff before Gate A8",
            ));
        };
        let store = RuntimeStore::new(self.data_directory.join("needle.sqlite3"));
        let prepared = store
            .prepared_change(change_id)
            .map_err(|error| ChangeActionProviderError::new(error.to_string()))?
            .ok_or_else(|| ChangeActionProviderError::new("review patch is missing"))?;
        if prepared.patch.id != patch.patch {
            return Err(ChangeActionProviderError::new("review patch binding changed"));
        }
        let mut reviewer = AntigravityReviewWorker::new(&self.data_directory);
        if let Some(cancellation) = self.cancellation.as_ref() {
            reviewer = reviewer.with_cancellation(Arc::clone(cancellation));
        }
        let review = reviewer
            .review(ReviewActionRequest {
                config: &self.config,
                repository_root: &self.repository_root,
                change_id,
                requirements_digest: *requirements_digest,
                patch_id: patch.patch,
                source_snapshot: context.request.artifact_request.source_snapshot_digest,
            })
            .map_err(ChangeActionProviderError::new)?;
        let usage = self.worker_usage(review.output_tokens)?;
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
        let mut source_validation = CanonicalHasher::new(b"needle-review-source-validation-v1");
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
        Ok(ChangeActionProviderOutput {
            output: ChangeActionOutput::Review(report),
            world: context.need.world.clone(),
            dependency_manifest: DependencyManifest {
                scope: CacheScope::SnapshotExact,
                observed_files_complete: false,
                dependencies: Vec::new(),
                gaps: vec![UNATTESTED_HOST_OBSERVATION_GAP.to_owned()],
            },
            review_manifest: Some(publication),
            review_transition: None,
            usage,
            host_usage: Some(review.host_usage),
        })
    }
}
