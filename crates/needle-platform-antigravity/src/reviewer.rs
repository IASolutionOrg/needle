use crate::{AntigravityCliAdapter, AntigravityExecutionRequest};
use needle_core::{
    CanonicalHasher, ChangeId, Digest, HostUsage, PatchId, ReviewCoverage, ReviewFinding,
    ReviewReportVerdict, WorkerConfig,
};
use needle_runtime::{
    IsolatedCheckout, RuntimeStore, capture_git_snapshot, materialize_patch_artifact,
};
use needle_worker_contract::{
    REVIEWER_INSTRUCTIONS, full_reviewer_output_schema, full_reviewer_prompt,
    normalize_full_review_output,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub(crate) struct AntigravityReviewWorker {
    data_directory: PathBuf,
    cancellation: Option<Arc<AtomicBool>>,
}

#[derive(Clone, Copy)]
pub(crate) struct ReviewActionRequest<'a> {
    pub config: &'a WorkerConfig,
    pub repository_root: &'a Path,
    pub change_id: &'a ChangeId,
    pub requirements_digest: Digest,
    pub patch_id: PatchId,
    pub source_snapshot: Digest,
}

#[derive(Clone, Debug)]
pub(crate) struct ReviewRunOutput {
    pub verdict: ReviewReportVerdict,
    pub acceptance_coverage: Vec<ReviewCoverage>,
    pub findings: Vec<ReviewFinding>,
    pub reviewer_definition: Digest,
    pub dependency_digest: Digest,
    pub provider_observation_digest: Digest,
    pub created_unix_ms: u64,
    pub output_tokens: u64,
    pub host_usage: HostUsage,
}

impl AntigravityReviewWorker {
    pub(crate) fn new(data_directory: impl Into<PathBuf>) -> Self {
        Self { data_directory: data_directory.into(), cancellation: None }
    }

    pub(crate) fn with_cancellation(mut self, cancellation: Arc<AtomicBool>) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    pub(crate) fn review(
        &self,
        request: ReviewActionRequest<'_>,
    ) -> Result<ReviewRunOutput, String> {
        let ReviewActionRequest {
            config,
            repository_root,
            change_id,
            requirements_digest,
            patch_id,
            source_snapshot,
        } = request;
        let store = RuntimeStore::new(self.data_directory.join("needle.sqlite3"));
        let prepared = store
            .prepared_change(change_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("change `{change_id}` is not prepared"))?;
        if prepared.patch.id != patch_id
            || prepared.source_snapshot != source_snapshot
            || prepared.request_digest != requirements_digest
            || prepared.request_digest != prepared.request.digest(source_snapshot)
        {
            return Err("review patch binding is stale or inconsistent".to_owned());
        }
        let repository_root = fs::canonicalize(repository_root)
            .map_err(|error| format!("cannot resolve review repository: {error}"))?;
        let sandbox = IsolatedCheckout::materialize(
            &repository_root,
            &self.data_directory.join("antigravity-review-runs"),
        )
        .map_err(|error| error.to_string())?;
        if sandbox.snapshot().source_digest != source_snapshot {
            return cleanup_after_error(
                sandbox,
                "active source snapshot changed before review".to_owned(),
            );
        }
        let blobs = match store.patch_file_blobs(prepared.patch.id) {
            Ok(blobs) => blobs,
            Err(error) => return cleanup_after_error(sandbox, error.to_string()),
        };
        if let Err(error) =
            materialize_patch_artifact(sandbox.checkout_root(), &prepared.patch, &blobs)
        {
            return cleanup_after_error(sandbox, error.to_string());
        }
        let (_, patched_snapshot) = match capture_git_snapshot(sandbox.checkout_root()) {
            Ok(snapshot) => snapshot,
            Err(error) => return cleanup_after_error(sandbox, error.to_string()),
        };
        let prompt = full_reviewer_prompt(&prepared.request, &prepared.patch);
        let output_schema = full_reviewer_output_schema();
        let transport_prompt = format!("{REVIEWER_INSTRUCTIONS}\n\nTask:\n{prompt}");
        let execution = AntigravityExecutionRequest {
            repository_root: sandbox.checkout_root().to_path_buf(),
            repository_snapshot: patched_snapshot.clone(),
            prompt: transport_prompt,
            output_schema: output_schema.clone(),
            model: config.model.clone(),
            reasoning: config.reasoning.clone(),
            timeout: Duration::from_secs(config.timeout_seconds),
        };
        let mut adapter = AntigravityCliAdapter::new(&self.data_directory, &config.executable);
        if let Some(cancellation) = self.cancellation.as_ref() {
            adapter = adapter.with_cancellation(Arc::clone(cancellation));
        }
        let host = adapter
            .execute_prepared_retained(&execution, sandbox)
            .map_err(|error| error.to_string())?
            .cleanup()
            .map_err(|error| error.to_string())?;
        let host_usage = host.usage.clone();
        let normalized = normalize_full_review_output(
            host.structured_output,
            &prepared.request,
            Some(host_usage.output_tokens),
        )?;
        let reviewer_definition = reviewer_definition_digest(config);
        let conversation_digest = Digest::blake3(host.conversation_id.as_bytes());
        let mut provider_observation =
            CanonicalHasher::new(b"needle-antigravity-review-provider-observation-v1");
        provider_observation.field_digest(AntigravityCliAdapter::contract().definition_digest);
        provider_observation.field_digest(config.digest());
        provider_observation.field_digest(source_snapshot);
        provider_observation.field_digest(patch_id.0);
        provider_observation.field_digest(requirements_digest);
        provider_observation.field_digest(patched_snapshot.source_digest);
        provider_observation.field_digest(conversation_digest);
        provider_observation.field_digest(Digest::blake3(prompt.as_bytes()));
        provider_observation.field_digest(Digest::blake3(
            serde_json::to_vec(&output_schema)
                .expect("the closed reviewer output schema serializes"),
        ));
        provider_observation.field_digest(normalized.response_digest);
        let provider_observation_digest = provider_observation.finish();

        let mut dependency = CanonicalHasher::new(b"needle-review-full-dependency-v1");
        dependency.field_digest(source_snapshot);
        dependency.field_digest(patch_id.0);
        dependency.field_digest(requirements_digest);
        dependency.field_digest(reviewer_definition);
        dependency.field_digest(patched_snapshot.source_digest);
        dependency.field_digest(provider_observation_digest);
        dependency.field_u8(0);
        for finding in &normalized.findings {
            dependency.field_digest(finding.id);
        }
        Ok(ReviewRunOutput {
            verdict: normalized.verdict,
            acceptance_coverage: normalized.acceptance_coverage,
            findings: normalized.findings,
            reviewer_definition,
            dependency_digest: dependency.finish(),
            provider_observation_digest,
            created_unix_ms: now_ms(),
            output_tokens: normalized.output_tokens.unwrap_or(host_usage.output_tokens),
            host_usage,
        })
    }
}

fn reviewer_definition_digest(config: &WorkerConfig) -> Digest {
    let mut hasher = CanonicalHasher::new(b"needle-antigravity-review-worker-v1");
    hasher.field_digest(AntigravityCliAdapter::contract().definition_digest);
    hasher.field_digest(config.digest());
    hasher.field_str(REVIEWER_INSTRUCTIONS);
    hasher.field_bytes(
        &serde_json::to_vec(&full_reviewer_output_schema())
            .expect("the closed reviewer output schema serializes"),
    );
    hasher.finish()
}

fn cleanup_after_error<T>(sandbox: IsolatedCheckout, error: String) -> Result<T, String> {
    match sandbox.cleanup() {
        Ok(()) => Err(error),
        Err(cleanup) => Err(format!("{error}; review checkout cleanup failed: {cleanup}")),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
