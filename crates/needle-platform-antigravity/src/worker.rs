use crate::{AntigravityCliAdapter, AntigravityExecutionRequest};
use needle_core::{
    HostUsage, SemanticArtifactResult, WorkerArtifactResult, WorkerConfig, WorkerFailure,
    WorkerObservationTrace, WorkerOutcome, WorkerRequest,
};
use needle_runtime::WorkerExecutor;
use needle_worker_contract::{
    HOST_NATIVE_REPOSITORY_INSPECTION_POLICY, normalize_worker_output, output_schema,
    requested_model_artifact_kinds, required_model_artifact_kinds, worker_prompt,
    worker_system_instructions,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

const MAX_FAILURE_DIAGNOSTIC_BYTES: usize = 4_096;
const UNATTESTED_HOST_OBSERVATION_GAP: &str =
    "antigravity_tool_paths_not_attested_by_host_protocol";

#[derive(Clone, Debug)]
pub struct AntigravityWorker {
    data_directory: PathBuf,
    cancellation: Option<Arc<AtomicBool>>,
}

impl AntigravityWorker {
    pub fn new(data_directory: impl Into<PathBuf>) -> Self {
        Self { data_directory: data_directory.into(), cancellation: None }
    }

    pub fn with_cancellation(mut self, cancellation: Arc<AtomicBool>) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    fn execute_inner(
        &self,
        config: &WorkerConfig,
        request: &WorkerRequest,
    ) -> Result<WorkerOutcome, Box<WorkerFailure>> {
        let requested = requested_model_artifact_kinds(request);
        let required = required_model_artifact_kinds(request);
        let schema = output_schema(request, &requested);
        let instructions =
            worker_system_instructions(request, HOST_NATIVE_REPOSITORY_INSPECTION_POLICY);
        let prompt = format!("{instructions}\n\nTask:\n{}", worker_prompt(request));
        let mut adapter = AntigravityCliAdapter::new(&self.data_directory, &config.executable);
        if let Some(cancellation) = &self.cancellation {
            adapter = adapter.with_cancellation(Arc::clone(cancellation));
        }
        let execution = AntigravityExecutionRequest {
            repository_root: PathBuf::from(&request.repository_root),
            repository_snapshot: request.repository_snapshot.clone(),
            prompt,
            output_schema: schema,
            model: config.model.clone(),
            reasoning: config.reasoning.clone(),
            timeout: Duration::from_secs(config.timeout_seconds),
        };
        let completed = adapter.execute_retained(&execution).map_err(|error| {
            let metadata = error
                .observation
                .as_deref()
                .map(|observation| WorkerFailureMetadata {
                    duration_ms: observation.duration_ms,
                    worker_turns: observation.worker_turns,
                    worker_session_id: observation.conversation_id.clone(),
                    session_cleanup_success: Some(error.checkout_cleanup_completed),
                    usage: observation.usage.clone(),
                })
                .unwrap_or(WorkerFailureMetadata {
                    session_cleanup_success: Some(error.checkout_cleanup_completed),
                    ..WorkerFailureMetadata::default()
                });
            Box::new(worker_failure(config, error.code, error.diagnostic, metadata))
        })?;
        let host = completed.result.clone();
        let checkout_root = completed.checkout_root().to_path_buf();
        let protocol = (|| {
            let mut normalized =
                normalize_worker_output(host.structured_output.clone(), &checkout_root, &requested);
            normalized.discard_unrequested_kinds(&requested);
            normalized.record_missing_requested_kinds(&required);
            let missing = normalized.missing_requested_kinds(&required);
            if !missing.is_empty() {
                return Err((
                    "artifact_protocol_incomplete".to_owned(),
                    format!("missing required artifact kinds: {}", missing.join(", ")),
                ));
            }
            if !normalized.has_facts() {
                return Err((
                    "no_valid_evidence".to_owned(),
                    "Antigravity returned no valid repository evidence".to_owned(),
                ));
            }
            let discarded_facts = normalized.discarded_facts;
            let (schema_id, artifacts, test_plan) =
                normalized.artifact_result().ok_or_else(|| {
                    (
                        "artifact_protocol_ambiguous".to_owned(),
                        "Antigravity returned incompatible artifact result schemas".to_owned(),
                    )
                })?;
            let semantic_artifacts = normalized.semantic_artifacts().to_vec();
            let result = normalized
                .into_need_result(&checkout_root)
                .map_err(|error| ("evidence_binding_failed".to_owned(), error))?;
            let trace = WorkerObservationTrace {
                observed_files: Vec::new(),
                gaps: vec![UNATTESTED_HOST_OBSERVATION_GAP.to_owned()],
            };
            let artifact_traces = request
                .requested_artifact_kinds
                .first()
                .filter(|_| request.requested_artifact_kinds.len() == 1)
                .map(|kind| BTreeMap::from([(kind.clone(), trace.clone())]))
                .unwrap_or_default();
            let semantic_artifact_result =
                (!semantic_artifacts.is_empty()).then(|| SemanticArtifactResult {
                    schema_id: needle_core::SEMANTIC_ARTIFACT_RESULT_SCHEMA_ID.to_owned(),
                    artifacts: semantic_artifacts,
                    observation_trace: trace.clone(),
                    artifact_traces: artifact_traces.clone(),
                });
            Ok((
                result,
                WorkerArtifactResult {
                    schema_id,
                    artifacts,
                    test_plan,
                    observation_trace: trace,
                    artifact_traces,
                },
                semantic_artifact_result,
                discarded_facts,
            ))
        })();
        let cleaned = completed.cleanup();
        let cleaned = cleaned.map_err(|error| {
            Box::new(worker_failure(
                config,
                error.code,
                error.diagnostic,
                WorkerFailureMetadata {
                    duration_ms: host.duration_ms,
                    worker_turns: 1,
                    worker_session_id: Some(host.conversation_id.clone()),
                    session_cleanup_success: Some(false),
                    usage: Some(host.usage.clone()),
                },
            ))
        })?;
        let (result, artifact_result, semantic_artifact_result, discarded_facts) = protocol
            .map_err(|(code, diagnostic)| {
                Box::new(worker_failure(
                    config,
                    code,
                    diagnostic,
                    WorkerFailureMetadata {
                        duration_ms: cleaned.duration_ms,
                        worker_turns: 1,
                        worker_session_id: Some(cleaned.conversation_id.clone()),
                        session_cleanup_success: Some(true),
                        usage: Some(cleaned.usage.clone()),
                    },
                ))
            })?;
        Ok(WorkerOutcome {
            result,
            artifact_result: Some(artifact_result),
            semantic_artifact_result,
            worker_model: config.model.clone(),
            worker_reasoning: config.reasoning.clone(),
            codex_version: cleaned.host_version,
            host_protocol_schema_digest: Some(cleaned.contract_digest),
            input_tokens: Some(cleaned.usage.input_tokens),
            cached_input_tokens: Some(cleaned.usage.cache_read_tokens),
            output_tokens: Some(cleaned.usage.output_tokens),
            duration_ms: cleaned.duration_ms,
            process_status: "success".to_owned(),
            logical_worker_spawns: 1,
            worker_turns: 1,
            repair_performed: false,
            discarded_facts,
            worker_session_id: Some(cleaned.conversation_id),
            session_cleanup_success: Some(true),
            role_profile_provenance: config.role_profile_provenance.clone(),
        })
    }
}

impl WorkerExecutor for AntigravityWorker {
    fn execute(
        &self,
        config: &WorkerConfig,
        request: &WorkerRequest,
    ) -> Result<WorkerOutcome, Box<WorkerFailure>> {
        self.execute_inner(config, request)
    }
}

#[derive(Default)]
struct WorkerFailureMetadata {
    duration_ms: u64,
    worker_turns: u32,
    worker_session_id: Option<String>,
    session_cleanup_success: Option<bool>,
    usage: Option<HostUsage>,
}

fn worker_failure(
    config: &WorkerConfig,
    code: String,
    diagnostic: String,
    metadata: WorkerFailureMetadata,
) -> WorkerFailure {
    let WorkerFailureMetadata {
        duration_ms,
        worker_turns,
        worker_session_id,
        session_cleanup_success,
        usage,
    } = metadata;
    WorkerFailure {
        code,
        diagnostic: diagnostic.chars().take(MAX_FAILURE_DIAGNOSTIC_BYTES).collect(),
        input_tokens: usage.as_ref().map(|usage| usage.input_tokens),
        cached_input_tokens: usage.as_ref().map(|usage| usage.cache_read_tokens),
        output_tokens: usage.as_ref().map(|usage| usage.output_tokens),
        duration_ms,
        logical_worker_spawns: u32::from(worker_turns > 0),
        worker_turns,
        repair_performed: false,
        discarded_facts: 0,
        worker_session_id,
        session_cleanup_success,
        role_profile_provenance: config.role_profile_provenance.clone(),
    }
}
