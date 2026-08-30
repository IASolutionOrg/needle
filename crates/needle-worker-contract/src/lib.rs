//! Host-neutral structured artifact protocol shared by native agent adapters.

mod protocol;
mod request;
mod review;

pub use protocol::{
    CompactWorkerResponse, GroupDiagnostic, LegacyCompactWorkerResponse, NormalizedResponse,
    SemanticCompactWorkerResponse, normalize_legacy_response, normalize_response,
    normalize_semantic_response, normalize_worker_output, repair_prompt,
    semantic_worker_output_schema_for_scenario, should_repair, worker_output_schema,
};
pub use request::{
    CODEX_REPOSITORY_INSPECTION_POLICY, HOST_NATIVE_REPOSITORY_INSPECTION_POLICY,
    effective_test_plan, output_schema, preferred_model_artifact_kinds,
    requested_model_artifact_kinds, required_model_artifact_kinds, worker_prompt,
    worker_system_instructions,
};
pub use review::{
    NormalizedFullReview, REVIEW_FINDING_FORMAT_INSTRUCTIONS, REVIEWER_INSTRUCTIONS,
    full_reviewer_output_schema, full_reviewer_prompt, normalize_full_review_output,
};
