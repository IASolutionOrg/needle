use super::{
    ActionDefinitionHandle, ArtifactHandle, AwcpReasonCode, AwcpValidationError, ExecutionReportId,
    MAX_AWCP_ARTIFACT_PROJECTION_BYTES, MAX_AWCP_SCHEMA_ID_BYTES, MAX_AWCP_WORKER_RESULT_BYTES,
    ResolutionTicket, validate_bound, validate_nonzero_bound, validate_revision,
};
use crate::{
    ArtifactId, ArtifactRequestId, ArtifactValidationCertificateId, CanonicalHasher, Digest,
    EffectClass,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedWorkerResult {
    pub schema_id: String,
    /// Canonical compact JSON. The runtime authenticates the ticket before
    /// parsing or semantically inspecting this value.
    pub canonical_json: String,
}

impl BoundedWorkerResult {
    pub fn from_value(
        schema_id: impl Into<String>,
        value: &Value,
    ) -> Result<Self, AwcpValidationError> {
        let canonical_json =
            serde_json::to_string(value).map_err(|_| AwcpValidationError::WorkerResultJson)?;
        let result = Self { schema_id: schema_id.into(), canonical_json };
        result.validate_after_authentication(MAX_AWCP_WORKER_RESULT_BYTES)?;
        Ok(result)
    }

    pub fn validate_envelope(&self, maximum: usize) -> Result<(), AwcpValidationError> {
        validate_schema_id(&self.schema_id)?;
        validate_nonzero_bound("worker_result.canonical_json", self.canonical_json.len(), maximum)
    }

    pub fn validate_after_authentication(
        &self,
        maximum: usize,
    ) -> Result<Value, AwcpValidationError> {
        self.validate_envelope(maximum)?;
        let value: Value = serde_json::from_str(&self.canonical_json)
            .map_err(|_| AwcpValidationError::WorkerResultJson)?;
        let canonical =
            serde_json::to_string(&value).map_err(|_| AwcpValidationError::WorkerResultJson)?;
        if canonical != self.canonical_json {
            return Err(AwcpValidationError::WorkerResultCanonical);
        }
        if contains_credential_key(&value) {
            return Err(AwcpValidationError::CredentialMaterial);
        }
        Ok(value)
    }

    pub fn digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"awcp-worker-result-v1");
        hasher.field_str(&self.schema_id);
        hasher.field_bytes(self.canonical_json.as_bytes());
        hasher.finish()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageProjection {
    pub input_tokens: Option<u64>,
    pub cached_input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerObservationProjection {
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
    pub usage: UsageProjection,
    pub cancelled: bool,
    pub cleanup_succeeded: bool,
    pub observed_effect: EffectClass,
    pub effect_receipt_digest: Option<Digest>,
}

impl WorkerObservationProjection {
    pub fn validate(self) -> Result<(), AwcpValidationError> {
        if self.completed_at_unix_ms < self.started_at_unix_ms {
            return Err(AwcpValidationError::ObservationTime);
        }
        if self.observed_effect == EffectClass::ExternalEffect
            && self.effect_receipt_digest.is_none()
        {
            return Err(AwcpValidationError::EffectReceipt);
        }
        Ok(())
    }

    pub fn digest(self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"awcp-worker-observation-v1");
        hasher.field_bytes(&self.started_at_unix_ms.to_le_bytes());
        hasher.field_bytes(&self.completed_at_unix_ms.to_le_bytes());
        hash_optional_u64(&mut hasher, self.usage.input_tokens);
        hash_optional_u64(&mut hasher, self.usage.cached_input_tokens);
        hash_optional_u64(&mut hasher, self.usage.output_tokens);
        hasher.field_u8(u8::from(self.cancelled));
        hasher.field_u8(u8::from(self.cleanup_succeeded));
        hasher.field_u8(effect_tag(self.observed_effect));
        hash_optional_digest(&mut hasher, self.effect_receipt_digest);
        hasher.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProvenanceProjection {
    pub worker_definition_digest: Digest,
    pub adapter_definition_digest: Digest,
    pub sandbox_identity_digest: Digest,
}

impl ExecutionProvenanceProjection {
    pub fn digest(self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"awcp-execution-provenance-v1");
        hasher.field_digest(self.worker_definition_digest);
        hasher.field_digest(self.adapter_definition_digest);
        hasher.field_digest(self.sandbox_identity_digest);
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishActionRequest {
    pub protocol_revision: u16,
    pub resolution_ticket: ResolutionTicket,
    pub action_request: ArtifactRequestId,
    pub action_contract: ActionDefinitionHandle,
    pub worker_result: BoundedWorkerResult,
    pub observation: WorkerObservationProjection,
    pub execution_provenance: ExecutionProvenanceProjection,
}

impl PublishActionRequest {
    /// Validates only bounded outer fields. Worker JSON is deliberately not
    /// parsed until the runtime authenticates the ticket.
    pub fn validate_envelope(&self) -> Result<(), AwcpValidationError> {
        validate_revision(self.protocol_revision)?;
        self.resolution_ticket.validate_shape()?;
        self.worker_result.validate_envelope(
            self.resolution_ticket.applied_limits.max_worker_result_bytes as usize,
        )?;
        self.observation.validate()
    }

    pub fn publication_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"awcp-publication-v1");
        hasher.field_digest(self.action_request.digest());
        hasher.field_digest(self.action_contract.definition_digest);
        hasher.field_digest(self.worker_result.digest());
        hasher.field_digest(self.observation.digest());
        hasher.field_digest(self.execution_provenance.digest());
        hasher.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishDisposition {
    AcceptedForValidation,
    Replayed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishActionResponse {
    pub protocol_revision: u16,
    pub disposition: PublishDisposition,
    pub artifact: Option<ArtifactHandle>,
    pub validation: Option<ArtifactValidationCertificateId>,
    pub reusable: bool,
    pub reason: AwcpReasonCode,
    pub publication_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetArtifactRequest {
    pub protocol_revision: u16,
    pub artifact: ArtifactId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetArtifactResponse {
    pub protocol_revision: u16,
    pub handle: ArtifactHandle,
    pub projection: Value,
}

impl GetArtifactResponse {
    pub fn validate_shape(&self) -> Result<(), AwcpValidationError> {
        validate_revision(self.protocol_revision)?;
        let bytes = serde_json::to_vec(&self.projection)
            .map_err(|_| AwcpValidationError::ArtifactProjectionJson)?;
        validate_bound("artifact.projection", bytes.len(), MAX_AWCP_ARTIFACT_PROJECTION_BYTES)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Started,
    Completed,
    Cancelled,
    Failed,
    Skipped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportExecutionRequest {
    pub protocol_revision: u16,
    pub resolution_ticket: ResolutionTicket,
    pub action_request: ArtifactRequestId,
    pub status: ExecutionStatus,
    pub observation: WorkerObservationProjection,
    pub execution_provenance: ExecutionProvenanceProjection,
}

impl ReportExecutionRequest {
    pub fn validate_shape(&self) -> Result<(), AwcpValidationError> {
        validate_revision(self.protocol_revision)?;
        self.resolution_ticket.validate_shape()?;
        self.observation.validate()
    }

    pub fn digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"awcp-execution-report-v1");
        hasher.field_digest(self.resolution_ticket.id.digest());
        hasher.field_digest(self.action_request.digest());
        hasher.field_u8(match self.status {
            ExecutionStatus::Started => 0,
            ExecutionStatus::Completed => 1,
            ExecutionStatus::Cancelled => 2,
            ExecutionStatus::Failed => 3,
            ExecutionStatus::Skipped => 4,
        });
        hasher.field_digest(self.observation.digest());
        hasher.field_digest(self.execution_provenance.digest());
        hasher.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportExecutionResponse {
    pub protocol_revision: u16,
    pub report: ExecutionReportId,
    pub reason: AwcpReasonCode,
}

fn validate_schema_id(value: &str) -> Result<(), AwcpValidationError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_AWCP_SCHEMA_ID_BYTES
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'.' | b'-' | b'/' | b'_')
        })
    {
        return Err(AwcpValidationError::WorkerResultSchema);
    }
    Ok(())
}

fn contains_credential_key(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.iter().any(|(key, value)| credential_key(key) || contains_credential_key(value))
        }
        Value::Array(values) => values.iter().any(contains_credential_key),
        _ => false,
    }
}

fn credential_key(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase().replace('-', "_");
    matches!(
        normalized.as_str(),
        "authorization"
            | "access_token"
            | "api_key"
            | "client_secret"
            | "credential"
            | "credentials"
            | "password"
            | "refresh_token"
            | "secret"
            | "token"
    )
}

fn effect_tag(effect: EffectClass) -> u8 {
    match effect {
        EffectClass::PureEvidence => 0,
        EffectClass::DerivedAnalysis => 1,
        EffectClass::TransformProposal => 2,
        EffectClass::ExecutionEvidence => 3,
        EffectClass::ExternalRead => 4,
        EffectClass::ExternalEffect => 5,
    }
}

fn hash_optional_digest(hasher: &mut CanonicalHasher, value: Option<Digest>) {
    match value {
        Some(value) => {
            hasher.field_u8(1);
            hasher.field_digest(value);
        }
        None => hasher.field_u8(0),
    }
}

fn hash_optional_u64(hasher: &mut CanonicalHasher, value: Option<u64>) {
    match value {
        Some(value) => {
            hasher.field_u8(1);
            hasher.field_bytes(&value.to_le_bytes());
        }
        None => hasher.field_u8(0),
    }
}
