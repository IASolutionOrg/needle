use crate::{AgentHost, CanonicalHasher, Digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use thiserror::Error;

pub const HOST_EXECUTION_CONTRACT_SCHEMA_V1: &str = "needle.host-execution-contract/1";
pub const HOST_EXECUTION_RESULT_SCHEMA_V1: &str = "needle.host-execution-result/1";
pub const MAX_HOST_VERSION_BYTES: usize = 128;
pub const MAX_HOST_ADAPTER_ID_BYTES: usize = 128;
pub const MAX_HOST_TOOL_EVENTS: usize = 128;
pub const MAX_HOST_TOOL_NAME_BYTES: usize = 128;
pub const MAX_HOST_CONVERSATION_ID_BYTES: usize = 256;
pub const MAX_HOST_STRUCTURED_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostCapability {
    Headless,
    StructuredOutput,
    StreamEvents,
    Usage,
    Cancellation,
    Sandbox,
}

impl HostCapability {
    const fn tag(self) -> u8 {
        match self {
            Self::Headless => 0,
            Self::StructuredOutput => 1,
            Self::StreamEvents => 2,
            Self::Usage => 3,
            Self::Cancellation => 4,
            Self::Sandbox => 5,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostExecutionContractV1 {
    pub schema: String,
    pub host: AgentHost,
    pub adapter_id: String,
    pub adapter_revision: u32,
    pub capabilities: BTreeSet<HostCapability>,
    pub definition_digest: Digest,
}

impl HostExecutionContractV1 {
    pub fn new(
        host: AgentHost,
        adapter_id: impl Into<String>,
        adapter_revision: u32,
        capabilities: impl IntoIterator<Item = HostCapability>,
    ) -> Result<Self, HostExecutionValidationError> {
        let mut contract = Self {
            schema: HOST_EXECUTION_CONTRACT_SCHEMA_V1.to_owned(),
            host,
            adapter_id: adapter_id.into(),
            adapter_revision,
            capabilities: capabilities.into_iter().collect(),
            definition_digest: Digest([0; 32]),
        };
        contract.validate_without_digest()?;
        contract.definition_digest = contract.compute_digest();
        Ok(contract)
    }

    pub fn validate(&self) -> Result<(), HostExecutionValidationError> {
        self.validate_without_digest()?;
        let expected = self.compute_digest();
        if self.definition_digest != expected {
            return Err(HostExecutionValidationError::DigestMismatch {
                expected,
                actual: self.definition_digest,
            });
        }
        Ok(())
    }

    fn validate_without_digest(&self) -> Result<(), HostExecutionValidationError> {
        if self.schema != HOST_EXECUTION_CONTRACT_SCHEMA_V1 {
            return Err(HostExecutionValidationError::Schema);
        }
        if self.adapter_id.is_empty()
            || self.adapter_id.len() > MAX_HOST_ADAPTER_ID_BYTES
            || !self.adapter_id.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-' | b'_')
            })
        {
            return Err(HostExecutionValidationError::AdapterId);
        }
        if self.adapter_revision == 0 {
            return Err(HostExecutionValidationError::AdapterRevision);
        }
        for required in [
            HostCapability::Headless,
            HostCapability::StructuredOutput,
            HostCapability::Cancellation,
            HostCapability::Sandbox,
        ] {
            if !self.capabilities.contains(&required) {
                return Err(HostExecutionValidationError::RequiredCapability(required));
            }
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"needle-host-execution-contract-v1");
        hasher.field_str(self.schema.as_str());
        hasher.field_str(self.host.as_str());
        hasher.field_str(self.adapter_id.as_str());
        hasher.field_bytes(&self.adapter_revision.to_le_bytes());
        hasher.field_bytes(&(self.capabilities.len() as u32).to_le_bytes());
        for capability in &self.capabilities {
            hasher.field_u8(capability.tag());
        }
        hasher.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostTerminalStatus {
    Success,
    Error,
    Canceled,
    Interrupted,
    Invalid,
    Waiting,
    Running,
}

impl HostTerminalStatus {
    pub const fn terminal(self) -> bool {
        !matches!(self, Self::Waiting | Self::Running)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub thinking_tokens: u64,
    pub cache_read_tokens: u64,
    pub total_tokens: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostToolEvent {
    pub name: String,
    pub completed: bool,
    pub parameters_digest: Option<Digest>,
    pub output_digest: Option<Digest>,
    pub failed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostExecutionResultV1 {
    pub schema: String,
    pub host: AgentHost,
    pub host_version: String,
    pub contract_digest: Digest,
    pub conversation_id: String,
    pub status: HostTerminalStatus,
    pub structured_output: Value,
    pub usage: HostUsage,
    pub duration_ms: u64,
    pub sandboxed: bool,
    pub process_cleanup_completed: bool,
    pub checkout_cleanup_completed: bool,
    pub tool_events: Vec<HostToolEvent>,
}

impl HostExecutionResultV1 {
    pub fn validate(
        &self,
        contract: &HostExecutionContractV1,
    ) -> Result<(), HostExecutionValidationError> {
        contract.validate()?;
        if self.schema != HOST_EXECUTION_RESULT_SCHEMA_V1 {
            return Err(HostExecutionValidationError::Schema);
        }
        if self.host != contract.host || self.contract_digest != contract.definition_digest {
            return Err(HostExecutionValidationError::ContractBinding);
        }
        if self.host_version.is_empty() || self.host_version.len() > MAX_HOST_VERSION_BYTES {
            return Err(HostExecutionValidationError::HostVersion);
        }
        if self.conversation_id.is_empty()
            || self.conversation_id.len() > MAX_HOST_CONVERSATION_ID_BYTES
        {
            return Err(HostExecutionValidationError::ConversationId);
        }
        if !self.status.terminal() {
            return Err(HostExecutionValidationError::TerminalStatus);
        }
        let structured_bytes = serde_json::to_vec(&self.structured_output)
            .map_err(|_| HostExecutionValidationError::StructuredOutput)?;
        if structured_bytes.len() > MAX_HOST_STRUCTURED_OUTPUT_BYTES {
            return Err(HostExecutionValidationError::StructuredOutput);
        }
        if !self.sandboxed || !self.process_cleanup_completed || !self.checkout_cleanup_completed {
            return Err(HostExecutionValidationError::Cleanup);
        }
        if self.tool_events.len() > MAX_HOST_TOOL_EVENTS
            || self
                .tool_events
                .iter()
                .any(|event| event.name.is_empty() || event.name.len() > MAX_HOST_TOOL_NAME_BYTES)
        {
            return Err(HostExecutionValidationError::ToolEvents);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum HostExecutionValidationError {
    #[error("host execution schema is unsupported")]
    Schema,
    #[error("host adapter id is invalid")]
    AdapterId,
    #[error("host adapter revision must be non-zero")]
    AdapterRevision,
    #[error("host adapter is missing required capability {0:?}")]
    RequiredCapability(HostCapability),
    #[error("host contract digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: Digest, actual: Digest },
    #[error("host execution result is bound to a different contract")]
    ContractBinding,
    #[error("host version is invalid")]
    HostVersion,
    #[error("host conversation id is invalid")]
    ConversationId,
    #[error("host result did not reach a terminal status")]
    TerminalStatus,
    #[error("host structured output is invalid or exceeds its bound")]
    StructuredOutput,
    #[error("host execution did not prove sandbox and cleanup completion")]
    Cleanup,
    #[error("host tool event projection is invalid or exceeds its bound")]
    ToolEvents,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn contract() -> HostExecutionContractV1 {
        HostExecutionContractV1::new(
            AgentHost::Antigravity,
            "needle.antigravity-cli",
            1,
            [
                HostCapability::Headless,
                HostCapability::StructuredOutput,
                HostCapability::StreamEvents,
                HostCapability::Usage,
                HostCapability::Cancellation,
                HostCapability::Sandbox,
            ],
        )
        .unwrap()
    }

    #[test]
    fn contract_identity_is_order_independent_and_host_bound() {
        let one = contract();
        let two = HostExecutionContractV1::new(
            AgentHost::Antigravity,
            "needle.antigravity-cli",
            1,
            one.capabilities.iter().rev().copied(),
        )
        .unwrap();
        assert_eq!(one, two);
        assert!(one.validate().is_ok());

        let codex = HostExecutionContractV1::new(
            AgentHost::Codex,
            "needle.antigravity-cli",
            1,
            one.capabilities.iter().copied(),
        )
        .unwrap();
        assert_ne!(one.definition_digest, codex.definition_digest);
    }

    #[test]
    fn result_fails_closed_on_non_terminal_or_incomplete_cleanup() {
        let contract = contract();
        let mut result = HostExecutionResultV1 {
            schema: HOST_EXECUTION_RESULT_SCHEMA_V1.to_owned(),
            host: AgentHost::Antigravity,
            host_version: "1.1.22".to_owned(),
            contract_digest: contract.definition_digest,
            conversation_id: "conversation".to_owned(),
            status: HostTerminalStatus::Success,
            structured_output: json!({"schema": "fixture/1"}),
            usage: HostUsage::default(),
            duration_ms: 1,
            sandboxed: true,
            process_cleanup_completed: true,
            checkout_cleanup_completed: true,
            tool_events: Vec::new(),
        };
        assert!(result.validate(&contract).is_ok());
        result.status = HostTerminalStatus::Running;
        assert_eq!(result.validate(&contract), Err(HostExecutionValidationError::TerminalStatus));
        result.status = HostTerminalStatus::Success;
        result.checkout_cleanup_completed = false;
        assert_eq!(result.validate(&contract), Err(HostExecutionValidationError::Cleanup));
    }
}
