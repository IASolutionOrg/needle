use crate::{AgentHost, CodexRole, Digest, EffectiveWorkerAllowancesV1, RoleProfileProvenance};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ApprovalDecision {
    Accept,
    Decline,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecisionSource {
    AutoPolicy,
    AiPolicy,
    WebUser,
    Timeout,
    Runtime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandClassification {
    AutoApprovedTest { policy_id: String },
    AutoApprovedReadOnly { policy_id: String },
    PendingUser,
    PendingAiEligible,
    RejectedFileChange,
    RejectedNetwork,
    RejectedUnparseable,
    RejectedPolicyMismatch,
    Expired,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOperation {
    #[default]
    CommandExecution,
    FilesystemChange,
    NetworkAccess,
    McpInvocation,
    ExternalEffect,
}

impl ApprovalOperation {
    const fn tag(self) -> u8 {
        match self {
            Self::CommandExecution => 0,
            Self::FilesystemChange => 1,
            Self::NetworkAccess => 2,
            Self::McpInvocation => 3,
            Self::ExternalEffect => 4,
        }
    }
}

fn default_approval_host() -> AgentHost {
    AgentHost::Codex
}

const fn default_payload_digest_revision() -> u8 {
    1
}

pub const APPROVAL_AUTOMATION_POLICY_SCHEMA_V1: &str = "needle.approval-automation-policy/1";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalAutomationMode {
    #[default]
    Disabled,
    Advisory,
    Decide,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalAutomationPolicy {
    pub schema: String,
    pub mode: ApprovalAutomationMode,
    pub evaluator_host: AgentHost,
    pub model: String,
    pub reasoning: String,
    pub timeout_seconds: u64,
}

impl Default for ApprovalAutomationPolicy {
    fn default() -> Self {
        Self {
            schema: APPROVAL_AUTOMATION_POLICY_SCHEMA_V1.to_owned(),
            mode: ApprovalAutomationMode::Disabled,
            evaluator_host: AgentHost::Codex,
            model: "gpt-5.6-luna".to_owned(),
            reasoning: "low".to_owned(),
            timeout_seconds: 30,
        }
    }
}

impl ApprovalAutomationPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != APPROVAL_AUTOMATION_POLICY_SCHEMA_V1 {
            return Err("unsupported approval automation policy schema");
        }
        if self.evaluator_host != AgentHost::Codex {
            return Err("only the Codex evaluator is currently implemented");
        }
        if self.model.is_empty()
            || self.model.len() > 128
            || !self
                .model
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err("approval automation model is invalid");
        }
        if !matches!(self.reasoning.as_str(), "none" | "low" | "medium" | "high" | "xhigh" | "max")
        {
            return Err("approval automation reasoning is invalid");
        }
        if !(5..=120).contains(&self.timeout_seconds) {
            return Err("approval automation timeout must be between 5 and 120 seconds");
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        let mut hasher = crate::CanonicalHasher::new(b"needle-approval-automation-policy-v1");
        hasher.field_str(self.schema.as_str());
        hasher.field_u8(match self.mode {
            ApprovalAutomationMode::Disabled => 0,
            ApprovalAutomationMode::Advisory => 1,
            ApprovalAutomationMode::Decide => 2,
        });
        hasher.field_str(self.evaluator_host.as_str());
        hasher.field_str(self.model.as_str());
        hasher.field_str(self.reasoning.as_str());
        hasher.field_bytes(&self.timeout_seconds.to_le_bytes());
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedPermissions {
    pub write_paths: Vec<String>,
    pub read_paths: Vec<String>,
    pub network: bool,
    pub raw: serde_json::Value,
}

impl Default for RequestedPermissions {
    fn default() -> Self {
        Self {
            write_paths: Vec::new(),
            read_paths: Vec::new(),
            network: false,
            raw: serde_json::Value::Null,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    #[serde(default = "default_approval_host")]
    pub host: AgentHost,
    #[serde(default)]
    pub worker_role: Option<CodexRole>,
    #[serde(default)]
    pub role_profile: Option<RoleProfileProvenance>,
    #[serde(default)]
    pub allowances: Option<EffectiveWorkerAllowancesV1>,
    #[serde(default)]
    pub operation: ApprovalOperation,
    pub id: String,
    pub protocol_request_id: serde_json::Value,
    pub protocol_approval_id: Option<String>,
    pub thread_id: String,
    pub turn_id: String,
    pub item_id: String,
    pub argv: Vec<String>,
    pub command_display: Option<String>,
    pub cwd: String,
    pub reason: Option<String>,
    pub requested_permissions: RequestedPermissions,
    pub route: String,
    pub repository_id: Digest,
    pub repository_root: String,
    pub expires_unix_ms: u64,
    pub classification: CommandClassification,
    pub payload_digest: Digest,
    #[serde(default = "default_payload_digest_revision")]
    pub payload_digest_revision: u8,
    #[serde(default)]
    pub automation_advice: Option<ApprovalAutomationAdvice>,
    pub decision: Option<ApprovalDecision>,
    pub decision_source: Option<ApprovalDecisionSource>,
    pub decided_unix_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
pub struct ApprovalPayloadDigestInputV2<'a> {
    pub host: AgentHost,
    pub worker_role: Option<CodexRole>,
    pub role_profile: Option<&'a RoleProfileProvenance>,
    pub allowances: Option<&'a EffectiveWorkerAllowancesV1>,
    pub operation: ApprovalOperation,
    pub argv: &'a [String],
    pub cwd: &'a str,
    pub requested_permissions: &'a RequestedPermissions,
}

impl ApprovalRequest {
    pub fn compute_payload_digest(
        argv: &[String],
        cwd: &str,
        requested_permissions: &RequestedPermissions,
    ) -> Result<Digest, serde_json::Error> {
        serde_json::to_vec(&(argv, cwd, requested_permissions)).map(Digest::blake3)
    }

    pub fn compute_payload_digest_v2(
        input: ApprovalPayloadDigestInputV2<'_>,
    ) -> Result<Digest, serde_json::Error> {
        serde_json::to_vec(&(
            2u8,
            input.host,
            input.worker_role,
            input.role_profile,
            input.allowances.map(|value| value.allowance_digest),
            input.operation.tag(),
            input.argv,
            input.cwd,
            input.requested_permissions,
        ))
        .map(Digest::blake3)
    }

    pub fn can_apply_decision(&self, expected_payload_digest: Digest, now_unix_ms: u64) -> bool {
        self.decision.is_none()
            && self.payload_digest == expected_payload_digest
            && now_unix_ms < self.expires_unix_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandExecutionEvidence {
    pub id: String,
    pub approval_id: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub source_snapshot_digest: Digest,
    pub runner: String,
    pub runner_version: Option<String>,
    pub exit_status: Option<i32>,
    pub duration_ms: u64,
    pub output_digest: Digest,
    pub output_preview: String,
    pub test_identifier: Option<String>,
    pub tests_executed: Option<u32>,
    pub infrastructure_failure: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestCommandPolicy {
    pub id: String,
    pub repository_id: Digest,
    pub trusted: bool,
    pub executable: String,
    pub argv_prefix: Vec<String>,
    pub maximum_executions_per_worker: u32,
}

impl TestCommandPolicy {
    pub fn certified_direct(repository_id: Digest, executable: impl Into<String>) -> Self {
        let executable = executable.into();
        Self {
            id: format!(
                "certified-direct-{}",
                Digest::blake3(format!("{repository_id}\n{executable}\n")).to_hex()
            ),
            repository_id,
            trusted: true,
            argv_prefix: vec![executable.clone()],
            executable,
            maximum_executions_per_worker: 1,
        }
    }

    /// Legacy convenience constructor retained for existing callers. New
    /// action-native execution derives a direct policy from each certified
    /// TestPlan instead of recognizing an ecosystem in the kernel.
    pub fn cargo_test(repository_id: Digest) -> Self {
        Self {
            id: "cargo-test-direct-v1".to_owned(),
            repository_id,
            trusted: true,
            executable: "cargo".to_owned(),
            argv_prefix: vec!["cargo".to_owned(), "test".to_owned()],
            maximum_executions_per_worker: 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalAutomationAdvice {
    pub policy_digest: Digest,
    pub input_digest: Digest,
    pub evaluator_host: AgentHost,
    pub model: String,
    pub reasoning: String,
    pub decision: bool,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub evaluated_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadOnlyCommandPolicy {
    pub id: String,
    pub repository_id: Digest,
    pub trusted: bool,
    pub maximum_executions_per_worker: u32,
}

impl ReadOnlyCommandPolicy {
    pub fn repository_inspection(repository_id: Digest) -> Self {
        Self {
            id: "repository-read-only-v1".to_owned(),
            repository_id,
            trusted: true,
            maximum_executions_per_worker: 16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_is_bound_to_payload_and_expiry() {
        let permissions = RequestedPermissions::default();
        let digest = ApprovalRequest::compute_payload_digest(
            &["cargo".into(), "test".into()],
            "C:/run",
            &permissions,
        )
        .unwrap();
        let request = ApprovalRequest {
            host: AgentHost::Codex,
            worker_role: None,
            role_profile: None,
            allowances: None,
            operation: ApprovalOperation::CommandExecution,
            id: "approval".to_owned(),
            protocol_request_id: serde_json::json!(7),
            protocol_approval_id: None,
            thread_id: "thread".to_owned(),
            turn_id: "turn".to_owned(),
            item_id: "item".to_owned(),
            argv: vec!["cargo".to_owned(), "test".to_owned()],
            command_display: None,
            cwd: "C:/run".to_owned(),
            reason: None,
            requested_permissions: permissions,
            route: "tests.relevant".to_owned(),
            repository_id: Digest::blake3("repo"),
            repository_root: "C:/run".to_owned(),
            expires_unix_ms: 20,
            classification: CommandClassification::PendingUser,
            payload_digest: digest,
            payload_digest_revision: 1,
            automation_advice: None,
            decision: None,
            decision_source: None,
            decided_unix_ms: None,
        };
        assert!(request.can_apply_decision(digest, 19));
        assert!(!request.can_apply_decision(Digest::blake3("changed"), 19));
        assert!(!request.can_apply_decision(digest, 20));
    }

    #[test]
    fn protocol_decisions_exclude_session_and_policy_amendments() {
        for decision in
            [ApprovalDecision::Accept, ApprovalDecision::Decline, ApprovalDecision::Cancel]
        {
            let json = serde_json::to_string(&decision).unwrap();
            assert!(!json.contains("Session"));
            assert!(!json.contains("Amendment"));
        }
    }

    #[test]
    fn approval_automation_defaults_to_disabled_luna_low_and_is_digest_bound() {
        let policy = ApprovalAutomationPolicy::default();
        policy.validate().unwrap();
        assert_eq!(policy.mode, ApprovalAutomationMode::Disabled);
        assert_eq!(policy.evaluator_host, AgentHost::Codex);
        assert_eq!(policy.model, "gpt-5.6-luna");
        assert_eq!(policy.reasoning, "low");
        let mut enabled = policy.clone();
        enabled.mode = ApprovalAutomationMode::Decide;
        assert_ne!(enabled.digest(), policy.digest());
    }

    #[test]
    fn legacy_approval_json_defaults_new_host_neutral_fields() {
        let permissions = RequestedPermissions::default();
        let digest =
            ApprovalRequest::compute_payload_digest(&["tool".into()], ".", &permissions).unwrap();
        let value = serde_json::json!({
            "id": "legacy",
            "protocol_request_id": 1,
            "protocol_approval_id": null,
            "thread_id": "thread",
            "turn_id": "turn",
            "item_id": "item",
            "argv": ["tool"],
            "command_display": "tool",
            "cwd": ".",
            "reason": null,
            "requested_permissions": permissions,
            "route": "legacy",
            "repository_id": Digest::blake3(b"repo"),
            "repository_root": ".",
            "expires_unix_ms": 100,
            "classification": "pending_user",
            "payload_digest": digest,
            "decision": null,
            "decision_source": null,
            "decided_unix_ms": null
        });
        let decoded: ApprovalRequest = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.host, AgentHost::Codex);
        assert_eq!(decoded.operation, ApprovalOperation::CommandExecution);
        assert_eq!(decoded.payload_digest_revision, 1);
        assert!(decoded.allowances.is_none());
        assert!(decoded.automation_advice.is_none());
    }
}
