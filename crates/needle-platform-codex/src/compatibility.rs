use crate::app_server::validate_compatibility_fixture;
use needle_core::Digest;
use serde_json::Value;
use sha2::{Digest as Sha2Digest, Sha256};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_PROTOCOL_SCHEMA_BYTES: u64 = 8 * 1024 * 1024;
const REQUIRED_APP_SERVER_METHODS: &[&str] = &[
    "thread/start",
    "turn/start",
    "turn/interrupt",
    "thread/delete",
    "item/agentMessage/delta",
    "item/commandExecution/requestApproval",
    "item/fileChange/requestApproval",
    "turn/completed",
    "thread/tokenUsage/updated",
];

pub(crate) struct ProtocolCompatibility {
    pub(crate) supported: bool,
    pub(crate) protocol_schema_digest: Digest,
    pub(crate) known_fixture_validated: bool,
    pub(crate) incompatibility_reason: Option<String>,
}

pub(crate) fn verify_protocol(
    executable: &str,
    codex_version: &str,
) -> Result<ProtocolCompatibility, String> {
    let schema = GeneratedProtocolSchema::generate(executable)?;
    let compatibility = validate_protocol_capabilities(&schema);
    let (supported, incompatibility_reason) = match compatibility {
        Ok(()) => (true, None),
        Err(error) => (false, Some(error)),
    };
    let known_fixture_validated =
        supported && known_compatibility_fixture_matches(codex_version, &schema)?;
    Ok(ProtocolCompatibility {
        supported,
        protocol_schema_digest: schema.protocol_digest,
        known_fixture_validated,
        incompatibility_reason,
    })
}

struct GeneratedProtocolSchema {
    root: PathBuf,
    protocol: Value,
    protocol_v2: Value,
    thread_start: Value,
    turn_start: Value,
    turn_interrupt: Value,
    command_approval: Value,
    command_approval_response: Value,
    file_change_approval_response: Value,
    token_usage_updated: Value,
    turn_completed: Value,
    protocol_digest: Digest,
    protocol_sha256: String,
    protocol_v2_sha256: String,
}

impl GeneratedProtocolSchema {
    fn generate(executable: &str) -> Result<Self, String> {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let root =
            env::temp_dir().join(format!("needle-codex-schema-{}-{suffix}", std::process::id()));
        fs::create_dir(&root)
            .map_err(|error| format!("cannot create Codex schema directory: {error}"))?;
        let generated = Command::new(executable)
            .args(["app-server", "generate-json-schema", "--experimental", "--out"])
            .arg(&root)
            .env_clear()
            .envs(crate::worker::sanitized_environment())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output();
        let output = match generated {
            Ok(output) => output,
            Err(error) => {
                let _ = fs::remove_dir_all(&root);
                return Err(format!("cannot generate Codex App Server schema: {error}"));
            }
        };
        if !output.status.success() {
            let diagnostic = bound_text(&String::from_utf8_lossy(&output.stderr), 1024);
            let _ = fs::remove_dir_all(&root);
            return Err(format!("Codex App Server schema generation failed: {diagnostic}"));
        }
        let result = (|| {
            let (_, protocol) =
                read_schema_json(&root.join("codex_app_server_protocol.schemas.json"))?;
            let (_, protocol_v2) =
                read_schema_json(&root.join("codex_app_server_protocol.v2.schemas.json"))?;
            let (_, thread_start) = read_schema_json(&root.join("v2/ThreadStartParams.json"))?;
            let (_, turn_start) = read_schema_json(&root.join("v2/TurnStartParams.json"))?;
            let (_, turn_interrupt) = read_schema_json(&root.join("v2/TurnInterruptParams.json"))?;
            let (_, command_approval) =
                read_schema_json(&root.join("CommandExecutionRequestApprovalParams.json"))?;
            let (_, command_approval_response) =
                read_schema_json(&root.join("CommandExecutionRequestApprovalResponse.json"))?;
            let (_, file_change_approval_response) =
                read_schema_json(&root.join("FileChangeRequestApprovalResponse.json"))?;
            let (_, token_usage_updated) =
                read_schema_json(&root.join("v2/ThreadTokenUsageUpdatedNotification.json"))?;
            let (_, turn_completed) =
                read_schema_json(&root.join("v2/TurnCompletedNotification.json"))?;
            Ok(Self {
                root: root.clone(),
                protocol_digest: Digest::blake3(canonical_json_bytes(&protocol_v2)?),
                protocol_sha256: canonical_json_sha256(&protocol)?,
                protocol_v2_sha256: canonical_json_sha256(&protocol_v2)?,
                protocol,
                protocol_v2,
                thread_start,
                turn_start,
                turn_interrupt,
                command_approval,
                command_approval_response,
                file_change_approval_response,
                token_usage_updated,
                turn_completed,
            })
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&root);
        }
        result
    }
}

impl Drop for GeneratedProtocolSchema {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn read_schema_json(path: &Path) -> Result<(Vec<u8>, Value), String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("missing generated Codex schema {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_PROTOCOL_SCHEMA_BYTES {
        return Err(format!(
            "generated Codex schema {} exceeds the bounded file contract",
            path.display()
        ));
    }
    let bytes = fs::read(path).map_err(|error| {
        format!("cannot read generated Codex schema {}: {error}", path.display())
    })?;
    let value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid generated Codex schema {}: {error}", path.display()))?;
    Ok((bytes, value))
}

fn canonical_json_sha256(value: &Value) -> Result<String, String> {
    let digest = Sha256::digest(canonical_json_bytes(value)?);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}")
            .expect("formatting a SHA-256 digest into a String cannot fail");
    }
    Ok(encoded)
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value)
        .map_err(|error| format!("cannot canonicalize generated Codex schema: {error}"))
}

fn validate_protocol_capabilities(schema: &GeneratedProtocolSchema) -> Result<(), String> {
    for required in REQUIRED_APP_SERVER_METHODS {
        if !json_contains_string(&schema.protocol, required)
            && !json_contains_string(&schema.protocol_v2, required)
        {
            return Err(format!("Codex App Server schema is missing required method {required}"));
        }
    }
    require_schema_properties(
        &schema.thread_start,
        "ThreadStartParams",
        &["approvalPolicy", "cwd", "model", "sandbox"],
    )?;
    require_schema_properties(
        &schema.turn_start,
        "TurnStartParams",
        &["approvalPolicy", "input", "outputSchema", "sandboxPolicy", "threadId"],
    )?;
    require_schema_properties(
        &schema.turn_interrupt,
        "TurnInterruptParams",
        &["threadId", "turnId"],
    )?;
    require_schema_properties(
        &schema.command_approval,
        "CommandExecutionRequestApprovalParams",
        &["itemId", "threadId", "turnId"],
    )?;
    require_schema_properties(
        &schema.command_approval_response,
        "CommandExecutionRequestApprovalResponse",
        &["decision"],
    )?;
    require_schema_properties(
        &schema.file_change_approval_response,
        "FileChangeRequestApprovalResponse",
        &["decision"],
    )?;
    require_schema_properties(
        &schema.token_usage_updated,
        "ThreadTokenUsageUpdatedNotification",
        &["threadId", "tokenUsage"],
    )?;
    require_schema_properties(
        &schema.turn_completed,
        "TurnCompletedNotification",
        &["threadId", "turn"],
    )?;
    Ok(())
}

fn json_contains_string(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(value) => value == expected,
        Value::Array(values) => values.iter().any(|value| json_contains_string(value, expected)),
        Value::Object(values) => values.values().any(|value| json_contains_string(value, expected)),
        _ => false,
    }
}

fn require_schema_properties(
    schema: &Value,
    schema_name: &str,
    required: &[&str],
) -> Result<(), String> {
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("Codex App Server schema has no {schema_name} properties"))?;
    for property in required {
        if !properties.contains_key(*property) {
            return Err(format!("Codex App Server schema is missing {schema_name}.{property}"));
        }
    }
    Ok(())
}

fn known_compatibility_fixture_matches(
    codex_version: &str,
    schema: &GeneratedProtocolSchema,
) -> Result<bool, String> {
    if codex_version != "0.144.0" {
        return Ok(false);
    }
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/codex-app-server/0.144.0/compatibility.json"
    ))
    .map_err(|error| format!("invalid App Server compatibility fixture: {error}"))?;
    validate_compatibility_fixture(codex_version, &fixture)?;
    Ok(fixture.get("protocol_schema_canonical_json_sha256").and_then(Value::as_str)
        == Some(schema.protocol_sha256.as_str())
        && fixture.get("protocol_v2_schema_canonical_json_sha256").and_then(Value::as_str)
            == Some(schema.protocol_v2_sha256.as_str()))
}

fn bound_text(value: &str, max_bytes: usize) -> String {
    let mut end = value.len().min(max_bytes);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn compatible_protocol_schema() -> GeneratedProtocolSchema {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        GeneratedProtocolSchema {
            root: env::temp_dir().join(format!(
                "needle-nonexistent-protocol-schema-test-{}-{suffix}",
                std::process::id()
            )),
            protocol: json!({"methods": [
                "item/commandExecution/requestApproval",
                "item/fileChange/requestApproval"
            ]}),
            protocol_v2: json!({"methods": [
                "thread/start", "turn/start", "turn/interrupt", "thread/delete",
                "item/agentMessage/delta", "turn/completed", "thread/tokenUsage/updated"
            ]}),
            thread_start: json!({"properties": {
                "approvalPolicy": {}, "cwd": {}, "model": {}, "sandbox": {}
            }}),
            turn_start: json!({"properties": {
                "approvalPolicy": {}, "input": {}, "outputSchema": {},
                "sandboxPolicy": {}, "threadId": {}
            }}),
            turn_interrupt: json!({"properties": {"threadId": {}, "turnId": {}}}),
            command_approval: json!({"properties": {
                "itemId": {}, "threadId": {}, "turnId": {}
            }}),
            command_approval_response: json!({"properties": {"decision": {}}}),
            file_change_approval_response: json!({"properties": {"decision": {}}}),
            token_usage_updated: json!({"properties": {
                "threadId": {}, "tokenUsage": {}
            }}),
            turn_completed: json!({"properties": {"threadId": {}, "turn": {}}}),
            protocol_digest: Digest::blake3(b"schema"),
            protocol_sha256: "fixture-v1".to_owned(),
            protocol_v2_sha256: "fixture-v2".to_owned(),
        }
    }

    #[test]
    fn app_server_compatibility_is_capability_based_across_protocol_generations() {
        let schema = compatible_protocol_schema();
        validate_protocol_capabilities(&schema).unwrap();

        let mut incomplete = compatible_protocol_schema();
        incomplete.protocol_v2 = json!({"methods": ["thread/start"]});
        let error = validate_protocol_capabilities(&incomplete).unwrap_err();
        assert!(error.contains("turn/start"));
    }
}
