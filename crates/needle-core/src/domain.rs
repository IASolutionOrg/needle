use crate::{
    ArtifactKind, Digest, HARD_RESULT_BYTES, HARD_RESULT_TOKENS, NeedFragment, NeedKey,
    RoleProfileProvenance, SemanticArtifactResult, TestPlan, WorkerArtifactResult,
    normalize_line_endings,
};
use serde::{Deserialize, Serialize};

pub const NEED_RESULT_SCHEMA_ID: &str = "needle.need-result/5";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteMatcher {
    pub platform: String,
    pub main_model: String,
    pub need_key: NeedKey,
    pub repository: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub id: String,
    pub enabled: bool,
    pub priority: i32,
    pub matcher: RouteMatcher,
    pub preset_id: String,
    pub definition_digest: Digest,
}

impl Route {
    pub fn new(
        id: impl Into<String>,
        priority: i32,
        matcher: RouteMatcher,
        preset_id: impl Into<String>,
    ) -> Self {
        let id = id.into();
        let preset_id = preset_id.into();
        let definition_digest =
            Self::compute_definition_digest(&id, priority, &matcher, &preset_id);
        Self { id, enabled: true, priority, matcher, preset_id, definition_digest }
    }

    pub fn has_valid_definition_digest(&self) -> bool {
        self.definition_digest
            == Self::compute_definition_digest(
                &self.id,
                self.priority,
                &self.matcher,
                &self.preset_id,
            )
    }

    fn compute_definition_digest(
        id: &str,
        priority: i32,
        matcher: &RouteMatcher,
        preset_id: &str,
    ) -> Digest {
        Digest::blake3(format!(
            "needle-route\n{id}\n{priority}\n{}\n{}\n{}\n{}\n{preset_id}\n",
            matcher.platform, matcher.main_model, matcher.need_key, matcher.repository,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    pub id: String,
    pub name: String,
    pub system_prompt: String,
    pub definition_digest: Digest,
}

impl Preset {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        system_prompt: impl Into<String>,
    ) -> Self {
        let id = id.into();
        let name = name.into();
        let system_prompt = normalize_line_endings(&system_prompt.into());
        let definition_digest = Self::compute_definition_digest(&id, &name, &system_prompt);
        Self { id, name, system_prompt, definition_digest }
    }

    pub fn has_valid_definition_digest(&self) -> bool {
        self.definition_digest
            == Self::compute_definition_digest(&self.id, &self.name, &self.system_prompt)
    }

    fn compute_definition_digest(id: &str, name: &str, system_prompt: &str) -> Digest {
        Digest::blake3(format!("needle-preset\n{id}\n{name}\n{system_prompt}\n"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerConfig {
    pub executable: String,
    pub model: String,
    pub reasoning: String,
    #[serde(default)]
    pub service_tier: Option<String>,
    pub timeout_seconds: u64,
    #[serde(default = "default_worker_max_turns")]
    pub max_turns: u8,
    #[serde(default)]
    pub evidence_failure_policy: EvidenceFailurePolicy,
    #[serde(default)]
    pub role_profile_provenance: Option<RoleProfileProvenance>,
}

impl WorkerConfig {
    pub fn digest(&self) -> Digest {
        Digest::blake3(format!(
            "needle-worker-config\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.executable,
            self.model,
            self.reasoning,
            self.service_tier.as_deref().unwrap_or_default(),
            self.timeout_seconds,
            self.max_turns,
            self.evidence_failure_policy.as_str(),
            self.role_profile_provenance
                .as_ref()
                .map(|provenance| {
                    format!(
                        "{}@{}#{}",
                        provenance.profile_id, provenance.revision, provenance.definition_digest
                    )
                })
                .unwrap_or_default(),
        ))
    }
}

const fn default_worker_max_turns() -> u8 {
    2
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFailurePolicy {
    #[default]
    DiscardInvalidFact,
    RepairOnce,
}

impl EvidenceFailurePolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DiscardInvalidFact => "discard_invalid_fact",
            Self::RepairOnce => "repair_once",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequest {
    pub root_task: String,
    pub need_key: NeedKey,
    pub need_body: String,
    pub preset: Preset,
    pub repository_root: String,
    pub repository_snapshot: RepositorySnapshot,
    #[serde(default)]
    pub declared_test_plan: Option<TestPlan>,
    #[serde(default)]
    pub trusted_test_execution: bool,
    #[serde(default)]
    pub requested_artifact_kinds: Vec<ArtifactKind>,
    #[serde(default)]
    pub preferred_artifact_kinds: Vec<ArtifactKind>,
    #[serde(default)]
    pub semantic_fragment: Option<NeedFragment>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerOutcome {
    pub result: NeedResult,
    #[serde(default)]
    pub artifact_result: Option<WorkerArtifactResult>,
    #[serde(default)]
    pub semantic_artifact_result: Option<SemanticArtifactResult>,
    pub worker_model: String,
    pub worker_reasoning: String,
    pub codex_version: String,
    #[serde(default)]
    pub host_protocol_schema_digest: Option<Digest>,
    pub input_tokens: Option<u64>,
    pub cached_input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub duration_ms: u64,
    pub process_status: String,
    #[serde(default = "one_u32")]
    pub logical_worker_spawns: u32,
    #[serde(default = "one_u32")]
    pub worker_turns: u32,
    #[serde(default)]
    pub repair_performed: bool,
    #[serde(default)]
    pub discarded_facts: u32,
    #[serde(default)]
    pub worker_session_id: Option<String>,
    #[serde(default)]
    pub session_cleanup_success: Option<bool>,
    #[serde(default)]
    pub role_profile_provenance: Option<RoleProfileProvenance>,
}

const fn one_u32() -> u32 {
    1
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, thiserror::Error)]
#[error("{code}: {diagnostic}")]
#[serde(deny_unknown_fields)]
pub struct WorkerFailure {
    pub code: String,
    pub diagnostic: String,
    pub input_tokens: Option<u64>,
    pub cached_input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub duration_ms: u64,
    pub logical_worker_spawns: u32,
    pub worker_turns: u32,
    pub repair_performed: bool,
    pub discarded_facts: u32,
    pub worker_session_id: Option<String>,
    pub session_cleanup_success: Option<bool>,
    #[serde(default)]
    pub role_profile_provenance: Option<RoleProfileProvenance>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NeedResult {
    #[serde(default)]
    pub complete: bool,
    pub summary: String,
    pub claims: Vec<Claim>,
    pub evidence: Vec<EvidenceReference>,
    #[serde(default)]
    pub suggested_reads: Vec<String>,
    #[serde(default)]
    pub suggested_commands: Vec<String>,
    #[serde(default)]
    pub uncertainty: Vec<Uncertainty>,
}

impl NeedResult {
    pub fn digest(&self) -> Result<Digest, serde_json::Error> {
        serde_json::to_vec(self).map(Digest::blake3)
    }

    pub fn render_evidence_brief(&self, _key: &NeedKey, _status: &str) -> String {
        let evidence_by_id = self
            .evidence
            .iter()
            .map(|evidence| (evidence.id.as_str(), evidence))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut rendered = String::from("[NEEDLE_CONTEXT]\n");
        for claim in &self.claims {
            rendered.push_str("- ");
            rendered.push_str(claim.statement.trim());
            if let Some(evidence) =
                claim.evidence_ids.first().and_then(|id| evidence_by_id.get(id.as_str()))
            {
                rendered.push_str(" — ");
                rendered.push_str(&evidence.path);
                if let Some(symbol) = evidence.symbol.as_deref() {
                    rendered.push_str(" :: ");
                    rendered.push_str(symbol);
                }
            }
            rendered.push('\n');
        }
        for command in &self.suggested_commands {
            rendered.push_str("cmd: ");
            rendered.push_str(command);
            rendered.push('\n');
        }
        rendered
            .push_str("[/NEEDLE_CONTEXT]\nUsa solo questo brief; non ispezionare il repository.");
        bound_evidence_brief(rendered)
    }
}

fn bound_evidence_brief(mut rendered: String) -> String {
    let maximum = HARD_RESULT_BYTES.min(HARD_RESULT_TOKENS.saturating_mul(4));
    if rendered.len() <= maximum {
        return rendered;
    }
    const FOOTER: &str = "\n- additional evidence omitted\n[/NEEDLE_CONTEXT]\nUsa solo questo brief; non ispezionare il repository.";
    let prefix_limit = maximum.saturating_sub(FOOTER.len());
    let mut end = prefix_limit.min(rendered.len());
    while end > 0 && !rendered.is_char_boundary(end) {
        end -= 1;
    }
    rendered.truncate(end);
    rendered.push_str(FOOTER);
    rendered
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub id: String,
    pub kind: String,
    pub subject: String,
    pub statement: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReference {
    pub id: String,
    pub path: String,
    pub symbol: Option<String>,
    pub content_digest: Digest,
    pub byte_start: Option<u64>,
    pub byte_end: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Uncertainty {
    pub statement: String,
}

pub const LEGACY_REPOSITORY_SNAPSHOT_IDENTITY_REVISION: u16 = 1;
pub const REPOSITORY_SNAPSHOT_IDENTITY_REVISION: u16 = 2;

const fn legacy_repository_snapshot_identity_revision() -> u16 {
    LEGACY_REPOSITORY_SNAPSHOT_IDENTITY_REVISION
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositorySnapshot {
    #[serde(default = "legacy_repository_snapshot_identity_revision")]
    pub identity_revision: u16,
    pub repository_id: Digest,
    pub head_sha: String,
    pub tracked_changes_digest: Digest,
    pub untracked_content_digest: Digest,
    pub source_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NeedCacheIdentity {
    pub repository_id: Digest,
    pub source_snapshot_digest: Digest,
    pub prompt_profile_digest: Digest,
    pub route_definition_digest: Digest,
    pub preset_definition_digest: Digest,
    pub need_key: NeedKey,
    pub normalized_request_digest: Digest,
    pub worker_configuration_digest: Digest,
    pub output_schema_digest: Digest,
    #[serde(default)]
    pub role_profile_provenance: Option<RoleProfileProvenance>,
}

impl NeedCacheIdentity {
    pub fn digest(&self) -> Digest {
        Digest::blake3(format!(
            "needle-cache-identity\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.repository_id,
            self.source_snapshot_digest,
            self.prompt_profile_digest,
            self.route_definition_digest,
            self.preset_definition_digest,
            self.need_key,
            self.normalized_request_digest,
            self.worker_configuration_digest,
            self.output_schema_digest,
            provenance_identity(self.role_profile_provenance.as_ref()),
        ))
    }

    pub fn logical_digest(&self) -> Digest {
        Digest::blake3(format!(
            "needle-cache-logical\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.repository_id,
            self.prompt_profile_digest,
            self.route_definition_digest,
            self.preset_definition_digest,
            self.need_key,
            self.normalized_request_digest,
            self.worker_configuration_digest,
            self.output_schema_digest,
            provenance_identity(self.role_profile_provenance.as_ref()),
        ))
    }
}

fn provenance_identity(provenance: Option<&RoleProfileProvenance>) -> String {
    provenance
        .map(|value| format!("{}@{}#{}", value.profile_id, value.revision, value.definition_digest))
        .unwrap_or_else(|| "unknown".to_owned())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NeedCacheEntry {
    pub identity: NeedCacheIdentity,
    pub result: NeedResult,
    pub worker_outcome: WorkerOutcome,
    pub created_unix_ms: u64,
    pub hit_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheLookup {
    Hit(Box<NeedCacheEntry>),
    Miss,
    Stale,
    Bypass(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_and_preset_definition_digests_are_deterministic() {
        let matcher = RouteMatcher {
            platform: "codex".to_owned(),
            main_model: "*".to_owned(),
            need_key: NeedKey::new("trace.state-flow").unwrap(),
            repository: "*".to_owned(),
        };
        assert_eq!(
            Route::new("trace", 1, matcher.clone(), "trace.state-flow").definition_digest,
            Route::new("trace", 1, matcher, "trace.state-flow").definition_digest
        );
        assert_eq!(
            Preset::new("p", "P", "line\r\nline").definition_digest,
            Preset::new("p", "P", "line\nline").definition_digest
        );
    }

    #[test]
    fn legacy_worker_outcome_without_host_protocol_digest_remains_decodable() {
        let outcome = WorkerOutcome {
            result: NeedResult {
                complete: true,
                summary: "fixture".to_owned(),
                claims: Vec::new(),
                evidence: Vec::new(),
                suggested_reads: Vec::new(),
                suggested_commands: Vec::new(),
                uncertainty: Vec::new(),
            },
            artifact_result: None,
            semantic_artifact_result: None,
            worker_model: "fixture".to_owned(),
            worker_reasoning: "low".to_owned(),
            codex_version: "0.144.0".to_owned(),
            host_protocol_schema_digest: Some(Digest::blake3(b"schema")),
            input_tokens: None,
            cached_input_tokens: None,
            output_tokens: None,
            duration_ms: 1,
            process_status: "success".to_owned(),
            logical_worker_spawns: 1,
            worker_turns: 1,
            repair_performed: false,
            discarded_facts: 0,
            worker_session_id: None,
            session_cleanup_success: Some(true),
            role_profile_provenance: None,
        };
        let mut legacy = serde_json::to_value(outcome).unwrap();
        legacy.as_object_mut().unwrap().remove("host_protocol_schema_digest");

        let decoded: WorkerOutcome = serde_json::from_value(legacy).unwrap();

        assert_eq!(decoded.host_protocol_schema_digest, None);
    }

    #[test]
    fn legacy_worker_request_without_semantic_fragment_remains_decodable() {
        let request = WorkerRequest {
            root_task: "fixture".to_owned(),
            need_key: NeedKey::new("locate.implementation").unwrap(),
            need_body: "Locate the fixture.".to_owned(),
            preset: Preset::new("locate.implementation", "Locate", "fixture"),
            repository_root: "repository".to_owned(),
            repository_snapshot: RepositorySnapshot {
                identity_revision: REPOSITORY_SNAPSHOT_IDENTITY_REVISION,
                repository_id: Digest::blake3(b"repository"),
                head_sha: "0".repeat(40),
                tracked_changes_digest: Digest::blake3(b"tracked"),
                untracked_content_digest: Digest::blake3(b"untracked"),
                source_digest: Digest::blake3(b"source"),
            },
            declared_test_plan: None,
            trusted_test_execution: false,
            requested_artifact_kinds: Vec::new(),
            preferred_artifact_kinds: Vec::new(),
            semantic_fragment: None,
        };
        let mut legacy = serde_json::to_value(request).unwrap();
        legacy.as_object_mut().unwrap().remove("semantic_fragment");

        let decoded: WorkerRequest = serde_json::from_value(legacy).unwrap();

        assert_eq!(decoded.semantic_fragment, None);
    }
}
