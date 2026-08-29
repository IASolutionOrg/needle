use super::{AppError, canonical_child_path, required_value};
use crate::lifecycle_explore_authority::{
    AUTHORITY_PREFLIGHT_FILE, DATABASE_FILE, LIVE_REPORT_FILE, LifecycleExploreAuthorityPreflight,
    MAX_AUTHORITY_PREFLIGHT_BYTES,
};
use crate::lifecycle_explore_authority_acceptance::{
    ACCEPTANCE_FILE, LifecycleExploreAuthorityAcceptance, MAX_ACCEPTANCE_BYTES,
};
use crate::lifecycle_explore_lifecycle_authority::{
    LIFECYCLE_AUTHORITY_PREFLIGHT_FILE, LifecycleExploreLifecycleAuthorityPreflight,
    MAX_LIFECYCLE_AUTHORITY_PREFLIGHT_BYTES,
};
use crate::lifecycle_explore_live::{
    MAX_LIFECYCLE_EXPLORE_LIVE_REPORT_BYTES, decode_authority_source,
};
use needle_bench::read_bounded_file;
use needle_core::{ActionCapabilityDecisionId, CanonicalHasher, CapabilityMode, Digest};
use needle_runtime::{
    ProviderBackedActionAssuranceInput, RuntimeStore, implementation_location_exact_capability,
};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

const LIFECYCLE_AUTHORITY_ACCEPTANCE_FORMAT_REVISION: u16 = 1;
const LIFECYCLE_AUTHORITY_ACCEPTANCE_SCHEMA: &str =
    "needle.lifecycle-explore-lifecycle-authority-acceptance/1";
pub(super) const LIFECYCLE_AUTHORITY_ACCEPTANCE_FILE: &str =
    "lifecycle-explore-lifecycle-authority-acceptance.json";
pub(super) const MAX_LIFECYCLE_AUTHORITY_ACCEPTANCE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LifecycleExploreLifecycleAuthorityAcceptance {
    format_revision: u16,
    schema: String,
    preflight_digest: Digest,
    source_authority_acceptance_digest: Digest,
    database_schema_version: u64,
    capability_class: needle_core::ActionCapabilityClassId,
    capability_definition_digest: Digest,
    evidence: needle_core::ActionAssuranceEvidenceId,
    evidence_definition_digest: Digest,
    previous_decision: ActionCapabilityDecisionId,
    previous_decision_recorded_unix_ms: u64,
    pub(super) decision: ActionCapabilityDecisionId,
    decision_definition_digest: Digest,
    pub(super) decision_recorded_unix_ms: u64,
    selected_mode: CapabilityMode,
    automatic_resolver_consumption_approved: bool,
    automatic_lifecycle_consumption_approved: bool,
    evidence_reused: bool,
    provider_call_performed: bool,
    database_migrated: bool,
    decision_persisted: bool,
    lifecycle_consumption_approved: bool,
    pub(super) acceptance_digest: Digest,
}

impl LifecycleExploreLifecycleAuthorityAcceptance {
    pub(super) fn decode_json(
        bytes: &[u8],
        preflight: &LifecycleExploreLifecycleAuthorityPreflight,
    ) -> Result<Self, AppError> {
        if bytes.len() > MAX_LIFECYCLE_AUTHORITY_ACCEPTANCE_BYTES {
            return Err(AppError::Experiment(format!(
                "lifecycle authority acceptance has {} bytes; maximum is {}",
                bytes.len(),
                MAX_LIFECYCLE_AUTHORITY_ACCEPTANCE_BYTES
            )));
        }
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate(preflight)?;
        Ok(value)
    }

    fn new(
        preflight: &LifecycleExploreLifecycleAuthorityPreflight,
        decision_recorded_unix_ms: u64,
    ) -> Result<Self, AppError> {
        let mut value = Self {
            format_revision: LIFECYCLE_AUTHORITY_ACCEPTANCE_FORMAT_REVISION,
            schema: LIFECYCLE_AUTHORITY_ACCEPTANCE_SCHEMA.to_owned(),
            preflight_digest: preflight.preflight_digest,
            source_authority_acceptance_digest: preflight.source_authority_acceptance_digest,
            database_schema_version: preflight.source_database_schema_version,
            capability_class: preflight.capability_class.id,
            capability_definition_digest: preflight.capability_class.definition_digest,
            evidence: preflight.evidence.id,
            evidence_definition_digest: preflight.evidence.definition_digest,
            previous_decision: preflight.current_decision.id,
            previous_decision_recorded_unix_ms: preflight.current_decision_recorded_unix_ms,
            decision: preflight.proposed_decision.id,
            decision_definition_digest: preflight.proposed_decision.definition_digest,
            decision_recorded_unix_ms,
            selected_mode: preflight.proposed_decision.selected_mode,
            automatic_resolver_consumption_approved: preflight
                .proposed_decision
                .automatic_resolver_consumption_approved,
            automatic_lifecycle_consumption_approved: preflight
                .proposed_decision
                .automatic_lifecycle_consumption_approved,
            evidence_reused: true,
            provider_call_performed: false,
            database_migrated: false,
            decision_persisted: true,
            lifecycle_consumption_approved: true,
            acceptance_digest: Digest([0; 32]),
        };
        value.validate_shape(preflight)?;
        value.acceptance_digest = value.compute_digest();
        Ok(value)
    }

    pub(super) fn validate(
        &self,
        preflight: &LifecycleExploreLifecycleAuthorityPreflight,
    ) -> Result<(), AppError> {
        self.validate_shape(preflight)?;
        if self.acceptance_digest != self.compute_digest() {
            return Err(AppError::Experiment(
                "lifecycle Explore lifecycle authority acceptance digest is inconsistent".into(),
            ));
        }
        Ok(())
    }

    fn validate_shape(
        &self,
        preflight: &LifecycleExploreLifecycleAuthorityPreflight,
    ) -> Result<(), AppError> {
        preflight.validate()?;
        if self.format_revision != LIFECYCLE_AUTHORITY_ACCEPTANCE_FORMAT_REVISION
            || self.schema != LIFECYCLE_AUTHORITY_ACCEPTANCE_SCHEMA
            || self.preflight_digest != preflight.preflight_digest
            || self.source_authority_acceptance_digest
                != preflight.source_authority_acceptance_digest
            || self.database_schema_version != 32
            || self.database_schema_version != preflight.source_database_schema_version
            || self.capability_class != preflight.capability_class.id
            || self.capability_definition_digest != preflight.capability_class.definition_digest
            || self.evidence != preflight.evidence.id
            || self.evidence_definition_digest != preflight.evidence.definition_digest
            || self.previous_decision != preflight.current_decision.id
            || self.previous_decision_recorded_unix_ms
                != preflight.current_decision_recorded_unix_ms
            || self.decision != preflight.proposed_decision.id
            || self.decision_definition_digest != preflight.proposed_decision.definition_digest
            || self.decision_recorded_unix_ms == 0
            || self.selected_mode != CapabilityMode::Authoritative
            || !self.automatic_resolver_consumption_approved
            || !self.automatic_lifecycle_consumption_approved
            || !self.evidence_reused
            || self.provider_call_performed
            || self.database_migrated
            || !self.decision_persisted
            || !self.lifecycle_consumption_approved
        {
            return Err(AppError::Experiment(
                "lifecycle Explore lifecycle authority acceptance shape is invalid".into(),
            ));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher =
            CanonicalHasher::new(b"lifecycle-explore-lifecycle-authority-acceptance-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_digest(self.preflight_digest);
        hasher.field_digest(self.source_authority_acceptance_digest);
        hasher.field_bytes(&self.database_schema_version.to_le_bytes());
        hasher.field_digest(self.capability_class.digest());
        hasher.field_digest(self.capability_definition_digest);
        hasher.field_digest(self.evidence.digest());
        hasher.field_digest(self.evidence_definition_digest);
        hasher.field_digest(self.previous_decision.digest());
        hasher.field_bytes(&self.previous_decision_recorded_unix_ms.to_le_bytes());
        hasher.field_digest(self.decision.digest());
        hasher.field_digest(self.decision_definition_digest);
        hasher.field_bytes(&self.decision_recorded_unix_ms.to_le_bytes());
        hasher.field_u8(capability_mode_tag(self.selected_mode));
        hasher.field_u8(u8::from(self.automatic_resolver_consumption_approved));
        hasher.field_u8(u8::from(self.automatic_lifecycle_consumption_approved));
        hasher.field_u8(u8::from(self.evidence_reused));
        hasher.field_u8(u8::from(self.provider_call_performed));
        hasher.field_u8(u8::from(self.database_migrated));
        hasher.field_u8(u8::from(self.decision_persisted));
        hasher.field_u8(u8::from(self.lifecycle_consumption_approved));
        hasher.finish()
    }
}

pub(super) fn run(arguments: &[String]) -> Result<(), AppError> {
    let parsed = Arguments::parse(arguments)?;
    parsed.validate()?;
    let artifact_root =
        canonical_child_path(Path::new(&required_value(arguments, "--artifact-root")?))?;
    let report_path = artifact_root.join(LIVE_REPORT_FILE);
    let database_path = artifact_root.join(DATABASE_FILE);
    let source_preflight_path = artifact_root.join(AUTHORITY_PREFLIGHT_FILE);
    let source_acceptance_path = artifact_root.join(ACCEPTANCE_FILE);
    let lifecycle_preflight_path = artifact_root.join(LIFECYCLE_AUTHORITY_PREFLIGHT_FILE);
    if !report_path.is_file()
        || !database_path.is_file()
        || !source_preflight_path.is_file()
        || !source_acceptance_path.is_file()
        || !lifecycle_preflight_path.is_file()
    {
        return Err(AppError::Experiment(
            "lifecycle authority acceptance requires the retained report, database, resolver preflight/acceptance, and lifecycle preflight"
                .into(),
        ));
    }

    let source_preflight = LifecycleExploreAuthorityPreflight::decode_json(
        &read_bounded_file(&source_preflight_path, MAX_AUTHORITY_PREFLIGHT_BYTES)
            .map_err(|error| AppError::Experiment(error.to_string()))?,
    )?;
    let source_acceptance = LifecycleExploreAuthorityAcceptance::decode_json(
        &read_bounded_file(&source_acceptance_path, MAX_ACCEPTANCE_BYTES)
            .map_err(|error| AppError::Experiment(error.to_string()))?,
        &source_preflight,
    )?;
    let lifecycle_preflight = LifecycleExploreLifecycleAuthorityPreflight::decode_json(
        &read_bounded_file(&lifecycle_preflight_path, MAX_LIFECYCLE_AUTHORITY_PREFLIGHT_BYTES)
            .map_err(|error| AppError::Experiment(error.to_string()))?,
    )?;
    verify_explicit_identity(&parsed, &lifecycle_preflight)?;

    let report_bytes = read_bounded_file(&report_path, MAX_LIFECYCLE_EXPLORE_LIVE_REPORT_BYTES)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let source = decode_authority_source(&report_bytes)?;
    let source_report_digest = Digest::blake3(&report_bytes);
    if source_report_digest != lifecycle_preflight.source_report_digest {
        return Err(AppError::Experiment(
            "lifecycle authority acceptance live report differs from the rendered preflight".into(),
        ));
    }
    let provider_input = ProviderBackedActionAssuranceInput {
        repository: source.repository,
        source_snapshot: source.source_snapshot,
        lifecycle: source.lifecycle,
        adapter_invocation: source.adapter_invocation,
        artifact: source.artifact,
        execution_evidence_digest: source_report_digest,
    };
    let store = RuntimeStore::new(&database_path);
    let before = store
        .preflight_provider_backed_action_assurance(provider_input)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let capability = implementation_location_exact_capability();
    let already_accepted = lifecycle_preflight.validate_acceptance_source(
        &source_preflight,
        &source_acceptance,
        &before,
        capability,
    )?;
    let output = artifact_root.join(LIFECYCLE_AUTHORITY_ACCEPTANCE_FILE);
    let existing_acceptance = if output.is_file() {
        let existing = LifecycleExploreLifecycleAuthorityAcceptance::decode_json(
            &read_bounded_file(&output, MAX_LIFECYCLE_AUTHORITY_ACCEPTANCE_BYTES)
                .map_err(|error| AppError::Experiment(error.to_string()))?,
            &lifecycle_preflight,
        )?;
        let effective = before.effective_decision.as_ref().ok_or_else(|| {
            AppError::Experiment(
                "existing lifecycle authority receipt has no effective decision head".into(),
            )
        })?;
        if !already_accepted || existing.decision_recorded_unix_ms != effective.recorded_unix_ms {
            return Err(AppError::Experiment(
                "existing lifecycle authority receipt does not match the persisted decision head"
                    .into(),
            ));
        }
        Some(existing)
    } else {
        None
    };

    let decision_record = store
        .accept_action_capability_decision(
            &lifecycle_preflight.evidence,
            &lifecycle_preflight.proposed_decision,
        )
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let effective = store
        .effective_action_capability_decision(lifecycle_preflight.capability_class.id)
        .map_err(|error| AppError::Experiment(error.to_string()))?
        .ok_or_else(|| {
            AppError::Experiment(
                "accepted lifecycle authority decision has no effective head".into(),
            )
        })?;
    if decision_record != effective
        || decision_record.decision != lifecycle_preflight.proposed_decision
        || decision_record.evidence != lifecycle_preflight.evidence
    {
        return Err(AppError::Experiment(
            "persisted lifecycle authority differs from the exact rendered proposal".into(),
        ));
    }
    let acceptance = LifecycleExploreLifecycleAuthorityAcceptance::new(
        &lifecycle_preflight,
        decision_record.recorded_unix_ms,
    )?;
    acceptance.validate(&lifecycle_preflight)?;
    drop(store);

    if existing_acceptance.as_ref().is_some_and(|existing| existing != &acceptance) {
        return Err(AppError::Experiment(
            "existing lifecycle authority receipt differs from the persisted decision".into(),
        ));
    }
    let created = write_create_new_or_verify_existing(&output, &acceptance)?;
    println!(
        "lifecycle Explore lifecycle authority acceptance {} {}",
        if created { "written to" } else { "verified at" },
        output.display()
    );
    println!("acceptance_digest={}", acceptance.acceptance_digest);
    println!("preflight_digest={}", acceptance.preflight_digest);
    println!("previous_decision_id={}", acceptance.previous_decision);
    println!("decision_id={}", acceptance.decision);
    println!("database_schema_version=32");
    println!("selected_mode=authoritative");
    println!("automatic_resolver_consumption_approved=true");
    println!("automatic_lifecycle_consumption_approved=true");
    println!("evidence_reused=true");
    println!("provider_call_performed=false");
    println!("database_migrated=false");
    println!("decision_persisted=true");
    println!("lifecycle_consumption_approved=true");
    Ok(())
}

fn verify_explicit_identity(
    arguments: &Arguments,
    preflight: &LifecycleExploreLifecycleAuthorityPreflight,
) -> Result<(), AppError> {
    let requested_preflight = Digest::parse(
        arguments
            .preflight_digest
            .as_deref()
            .ok_or_else(|| AppError::Usage("--preflight-digest is required".into()))?,
    )
    .map_err(|error| AppError::Usage(format!("invalid --preflight-digest: {error}")))?;
    let requested_current = parse_decision_id(
        arguments
            .current_decision_id
            .as_deref()
            .ok_or_else(|| AppError::Usage("--current-decision-id is required".into()))?,
        "--current-decision-id",
    )?;
    let requested_decision = parse_decision_id(
        arguments
            .decision_id
            .as_deref()
            .ok_or_else(|| AppError::Usage("--decision-id is required".into()))?,
        "--decision-id",
    )?;
    if requested_preflight != preflight.preflight_digest
        || requested_current != preflight.current_decision.id
        || requested_decision != preflight.proposed_decision.id
    {
        return Err(AppError::Experiment(
            "lifecycle authority acceptance identity differs from the explicit operator confirmation"
                .into(),
        ));
    }
    Ok(())
}

fn parse_decision_id(value: &str, argument: &str) -> Result<ActionCapabilityDecisionId, AppError> {
    Digest::parse(value)
        .map(ActionCapabilityDecisionId::new)
        .map_err(|error| AppError::Usage(format!("invalid {argument}: {error}")))
}

fn write_create_new_or_verify_existing(
    path: &Path,
    value: &LifecycleExploreLifecycleAuthorityAcceptance,
) -> Result<bool, AppError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_LIFECYCLE_AUTHORITY_ACCEPTANCE_BYTES {
        return Err(AppError::Experiment(format!(
            "lifecycle authority acceptance has {} bytes; maximum is {}",
            bytes.len(),
            MAX_LIFECYCLE_AUTHORITY_ACCEPTANCE_BYTES
        )));
    }
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(&bytes)?;
            file.sync_all()?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_bounded_file(path, MAX_LIFECYCLE_AUTHORITY_ACCEPTANCE_BYTES)
                .map_err(|error| AppError::Experiment(error.to_string()))?;
            if existing == bytes {
                Ok(false)
            } else {
                Err(AppError::Experiment(
                    "lifecycle authority acceptance output already exists with different canonical content"
                        .into(),
                ))
            }
        }
        Err(error) => Err(AppError::Io(error)),
    }
}

const fn capability_mode_tag(value: CapabilityMode) -> u8 {
    match value {
        CapabilityMode::Disabled => 0,
        CapabilityMode::Shadow => 1,
        CapabilityMode::Advisory => 2,
        CapabilityMode::Authoritative => 3,
    }
}

#[derive(Default)]
struct Arguments {
    artifact_root: Option<String>,
    preflight_digest: Option<String>,
    current_decision_id: Option<String>,
    decision_id: Option<String>,
    confirm_lifecycle_consumption: bool,
    confirm_exact_read_only_scope: bool,
    confirm_no_provider_call: bool,
}

impl Arguments {
    fn parse(arguments: &[String]) -> Result<Self, AppError> {
        let mut parsed = Self::default();
        let mut index = 0;
        while index < arguments.len() {
            match arguments[index].as_str() {
                "--artifact-root"
                | "--preflight-digest"
                | "--current-decision-id"
                | "--decision-id" => {
                    let value = arguments.get(index + 1).ok_or_else(|| {
                        AppError::Usage(format!("{} requires a value", arguments[index]))
                    })?;
                    match arguments[index].as_str() {
                        "--artifact-root" => parsed.artifact_root = Some(value.clone()),
                        "--preflight-digest" => parsed.preflight_digest = Some(value.clone()),
                        "--current-decision-id" => {
                            parsed.current_decision_id = Some(value.clone());
                        }
                        "--decision-id" => parsed.decision_id = Some(value.clone()),
                        _ => unreachable!(),
                    }
                    index += 2;
                }
                "--confirm-authoritative-lifecycle-consumption" => {
                    parsed.confirm_lifecycle_consumption = true;
                    index += 1;
                }
                "--confirm-exact-read-only-explore-only" => {
                    parsed.confirm_exact_read_only_scope = true;
                    index += 1;
                }
                "--confirm-no-provider-call" => {
                    parsed.confirm_no_provider_call = true;
                    index += 1;
                }
                argument => {
                    return Err(AppError::Usage(format!(
                        "unknown lifecycle-explore-lifecycle-authority-accept argument `{argument}`"
                    )));
                }
            }
        }
        Ok(parsed)
    }

    fn validate(&self) -> Result<(), AppError> {
        if self.artifact_root.is_none()
            || self.preflight_digest.is_none()
            || self.current_decision_id.is_none()
            || self.decision_id.is_none()
            || !self.confirm_lifecycle_consumption
            || !self.confirm_exact_read_only_scope
            || !self.confirm_no_provider_call
        {
            return Err(AppError::Usage(
                "lifecycle authority acceptance requires exact identities plus all three explicit confirmation flags"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle_explore_lifecycle_authority::LifecycleExploreLifecycleAuthorityPreflightInput;
    use needle_core::{
        ActionAssuranceEvidence, ActionAssuranceEvidenceInput, ActionAssuranceEvidenceKind,
        ActionCapabilityDecision, ActionCapabilityDecisionInput, ArtifactId, ArtifactRequestId,
        ArtifactValidationCertificateId, LifecycleId,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn digest(label: &str) -> Digest {
        Digest::blake3(label.as_bytes())
    }

    fn preflight() -> LifecycleExploreLifecycleAuthorityPreflight {
        let capability = implementation_location_exact_capability().clone();
        let report_digest = digest("report");
        let evidence = ActionAssuranceEvidence::new(ActionAssuranceEvidenceInput {
            capability_class: capability.id,
            capability_definition_digest: capability.definition_digest,
            action_request: ArtifactRequestId::new(digest("request")),
            artifact: ArtifactId::new(digest("artifact")),
            validation_certificate: ArtifactValidationCertificateId::new(digest("certificate")),
            repository: digest("repository"),
            source_snapshot: digest("source"),
            lifecycle: LifecycleId(digest("lifecycle")),
            adapter_invocation: digest("invocation"),
            evidence_kind: ActionAssuranceEvidenceKind::ProviderBackedFresh,
            execution_evidence_digest: report_digest,
            observed_unix_ms: 10,
        })
        .unwrap();
        let current_decision = ActionCapabilityDecision::new(ActionCapabilityDecisionInput {
            capability_class: capability.id,
            capability_definition_digest: capability.definition_digest,
            evidence: evidence.id,
            evidence_definition_digest: evidence.definition_digest,
            previous_decision: None,
            selected_mode: CapabilityMode::Authoritative,
            automatic_resolver_consumption_approved: true,
            automatic_lifecycle_consumption_approved: false,
            decider_id: "local-owner".to_owned(),
            decided_unix_ms: 20,
        })
        .unwrap();
        let proposed_decision = ActionCapabilityDecision::new(ActionCapabilityDecisionInput {
            capability_class: capability.id,
            capability_definition_digest: capability.definition_digest,
            evidence: evidence.id,
            evidence_definition_digest: evidence.definition_digest,
            previous_decision: Some(current_decision.id),
            selected_mode: CapabilityMode::Authoritative,
            automatic_resolver_consumption_approved: true,
            automatic_lifecycle_consumption_approved: true,
            decider_id: "local-owner".to_owned(),
            decided_unix_ms: 40,
        })
        .unwrap();
        LifecycleExploreLifecycleAuthorityPreflight::new(
            LifecycleExploreLifecycleAuthorityPreflightInput {
                source_report_digest: report_digest,
                source_authority_preflight_digest: digest("source-preflight"),
                source_authority_acceptance_digest: digest("source-acceptance"),
                source_database_schema_version: 32,
                capability_class: capability,
                evidence,
                current_decision,
                current_decision_recorded_unix_ms: 30,
                proposed_decision,
            },
        )
        .unwrap()
    }

    #[test]
    fn receipt_is_canonical_lifecycle_enabled_and_provider_free() {
        let preflight = preflight();
        let receipt = LifecycleExploreLifecycleAuthorityAcceptance::new(&preflight, 50).unwrap();
        receipt.validate(&preflight).unwrap();
        assert_eq!(receipt.previous_decision, preflight.current_decision.id);
        assert_eq!(receipt.decision, preflight.proposed_decision.id);
        assert!(receipt.automatic_resolver_consumption_approved);
        assert!(receipt.automatic_lifecycle_consumption_approved);
        assert!(receipt.evidence_reused);
        assert!(!receipt.provider_call_performed);
        assert!(!receipt.database_migrated);
        assert!(receipt.decision_persisted);
        assert!(receipt.lifecycle_consumption_approved);

        let mut tampered = receipt;
        tampered.provider_call_performed = true;
        assert!(tampered.validate(&preflight).is_err());
    }

    #[test]
    fn arguments_require_exact_identities_and_all_confirmations() {
        let parsed = Arguments::parse(&[
            "--artifact-root".into(),
            "target/live".into(),
            "--preflight-digest".into(),
            digest("preflight").to_string(),
            "--current-decision-id".into(),
            digest("current").to_string(),
            "--decision-id".into(),
            digest("decision").to_string(),
            "--confirm-authoritative-lifecycle-consumption".into(),
            "--confirm-exact-read-only-explore-only".into(),
            "--confirm-no-provider-call".into(),
        ])
        .unwrap();
        parsed.validate().unwrap();

        let missing = Arguments::parse(&[
            "--artifact-root".into(),
            "target/live".into(),
            "--preflight-digest".into(),
            digest("preflight").to_string(),
            "--current-decision-id".into(),
            digest("current").to_string(),
            "--decision-id".into(),
            digest("decision").to_string(),
        ])
        .unwrap();
        assert!(missing.validate().is_err());
        assert!(Arguments::parse(&["--provider".into()]).is_err());
    }

    #[test]
    fn explicit_identity_must_match_the_exact_rendered_chain() {
        let preflight = preflight();
        let arguments = Arguments {
            artifact_root: Some("target/live".into()),
            preflight_digest: Some(preflight.preflight_digest.to_string()),
            current_decision_id: Some(preflight.current_decision.id.to_string()),
            decision_id: Some(preflight.proposed_decision.id.to_string()),
            confirm_lifecycle_consumption: true,
            confirm_exact_read_only_scope: true,
            confirm_no_provider_call: true,
        };
        verify_explicit_identity(&arguments, &preflight).unwrap();

        let mut tampered = arguments;
        tampered.decision_id = Some(digest("other-decision").to_string());
        assert!(verify_explicit_identity(&tampered, &preflight).is_err());
    }

    #[test]
    fn exact_existing_receipt_is_verified_but_never_overwritten() {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!(
            "needle-lifecycle-authority-acceptance-{}-{suffix}.json",
            std::process::id()
        ));
        let preflight = preflight();
        let receipt = LifecycleExploreLifecycleAuthorityAcceptance::new(&preflight, 50).unwrap();
        assert!(write_create_new_or_verify_existing(&path, &receipt).unwrap());
        assert!(!write_create_new_or_verify_existing(&path, &receipt).unwrap());
        std::fs::write(&path, b"different\n").unwrap();
        assert!(write_create_new_or_verify_existing(&path, &receipt).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
