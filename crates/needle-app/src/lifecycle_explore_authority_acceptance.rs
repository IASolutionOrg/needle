use super::{AppError, canonical_child_path, required_value};
use crate::lifecycle_explore_authority::{
    AUTHORITY_PREFLIGHT_FILE, DATABASE_FILE, LIVE_REPORT_FILE, LifecycleExploreAuthorityPreflight,
    MAX_AUTHORITY_PREFLIGHT_BYTES,
};
use crate::lifecycle_explore_live::{
    MAX_LIFECYCLE_EXPLORE_LIVE_REPORT_BYTES, decode_authority_source,
};
use needle_bench::read_bounded_file;
use needle_core::{ActionCapabilityDecisionId, CanonicalHasher, CapabilityMode, Digest};
use needle_runtime::{
    ActionAssurancePreflight, ProviderBackedActionAssuranceInput, RuntimeStore,
    implementation_location_exact_capability,
};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

const ACCEPTANCE_FORMAT_REVISION: u16 = 1;
const ACCEPTANCE_SCHEMA: &str = "needle.lifecycle-explore-authority-acceptance/1";
pub(super) const ACCEPTANCE_FILE: &str = "lifecycle-explore-authority-acceptance.json";
pub(super) const MAX_ACCEPTANCE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LifecycleExploreAuthorityAcceptance {
    pub(super) format_revision: u16,
    pub(super) schema: String,
    pub(super) preflight_digest: Digest,
    pub(super) source_database_schema_version: u64,
    pub(super) persisted_database_schema_version: u64,
    pub(super) capability_class: needle_core::ActionCapabilityClassId,
    pub(super) capability_definition_digest: Digest,
    pub(super) evidence: needle_core::ActionAssuranceEvidenceId,
    pub(super) evidence_definition_digest: Digest,
    pub(super) decision: ActionCapabilityDecisionId,
    pub(super) decision_definition_digest: Digest,
    pub(super) evidence_recorded_unix_ms: u64,
    pub(super) decision_recorded_unix_ms: u64,
    pub(super) selected_mode: CapabilityMode,
    pub(super) automatic_resolver_consumption_approved: bool,
    pub(super) automatic_lifecycle_consumption_approved: bool,
    pub(super) provider_call_performed: bool,
    pub(super) acceptance_digest: Digest,
}

impl LifecycleExploreAuthorityAcceptance {
    pub(super) fn decode_json(
        bytes: &[u8],
        preflight: &LifecycleExploreAuthorityPreflight,
    ) -> Result<Self, AppError> {
        if bytes.len() > MAX_ACCEPTANCE_BYTES {
            return Err(AppError::Experiment(format!(
                "authority acceptance has {} bytes; maximum is {}",
                bytes.len(),
                MAX_ACCEPTANCE_BYTES
            )));
        }
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate(preflight)?;
        Ok(value)
    }

    pub(super) fn new(
        preflight: &LifecycleExploreAuthorityPreflight,
        evidence_recorded_unix_ms: u64,
        decision_recorded_unix_ms: u64,
    ) -> Result<Self, AppError> {
        let decision = &preflight.proposed_decision;
        let mut value = Self {
            format_revision: ACCEPTANCE_FORMAT_REVISION,
            schema: ACCEPTANCE_SCHEMA.to_owned(),
            preflight_digest: preflight.preflight_digest,
            source_database_schema_version: preflight.source_database_schema_version,
            persisted_database_schema_version: 32,
            capability_class: preflight.capability_class.id,
            capability_definition_digest: preflight.capability_class.definition_digest,
            evidence: preflight.evidence.id,
            evidence_definition_digest: preflight.evidence.definition_digest,
            decision: decision.id,
            decision_definition_digest: decision.definition_digest,
            evidence_recorded_unix_ms,
            decision_recorded_unix_ms,
            selected_mode: decision.selected_mode,
            automatic_resolver_consumption_approved: decision
                .automatic_resolver_consumption_approved,
            automatic_lifecycle_consumption_approved: decision
                .automatic_lifecycle_consumption_approved,
            provider_call_performed: false,
            acceptance_digest: Digest([0; 32]),
        };
        value.validate_shape(preflight)?;
        value.acceptance_digest = value.compute_digest();
        Ok(value)
    }

    pub(super) fn validate(
        &self,
        preflight: &LifecycleExploreAuthorityPreflight,
    ) -> Result<(), AppError> {
        self.validate_shape(preflight)?;
        if self.acceptance_digest != self.compute_digest() {
            return Err(AppError::Experiment(
                "lifecycle Explore authority acceptance digest is inconsistent".into(),
            ));
        }
        Ok(())
    }

    fn validate_shape(
        &self,
        preflight: &LifecycleExploreAuthorityPreflight,
    ) -> Result<(), AppError> {
        if self.format_revision != ACCEPTANCE_FORMAT_REVISION
            || self.schema != ACCEPTANCE_SCHEMA
            || self.preflight_digest != preflight.preflight_digest
            || self.source_database_schema_version != preflight.source_database_schema_version
            || self.persisted_database_schema_version != 32
            || self.capability_class != preflight.capability_class.id
            || self.capability_definition_digest != preflight.capability_class.definition_digest
            || self.evidence != preflight.evidence.id
            || self.evidence_definition_digest != preflight.evidence.definition_digest
            || self.decision != preflight.proposed_decision.id
            || self.decision_definition_digest != preflight.proposed_decision.definition_digest
            || self.evidence_recorded_unix_ms == 0
            || self.decision_recorded_unix_ms == 0
            || self.selected_mode != CapabilityMode::Authoritative
            || !self.automatic_resolver_consumption_approved
            || self.automatic_lifecycle_consumption_approved
            || self.provider_call_performed
        {
            return Err(AppError::Experiment(
                "lifecycle Explore authority acceptance shape is invalid".into(),
            ));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"lifecycle-explore-authority-acceptance-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_digest(self.preflight_digest);
        hasher.field_bytes(&self.source_database_schema_version.to_le_bytes());
        hasher.field_bytes(&self.persisted_database_schema_version.to_le_bytes());
        hasher.field_digest(self.capability_class.digest());
        hasher.field_digest(self.capability_definition_digest);
        hasher.field_digest(self.evidence.digest());
        hasher.field_digest(self.evidence_definition_digest);
        hasher.field_digest(self.decision.digest());
        hasher.field_digest(self.decision_definition_digest);
        hasher.field_bytes(&self.evidence_recorded_unix_ms.to_le_bytes());
        hasher.field_bytes(&self.decision_recorded_unix_ms.to_le_bytes());
        hasher.field_u8(capability_mode_tag(self.selected_mode));
        hasher.field_u8(u8::from(self.automatic_resolver_consumption_approved));
        hasher.field_u8(u8::from(self.automatic_lifecycle_consumption_approved));
        hasher.field_u8(u8::from(self.provider_call_performed));
        hasher.finish()
    }
}

pub(super) fn run(arguments: &[String]) -> Result<(), AppError> {
    let parsed = Arguments::parse(arguments)?;
    parsed.validate()?;
    let artifact_root =
        canonical_child_path(Path::new(&required_value(arguments, "--artifact-root")?))?;
    let preflight_path = artifact_root.join(AUTHORITY_PREFLIGHT_FILE);
    let report_path = artifact_root.join(LIVE_REPORT_FILE);
    let database_path = artifact_root.join(DATABASE_FILE);
    if !preflight_path.is_file() || !report_path.is_file() || !database_path.is_file() {
        return Err(AppError::Experiment(
            "authority acceptance requires the retained preflight, live report, and database"
                .into(),
        ));
    }
    let preflight = LifecycleExploreAuthorityPreflight::decode_json(
        &read_bounded_file(&preflight_path, MAX_AUTHORITY_PREFLIGHT_BYTES)
            .map_err(|error| AppError::Experiment(error.to_string()))?,
    )?;
    verify_explicit_identity(&parsed, &preflight)?;
    let report_bytes = read_bounded_file(&report_path, MAX_LIFECYCLE_EXPLORE_LIVE_REPORT_BYTES)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let source = decode_authority_source(&report_bytes)?;
    if Digest::blake3(&report_bytes) != preflight.source_report_digest {
        return Err(AppError::Experiment(
            "authority acceptance live report differs from the accepted preflight".into(),
        ));
    }
    let provider_input = ProviderBackedActionAssuranceInput {
        repository: source.repository,
        source_snapshot: source.source_snapshot,
        lifecycle: source.lifecycle,
        adapter_invocation: source.adapter_invocation,
        artifact: source.artifact,
        execution_evidence_digest: preflight.source_report_digest,
    };

    let store = RuntimeStore::new(&database_path);
    let before = store
        .preflight_provider_backed_action_assurance(provider_input.clone())
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    validate_runtime_material(&preflight, &before, true)?;
    store.initialize().map_err(|error| AppError::Experiment(error.to_string()))?;
    drop(store);

    let store = RuntimeStore::new(&database_path);
    let after = store
        .preflight_provider_backed_action_assurance(provider_input)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    if after.source_schema_version != 32 {
        return Err(AppError::Experiment(
            "authority acceptance migration did not reach schema version 32".into(),
        ));
    }
    validate_runtime_material(&preflight, &after, false)?;
    let decision_record = store
        .accept_action_capability_decision(&preflight.evidence, &preflight.proposed_decision)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let evidence_record = store
        .action_assurance_evidence(preflight.evidence.id)
        .map_err(|error| AppError::Experiment(error.to_string()))?
        .ok_or_else(|| {
            AppError::Experiment("accepted action assurance evidence is unavailable".into())
        })?;
    let effective = store
        .effective_action_capability_decision(preflight.capability_class.id)
        .map_err(|error| AppError::Experiment(error.to_string()))?
        .ok_or_else(|| {
            AppError::Experiment("accepted action capability decision is unavailable".into())
        })?;
    if evidence_record.evidence != preflight.evidence
        || decision_record.decision != preflight.proposed_decision
        || effective != decision_record
    {
        return Err(AppError::Experiment(
            "persisted authority material differs from the accepted preflight".into(),
        ));
    }
    let acceptance = LifecycleExploreAuthorityAcceptance::new(
        &preflight,
        evidence_record.recorded_unix_ms,
        decision_record.recorded_unix_ms,
    )?;
    acceptance.validate(&preflight)?;
    let acceptance_path = artifact_root.join(ACCEPTANCE_FILE);
    let created = write_create_new_or_verify_existing(&acceptance_path, &acceptance)?;
    println!(
        "lifecycle Explore authority acceptance {} {}",
        if created { "written to" } else { "verified at" },
        acceptance_path.display()
    );
    println!("acceptance_digest={}", acceptance.acceptance_digest);
    println!("preflight_digest={}", acceptance.preflight_digest);
    println!("evidence_id={}", acceptance.evidence);
    println!("decision_id={}", acceptance.decision);
    println!("persisted_database_schema_version=32");
    println!("selected_mode=authoritative");
    println!("automatic_resolver_consumption_approved=true");
    println!("automatic_lifecycle_consumption_approved=false");
    println!("provider_call_performed=false");
    Ok(())
}

fn validate_runtime_material(
    proposal: &LifecycleExploreAuthorityPreflight,
    runtime: &ActionAssurancePreflight,
    require_source_schema: bool,
) -> Result<(), AppError> {
    let current_capability = implementation_location_exact_capability();
    if &proposal.capability_class != current_capability || proposal.evidence != runtime.evidence {
        return Err(AppError::Experiment(
            "authority acceptance runtime material differs from the exact proposal".into(),
        ));
    }
    let current = runtime.effective_decision.as_ref().map(|record| &record.decision);
    let already_accepted = current.is_some_and(|decision| decision == &proposal.proposed_decision);
    if require_source_schema
        && runtime.source_schema_version != proposal.source_database_schema_version
        && !already_accepted
    {
        return Err(AppError::Experiment(
            "authority acceptance source schema differs from the exact proposal".into(),
        ));
    }
    let expected_previous = proposal.proposed_decision.previous_decision;
    if already_accepted {
        return Ok(());
    }
    if current.map(|decision| decision.id) != expected_previous {
        return Err(AppError::Experiment(
            "authority acceptance proposal no longer extends the effective decision head".into(),
        ));
    }
    Ok(())
}

fn verify_explicit_identity(
    arguments: &Arguments,
    preflight: &LifecycleExploreAuthorityPreflight,
) -> Result<(), AppError> {
    let requested_preflight = Digest::parse(
        arguments
            .preflight_digest
            .as_deref()
            .ok_or_else(|| AppError::Usage("--preflight-digest is required".into()))?,
    )
    .map_err(|error| AppError::Usage(format!("invalid --preflight-digest: {error}")))?;
    let requested_decision = Digest::parse(
        arguments
            .decision_id
            .as_deref()
            .ok_or_else(|| AppError::Usage("--decision-id is required".into()))?,
    )
    .map(ActionCapabilityDecisionId::new)
    .map_err(|error| AppError::Usage(format!("invalid --decision-id: {error}")))?;
    if requested_preflight != preflight.preflight_digest
        || requested_decision != preflight.proposed_decision.id
    {
        return Err(AppError::Experiment(
            "authority acceptance identity differs from the explicit operator confirmation".into(),
        ));
    }
    Ok(())
}

fn write_create_new_or_verify_existing(
    path: &Path,
    value: &LifecycleExploreAuthorityAcceptance,
) -> Result<bool, AppError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_ACCEPTANCE_BYTES {
        return Err(AppError::Experiment(format!(
            "authority acceptance has {} bytes; maximum is {}",
            bytes.len(),
            MAX_ACCEPTANCE_BYTES
        )));
    }
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(&bytes)?;
            file.sync_all()?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_bounded_file(path, MAX_ACCEPTANCE_BYTES)
                .map_err(|error| AppError::Experiment(error.to_string()))?;
            if existing == bytes {
                Ok(false)
            } else {
                Err(AppError::Experiment(
                    "authority acceptance output already exists with different canonical content"
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
    decision_id: Option<String>,
    confirm_migration: bool,
    confirm_resolver_only: bool,
    confirm_lifecycle_disabled: bool,
}

impl Arguments {
    fn parse(arguments: &[String]) -> Result<Self, AppError> {
        let mut parsed = Self::default();
        let mut index = 0;
        while index < arguments.len() {
            match arguments[index].as_str() {
                "--artifact-root" | "--preflight-digest" | "--decision-id" => {
                    let value = arguments.get(index + 1).ok_or_else(|| {
                        AppError::Usage(format!("{} requires a value", arguments[index]))
                    })?;
                    match arguments[index].as_str() {
                        "--artifact-root" => parsed.artifact_root = Some(value.clone()),
                        "--preflight-digest" => parsed.preflight_digest = Some(value.clone()),
                        "--decision-id" => parsed.decision_id = Some(value.clone()),
                        _ => unreachable!(),
                    }
                    index += 2;
                }
                "--confirm-migrate-v31-to-v32" => {
                    parsed.confirm_migration = true;
                    index += 1;
                }
                "--confirm-authoritative-resolver-only" => {
                    parsed.confirm_resolver_only = true;
                    index += 1;
                }
                "--confirm-lifecycle-consumption-disabled" => {
                    parsed.confirm_lifecycle_disabled = true;
                    index += 1;
                }
                argument => {
                    return Err(AppError::Usage(format!(
                        "unknown lifecycle-explore-authority-accept argument `{argument}`"
                    )));
                }
            }
        }
        Ok(parsed)
    }

    fn validate(&self) -> Result<(), AppError> {
        if self.artifact_root.is_none()
            || self.preflight_digest.is_none()
            || self.decision_id.is_none()
            || !self.confirm_migration
            || !self.confirm_resolver_only
            || !self.confirm_lifecycle_disabled
        {
            return Err(AppError::Usage(
                "authority acceptance requires exact identities plus all three explicit confirmation flags"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use needle_core::{
        ActionAssuranceEvidence, ActionAssuranceEvidenceInput, ActionAssuranceEvidenceKind,
        ActionCapabilityDecision, ActionCapabilityDecisionInput, ArtifactId, ArtifactRequestId,
        ArtifactValidationCertificateId, LifecycleId,
    };

    fn digest(label: &str) -> Digest {
        Digest::blake3(label.as_bytes())
    }

    fn proposal() -> LifecycleExploreAuthorityPreflight {
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
        let decision = ActionCapabilityDecision::new(ActionCapabilityDecisionInput {
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
        LifecycleExploreAuthorityPreflight::new(report_digest, 31, capability, evidence, decision)
            .unwrap()
    }

    #[test]
    fn arguments_require_exact_identities_and_all_safety_confirmations() {
        let parsed = Arguments::parse(&[
            "--artifact-root".into(),
            "target/live".into(),
            "--preflight-digest".into(),
            "b3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            "--decision-id".into(),
            "b3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            "--confirm-migrate-v31-to-v32".into(),
            "--confirm-authoritative-resolver-only".into(),
            "--confirm-lifecycle-consumption-disabled".into(),
        ])
        .unwrap();
        parsed.validate().unwrap();

        let missing = Arguments::parse(&[
            "--artifact-root".into(),
            "target/live".into(),
            "--preflight-digest".into(),
            "digest".into(),
            "--decision-id".into(),
            "decision".into(),
        ])
        .unwrap();
        assert!(missing.validate().is_err());
        assert!(Arguments::parse(&["--provider".into()]).is_err());
    }

    #[test]
    fn acceptance_receipt_is_canonical_and_keeps_lifecycle_disabled() {
        let proposal = proposal();
        let receipt = LifecycleExploreAuthorityAcceptance::new(&proposal, 30, 31).unwrap();
        receipt.validate(&proposal).unwrap();
        assert_eq!(receipt.selected_mode, CapabilityMode::Authoritative);
        assert!(receipt.automatic_resolver_consumption_approved);
        assert!(!receipt.automatic_lifecycle_consumption_approved);
        assert!(!receipt.provider_call_performed);

        let mut tampered = receipt;
        tampered.automatic_lifecycle_consumption_approved = true;
        assert!(tampered.validate(&proposal).is_err());
    }
}
