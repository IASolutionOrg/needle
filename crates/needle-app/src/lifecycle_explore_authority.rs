use super::{AppError, canonical_child_path, required_value};
use crate::lifecycle_explore_live::{
    MAX_LIFECYCLE_EXPLORE_LIVE_REPORT_BYTES, decode_authority_source,
};
use needle_bench::read_bounded_file;
use needle_core::{
    ActionAssuranceEvidence, ActionCapabilityClass, ActionCapabilityDecision,
    ActionCapabilityDecisionInput, CanonicalHasher, CapabilityMode, Digest,
};
use needle_runtime::{
    ProviderBackedActionAssuranceInput, RuntimeStore, implementation_location_exact_capability,
};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

const AUTHORITY_PREFLIGHT_FORMAT_REVISION: u16 = 1;
const AUTHORITY_PREFLIGHT_SCHEMA: &str = "needle.lifecycle-explore-authority-preflight/1";
pub(super) const AUTHORITY_PREFLIGHT_FILE: &str = "lifecycle-explore-authority-preflight.json";
pub(super) const LIVE_REPORT_FILE: &str = "lifecycle-explore-live-report.json";
pub(super) const DATABASE_FILE: &str = "data/needle.sqlite3";
pub(super) const MAX_AUTHORITY_PREFLIGHT_BYTES: usize = 192 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LifecycleExploreAuthorityPreflight {
    pub(super) format_revision: u16,
    pub(super) schema: String,
    pub(super) source_report_digest: Digest,
    pub(super) source_database_schema_version: u64,
    pub(super) capability_class: ActionCapabilityClass,
    pub(super) evidence: ActionAssuranceEvidence,
    pub(super) proposed_decision: ActionCapabilityDecision,
    pub(super) provider_call_performed: bool,
    pub(super) evidence_persisted: bool,
    pub(super) decision_persisted: bool,
    pub(super) lifecycle_consumption_approved: bool,
    pub(super) preflight_digest: Digest,
}

impl LifecycleExploreAuthorityPreflight {
    pub(super) fn new(
        source_report_digest: Digest,
        source_database_schema_version: u64,
        capability_class: ActionCapabilityClass,
        evidence: ActionAssuranceEvidence,
        proposed_decision: ActionCapabilityDecision,
    ) -> Result<Self, AppError> {
        let mut value = Self {
            format_revision: AUTHORITY_PREFLIGHT_FORMAT_REVISION,
            schema: AUTHORITY_PREFLIGHT_SCHEMA.to_owned(),
            source_report_digest,
            source_database_schema_version,
            capability_class,
            evidence,
            proposed_decision,
            provider_call_performed: false,
            evidence_persisted: false,
            decision_persisted: false,
            lifecycle_consumption_approved: false,
            preflight_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.preflight_digest = value.compute_digest();
        Ok(value)
    }

    pub(super) fn decode_json(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() > MAX_AUTHORITY_PREFLIGHT_BYTES {
            return Err(AppError::Experiment(format!(
                "authority preflight has {} bytes; maximum is {}",
                bytes.len(),
                MAX_AUTHORITY_PREFLIGHT_BYTES
            )));
        }
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate()?;
        Ok(value)
    }

    pub(super) fn validate(&self) -> Result<(), AppError> {
        self.validate_shape()?;
        if self.preflight_digest != self.compute_digest() {
            return Err(AppError::Experiment(
                "lifecycle Explore authority preflight digest is inconsistent".into(),
            ));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), AppError> {
        self.capability_class
            .validate()
            .map_err(|error| AppError::Experiment(error.to_string()))?;
        self.evidence
            .validate_for(&self.capability_class)
            .map_err(|error| AppError::Experiment(error.to_string()))?;
        self.proposed_decision
            .validate_for(&self.capability_class, &self.evidence)
            .map_err(|error| AppError::Experiment(error.to_string()))?;
        if self.format_revision != AUTHORITY_PREFLIGHT_FORMAT_REVISION
            || self.schema != AUTHORITY_PREFLIGHT_SCHEMA
            || self.source_report_digest == Digest([0; 32])
            || !matches!(self.source_database_schema_version, 31 | 32)
            || self.evidence.execution_evidence_digest != self.source_report_digest
            || self.capability_class.mode != CapabilityMode::Shadow
            || self.proposed_decision.selected_mode != CapabilityMode::Authoritative
            || !self.proposed_decision.automatic_resolver_consumption_approved
            || self.proposed_decision.automatic_lifecycle_consumption_approved
            || self.provider_call_performed
            || self.evidence_persisted
            || self.decision_persisted
            || self.lifecycle_consumption_approved
        {
            return Err(AppError::Experiment(
                "lifecycle Explore authority preflight shape is invalid".into(),
            ));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"lifecycle-explore-authority-preflight-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_digest(self.source_report_digest);
        hasher.field_bytes(&self.source_database_schema_version.to_le_bytes());
        hasher.field_digest(self.capability_class.id.digest());
        hasher.field_digest(self.capability_class.definition_digest);
        hasher.field_digest(self.evidence.id.digest());
        hasher.field_digest(self.evidence.definition_digest);
        hasher.field_digest(self.proposed_decision.id.digest());
        hasher.field_digest(self.proposed_decision.definition_digest);
        hasher.field_u8(u8::from(self.provider_call_performed));
        hasher.field_u8(u8::from(self.evidence_persisted));
        hasher.field_u8(u8::from(self.decision_persisted));
        hasher.field_u8(u8::from(self.lifecycle_consumption_approved));
        hasher.finish()
    }
}

pub(super) fn run(arguments: &[String]) -> Result<(), AppError> {
    validate_arguments(arguments)?;
    let artifact_root =
        canonical_child_path(Path::new(&required_value(arguments, "--artifact-root")?))?;
    let decider_id = required_value(arguments, "--decider-id")?;
    let decided_unix_ms = required_value(arguments, "--decided-unix-ms")?
        .parse::<u64>()
        .map_err(|error| AppError::Usage(format!("invalid --decided-unix-ms: {error}")))?;
    let report_path = artifact_root.join(LIVE_REPORT_FILE);
    let database_path = artifact_root.join(DATABASE_FILE);
    if !report_path.is_file() || !database_path.is_file() {
        return Err(AppError::Experiment(
            "authority preflight requires the retained live report and SQLite database".into(),
        ));
    }
    let report_bytes = read_bounded_file(&report_path, MAX_LIFECYCLE_EXPLORE_LIVE_REPORT_BYTES)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let source = decode_authority_source(&report_bytes)?;
    let source_report_digest = Digest::blake3(&report_bytes);
    let store = RuntimeStore::new(database_path);
    let runtime_preflight = store
        .preflight_provider_backed_action_assurance(ProviderBackedActionAssuranceInput {
            repository: source.repository,
            source_snapshot: source.source_snapshot,
            lifecycle: source.lifecycle,
            adapter_invocation: source.adapter_invocation,
            artifact: source.artifact,
            execution_evidence_digest: source_report_digest,
        })
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let capability = implementation_location_exact_capability().clone();
    let proposed_decision = ActionCapabilityDecision::new(ActionCapabilityDecisionInput {
        capability_class: capability.id,
        capability_definition_digest: capability.definition_digest,
        evidence: runtime_preflight.evidence.id,
        evidence_definition_digest: runtime_preflight.evidence.definition_digest,
        previous_decision: runtime_preflight
            .effective_decision
            .as_ref()
            .map(|record| record.decision.id),
        selected_mode: CapabilityMode::Authoritative,
        automatic_resolver_consumption_approved: true,
        automatic_lifecycle_consumption_approved: false,
        decider_id,
        decided_unix_ms,
    })
    .map_err(|error| AppError::Experiment(error.to_string()))?;
    let preflight = LifecycleExploreAuthorityPreflight::new(
        source_report_digest,
        runtime_preflight.source_schema_version,
        capability,
        runtime_preflight.evidence,
        proposed_decision,
    )?;
    preflight.validate()?;
    let output = artifact_root.join(AUTHORITY_PREFLIGHT_FILE);
    let created = write_create_new_or_verify_existing(&output, &preflight)?;
    println!(
        "lifecycle Explore authority preflight {} {}",
        if created { "written to" } else { "verified at" },
        output.display()
    );
    println!("preflight_digest={}", preflight.preflight_digest);
    println!("source_database_schema_version={}", preflight.source_database_schema_version);
    println!("capability_class_id={}", preflight.capability_class.id);
    println!("capability_definition_digest={}", preflight.capability_class.definition_digest);
    println!("evidence_id={}", preflight.evidence.id);
    println!("proposed_decision_id={}", preflight.proposed_decision.id);
    println!("selected_mode=authoritative");
    println!("automatic_resolver_consumption_approved=true");
    println!("automatic_lifecycle_consumption_approved=false");
    println!("provider_call_performed=false");
    println!("evidence_persisted=false");
    println!("decision_persisted=false");
    Ok(())
}

fn write_create_new_or_verify_existing(
    path: &Path,
    value: &LifecycleExploreAuthorityPreflight,
) -> Result<bool, AppError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_AUTHORITY_PREFLIGHT_BYTES {
        return Err(AppError::Experiment(format!(
            "authority preflight has {} bytes; maximum is {}",
            bytes.len(),
            MAX_AUTHORITY_PREFLIGHT_BYTES
        )));
    }
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(&bytes)?;
            file.sync_all()?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_bounded_file(path, MAX_AUTHORITY_PREFLIGHT_BYTES)
                .map_err(|error| AppError::Experiment(error.to_string()))?;
            if existing == bytes {
                Ok(false)
            } else {
                Err(AppError::Experiment(
                    "authority preflight output already exists with different canonical content"
                        .into(),
                ))
            }
        }
        Err(error) => Err(AppError::Io(error)),
    }
}

fn validate_arguments(arguments: &[String]) -> Result<(), AppError> {
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--artifact-root" | "--decider-id" | "--decided-unix-ms" => {
                if arguments.get(index + 1).is_none() {
                    return Err(AppError::Usage(format!("{} requires a value", arguments[index])));
                }
                index += 2;
            }
            argument => {
                return Err(AppError::Usage(format!(
                    "unknown lifecycle-explore-authority-preflight argument `{argument}`"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use needle_core::{
        ActionAssuranceEvidenceInput, ActionAssuranceEvidenceKind, ArtifactId, ArtifactRequestId,
        ArtifactValidationCertificateId, LifecycleId,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn digest(label: &str) -> Digest {
        Digest::blake3(label.as_bytes())
    }

    fn preflight() -> LifecycleExploreAuthorityPreflight {
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
        LifecycleExploreAuthorityPreflight::new(report_digest, 32, capability, evidence, decision)
            .unwrap()
    }

    #[test]
    fn proposal_is_canonical_and_resolver_only() {
        let proposal = preflight();
        proposal.validate().unwrap();
        assert_eq!(proposal.proposed_decision.selected_mode, CapabilityMode::Authoritative);
        assert!(proposal.proposed_decision.automatic_resolver_consumption_approved);
        assert!(!proposal.proposed_decision.automatic_lifecycle_consumption_approved);
        assert!(!proposal.provider_call_performed);
        assert!(!proposal.evidence_persisted);
        assert!(!proposal.decision_persisted);

        let mut tampered = proposal;
        tampered.decision_persisted = true;
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn arguments_are_bounded_to_read_only_preflight_inputs() {
        validate_arguments(&[
            "--artifact-root".into(),
            "target/live".into(),
            "--decider-id".into(),
            "local-owner".into(),
            "--decided-unix-ms".into(),
            "1".into(),
        ])
        .unwrap();
        assert!(validate_arguments(&["--accept".into()]).is_err());
    }

    #[test]
    fn exact_existing_proposal_is_verified_but_never_overwritten() {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!(
            "needle-lifecycle-authority-preflight-{}-{suffix}.json",
            std::process::id()
        ));
        let proposal = preflight();
        assert!(write_create_new_or_verify_existing(&path, &proposal).unwrap());
        assert!(!write_create_new_or_verify_existing(&path, &proposal).unwrap());
        std::fs::write(&path, b"different\n").unwrap();
        assert!(write_create_new_or_verify_existing(&path, &proposal).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
