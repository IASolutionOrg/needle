use super::{AppError, canonical_child_path, required_value};
use crate::lifecycle_explore_authority::{
    AUTHORITY_PREFLIGHT_FILE, DATABASE_FILE, LIVE_REPORT_FILE, LifecycleExploreAuthorityPreflight,
    MAX_AUTHORITY_PREFLIGHT_BYTES,
};
use crate::lifecycle_explore_authority_acceptance::{
    ACCEPTANCE_FILE, LifecycleExploreAuthorityAcceptance, MAX_ACCEPTANCE_BYTES,
};
use crate::lifecycle_explore_live::{
    MAX_LIFECYCLE_EXPLORE_LIVE_REPORT_BYTES, decode_authority_source,
};
use needle_bench::read_bounded_file;
use needle_core::{
    ActionAssuranceEvidence, ActionCapabilityClass, ActionCapabilityDecision,
    ActionCapabilityDecisionInput, CanonicalHasher, CapabilityMode, Digest,
};
use needle_runtime::{
    ActionAssurancePreflight, ProviderBackedActionAssuranceInput, RuntimeStore,
    implementation_location_exact_capability,
};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

const LIFECYCLE_AUTHORITY_PREFLIGHT_FORMAT_REVISION: u16 = 1;
const LIFECYCLE_AUTHORITY_PREFLIGHT_SCHEMA: &str =
    "needle.lifecycle-explore-lifecycle-authority-preflight/1";
pub(super) const LIFECYCLE_AUTHORITY_PREFLIGHT_FILE: &str =
    "lifecycle-explore-lifecycle-authority-preflight.json";
pub(super) const MAX_LIFECYCLE_AUTHORITY_PREFLIGHT_BYTES: usize = 192 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LifecycleExploreLifecycleAuthorityPreflightInput {
    pub(super) source_report_digest: Digest,
    pub(super) source_authority_preflight_digest: Digest,
    pub(super) source_authority_acceptance_digest: Digest,
    pub(super) source_database_schema_version: u64,
    pub(super) capability_class: ActionCapabilityClass,
    pub(super) evidence: ActionAssuranceEvidence,
    pub(super) current_decision: ActionCapabilityDecision,
    pub(super) current_decision_recorded_unix_ms: u64,
    pub(super) proposed_decision: ActionCapabilityDecision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LifecycleExploreLifecycleAuthorityPreflight {
    pub(super) format_revision: u16,
    pub(super) schema: String,
    pub(super) source_report_digest: Digest,
    pub(super) source_authority_preflight_digest: Digest,
    pub(super) source_authority_acceptance_digest: Digest,
    pub(super) source_database_schema_version: u64,
    pub(super) capability_class: ActionCapabilityClass,
    pub(super) evidence: ActionAssuranceEvidence,
    pub(super) current_decision: ActionCapabilityDecision,
    pub(super) current_decision_recorded_unix_ms: u64,
    pub(super) proposed_decision: ActionCapabilityDecision,
    pub(super) source_resolver_authority_persisted: bool,
    pub(super) provider_call_performed: bool,
    pub(super) database_mutated: bool,
    pub(super) proposed_decision_persisted: bool,
    pub(super) lifecycle_consumption_approved: bool,
    pub(super) preflight_digest: Digest,
}

impl LifecycleExploreLifecycleAuthorityPreflight {
    pub(super) fn new(
        input: LifecycleExploreLifecycleAuthorityPreflightInput,
    ) -> Result<Self, AppError> {
        let mut value = Self {
            format_revision: LIFECYCLE_AUTHORITY_PREFLIGHT_FORMAT_REVISION,
            schema: LIFECYCLE_AUTHORITY_PREFLIGHT_SCHEMA.to_owned(),
            source_report_digest: input.source_report_digest,
            source_authority_preflight_digest: input.source_authority_preflight_digest,
            source_authority_acceptance_digest: input.source_authority_acceptance_digest,
            source_database_schema_version: input.source_database_schema_version,
            capability_class: input.capability_class,
            evidence: input.evidence,
            current_decision: input.current_decision,
            current_decision_recorded_unix_ms: input.current_decision_recorded_unix_ms,
            proposed_decision: input.proposed_decision,
            source_resolver_authority_persisted: true,
            provider_call_performed: false,
            database_mutated: false,
            proposed_decision_persisted: false,
            lifecycle_consumption_approved: false,
            preflight_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.preflight_digest = value.compute_digest();
        Ok(value)
    }

    pub(super) fn decode_json(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() > MAX_LIFECYCLE_AUTHORITY_PREFLIGHT_BYTES {
            return Err(AppError::Experiment(format!(
                "lifecycle authority preflight has {} bytes; maximum is {}",
                bytes.len(),
                MAX_LIFECYCLE_AUTHORITY_PREFLIGHT_BYTES
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
                "lifecycle Explore lifecycle authority preflight digest is inconsistent".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn validate_acceptance_source(
        &self,
        source_preflight: &LifecycleExploreAuthorityPreflight,
        source_acceptance: &LifecycleExploreAuthorityAcceptance,
        runtime: &ActionAssurancePreflight,
        capability: &ActionCapabilityClass,
    ) -> Result<bool, AppError> {
        self.validate()?;
        validate_source_foundation(source_preflight, source_acceptance, runtime, capability)?;
        let Some(effective) = runtime.effective_decision.as_ref() else {
            return Err(AppError::Experiment(
                "lifecycle authority acceptance requires an effective decision head".into(),
            ));
        };
        if self.source_report_digest != source_preflight.source_report_digest
            || self.source_authority_preflight_digest != source_preflight.preflight_digest
            || self.source_authority_acceptance_digest != source_acceptance.acceptance_digest
            || self.source_database_schema_version != runtime.source_schema_version
            || self.capability_class != *capability
            || self.evidence != runtime.evidence
            || self.current_decision != source_preflight.proposed_decision
            || self.current_decision_recorded_unix_ms != source_acceptance.decision_recorded_unix_ms
            || effective.evidence != runtime.evidence
        {
            return Err(AppError::Experiment(
                "lifecycle authority acceptance source differs from the rendered preflight".into(),
            ));
        }
        if effective.decision == self.current_decision {
            if effective.recorded_unix_ms != self.current_decision_recorded_unix_ms {
                return Err(AppError::Experiment(
                    "resolver-only decision record time differs from the rendered preflight".into(),
                ));
            }
            return Ok(false);
        }
        if effective.decision == self.proposed_decision {
            return Ok(true);
        }
        Err(AppError::Experiment(
            "effective decision is neither the rendered previous head nor the exact proposed head"
                .into(),
        ))
    }

    fn validate_shape(&self) -> Result<(), AppError> {
        self.capability_class
            .validate()
            .map_err(|error| AppError::Experiment(error.to_string()))?;
        self.evidence
            .validate_for(&self.capability_class)
            .map_err(|error| AppError::Experiment(error.to_string()))?;
        self.current_decision
            .validate_for(&self.capability_class, &self.evidence)
            .map_err(|error| AppError::Experiment(error.to_string()))?;
        self.proposed_decision
            .validate_for(&self.capability_class, &self.evidence)
            .map_err(|error| AppError::Experiment(error.to_string()))?;
        if self.format_revision != LIFECYCLE_AUTHORITY_PREFLIGHT_FORMAT_REVISION
            || self.schema != LIFECYCLE_AUTHORITY_PREFLIGHT_SCHEMA
            || self.source_report_digest == Digest([0; 32])
            || self.source_authority_preflight_digest == Digest([0; 32])
            || self.source_authority_acceptance_digest == Digest([0; 32])
            || self.source_database_schema_version != 32
            || self.capability_class.mode != CapabilityMode::Shadow
            || self.evidence.execution_evidence_digest != self.source_report_digest
            || self.current_decision.selected_mode != CapabilityMode::Authoritative
            || !self.current_decision.automatic_resolver_consumption_approved
            || self.current_decision.automatic_lifecycle_consumption_approved
            || self.current_decision_recorded_unix_ms == 0
            || self.proposed_decision.previous_decision != Some(self.current_decision.id)
            || self.proposed_decision.selected_mode != CapabilityMode::Authoritative
            || !self.proposed_decision.automatic_resolver_consumption_approved
            || !self.proposed_decision.automatic_lifecycle_consumption_approved
            || self.proposed_decision.decided_unix_ms <= self.current_decision.decided_unix_ms
            || !self.source_resolver_authority_persisted
            || self.provider_call_performed
            || self.database_mutated
            || self.proposed_decision_persisted
            || self.lifecycle_consumption_approved
        {
            return Err(AppError::Experiment(
                "lifecycle Explore lifecycle authority preflight shape is invalid".into(),
            ));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher =
            CanonicalHasher::new(b"lifecycle-explore-lifecycle-authority-preflight-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_digest(self.source_report_digest);
        hasher.field_digest(self.source_authority_preflight_digest);
        hasher.field_digest(self.source_authority_acceptance_digest);
        hasher.field_bytes(&self.source_database_schema_version.to_le_bytes());
        hasher.field_digest(self.capability_class.id.digest());
        hasher.field_digest(self.capability_class.definition_digest);
        hasher.field_digest(self.evidence.id.digest());
        hasher.field_digest(self.evidence.definition_digest);
        hasher.field_digest(self.current_decision.id.digest());
        hasher.field_digest(self.current_decision.definition_digest);
        hasher.field_bytes(&self.current_decision_recorded_unix_ms.to_le_bytes());
        hasher.field_digest(self.proposed_decision.id.digest());
        hasher.field_digest(self.proposed_decision.definition_digest);
        hasher.field_u8(u8::from(self.source_resolver_authority_persisted));
        hasher.field_u8(u8::from(self.provider_call_performed));
        hasher.field_u8(u8::from(self.database_mutated));
        hasher.field_u8(u8::from(self.proposed_decision_persisted));
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
    let source_preflight_path = artifact_root.join(AUTHORITY_PREFLIGHT_FILE);
    let source_acceptance_path = artifact_root.join(ACCEPTANCE_FILE);
    if !report_path.is_file()
        || !database_path.is_file()
        || !source_preflight_path.is_file()
        || !source_acceptance_path.is_file()
    {
        return Err(AppError::Experiment(
            "lifecycle authority preflight requires the retained live report, database, resolver preflight, and resolver acceptance"
                .into(),
        ));
    }

    let report_bytes = read_bounded_file(&report_path, MAX_LIFECYCLE_EXPLORE_LIVE_REPORT_BYTES)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let source = decode_authority_source(&report_bytes)?;
    let source_report_digest = Digest::blake3(&report_bytes);
    let source_preflight_bytes =
        read_bounded_file(&source_preflight_path, MAX_AUTHORITY_PREFLIGHT_BYTES)
            .map_err(|error| AppError::Experiment(error.to_string()))?;
    let source_preflight =
        LifecycleExploreAuthorityPreflight::decode_json(&source_preflight_bytes)?;
    let source_acceptance_bytes = read_bounded_file(&source_acceptance_path, MAX_ACCEPTANCE_BYTES)
        .map_err(|error| AppError::Experiment(error.to_string()))?;
    let source_acceptance = LifecycleExploreAuthorityAcceptance::decode_json(
        &source_acceptance_bytes,
        &source_preflight,
    )?;
    if source_report_digest != source_preflight.source_report_digest {
        return Err(AppError::Experiment(
            "lifecycle authority preflight live report differs from the accepted resolver preflight"
                .into(),
        ));
    }

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
    validate_source_material(
        &source_preflight,
        &source_acceptance,
        &runtime_preflight,
        &capability,
    )?;
    let current = runtime_preflight.effective_decision.as_ref().ok_or_else(|| {
        AppError::Experiment(
            "lifecycle authority preflight lost its validated effective decision".into(),
        )
    })?;
    let proposed_decision = ActionCapabilityDecision::new(ActionCapabilityDecisionInput {
        capability_class: capability.id,
        capability_definition_digest: capability.definition_digest,
        evidence: runtime_preflight.evidence.id,
        evidence_definition_digest: runtime_preflight.evidence.definition_digest,
        previous_decision: Some(current.decision.id),
        selected_mode: CapabilityMode::Authoritative,
        automatic_resolver_consumption_approved: true,
        automatic_lifecycle_consumption_approved: true,
        decider_id,
        decided_unix_ms,
    })
    .map_err(|error| AppError::Experiment(error.to_string()))?;
    let preflight = LifecycleExploreLifecycleAuthorityPreflight::new(
        LifecycleExploreLifecycleAuthorityPreflightInput {
            source_report_digest,
            source_authority_preflight_digest: source_preflight.preflight_digest,
            source_authority_acceptance_digest: source_acceptance.acceptance_digest,
            source_database_schema_version: runtime_preflight.source_schema_version,
            capability_class: capability,
            evidence: runtime_preflight.evidence,
            current_decision: current.decision.clone(),
            current_decision_recorded_unix_ms: current.recorded_unix_ms,
            proposed_decision,
        },
    )?;
    preflight.validate()?;
    let output = artifact_root.join(LIFECYCLE_AUTHORITY_PREFLIGHT_FILE);
    let created = write_create_new_or_verify_existing(&output, &preflight)?;
    println!(
        "lifecycle Explore lifecycle authority preflight {} {}",
        if created { "written to" } else { "verified at" },
        output.display()
    );
    println!("preflight_digest={}", preflight.preflight_digest);
    println!("source_authority_acceptance_digest={}", preflight.source_authority_acceptance_digest);
    println!("current_decision_id={}", preflight.current_decision.id);
    println!("proposed_decision_id={}", preflight.proposed_decision.id);
    println!("selected_mode=authoritative");
    println!("automatic_resolver_consumption_approved=true");
    println!("automatic_lifecycle_consumption_approved=true");
    println!("provider_call_performed=false");
    println!("database_mutated=false");
    println!("proposed_decision_persisted=false");
    println!("lifecycle_consumption_approved=false");
    Ok(())
}

fn validate_source_material(
    source_preflight: &LifecycleExploreAuthorityPreflight,
    source_acceptance: &LifecycleExploreAuthorityAcceptance,
    runtime: &ActionAssurancePreflight,
    capability: &ActionCapabilityClass,
) -> Result<(), AppError> {
    validate_source_foundation(source_preflight, source_acceptance, runtime, capability)?;
    let Some(current) = runtime.effective_decision.as_ref() else {
        return Err(AppError::Experiment(
            "lifecycle authority preflight requires an effective resolver authority head".into(),
        ));
    };
    if current.evidence != runtime.evidence
        || current.decision != source_preflight.proposed_decision
        || current.recorded_unix_ms != source_acceptance.decision_recorded_unix_ms
        || current.decision.selected_mode != CapabilityMode::Authoritative
        || !current.decision.automatic_resolver_consumption_approved
        || current.decision.automatic_lifecycle_consumption_approved
    {
        return Err(AppError::Experiment(
            "lifecycle authority preflight source material is not the exact accepted resolver-only head"
                .into(),
        ));
    }
    Ok(())
}

fn validate_source_foundation(
    source_preflight: &LifecycleExploreAuthorityPreflight,
    source_acceptance: &LifecycleExploreAuthorityAcceptance,
    runtime: &ActionAssurancePreflight,
    capability: &ActionCapabilityClass,
) -> Result<(), AppError> {
    source_preflight.validate()?;
    source_acceptance.validate(source_preflight)?;
    if runtime.source_schema_version != 32
        || source_acceptance.persisted_database_schema_version != runtime.source_schema_version
        || source_preflight.capability_class != *capability
        || runtime.evidence != source_preflight.evidence
    {
        return Err(AppError::Experiment(
            "lifecycle authority source foundation differs from the accepted resolver material"
                .into(),
        ));
    }
    Ok(())
}

fn write_create_new_or_verify_existing(
    path: &Path,
    value: &LifecycleExploreLifecycleAuthorityPreflight,
) -> Result<bool, AppError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_LIFECYCLE_AUTHORITY_PREFLIGHT_BYTES {
        return Err(AppError::Experiment(format!(
            "lifecycle authority preflight has {} bytes; maximum is {}",
            bytes.len(),
            MAX_LIFECYCLE_AUTHORITY_PREFLIGHT_BYTES
        )));
    }
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(&bytes)?;
            file.sync_all()?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_bounded_file(path, MAX_LIFECYCLE_AUTHORITY_PREFLIGHT_BYTES)
                .map_err(|error| AppError::Experiment(error.to_string()))?;
            if existing == bytes {
                Ok(false)
            } else {
                Err(AppError::Experiment(
                    "lifecycle authority preflight output already exists with different canonical content"
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
                    "unknown lifecycle-explore-lifecycle-authority-preflight argument `{argument}`"
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
    use needle_runtime::ActionCapabilityDecisionRecord;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct SourceFixture {
        source_preflight: LifecycleExploreAuthorityPreflight,
        source_acceptance: LifecycleExploreAuthorityAcceptance,
        runtime: ActionAssurancePreflight,
        capability: ActionCapabilityClass,
    }

    fn digest(label: &str) -> Digest {
        Digest::blake3(label.as_bytes())
    }

    fn source_fixture() -> SourceFixture {
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
        let source_preflight = LifecycleExploreAuthorityPreflight::new(
            report_digest,
            31,
            capability.clone(),
            evidence.clone(),
            current_decision.clone(),
        )
        .unwrap();
        let source_acceptance =
            LifecycleExploreAuthorityAcceptance::new(&source_preflight, 30, 31).unwrap();
        let runtime = ActionAssurancePreflight {
            source_schema_version: 32,
            evidence: evidence.clone(),
            effective_decision: Some(ActionCapabilityDecisionRecord {
                decision: current_decision,
                evidence,
                recorded_unix_ms: 31,
            }),
        };
        SourceFixture { source_preflight, source_acceptance, runtime, capability }
    }

    fn lifecycle_preflight(
        fixture: &SourceFixture,
        decided_unix_ms: u64,
    ) -> Result<LifecycleExploreLifecycleAuthorityPreflight, AppError> {
        let current = fixture.runtime.effective_decision.as_ref().unwrap();
        let proposed_decision = ActionCapabilityDecision::new(ActionCapabilityDecisionInput {
            capability_class: fixture.capability.id,
            capability_definition_digest: fixture.capability.definition_digest,
            evidence: fixture.runtime.evidence.id,
            evidence_definition_digest: fixture.runtime.evidence.definition_digest,
            previous_decision: Some(current.decision.id),
            selected_mode: CapabilityMode::Authoritative,
            automatic_resolver_consumption_approved: true,
            automatic_lifecycle_consumption_approved: true,
            decider_id: "local-owner".to_owned(),
            decided_unix_ms,
        })
        .unwrap();
        LifecycleExploreLifecycleAuthorityPreflight::new(
            LifecycleExploreLifecycleAuthorityPreflightInput {
                source_report_digest: fixture.source_preflight.source_report_digest,
                source_authority_preflight_digest: fixture.source_preflight.preflight_digest,
                source_authority_acceptance_digest: fixture.source_acceptance.acceptance_digest,
                source_database_schema_version: fixture.runtime.source_schema_version,
                capability_class: fixture.capability.clone(),
                evidence: fixture.runtime.evidence.clone(),
                current_decision: current.decision.clone(),
                current_decision_recorded_unix_ms: current.recorded_unix_ms,
                proposed_decision,
            },
        )
    }

    #[test]
    fn proposal_is_canonical_lifecycle_enabled_and_still_unaccepted() {
        let fixture = source_fixture();
        validate_source_material(
            &fixture.source_preflight,
            &fixture.source_acceptance,
            &fixture.runtime,
            &fixture.capability,
        )
        .unwrap();
        let proposal = lifecycle_preflight(&fixture, 40).unwrap();
        proposal.validate().unwrap();
        assert_eq!(
            proposal.proposed_decision.previous_decision,
            Some(proposal.current_decision.id)
        );
        assert!(proposal.proposed_decision.automatic_resolver_consumption_approved);
        assert!(proposal.proposed_decision.automatic_lifecycle_consumption_approved);
        assert!(proposal.source_resolver_authority_persisted);
        assert!(!proposal.provider_call_performed);
        assert!(!proposal.database_mutated);
        assert!(!proposal.proposed_decision_persisted);
        assert!(!proposal.lifecycle_consumption_approved);

        let encoded = serde_json::to_vec(&proposal).unwrap();
        let decoded: LifecycleExploreLifecycleAuthorityPreflight =
            serde_json::from_slice(&encoded).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded, proposal);
    }

    #[test]
    fn source_must_be_the_exact_persisted_resolver_only_head() {
        let mut fixture = source_fixture();
        fixture.runtime.effective_decision = None;
        assert!(
            validate_source_material(
                &fixture.source_preflight,
                &fixture.source_acceptance,
                &fixture.runtime,
                &fixture.capability,
            )
            .is_err()
        );

        let mut fixture = source_fixture();
        fixture.runtime.effective_decision.as_mut().unwrap().recorded_unix_ms += 1;
        assert!(
            validate_source_material(
                &fixture.source_preflight,
                &fixture.source_acceptance,
                &fixture.runtime,
                &fixture.capability,
            )
            .is_err()
        );
    }

    #[test]
    fn acceptance_source_allows_only_the_rendered_before_or_after_head() {
        let mut fixture = source_fixture();
        let proposal = lifecycle_preflight(&fixture, 40).unwrap();
        assert!(
            !proposal
                .validate_acceptance_source(
                    &fixture.source_preflight,
                    &fixture.source_acceptance,
                    &fixture.runtime,
                    &fixture.capability,
                )
                .unwrap()
        );

        fixture.runtime.effective_decision = Some(ActionCapabilityDecisionRecord {
            decision: proposal.proposed_decision.clone(),
            evidence: fixture.runtime.evidence.clone(),
            recorded_unix_ms: 50,
        });
        assert!(
            proposal
                .validate_acceptance_source(
                    &fixture.source_preflight,
                    &fixture.source_acceptance,
                    &fixture.runtime,
                    &fixture.capability,
                )
                .unwrap()
        );

        let unrelated = ActionCapabilityDecision::new(ActionCapabilityDecisionInput {
            capability_class: fixture.capability.id,
            capability_definition_digest: fixture.capability.definition_digest,
            evidence: fixture.runtime.evidence.id,
            evidence_definition_digest: fixture.runtime.evidence.definition_digest,
            previous_decision: Some(proposal.proposed_decision.id),
            selected_mode: CapabilityMode::Authoritative,
            automatic_resolver_consumption_approved: true,
            automatic_lifecycle_consumption_approved: false,
            decider_id: "local-owner".to_owned(),
            decided_unix_ms: 60,
        })
        .unwrap();
        fixture.runtime.effective_decision = Some(ActionCapabilityDecisionRecord {
            decision: unrelated,
            evidence: fixture.runtime.evidence.clone(),
            recorded_unix_ms: 61,
        });
        assert!(
            proposal
                .validate_acceptance_source(
                    &fixture.source_preflight,
                    &fixture.source_acceptance,
                    &fixture.runtime,
                    &fixture.capability,
                )
                .is_err()
        );
    }

    #[test]
    fn proposal_must_advance_time_and_cannot_claim_persistence() {
        let fixture = source_fixture();
        assert!(lifecycle_preflight(&fixture, 20).is_err());

        let mut proposal = lifecycle_preflight(&fixture, 40).unwrap();
        proposal.proposed_decision_persisted = true;
        assert!(proposal.validate().is_err());
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
        assert!(validate_arguments(&["--provider".into()]).is_err());
    }

    #[test]
    fn exact_existing_proposal_is_verified_but_never_overwritten() {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!(
            "needle-lifecycle-authority-preflight-{}-{suffix}.json",
            std::process::id()
        ));
        let fixture = source_fixture();
        let proposal = lifecycle_preflight(&fixture, 40).unwrap();
        assert!(write_create_new_or_verify_existing(&path, &proposal).unwrap());
        assert!(!write_create_new_or_verify_existing(&path, &proposal).unwrap());
        std::fs::write(&path, b"different\n").unwrap();
        assert!(write_create_new_or_verify_existing(&path, &proposal).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
