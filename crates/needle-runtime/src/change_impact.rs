mod patch;
mod projection;

use patch::bound_blob_map;
pub use patch::derive_change_impact_change_set;
pub use projection::{assemble_change_impacts, project_change_impact};

use crate::store::PatchFileBlob;
use crate::test_target_inventory::TestTargetInventoryValidationCertificate;
use needle_core::{
    CanonicalHasher, ChangeImpact, ChangeImpactConstraint, ChangeImpactError,
    ChangeImpactEvidenceRole, ChangeImpactEvidenceState, ChangeImpactInputReference,
    ChangeImpactRequirement, ChangeImpactScope, Digest, PatchArtifact, Subject,
    TestTargetInventory,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Take};
use std::path::{Component, Path};
use thiserror::Error;

pub const CHANGE_IMPACT_ANALYSIS_REVISION: u32 = 1;
pub const MAX_CHANGE_IMPACT_BLOB_FILE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CHANGE_IMPACT_BLOB_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const CHANGE_IMPACT_VALIDATION_FORMAT_REVISION: u16 = 1;

#[derive(Clone, Copy)]
pub struct ChangeImpactValidationInput<'a> {
    pub repository_root: &'a Path,
    pub repository_lineage: Digest,
    pub source_selector: &'a str,
    pub patch: &'a PatchArtifact,
    pub patch_blobs: &'a [PatchFileBlob],
    pub scope: &'a ChangeImpactScope,
    pub requirements: &'a [ChangeImpactRequirement],
    pub constraints: &'a [ChangeImpactConstraint],
    pub subjects: &'a [Subject],
    pub accepted_inputs: &'a [ChangeImpactInputReference],
    pub test_inventory: Option<&'a TestTargetInventory>,
    pub test_inventory_certificate: Option<&'a TestTargetInventoryValidationCertificate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpactValidationCertificate {
    pub format_revision: u16,
    pub impact: Digest,
    pub change_set_digest: Digest,
    pub scope_digest: Digest,
    pub analysis_definition_digest: Digest,
    pub validator_definition_digest: Digest,
    pub input_binding_digest: Digest,
    pub evidence_checks_digest: Digest,
    pub test_inventory_digest: Option<Digest>,
    pub id: Digest,
}

impl ChangeImpactValidationCertificate {
    pub fn validate(&self) -> Result<(), ChangeImpactRuntimeError> {
        if self.format_revision != CHANGE_IMPACT_VALIDATION_FORMAT_REVISION
            || self.analysis_definition_digest != change_impact_analysis_definition()
            || self.validator_definition_digest != change_impact_validator_definition()
            || self.id != self.compute_id()
        {
            return Err(ChangeImpactRuntimeError::Certificate);
        }
        Ok(())
    }

    fn compute_id(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"change-impact-validation-certificate-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.impact);
        hasher.field_digest(self.change_set_digest);
        hasher.field_digest(self.scope_digest);
        hasher.field_digest(self.analysis_definition_digest);
        hasher.field_digest(self.validator_definition_digest);
        hasher.field_digest(self.input_binding_digest);
        hasher.field_digest(self.evidence_checks_digest);
        hash_optional_digest(&mut hasher, self.test_inventory_digest);
        hasher.finish()
    }
}

pub fn change_impact_analysis_definition() -> Digest {
    let mut hasher = CanonicalHasher::new(b"change-impact-analysis-definition-v1");
    hasher.field_u32(CHANGE_IMPACT_ANALYSIS_REVISION);
    hasher.field_str(needle_core::CHANGE_IMPACT_SCHEMA_ID);
    hasher.field_str("patch-artifact-and-blob-bound-change-surface");
    hasher.field_str("requirement-subject-components");
    hasher.field_str("model-authored-assessments-with-structural-evidence");
    hasher.field_str("accepted-inputs-are-referenced-not-recertified");
    hasher.finish()
}

pub fn change_impact_validator_definition() -> Digest {
    let mut hasher = CanonicalHasher::new(b"change-impact-validator-definition-v1");
    hasher.field_digest(change_impact_analysis_definition());
    hasher.field_str("bounded-patch-blob-integrity");
    hasher.field_str("safe-before-after-virtual-files");
    hasher.field_str("exact-requirement-subject-coverage");
    hasher.field_str("current-base-and-patch-evidence-digests");
    hasher.field_str("test-target-references-require-current-inventory");
    hasher.field_str("model-authored-impact-prose-not-semantically-certified");
    hasher.finish()
}

pub fn change_impact_partition_policy_definition() -> Digest {
    let mut hasher = CanonicalHasher::new(b"change-impact-partition-policy-v1");
    hasher.field_digest(change_impact_analysis_definition());
    hasher.field_str("project-by-requirement-subject-component");
    hasher.field_str("assemble-disjoint-components-with-identical-input-bindings");
    hasher.field_str("refresh-deferred-until-state-delta");
    hasher.finish()
}

pub fn validate_change_impact(
    input: ChangeImpactValidationInput<'_>,
    impact: &ChangeImpact,
) -> Result<ChangeImpactValidationCertificate, ChangeImpactRuntimeError> {
    let expected_change_set = derive_change_impact_change_set(input.patch, input.patch_blobs)?;
    input.scope.validate()?;
    impact.validate()?;
    if impact.repository_lineage != input.repository_lineage
        || impact.source_selector != input.source_selector
        || impact.change_set != expected_change_set
        || &impact.scope != input.scope
        || impact.analysis_definition_digest != change_impact_analysis_definition()
        || impact.requirement_universe != input.requirements
        || impact.constraints != input.constraints
        || impact.subject_universe != input.subjects
        || impact.accepted_inputs != input.accepted_inputs
    {
        return Err(ChangeImpactRuntimeError::Binding);
    }

    let (test_inventory_digest, test_inventory_certificate) =
        validate_test_inventory(input, impact)?;
    let root = std::fs::canonicalize(input.repository_root).map_err(|error| {
        ChangeImpactRuntimeError::Io {
            path: input.repository_root.display().to_string(),
            message: error.to_string(),
        }
    })?;
    let blobs = bound_blob_map(input.patch, input.patch_blobs)?;
    let mut checked = BTreeMap::<(ChangeImpactEvidenceState, String), CheckedFile>::new();
    let mut total_bytes = 0usize;
    let mut evidence_checks = CanonicalHasher::new(b"change-impact-evidence-checks-v1");
    for evidence in &impact.evidence {
        let cache_key = (evidence.state, evidence.path.clone());
        let file = if let Some(value) = checked.get(&cache_key) {
            value.clone()
        } else {
            let value = read_virtual_file(&root, &blobs, evidence.state, &evidence.path)?;
            total_bytes = total_bytes.checked_add(value.bytes).ok_or(
                ChangeImpactRuntimeError::EvidenceTotalBound {
                    actual: usize::MAX,
                    maximum: MAX_CHANGE_IMPACT_BLOB_TOTAL_BYTES,
                },
            )?;
            if total_bytes > MAX_CHANGE_IMPACT_BLOB_TOTAL_BYTES {
                return Err(ChangeImpactRuntimeError::EvidenceTotalBound {
                    actual: total_bytes,
                    maximum: MAX_CHANGE_IMPACT_BLOB_TOTAL_BYTES,
                });
            }
            checked.insert(cache_key, value.clone());
            value
        };
        if file.digest != evidence.content_digest {
            return Err(ChangeImpactRuntimeError::EvidenceDrift(evidence.path.clone()));
        }
        if evidence.byte_end.is_some_and(|end| end > file.bytes as u64) {
            return Err(ChangeImpactRuntimeError::EvidenceRange(evidence.path.clone()));
        }
        evidence_checks.field_digest(evidence.id);
        evidence_checks.field_digest(file.digest);
        evidence_checks.field_u32(file.bytes.try_into().unwrap_or(u32::MAX));
    }
    validate_changed_surface_coverage(impact)?;

    let mut certificate = ChangeImpactValidationCertificate {
        format_revision: CHANGE_IMPACT_VALIDATION_FORMAT_REVISION,
        impact: impact.content_digest,
        change_set_digest: impact.change_set.digest,
        scope_digest: impact.scope.digest(),
        analysis_definition_digest: change_impact_analysis_definition(),
        validator_definition_digest: change_impact_validator_definition(),
        input_binding_digest: input_binding_digest(
            input,
            test_inventory_digest,
            test_inventory_certificate,
        ),
        evidence_checks_digest: evidence_checks.finish(),
        test_inventory_digest,
        id: Digest([0; 32]),
    };
    certificate.id = certificate.compute_id();
    certificate.validate()?;
    Ok(certificate)
}

fn validate_test_inventory(
    input: ChangeImpactValidationInput<'_>,
    impact: &ChangeImpact,
) -> Result<(Option<Digest>, Option<Digest>), ChangeImpactRuntimeError> {
    match (input.test_inventory, input.test_inventory_certificate) {
        (Some(inventory), Some(certificate)) => {
            inventory.validate()?;
            certificate.validate().map_err(|_| ChangeImpactRuntimeError::TestInventoryBinding)?;
            if inventory.repository_lineage != input.repository_lineage
                || inventory.source_selector != input.source_selector
                || impact.test_inventory_digest != Some(inventory.content_digest)
                || certificate.inventory != inventory.content_digest
                || certificate.adapter_definition_digest != inventory.adapter_definition_digest
                || certificate.metadata_digest != inventory.metadata_digest
                || certificate.dependency_set_digest
                    != test_inventory_dependency_set_digest(inventory)
                || impact.test_inventory_validation_certificate
                    != Some(certificate.certificate_digest)
            {
                return Err(ChangeImpactRuntimeError::TestInventoryBinding);
            }
            let targets = inventory
                .partitions
                .iter()
                .map(|target| target.content_digest)
                .collect::<BTreeSet<_>>();
            if impact
                .assessments
                .iter()
                .flat_map(|assessment| &assessment.test_target_ids)
                .any(|target| !targets.contains(target))
            {
                return Err(ChangeImpactRuntimeError::TestTargetReference);
            }
            Ok((Some(inventory.content_digest), Some(certificate.certificate_digest)))
        }
        (None, None)
            if impact.test_inventory_digest.is_none()
                && impact.test_inventory_validation_certificate.is_none()
                && impact.assessments.iter().all(|value| value.test_target_ids.is_empty()) =>
        {
            Ok((None, None))
        }
        _ => Err(ChangeImpactRuntimeError::TestInventoryBinding),
    }
}

fn test_inventory_dependency_set_digest(inventory: &TestTargetInventory) -> Digest {
    let mut hasher = CanonicalHasher::new(b"test-target-inventory-dependency-set-v1");
    for locator in &inventory.collection_dependencies {
        hasher.field_digest(locator.id);
    }
    hasher.finish()
}

fn validate_changed_surface_coverage(
    impact: &ChangeImpact,
) -> Result<(), ChangeImpactRuntimeError> {
    for file in &impact.change_set.files {
        let required_states: &[ChangeImpactEvidenceState] = match file.operation {
            needle_core::PatchOperation::Create => &[ChangeImpactEvidenceState::After],
            needle_core::PatchOperation::Update => {
                &[ChangeImpactEvidenceState::Before, ChangeImpactEvidenceState::After]
            }
            needle_core::PatchOperation::Delete => &[ChangeImpactEvidenceState::Before],
        };
        for state in required_states {
            let covered = impact.evidence.iter().any(|evidence| {
                evidence.path == file.path
                    && evidence.state == *state
                    && evidence
                        .roles
                        .binary_search(&ChangeImpactEvidenceRole::ChangedSurface)
                        .is_ok()
            });
            if !covered {
                return Err(ChangeImpactRuntimeError::ChangedSurfaceCoverage(file.path.clone()));
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
struct CheckedFile {
    digest: Digest,
    bytes: usize,
}

fn read_virtual_file(
    root: &Path,
    blobs: &BTreeMap<&str, &PatchFileBlob>,
    state: ChangeImpactEvidenceState,
    relative: &str,
) -> Result<CheckedFile, ChangeImpactRuntimeError> {
    validate_relative_path(relative)?;
    if let Some(blob) = blobs.get(relative) {
        let bytes = match state {
            ChangeImpactEvidenceState::Before => blob.before.as_deref(),
            ChangeImpactEvidenceState::After => blob.after.as_deref(),
        }
        .ok_or_else(|| ChangeImpactRuntimeError::MissingEvidence(relative.to_owned()))?;
        return Ok(CheckedFile { digest: Digest::blake3(bytes), bytes: bytes.len() });
    }
    read_base_file(root, relative)
}

fn read_base_file(root: &Path, relative: &str) -> Result<CheckedFile, ChangeImpactRuntimeError> {
    let path = root.join(relative);
    let canonical = std::fs::canonicalize(&path)
        .map_err(|_| ChangeImpactRuntimeError::MissingEvidence(relative.to_owned()))?;
    let canonical_relative = canonical
        .strip_prefix(root)
        .map_err(|_| ChangeImpactRuntimeError::UnsafeEvidence(relative.to_owned()))?;
    if normalize_relative(canonical_relative).as_deref() != Some(relative) || !canonical.is_file() {
        return Err(ChangeImpactRuntimeError::UnsafeEvidence(relative.to_owned()));
    }
    let file = File::open(&canonical).map_err(|error| ChangeImpactRuntimeError::Io {
        path: relative.to_owned(),
        message: error.to_string(),
    })?;
    read_bounded(file.take((MAX_CHANGE_IMPACT_BLOB_FILE_BYTES + 1) as u64), relative)
}

fn read_bounded(
    mut reader: Take<File>,
    relative: &str,
) -> Result<CheckedFile, ChangeImpactRuntimeError> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(|error| ChangeImpactRuntimeError::Io {
        path: relative.to_owned(),
        message: error.to_string(),
    })?;
    if bytes.len() > MAX_CHANGE_IMPACT_BLOB_FILE_BYTES {
        return Err(ChangeImpactRuntimeError::EvidenceFileBound {
            path: relative.to_owned(),
            actual: bytes.len(),
            maximum: MAX_CHANGE_IMPACT_BLOB_FILE_BYTES,
        });
    }
    Ok(CheckedFile { digest: Digest::blake3(&bytes), bytes: bytes.len() })
}

fn validate_relative_path(value: &str) -> Result<(), ChangeImpactRuntimeError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > needle_core::MAX_CHANGE_IMPACT_PATH_BYTES
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || path.is_absolute()
        || path.components().any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ChangeImpactRuntimeError::UnsafeEvidence(value.to_owned()));
    }
    Ok(())
}

fn normalize_relative(path: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_str()?.to_owned()),
            _ => return None,
        }
    }
    Some(parts.join("/"))
}

fn input_binding_digest(
    input: ChangeImpactValidationInput<'_>,
    test_inventory_digest: Option<Digest>,
    test_inventory_certificate: Option<Digest>,
) -> Digest {
    let mut hasher = CanonicalHasher::new(b"change-impact-input-binding-v1");
    hasher.field_digest(input.repository_lineage);
    hasher.field_str(input.source_selector);
    hasher.field_digest(input.scope.digest());
    for requirement in input.requirements {
        hasher.field_digest(requirement.id.digest());
    }
    for constraint in input.constraints {
        hasher.field_digest(constraint.id);
    }
    for subject in input.subjects {
        hasher.field_digest(subject.id.digest());
    }
    for reference in input.accepted_inputs {
        hasher.field_str(&reference.contract_id);
        hasher.field_u32(reference.contract_revision);
        hasher.field_digest(reference.artifact.digest());
        hasher.field_digest(reference.validation_certificate);
        hasher.field_digest(reference.definition_digest);
    }
    hash_optional_digest(&mut hasher, test_inventory_digest);
    hash_optional_digest(&mut hasher, test_inventory_certificate);
    hasher.finish()
}

fn hash_optional_digest(hasher: &mut CanonicalHasher, value: Option<Digest>) {
    hasher.field_u8(u8::from(value.is_some()));
    if let Some(value) = value {
        hasher.field_digest(value);
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ChangeImpactRuntimeError {
    #[error("change impact is not bound to the current request, patch, or definitions")]
    Binding,
    #[error("patch artifact or blob set is invalid: {0}")]
    Patch(String),
    #[error("patch blob `{path}` contains {actual} bytes; the maximum is {maximum}")]
    BlobFileBound { path: String, actual: usize, maximum: usize },
    #[error("patch blobs contain {actual} total bytes; the maximum is {maximum}")]
    BlobTotalBound { actual: usize, maximum: usize },
    #[error("change impact evidence `{0}` is missing")]
    MissingEvidence(String),
    #[error("change impact evidence `{0}` is unsafe or outside the repository root")]
    UnsafeEvidence(String),
    #[error("change impact evidence `{0}` changed")]
    EvidenceDrift(String),
    #[error("change impact evidence range exceeds `{0}`")]
    EvidenceRange(String),
    #[error("change impact evidence `{path}` contains {actual} bytes; the maximum is {maximum}")]
    EvidenceFileBound { path: String, actual: usize, maximum: usize },
    #[error("change impact evidence contains {actual} total bytes; the maximum is {maximum}")]
    EvidenceTotalBound { actual: usize, maximum: usize },
    #[error("changed-surface evidence is incomplete for `{0}`")]
    ChangedSurfaceCoverage(String),
    #[error("test inventory is absent, stale, or bound to another source world")]
    TestInventoryBinding,
    #[error("change impact references a test target outside the validated inventory")]
    TestTargetReference,
    #[error("change impact projection scope is invalid")]
    ProjectionScope,
    #[error("change impact assembly inputs are incompatible or overlapping")]
    Assembly,
    #[error("change impact validation certificate is invalid")]
    Certificate,
    #[error("repository I/O failed for `{path}`: {message}")]
    Io { path: String, message: String },
    #[error(transparent)]
    Impact(#[from] ChangeImpactError),
    #[error(transparent)]
    Inventory(#[from] needle_core::TestTargetInventoryError),
}

#[cfg(test)]
mod tests;
