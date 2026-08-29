mod projection;

pub use projection::{assemble_architecture_briefs, project_architecture_brief};

use needle_core::{
    ArchitectureBrief, ArchitectureBriefError, ArchitectureBriefScope, ArchitectureEvidenceRole,
    CanonicalHasher, Digest, TestTargetPackageKey,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};
use thiserror::Error;

pub const ARCHITECTURE_BRIEF_ANALYSIS_REVISION: u32 = 1;
pub const MAX_ARCHITECTURE_EVIDENCE_FILE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_ARCHITECTURE_EVIDENCE_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const ARCHITECTURE_BRIEF_VALIDATION_FORMAT_REVISION: u16 = 1;

#[derive(Clone, Copy)]
pub struct ArchitectureBriefValidationInput<'a> {
    pub repository_root: &'a Path,
    pub repository_lineage: Digest,
    pub source_selector: &'a str,
    pub workspace_manifest: &'a str,
    pub scope: &'a ArchitectureBriefScope,
    pub package_universe: &'a [TestTargetPackageKey],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureBriefValidationCertificate {
    pub format_revision: u16,
    pub brief: Digest,
    pub analysis_definition_digest: Digest,
    pub validator_definition_digest: Digest,
    pub package_universe_digest: Digest,
    pub evidence_checks_digest: Digest,
    pub id: Digest,
}

impl ArchitectureBriefValidationCertificate {
    pub fn validate(&self) -> Result<(), ArchitectureBriefRuntimeError> {
        if self.format_revision != ARCHITECTURE_BRIEF_VALIDATION_FORMAT_REVISION
            || self.analysis_definition_digest != architecture_brief_analysis_definition()
            || self.validator_definition_digest != architecture_brief_validator_definition()
            || self.id != self.compute_id()
        {
            return Err(ArchitectureBriefRuntimeError::Certificate);
        }
        Ok(())
    }

    fn compute_id(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"architecture-brief-validation-certificate-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.brief);
        hasher.field_digest(self.analysis_definition_digest);
        hasher.field_digest(self.validator_definition_digest);
        hasher.field_digest(self.package_universe_digest);
        hasher.field_digest(self.evidence_checks_digest);
        hasher.finish()
    }
}

pub fn architecture_brief_analysis_definition() -> Digest {
    let mut hasher = CanonicalHasher::new(b"architecture-brief-analysis-definition-v1");
    hasher.field_u32(ARCHITECTURE_BRIEF_ANALYSIS_REVISION);
    hasher.field_str(needle_core::ARCHITECTURE_BRIEF_SCHEMA_ID);
    hasher.field_str("cargo-package-partitions");
    hasher.field_str("model-authored-assertions-with-structural-evidence");
    hasher.field_str("no-aggregate-summary");
    hasher.finish()
}

pub fn architecture_brief_validator_definition() -> Digest {
    let mut hasher = CanonicalHasher::new(b"architecture-brief-validator-definition-v1");
    hasher.field_digest(architecture_brief_analysis_definition());
    hasher.field_str("canonical-complete-scope");
    hasher.field_str("current-bounded-file-content");
    hasher.field_str("workspace-and-package-manifest-coverage");
    hasher.field_str("evidence-role-and-package-reference-integrity");
    hasher.field_str("model-authored-prose-not-semantically-certified");
    hasher.finish()
}

pub fn architecture_brief_partition_policy_definition() -> Digest {
    let mut hasher = CanonicalHasher::new(b"architecture-brief-partition-policy-v1");
    hasher.field_digest(architecture_brief_analysis_definition());
    hasher.field_digest(architecture_brief_validator_definition());
    hasher.field_str("project-package-subset");
    hasher.field_str("assemble-disjoint-package-scopes");
    hasher.field_str("refresh-disabled");
    hasher.finish()
}

pub fn validate_architecture_brief(
    input: ArchitectureBriefValidationInput<'_>,
    brief: &ArchitectureBrief,
) -> Result<ArchitectureBriefValidationCertificate, ArchitectureBriefRuntimeError> {
    validate_input(input)?;
    brief.validate()?;
    if brief.repository_lineage != input.repository_lineage
        || brief.source_selector != input.source_selector
        || brief.workspace_manifest != input.workspace_manifest
        || &brief.scope != input.scope
        || brief.analysis_definition_digest != architecture_brief_analysis_definition()
        || brief.package_universe != input.package_universe
    {
        return Err(ArchitectureBriefRuntimeError::Binding);
    }

    let root = std::fs::canonicalize(input.repository_root).map_err(|error| {
        ArchitectureBriefRuntimeError::Io {
            path: input.repository_root.display().to_string(),
            message: error.to_string(),
        }
    })?;
    let mut checked_files = BTreeMap::<String, CheckedFile>::new();
    let mut total_bytes = 0usize;
    let mut evidence_checks = CanonicalHasher::new(b"architecture-brief-evidence-checks-v1");
    for evidence in &brief.evidence {
        let checked = if let Some(checked) = checked_files.get(&evidence.path) {
            checked.clone()
        } else {
            let checked = read_current_file(&root, &evidence.path)?;
            total_bytes = total_bytes.checked_add(checked.bytes).ok_or(
                ArchitectureBriefRuntimeError::EvidenceTotalBound {
                    actual: usize::MAX,
                    maximum: MAX_ARCHITECTURE_EVIDENCE_TOTAL_BYTES,
                },
            )?;
            if total_bytes > MAX_ARCHITECTURE_EVIDENCE_TOTAL_BYTES {
                return Err(ArchitectureBriefRuntimeError::EvidenceTotalBound {
                    actual: total_bytes,
                    maximum: MAX_ARCHITECTURE_EVIDENCE_TOTAL_BYTES,
                });
            }
            checked_files.insert(evidence.path.clone(), checked.clone());
            checked
        };
        if evidence.content_digest != checked.digest {
            return Err(ArchitectureBriefRuntimeError::EvidenceDrift(evidence.path.clone()));
        }
        if evidence.byte_end.is_some_and(|end| end > checked.bytes as u64) {
            return Err(ArchitectureBriefRuntimeError::EvidenceRange(evidence.path.clone()));
        }
        evidence_checks.field_digest(evidence.id);
        evidence_checks.field_digest(checked.digest);
        evidence_checks.field_u32(checked.bytes.try_into().unwrap_or(u32::MAX));
    }
    validate_manifest_coverage(brief)?;

    let mut certificate = ArchitectureBriefValidationCertificate {
        format_revision: ARCHITECTURE_BRIEF_VALIDATION_FORMAT_REVISION,
        brief: brief.content_digest,
        analysis_definition_digest: architecture_brief_analysis_definition(),
        validator_definition_digest: architecture_brief_validator_definition(),
        package_universe_digest: brief.package_universe_digest(),
        evidence_checks_digest: evidence_checks.finish(),
        id: Digest([0; 32]),
    };
    certificate.id = certificate.compute_id();
    certificate.validate()?;
    Ok(certificate)
}

#[derive(Clone)]
struct CheckedFile {
    digest: Digest,
    bytes: usize,
}

fn read_current_file(
    root: &Path,
    relative: &str,
) -> Result<CheckedFile, ArchitectureBriefRuntimeError> {
    validate_relative_path(relative)?;
    let path = root.join(relative);
    let canonical = std::fs::canonicalize(&path)
        .map_err(|_| ArchitectureBriefRuntimeError::MissingEvidence(relative.to_owned()))?;
    let canonical_relative = canonical
        .strip_prefix(root)
        .map_err(|_| ArchitectureBriefRuntimeError::UnsafeEvidence(relative.to_owned()))?;
    if normalize_relative(canonical_relative).as_deref() != Some(relative) || !canonical.is_file() {
        return Err(ArchitectureBriefRuntimeError::UnsafeEvidence(relative.to_owned()));
    }
    let file = File::open(&canonical).map_err(|error| ArchitectureBriefRuntimeError::Io {
        path: relative.to_owned(),
        message: error.to_string(),
    })?;
    let mut bytes = Vec::new();
    file.take((MAX_ARCHITECTURE_EVIDENCE_FILE_BYTES + 1) as u64).read_to_end(&mut bytes).map_err(
        |error| ArchitectureBriefRuntimeError::Io {
            path: relative.to_owned(),
            message: error.to_string(),
        },
    )?;
    if bytes.len() > MAX_ARCHITECTURE_EVIDENCE_FILE_BYTES {
        return Err(ArchitectureBriefRuntimeError::EvidenceFileBound {
            path: relative.to_owned(),
            actual: bytes.len(),
            maximum: MAX_ARCHITECTURE_EVIDENCE_FILE_BYTES,
        });
    }
    Ok(CheckedFile { digest: Digest::blake3(&bytes), bytes: bytes.len() })
}

fn validate_manifest_coverage(
    brief: &ArchitectureBrief,
) -> Result<(), ArchitectureBriefRuntimeError> {
    let workspace_covered = brief.evidence.iter().any(|evidence| {
        evidence.path == brief.workspace_manifest
            && evidence.roles.binary_search(&ArchitectureEvidenceRole::Manifest).is_ok()
            && evidence.packages.is_empty()
    });
    if !workspace_covered {
        return Err(ArchitectureBriefRuntimeError::ManifestCoverage(
            brief.workspace_manifest.clone(),
        ));
    }
    let packages = if brief.scope.packages.is_empty() {
        &brief.package_universe
    } else {
        &brief.scope.packages
    };
    for package in packages {
        let covered = brief.evidence.iter().any(|evidence| {
            evidence.path == package.manifest_path
                && evidence.roles.binary_search(&ArchitectureEvidenceRole::Manifest).is_ok()
                && evidence.packages.binary_search(package).is_ok()
        });
        if !covered {
            return Err(ArchitectureBriefRuntimeError::ManifestCoverage(
                package.manifest_path.clone(),
            ));
        }
    }
    Ok(())
}

fn validate_input(
    input: ArchitectureBriefValidationInput<'_>,
) -> Result<(), ArchitectureBriefRuntimeError> {
    input.scope.validate()?;
    validate_relative_path(input.workspace_manifest)?;
    if input.source_selector.is_empty()
        || input.source_selector.len() > needle_core::MAX_ARCHITECTURE_SOURCE_SELECTOR_BYTES
        || input.source_selector.chars().any(char::is_control)
        || input.package_universe.is_empty()
        || input.package_universe.len() > needle_core::MAX_ARCHITECTURE_PACKAGES
        || !input.package_universe.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(ArchitectureBriefRuntimeError::Input);
    }
    for package in input.package_universe {
        package.validate()?;
    }
    if input
        .scope
        .packages
        .iter()
        .any(|package| input.package_universe.binary_search(package).is_err())
    {
        return Err(ArchitectureBriefRuntimeError::Input);
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), ArchitectureBriefRuntimeError> {
    if value.is_empty()
        || value.len() > needle_core::MAX_ARCHITECTURE_PATH_BYTES
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || Path::new(value).is_absolute()
        || Path::new(value).components().any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ArchitectureBriefRuntimeError::UnsafeEvidence(value.to_owned()));
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

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ArchitectureBriefRuntimeError {
    #[error("architecture brief validation input is invalid")]
    Input,
    #[error("architecture brief is not bound to the current request and definitions")]
    Binding,
    #[error("architecture evidence `{0}` is missing")]
    MissingEvidence(String),
    #[error("architecture evidence `{0}` is unsafe or outside the repository root")]
    UnsafeEvidence(String),
    #[error("architecture evidence `{0}` changed")]
    EvidenceDrift(String),
    #[error("architecture evidence range exceeds `{0}`")]
    EvidenceRange(String),
    #[error("architecture evidence `{path}` contains {actual} bytes; the maximum is {maximum}")]
    EvidenceFileBound { path: String, actual: usize, maximum: usize },
    #[error("architecture evidence contains {actual} total bytes; the maximum is {maximum}")]
    EvidenceTotalBound { actual: usize, maximum: usize },
    #[error("architecture manifest evidence is incomplete for `{0}`")]
    ManifestCoverage(String),
    #[error("architecture brief projection scope is invalid")]
    ProjectionScope,
    #[error("architecture brief assembly inputs are incompatible or overlapping")]
    Assembly,
    #[error("architecture brief validation certificate is invalid")]
    Certificate,
    #[error("repository I/O failed for `{path}`: {message}")]
    Io { path: String, message: String },
    #[error(transparent)]
    Brief(#[from] ArchitectureBriefError),
    #[error(transparent)]
    Package(#[from] needle_core::TestTargetInventoryError),
}

#[cfg(test)]
mod tests;
