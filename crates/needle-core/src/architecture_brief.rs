use crate::{CanonicalHasher, Digest, TestTargetPackageKey};
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::marker::PhantomData;
use std::path::{Component, Path};
use thiserror::Error;

pub const ARCHITECTURE_BRIEF_FORMAT_REVISION: u16 = 1;
pub const ARCHITECTURE_BRIEF_SCHEMA_ID: &str = "needle.architecture-brief/1";
pub const ARCHITECTURE_BRIEF_OUTPUT_CONTRACT_ID: &str = "needle.repository.architecture-brief";
pub const ARCHITECTURE_BRIEF_OUTPUT_CONTRACT_REVISION: u32 = 1;
pub const MAX_ARCHITECTURE_BRIEF_WIRE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_ARCHITECTURE_PACKAGES: usize = 256;
pub const MAX_ARCHITECTURE_EVIDENCE: usize = 4_096;
pub const MAX_ARCHITECTURE_EVIDENCE_PER_ASSERTION: usize = 16;
pub const MAX_ARCHITECTURE_SUMMARY_EVIDENCE: usize = 64;
pub const MAX_ARCHITECTURE_ASSERTIONS_PER_PACKAGE: usize = 64;
pub const MAX_ARCHITECTURE_RELATED_PACKAGES: usize = 16;
pub const MAX_ARCHITECTURE_GAPS_PER_PACKAGE: usize = 32;
pub const MAX_ARCHITECTURE_ROLES_PER_EVIDENCE: usize = 8;
pub const MAX_ARCHITECTURE_PATH_BYTES: usize = 512;
pub const MAX_ARCHITECTURE_SOURCE_SELECTOR_BYTES: usize = 2_048;
pub const MAX_ARCHITECTURE_SUMMARY_BYTES: usize = 8 * 1024;
pub const MAX_ARCHITECTURE_ASSERTION_BYTES: usize = 2 * 1024;
pub const MAX_ARCHITECTURE_GAP_BYTES: usize = 2 * 1024;
pub const MAX_ARCHITECTURE_TOTAL_TEXT_BYTES: usize = 1024 * 1024;
pub const MAX_ARCHITECTURE_TOTAL_REFERENCES: usize = 32_768;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchitectureAnalysisAuthority {
    ModelAuthored,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchitectureEvidenceRole {
    Manifest,
    EntryPoint,
    PublicBoundary,
    DependencyDeclaration,
    Supporting,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchitectureAssertionKind {
    Responsibility,
    EntryPoint,
    PublicBoundary,
    Dependency,
    DesignConstraint,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureBriefScope {
    #[serde(deserialize_with = "deserialize_packages")]
    pub packages: Vec<TestTargetPackageKey>,
}

impl ArchitectureBriefScope {
    pub fn all() -> Self {
        Self { packages: Vec::new() }
    }

    pub fn new(mut packages: Vec<TestTargetPackageKey>) -> Result<Self, ArchitectureBriefError> {
        packages.sort();
        let value = Self { packages };
        value.validate()?;
        Ok(value)
    }

    pub fn includes(&self, package: &TestTargetPackageKey) -> bool {
        self.packages.is_empty() || self.packages.binary_search(package).is_ok()
    }

    pub fn is_projection_of(&self, broader: &Self) -> bool {
        broader.packages.is_empty()
            || (!self.packages.is_empty()
                && self
                    .packages
                    .iter()
                    .all(|package| broader.packages.binary_search(package).is_ok()))
    }

    pub fn digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"architecture-brief-scope-v1");
        hasher.field_u16(self.packages.len().try_into().unwrap_or(u16::MAX));
        for package in &self.packages {
            hash_package(&mut hasher, package);
        }
        hasher.finish()
    }

    pub fn validate(&self) -> Result<(), ArchitectureBriefError> {
        validate_canonical_set("scope.packages", &self.packages, MAX_ARCHITECTURE_PACKAGES)?;
        for package in &self.packages {
            package.validate()?;
        }
        Ok(())
    }
}

impl Default for ArchitectureBriefScope {
    fn default() -> Self {
        Self::all()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureEvidence {
    pub id: Digest,
    #[serde(deserialize_with = "deserialize_path")]
    pub path: String,
    pub content_digest: Digest,
    pub byte_start: Option<u64>,
    pub byte_end: Option<u64>,
    #[serde(deserialize_with = "deserialize_roles")]
    pub roles: Vec<ArchitectureEvidenceRole>,
    #[serde(deserialize_with = "deserialize_packages")]
    pub packages: Vec<TestTargetPackageKey>,
}

impl ArchitectureEvidence {
    pub fn new(
        path: impl Into<String>,
        content_digest: Digest,
        byte_start: Option<u64>,
        byte_end: Option<u64>,
        mut roles: Vec<ArchitectureEvidenceRole>,
        mut packages: Vec<TestTargetPackageKey>,
    ) -> Result<Self, ArchitectureBriefError> {
        roles.sort();
        packages.sort();
        let mut value = Self {
            id: Digest([0; 32]),
            path: path.into(),
            content_digest,
            byte_start,
            byte_end,
            roles,
            packages,
        };
        value.validate_shape()?;
        value.id = value.compute_id();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ArchitectureBriefError> {
        self.validate_shape()?;
        if self.id != self.compute_id() {
            return Err(ArchitectureBriefError::Digest("evidence.id"));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ArchitectureBriefError> {
        validate_relative_path("evidence.path", &self.path)?;
        validate_canonical_set("evidence.roles", &self.roles, MAX_ARCHITECTURE_ROLES_PER_EVIDENCE)?;
        if self.roles.is_empty() {
            return Err(ArchitectureBriefError::Empty("evidence.roles"));
        }
        validate_canonical_set("evidence.packages", &self.packages, MAX_ARCHITECTURE_PACKAGES)?;
        for package in &self.packages {
            package.validate()?;
        }
        match (self.byte_start, self.byte_end) {
            (None, None) => Ok(()),
            (Some(start), Some(end)) if start < end => Ok(()),
            _ => Err(ArchitectureBriefError::Range),
        }
    }

    fn compute_id(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"architecture-evidence-v1");
        hasher.field_str(&self.path);
        hasher.field_digest(self.content_digest);
        match (self.byte_start, self.byte_end) {
            (Some(start), Some(end)) => {
                hasher.field_u8(1);
                hasher.field_bytes(&start.to_le_bytes());
                hasher.field_bytes(&end.to_le_bytes());
            }
            _ => hasher.field_u8(0),
        }
        hasher.field_u16(self.roles.len().try_into().unwrap_or(u16::MAX));
        for role in &self.roles {
            hasher.field_u8(evidence_role_tag(*role));
        }
        hasher.field_u16(self.packages.len().try_into().unwrap_or(u16::MAX));
        for package in &self.packages {
            hash_package(&mut hasher, package);
        }
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureAssertion {
    pub id: Digest,
    pub authority: ArchitectureAnalysisAuthority,
    pub kind: ArchitectureAssertionKind,
    #[serde(deserialize_with = "deserialize_assertion_text")]
    pub text: String,
    #[serde(deserialize_with = "deserialize_assertion_evidence_ids")]
    pub evidence_ids: Vec<Digest>,
    #[serde(deserialize_with = "deserialize_related_packages")]
    pub related_packages: Vec<TestTargetPackageKey>,
}

impl ArchitectureAssertion {
    pub fn new(
        kind: ArchitectureAssertionKind,
        text: impl Into<String>,
        mut evidence_ids: Vec<Digest>,
        mut related_packages: Vec<TestTargetPackageKey>,
    ) -> Result<Self, ArchitectureBriefError> {
        evidence_ids.sort();
        related_packages.sort();
        let mut value = Self {
            id: Digest([0; 32]),
            authority: ArchitectureAnalysisAuthority::ModelAuthored,
            kind,
            text: normalize_analysis_text(text.into()),
            evidence_ids,
            related_packages,
        };
        value.validate_shape()?;
        value.id = value.compute_id();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ArchitectureBriefError> {
        self.validate_shape()?;
        if self.id != self.compute_id() {
            return Err(ArchitectureBriefError::Digest("assertion.id"));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ArchitectureBriefError> {
        if self.authority != ArchitectureAnalysisAuthority::ModelAuthored {
            return Err(ArchitectureBriefError::Authority);
        }
        validate_analysis_text(
            "assertion.text",
            &self.text,
            MAX_ARCHITECTURE_ASSERTION_BYTES,
            false,
        )?;
        validate_canonical_set(
            "assertion.evidence_ids",
            &self.evidence_ids,
            MAX_ARCHITECTURE_EVIDENCE_PER_ASSERTION,
        )?;
        if self.evidence_ids.is_empty() {
            return Err(ArchitectureBriefError::Empty("assertion.evidence_ids"));
        }
        validate_canonical_set(
            "assertion.related_packages",
            &self.related_packages,
            MAX_ARCHITECTURE_RELATED_PACKAGES,
        )?;
        for package in &self.related_packages {
            package.validate()?;
        }
        if self.kind == ArchitectureAssertionKind::Dependency {
            if self.related_packages.is_empty() {
                return Err(ArchitectureBriefError::Empty("assertion.related_packages"));
            }
        } else if !self.related_packages.is_empty() {
            return Err(ArchitectureBriefError::Reference("assertion.related_packages"));
        }
        Ok(())
    }

    fn compute_id(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"architecture-assertion-v1");
        hasher.field_u8(assertion_kind_tag(self.kind));
        hasher.field_str(&self.text);
        hasher.field_u16(self.evidence_ids.len().try_into().unwrap_or(u16::MAX));
        for evidence in &self.evidence_ids {
            hasher.field_digest(*evidence);
        }
        hasher.field_u16(self.related_packages.len().try_into().unwrap_or(u16::MAX));
        for package in &self.related_packages {
            hash_package(&mut hasher, package);
        }
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitecturePackageBrief {
    pub package: TestTargetPackageKey,
    #[serde(deserialize_with = "deserialize_summary")]
    pub summary: String,
    #[serde(deserialize_with = "deserialize_summary_evidence_ids")]
    pub summary_evidence_ids: Vec<Digest>,
    #[serde(deserialize_with = "deserialize_assertions")]
    pub assertions: Vec<ArchitectureAssertion>,
    #[serde(deserialize_with = "deserialize_gaps")]
    pub gaps: Vec<String>,
    pub content_digest: Digest,
}

impl ArchitecturePackageBrief {
    pub fn new(
        package: TestTargetPackageKey,
        summary: impl Into<String>,
        mut summary_evidence_ids: Vec<Digest>,
        mut assertions: Vec<ArchitectureAssertion>,
        mut gaps: Vec<String>,
    ) -> Result<Self, ArchitectureBriefError> {
        summary_evidence_ids.sort();
        assertions.sort_by_key(|assertion| assertion.id);
        gaps = gaps.into_iter().map(normalize_analysis_text).collect();
        gaps.sort();
        let mut value = Self {
            package,
            summary: normalize_analysis_text(summary.into()),
            summary_evidence_ids,
            assertions,
            gaps,
            content_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.content_digest = value.compute_digest();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ArchitectureBriefError> {
        self.validate_shape()?;
        if self.content_digest != self.compute_digest() {
            return Err(ArchitectureBriefError::Digest("package.content_digest"));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ArchitectureBriefError> {
        self.package.validate()?;
        validate_analysis_text(
            "package.summary",
            &self.summary,
            MAX_ARCHITECTURE_SUMMARY_BYTES,
            true,
        )?;
        validate_canonical_set(
            "package.summary_evidence_ids",
            &self.summary_evidence_ids,
            MAX_ARCHITECTURE_SUMMARY_EVIDENCE,
        )?;
        if self.summary.is_empty() != self.summary_evidence_ids.is_empty() {
            return Err(ArchitectureBriefError::Reference("package.summary_evidence_ids"));
        }
        validate_canonical_by_key(
            "package.assertions",
            &self.assertions,
            MAX_ARCHITECTURE_ASSERTIONS_PER_PACKAGE,
            |assertion| assertion.id,
        )?;
        for assertion in &self.assertions {
            assertion.validate()?;
        }
        validate_canonical_text_set(
            "package.gaps",
            &self.gaps,
            MAX_ARCHITECTURE_GAPS_PER_PACKAGE,
            MAX_ARCHITECTURE_GAP_BYTES,
        )?;
        if self.summary.is_empty() && self.assertions.is_empty() && self.gaps.is_empty() {
            return Err(ArchitectureBriefError::Empty("package"));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"architecture-package-brief-v1");
        hash_package(&mut hasher, &self.package);
        hasher.field_str(&self.summary);
        hasher.field_u16(self.summary_evidence_ids.len().try_into().unwrap_or(u16::MAX));
        for evidence in &self.summary_evidence_ids {
            hasher.field_digest(*evidence);
        }
        hasher.field_u16(self.assertions.len().try_into().unwrap_or(u16::MAX));
        for assertion in &self.assertions {
            hasher.field_digest(assertion.id);
        }
        hasher.field_u16(self.gaps.len().try_into().unwrap_or(u16::MAX));
        for gap in &self.gaps {
            hasher.field_str(gap);
        }
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureBrief {
    pub format_revision: u16,
    #[serde(deserialize_with = "deserialize_schema")]
    pub schema: String,
    pub analysis_authority: ArchitectureAnalysisAuthority,
    pub repository_lineage: Digest,
    #[serde(deserialize_with = "deserialize_source_selector")]
    pub source_selector: String,
    #[serde(deserialize_with = "deserialize_path")]
    pub workspace_manifest: String,
    pub scope: ArchitectureBriefScope,
    pub analysis_definition_digest: Digest,
    #[serde(deserialize_with = "deserialize_packages")]
    pub package_universe: Vec<TestTargetPackageKey>,
    #[serde(deserialize_with = "deserialize_evidence")]
    pub evidence: Vec<ArchitectureEvidence>,
    #[serde(deserialize_with = "deserialize_package_briefs")]
    pub packages: Vec<ArchitecturePackageBrief>,
    pub content_digest: Digest,
}

impl ArchitectureBrief {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository_lineage: Digest,
        source_selector: impl Into<String>,
        workspace_manifest: impl Into<String>,
        scope: ArchitectureBriefScope,
        analysis_definition_digest: Digest,
        mut package_universe: Vec<TestTargetPackageKey>,
        mut evidence: Vec<ArchitectureEvidence>,
        mut packages: Vec<ArchitecturePackageBrief>,
    ) -> Result<Self, ArchitectureBriefError> {
        package_universe.sort();
        evidence.sort_by_key(|item| item.id);
        packages.sort_by(|left, right| left.package.cmp(&right.package));
        let mut value = Self {
            format_revision: ARCHITECTURE_BRIEF_FORMAT_REVISION,
            schema: ARCHITECTURE_BRIEF_SCHEMA_ID.to_owned(),
            analysis_authority: ArchitectureAnalysisAuthority::ModelAuthored,
            repository_lineage,
            source_selector: source_selector.into(),
            workspace_manifest: workspace_manifest.into(),
            scope,
            analysis_definition_digest,
            package_universe,
            evidence,
            packages,
            content_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.content_digest = value.compute_digest();
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, ArchitectureBriefError> {
        if bytes.len() > MAX_ARCHITECTURE_BRIEF_WIRE_BYTES {
            return Err(ArchitectureBriefError::Bound {
                field: "brief.wire_bytes",
                actual: bytes.len(),
                maximum: MAX_ARCHITECTURE_BRIEF_WIRE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ArchitectureBriefError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ArchitectureBriefError> {
        self.validate_shape()?;
        if self.content_digest != self.compute_digest() {
            return Err(ArchitectureBriefError::Digest("brief.content_digest"));
        }
        Ok(())
    }

    pub fn is_canonical(&self) -> bool {
        self.validate().is_ok()
    }

    pub fn package_universe_digest(&self) -> Digest {
        package_universe_digest(&self.workspace_manifest, &self.package_universe)
    }

    fn validate_shape(&self) -> Result<(), ArchitectureBriefError> {
        if self.format_revision != ARCHITECTURE_BRIEF_FORMAT_REVISION {
            return Err(ArchitectureBriefError::FormatRevision(self.format_revision));
        }
        if self.schema != ARCHITECTURE_BRIEF_SCHEMA_ID {
            return Err(ArchitectureBriefError::Schema);
        }
        if self.analysis_authority != ArchitectureAnalysisAuthority::ModelAuthored {
            return Err(ArchitectureBriefError::Authority);
        }
        validate_plain_text(
            "brief.source_selector",
            &self.source_selector,
            MAX_ARCHITECTURE_SOURCE_SELECTOR_BYTES,
        )?;
        validate_relative_path("brief.workspace_manifest", &self.workspace_manifest)?;
        self.scope.validate()?;
        validate_canonical_set(
            "brief.package_universe",
            &self.package_universe,
            MAX_ARCHITECTURE_PACKAGES,
        )?;
        if self.package_universe.is_empty() {
            return Err(ArchitectureBriefError::Empty("brief.package_universe"));
        }
        for package in &self.package_universe {
            package.validate()?;
        }
        if self
            .scope
            .packages
            .iter()
            .any(|package| self.package_universe.binary_search(package).is_err())
        {
            return Err(ArchitectureBriefError::Reference("scope.packages"));
        }
        validate_canonical_by_key(
            "brief.evidence",
            &self.evidence,
            MAX_ARCHITECTURE_EVIDENCE,
            |evidence| evidence.id,
        )?;
        let mut evidence_ids = BTreeSet::new();
        for evidence in &self.evidence {
            evidence.validate()?;
            if evidence
                .packages
                .iter()
                .any(|package| self.package_universe.binary_search(package).is_err())
            {
                return Err(ArchitectureBriefError::Reference("evidence.packages"));
            }
            evidence_ids.insert(evidence.id);
        }
        validate_canonical_by_key(
            "brief.packages",
            &self.packages,
            MAX_ARCHITECTURE_PACKAGES,
            |package| package.package.clone(),
        )?;
        let expected_packages = if self.scope.packages.is_empty() {
            &self.package_universe
        } else {
            &self.scope.packages
        };
        let actual_packages =
            self.packages.iter().map(|package| &package.package).collect::<Vec<_>>();
        if actual_packages != expected_packages.iter().collect::<Vec<_>>() {
            return Err(ArchitectureBriefError::Reference("brief.packages"));
        }

        let mut referenced_evidence = BTreeSet::new();
        let mut total_text = 0usize;
        let mut total_references = 0usize;
        for package in &self.packages {
            package.validate()?;
            total_text = bounded_add(total_text, package.summary.len(), "brief.total_text")?;
            validate_evidence_references(
                &package.package,
                &package.summary_evidence_ids,
                None,
                &self.evidence,
                &evidence_ids,
                &mut referenced_evidence,
            )?;
            total_references = bounded_add(
                total_references,
                package.summary_evidence_ids.len(),
                "brief.total_references",
            )?;
            for assertion in &package.assertions {
                total_text = bounded_add(total_text, assertion.text.len(), "brief.total_text")?;
                total_references = bounded_add(
                    total_references,
                    assertion.evidence_ids.len() + assertion.related_packages.len(),
                    "brief.total_references",
                )?;
                if assertion.related_packages.iter().any(|related| {
                    related == &package.package
                        || self.package_universe.binary_search(related).is_err()
                }) {
                    return Err(ArchitectureBriefError::Reference("assertion.related_packages"));
                }
                validate_evidence_references(
                    &package.package,
                    &assertion.evidence_ids,
                    Some(required_evidence_role(assertion.kind)),
                    &self.evidence,
                    &evidence_ids,
                    &mut referenced_evidence,
                )?;
            }
            for gap in &package.gaps {
                total_text = bounded_add(total_text, gap.len(), "brief.total_text")?;
            }
        }
        if total_text > MAX_ARCHITECTURE_TOTAL_TEXT_BYTES {
            return Err(ArchitectureBriefError::Bound {
                field: "brief.total_text",
                actual: total_text,
                maximum: MAX_ARCHITECTURE_TOTAL_TEXT_BYTES,
            });
        }
        if total_references > MAX_ARCHITECTURE_TOTAL_REFERENCES {
            return Err(ArchitectureBriefError::Bound {
                field: "brief.total_references",
                actual: total_references,
                maximum: MAX_ARCHITECTURE_TOTAL_REFERENCES,
            });
        }
        if referenced_evidence != evidence_ids {
            return Err(ArchitectureBriefError::Reference("brief.evidence"));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"architecture-brief-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_u8(0);
        hasher.field_digest(self.repository_lineage);
        hasher.field_str(&self.source_selector);
        hasher.field_str(&self.workspace_manifest);
        hasher.field_digest(self.scope.digest());
        hasher.field_digest(self.analysis_definition_digest);
        hasher.field_digest(self.package_universe_digest());
        hasher.field_u16(self.evidence.len().try_into().unwrap_or(u16::MAX));
        for evidence in &self.evidence {
            hasher.field_digest(evidence.id);
        }
        hasher.field_u16(self.packages.len().try_into().unwrap_or(u16::MAX));
        for package in &self.packages {
            hasher.field_digest(package.content_digest);
        }
        hasher.finish()
    }
}

pub fn package_universe_digest(
    workspace_manifest: &str,
    packages: &[TestTargetPackageKey],
) -> Digest {
    let mut hasher = CanonicalHasher::new(b"architecture-package-universe-v1");
    hasher.field_str(workspace_manifest);
    hasher.field_u16(packages.len().try_into().unwrap_or(u16::MAX));
    for package in packages {
        hash_package(&mut hasher, package);
    }
    hasher.finish()
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ArchitectureBriefError {
    #[error("architecture brief format revision {0} is unsupported")]
    FormatRevision(u16),
    #[error("architecture brief schema is unsupported")]
    Schema,
    #[error("architecture brief analysis authority must remain model-authored")]
    Authority,
    #[error("{field} contains {actual} entries or bytes; the maximum is {maximum}")]
    Bound { field: &'static str, actual: usize, maximum: usize },
    #[error("{0} must be non-empty, canonical, and bounded")]
    Text(&'static str),
    #[error("{0} must be a safe repository-relative path")]
    Path(&'static str),
    #[error("architecture evidence byte range is invalid")]
    Range,
    #[error("{0} must be ordered and unique")]
    Canonical(&'static str),
    #[error("{0} must not be empty")]
    Empty(&'static str),
    #[error("{0} contains an unknown or incompatible reference")]
    Reference(&'static str),
    #[error("{0} digest is inconsistent")]
    Digest(&'static str),
    #[error("architecture brief JSON is invalid: {0}")]
    Json(String),
    #[error(transparent)]
    Package(#[from] crate::TestTargetInventoryError),
}

fn validate_evidence_references(
    package: &TestTargetPackageKey,
    references: &[Digest],
    required_role: Option<ArchitectureEvidenceRole>,
    evidence: &[ArchitectureEvidence],
    evidence_ids: &BTreeSet<Digest>,
    referenced: &mut BTreeSet<Digest>,
) -> Result<(), ArchitectureBriefError> {
    let mut found_required_role = required_role.is_none();
    for id in references {
        if !evidence_ids.contains(id) {
            return Err(ArchitectureBriefError::Reference("assertion.evidence_ids"));
        }
        let item = evidence
            .binary_search_by_key(id, |item| item.id)
            .ok()
            .map(|index| &evidence[index])
            .ok_or(ArchitectureBriefError::Reference("assertion.evidence_ids"))?;
        if !item.packages.is_empty() && item.packages.binary_search(package).is_err() {
            return Err(ArchitectureBriefError::Reference("evidence.packages"));
        }
        if required_role.is_some_and(|role| item.roles.binary_search(&role).is_ok()) {
            found_required_role = true;
        }
        referenced.insert(*id);
    }
    if !found_required_role {
        return Err(ArchitectureBriefError::Reference("assertion.evidence_role"));
    }
    Ok(())
}

fn required_evidence_role(kind: ArchitectureAssertionKind) -> ArchitectureEvidenceRole {
    match kind {
        ArchitectureAssertionKind::Responsibility | ArchitectureAssertionKind::DesignConstraint => {
            ArchitectureEvidenceRole::Supporting
        }
        ArchitectureAssertionKind::EntryPoint => ArchitectureEvidenceRole::EntryPoint,
        ArchitectureAssertionKind::PublicBoundary => ArchitectureEvidenceRole::PublicBoundary,
        ArchitectureAssertionKind::Dependency => ArchitectureEvidenceRole::DependencyDeclaration,
    }
}

fn evidence_role_tag(role: ArchitectureEvidenceRole) -> u8 {
    match role {
        ArchitectureEvidenceRole::Manifest => 0,
        ArchitectureEvidenceRole::EntryPoint => 1,
        ArchitectureEvidenceRole::PublicBoundary => 2,
        ArchitectureEvidenceRole::DependencyDeclaration => 3,
        ArchitectureEvidenceRole::Supporting => 4,
    }
}

fn assertion_kind_tag(kind: ArchitectureAssertionKind) -> u8 {
    match kind {
        ArchitectureAssertionKind::Responsibility => 0,
        ArchitectureAssertionKind::EntryPoint => 1,
        ArchitectureAssertionKind::PublicBoundary => 2,
        ArchitectureAssertionKind::Dependency => 3,
        ArchitectureAssertionKind::DesignConstraint => 4,
    }
}

fn hash_package(hasher: &mut CanonicalHasher, package: &TestTargetPackageKey) {
    hasher.field_str(&package.name);
    hasher.field_str(&package.manifest_path);
}

fn bounded_add(
    current: usize,
    added: usize,
    field: &'static str,
) -> Result<usize, ArchitectureBriefError> {
    current.checked_add(added).ok_or(ArchitectureBriefError::Bound {
        field,
        actual: usize::MAX,
        maximum: if field == "brief.total_text" {
            MAX_ARCHITECTURE_TOTAL_TEXT_BYTES
        } else {
            MAX_ARCHITECTURE_TOTAL_REFERENCES
        },
    })
}

fn normalize_analysis_text(value: String) -> String {
    value.replace("\r\n", "\n").replace('\r', "\n").trim().to_owned()
}

fn validate_plain_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), ArchitectureBriefError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(ArchitectureBriefError::Text(field));
    }
    Ok(())
}

fn validate_analysis_text(
    field: &'static str,
    value: &str,
    maximum: usize,
    allow_empty: bool,
) -> Result<(), ArchitectureBriefError> {
    if (!allow_empty && value.is_empty())
        || value.len() > maximum
        || value != value.trim()
        || value.contains('\r')
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(ArchitectureBriefError::Text(field));
    }
    Ok(())
}

fn validate_relative_path(field: &'static str, value: &str) -> Result<(), ArchitectureBriefError> {
    if value.is_empty()
        || value.len() > MAX_ARCHITECTURE_PATH_BYTES
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return Err(ArchitectureBriefError::Path(field));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_)) || component.as_os_str().to_str().is_none()
        })
    {
        return Err(ArchitectureBriefError::Path(field));
    }
    Ok(())
}

fn validate_canonical_set<T: Ord>(
    field: &'static str,
    values: &[T],
    maximum: usize,
) -> Result<(), ArchitectureBriefError> {
    if values.len() > maximum {
        return Err(ArchitectureBriefError::Bound { field, actual: values.len(), maximum });
    }
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ArchitectureBriefError::Canonical(field));
    }
    Ok(())
}

fn validate_canonical_by_key<T, K: Ord>(
    field: &'static str,
    values: &[T],
    maximum: usize,
    key: impl Fn(&T) -> K,
) -> Result<(), ArchitectureBriefError> {
    if values.len() > maximum {
        return Err(ArchitectureBriefError::Bound { field, actual: values.len(), maximum });
    }
    if !values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1])) {
        return Err(ArchitectureBriefError::Canonical(field));
    }
    Ok(())
}

fn validate_canonical_text_set(
    field: &'static str,
    values: &[String],
    maximum_items: usize,
    maximum_bytes: usize,
) -> Result<(), ArchitectureBriefError> {
    validate_canonical_set(field, values, maximum_items)?;
    for value in values {
        validate_analysis_text(field, value, maximum_bytes, false)?;
    }
    Ok(())
}

struct BoundedString<const MAX: usize>(String);

impl<'de, const MAX: usize> Deserialize<'de> for BoundedString<MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringVisitor<const MAX: usize>;
        impl<'de, const MAX: usize> Visitor<'de> for StringVisitor<MAX> {
            type Value = BoundedString<MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a string containing at most {MAX} bytes")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() > MAX {
                    return Err(E::custom("string bound exceeded"));
                }
                Ok(BoundedString(value.to_owned()))
            }

            fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(value)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() > MAX {
                    return Err(E::custom("string bound exceeded"));
                }
                Ok(BoundedString(value))
            }
        }
        deserializer.deserialize_string(StringVisitor::<MAX>)
    }
}

fn deserialize_bounded_string<'de, D, const MAX: usize>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    BoundedString::<MAX>::deserialize(deserializer).map(|value| value.0)
}

struct BoundedVecVisitor<T, const MAX: usize>(PhantomData<T>);

impl<'de, T, const MAX: usize> Visitor<'de> for BoundedVecVisitor<T, MAX>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a sequence containing at most {MAX} entries")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence.size_hint().is_some_and(|size| size > MAX) {
            return Err(A::Error::custom("collection bound exceeded"));
        }
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or_default().min(MAX));
        while let Some(value) = sequence.next_element()? {
            if values.len() == MAX {
                return Err(A::Error::custom("collection bound exceeded"));
            }
            values.push(value);
        }
        Ok(values)
    }
}

fn deserialize_bounded_vec<'de, D, T, const MAX: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(BoundedVecVisitor::<T, MAX>(PhantomData))
}

struct BoundedStringVecVisitor<const ITEMS: usize, const BYTES: usize>;

impl<'de, const ITEMS: usize, const BYTES: usize> Visitor<'de>
    for BoundedStringVecVisitor<ITEMS, BYTES>
{
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a bounded string sequence")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence.size_hint().is_some_and(|size| size > ITEMS) {
            return Err(A::Error::custom("collection bound exceeded"));
        }
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or_default().min(ITEMS));
        while let Some(value) = sequence.next_element::<BoundedString<BYTES>>()? {
            if values.len() == ITEMS {
                return Err(A::Error::custom("collection bound exceeded"));
            }
            values.push(value.0);
        }
        Ok(values)
    }
}

fn deserialize_schema<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string::<D, 64>(deserializer)
}

fn deserialize_source_selector<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string::<D, MAX_ARCHITECTURE_SOURCE_SELECTOR_BYTES>(deserializer)
}

fn deserialize_path<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string::<D, MAX_ARCHITECTURE_PATH_BYTES>(deserializer)
}

fn deserialize_summary<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string::<D, MAX_ARCHITECTURE_SUMMARY_BYTES>(deserializer)
}

fn deserialize_assertion_text<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string::<D, MAX_ARCHITECTURE_ASSERTION_BYTES>(deserializer)
}

fn deserialize_packages<'de, D>(deserializer: D) -> Result<Vec<TestTargetPackageKey>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, TestTargetPackageKey, MAX_ARCHITECTURE_PACKAGES>(deserializer)
}

fn deserialize_related_packages<'de, D>(
    deserializer: D,
) -> Result<Vec<TestTargetPackageKey>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, TestTargetPackageKey, MAX_ARCHITECTURE_RELATED_PACKAGES>(
        deserializer,
    )
}

fn deserialize_roles<'de, D>(deserializer: D) -> Result<Vec<ArchitectureEvidenceRole>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, ArchitectureEvidenceRole, MAX_ARCHITECTURE_ROLES_PER_EVIDENCE>(
        deserializer,
    )
}

fn deserialize_assertion_evidence_ids<'de, D>(deserializer: D) -> Result<Vec<Digest>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, Digest, MAX_ARCHITECTURE_EVIDENCE_PER_ASSERTION>(deserializer)
}

fn deserialize_summary_evidence_ids<'de, D>(deserializer: D) -> Result<Vec<Digest>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, Digest, MAX_ARCHITECTURE_SUMMARY_EVIDENCE>(deserializer)
}

fn deserialize_assertions<'de, D>(deserializer: D) -> Result<Vec<ArchitectureAssertion>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, ArchitectureAssertion, MAX_ARCHITECTURE_ASSERTIONS_PER_PACKAGE>(
        deserializer,
    )
}

fn deserialize_gaps<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(
        BoundedStringVecVisitor::<MAX_ARCHITECTURE_GAPS_PER_PACKAGE, MAX_ARCHITECTURE_GAP_BYTES>,
    )
}

fn deserialize_evidence<'de, D>(deserializer: D) -> Result<Vec<ArchitectureEvidence>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, ArchitectureEvidence, MAX_ARCHITECTURE_EVIDENCE>(deserializer)
}

fn deserialize_package_briefs<'de, D>(
    deserializer: D,
) -> Result<Vec<ArchitecturePackageBrief>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, ArchitecturePackageBrief, MAX_ARCHITECTURE_PACKAGES>(deserializer)
}

#[cfg(test)]
mod tests;
