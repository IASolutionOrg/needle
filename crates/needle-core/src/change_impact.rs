mod wire;

use crate::{
    ArtifactId, CanonicalHasher, Digest, PatchArtifact, PatchFile, PatchId, PatchOperation,
    Subject, SubjectId,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

pub const CHANGE_IMPACT_FORMAT_REVISION: u16 = 1;
pub const CHANGE_IMPACT_SCHEMA_ID: &str = "needle.change-impact/1";
pub const CHANGE_IMPACT_OUTPUT_CONTRACT_ID: &str = "needle.analysis.change-impact";
pub const CHANGE_IMPACT_OUTPUT_CONTRACT_REVISION: u32 = 1;
pub const MAX_CHANGE_IMPACT_WIRE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CHANGE_IMPACT_REQUIREMENTS: usize = 16;
pub const MAX_CHANGE_IMPACT_CONSTRAINTS: usize = 16;
pub const MAX_CHANGE_IMPACT_SUBJECTS: usize = 16;
pub const MAX_CHANGE_IMPACT_COMPONENTS: usize = 128;
pub const MAX_CHANGE_IMPACT_FILES: usize = 128;
pub const MAX_CHANGE_IMPACT_EVIDENCE: usize = 256;
pub const MAX_CHANGE_IMPACT_INPUTS: usize = 16;
pub const MAX_CHANGE_IMPACT_REFERENCES: usize = 64;
pub const MAX_CHANGE_IMPACT_TEST_TARGETS: usize = 128;
pub const MAX_CHANGE_IMPACT_TEXT_BYTES: usize = 4 * 1024;
pub const MAX_CHANGE_IMPACT_TOTAL_TEXT_BYTES: usize = 256 * 1024;
pub const MAX_CHANGE_IMPACT_PATH_BYTES: usize = 512;
pub const MAX_CHANGE_IMPACT_IDENTIFIER_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeImpactAnalysisAuthority {
    ModelAuthored,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeImpactDisposition {
    Affected,
    NoImpactIdentified,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeImpactKind {
    Build,
    RuntimeBehavior,
    PublicApi,
    Compatibility,
    Test,
    Documentation,
    Operational,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeImpactEvidenceState {
    Before,
    After,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeImpactEvidenceRole {
    ChangedSurface,
    DependencyDeclaration,
    Implementation,
    PublicBoundary,
    Test,
    Supporting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChangeImpactRequirementId(pub Digest);

impl ChangeImpactRequirementId {
    pub const fn digest(self) -> Digest {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpactRequirement {
    pub id: ChangeImpactRequirementId,
    #[serde(deserialize_with = "wire::deserialize_text")]
    pub text: String,
}

impl ChangeImpactRequirement {
    pub fn new(text: impl Into<String>) -> Result<Self, ChangeImpactError> {
        let text = text.into();
        validate_text("requirement.text", &text, MAX_CHANGE_IMPACT_TEXT_BYTES)?;
        let mut hasher = CanonicalHasher::new(b"change-impact-requirement-v1");
        hasher.field_normalized_lines(&text);
        Ok(Self { id: ChangeImpactRequirementId(hasher.finish()), text })
    }

    pub fn validate(&self) -> Result<(), ChangeImpactError> {
        let canonical = Self::new(self.text.clone())?;
        if self.id != canonical.id {
            return Err(ChangeImpactError::Digest("requirement.id"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpactConstraint {
    pub id: Digest,
    #[serde(deserialize_with = "wire::deserialize_text")]
    pub text: String,
}

impl ChangeImpactConstraint {
    pub fn new(text: impl Into<String>) -> Result<Self, ChangeImpactError> {
        let text = text.into();
        validate_text("constraint.text", &text, MAX_CHANGE_IMPACT_TEXT_BYTES)?;
        let mut hasher = CanonicalHasher::new(b"change-impact-constraint-v1");
        hasher.field_normalized_lines(&text);
        Ok(Self { id: hasher.finish(), text })
    }

    pub fn validate(&self) -> Result<(), ChangeImpactError> {
        let canonical = Self::new(self.text.clone())?;
        if self.id != canonical.id {
            return Err(ChangeImpactError::Digest("constraint.id"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpactFile {
    #[serde(deserialize_with = "wire::deserialize_path")]
    pub path: String,
    pub operation: PatchOperation,
    pub before_digest: Option<Digest>,
    pub after_digest: Option<Digest>,
    pub before_bytes: u64,
    pub after_bytes: u64,
}

impl ChangeImpactFile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: impl Into<String>,
        operation: PatchOperation,
        before_digest: Option<Digest>,
        after_digest: Option<Digest>,
        before_bytes: u64,
        after_bytes: u64,
    ) -> Result<Self, ChangeImpactError> {
        let value = Self {
            path: path.into(),
            operation,
            before_digest,
            after_digest,
            before_bytes,
            after_bytes,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ChangeImpactError> {
        validate_relative_path("change_file.path", &self.path)?;
        let valid = match self.operation {
            PatchOperation::Create => {
                self.before_digest.is_none()
                    && self.before_bytes == 0
                    && self.after_digest.is_some()
            }
            PatchOperation::Update => {
                self.before_digest.is_some()
                    && self.after_digest.is_some()
                    && self.before_digest != self.after_digest
            }
            PatchOperation::Delete => {
                self.before_digest.is_some() && self.after_digest.is_none() && self.after_bytes == 0
            }
        };
        if !valid {
            return Err(ChangeImpactError::ChangeFile(self.path.clone()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpactChangeSet {
    pub patch_id: PatchId,
    pub source_snapshot: Digest,
    #[serde(deserialize_with = "wire::deserialize_change_files")]
    pub files: Vec<ChangeImpactFile>,
    pub digest: Digest,
}

impl ChangeImpactChangeSet {
    pub fn new(
        patch_id: PatchId,
        source_snapshot: Digest,
        mut files: Vec<ChangeImpactFile>,
    ) -> Result<Self, ChangeImpactError> {
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let mut value = Self { patch_id, source_snapshot, files, digest: Digest([0; 32]) };
        value.validate_shape()?;
        value.digest = value.compute_digest();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ChangeImpactError> {
        self.validate_shape()?;
        if self.digest != self.compute_digest() {
            return Err(ChangeImpactError::Digest("change_set.digest"));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ChangeImpactError> {
        validate_canonical_by(
            "change_set.files",
            &self.files,
            MAX_CHANGE_IMPACT_FILES,
            |left, right| left.path < right.path,
        )?;
        for file in &self.files {
            file.validate()?;
        }
        if self.files.is_empty() {
            return Err(ChangeImpactError::Empty("change_set.files"));
        }
        let patch_files = self
            .files
            .iter()
            .map(|file| PatchFile {
                path: file.path.clone(),
                operation: file.operation,
                before_digest: file.before_digest,
                after_digest: file.after_digest,
                before_bytes: file.before_bytes,
                after_bytes: file.after_bytes,
            })
            .collect::<Vec<_>>();
        if self.patch_id != PatchArtifact::compute_id(self.source_snapshot, &patch_files) {
            return Err(ChangeImpactError::Digest("change_set.patch_id"));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"change-impact-change-set-v1");
        hasher.field_digest(self.patch_id.0);
        hasher.field_digest(self.source_snapshot);
        hasher.field_u16(self.files.len().try_into().unwrap_or(u16::MAX));
        for file in &self.files {
            hasher.field_str(&file.path);
            hasher.field_u8(patch_operation_tag(file.operation));
            hash_optional_digest(&mut hasher, file.before_digest);
            hash_optional_digest(&mut hasher, file.after_digest);
            hasher.field_bytes(&file.before_bytes.to_le_bytes());
            hasher.field_bytes(&file.after_bytes.to_le_bytes());
        }
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpactInputReference {
    #[serde(deserialize_with = "wire::deserialize_identifier")]
    pub contract_id: String,
    pub contract_revision: u32,
    pub artifact: ArtifactId,
    pub validation_certificate: Digest,
    pub definition_digest: Digest,
}

impl ChangeImpactInputReference {
    pub fn new(
        contract_id: impl Into<String>,
        contract_revision: u32,
        artifact: ArtifactId,
        validation_certificate: Digest,
        definition_digest: Digest,
    ) -> Result<Self, ChangeImpactError> {
        let value = Self {
            contract_id: contract_id.into(),
            contract_revision,
            artifact,
            validation_certificate,
            definition_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ChangeImpactError> {
        validate_identifier("input.contract_id", &self.contract_id)?;
        if self.contract_revision == 0 {
            return Err(ChangeImpactError::Input("input.contract_revision"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpactComponentKey {
    pub requirement: ChangeImpactRequirementId,
    pub subject: SubjectId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpactScope {
    #[serde(deserialize_with = "wire::deserialize_component_keys")]
    pub components: Vec<ChangeImpactComponentKey>,
}

impl ChangeImpactScope {
    pub fn all() -> Self {
        Self { components: Vec::new() }
    }

    pub fn new(mut components: Vec<ChangeImpactComponentKey>) -> Result<Self, ChangeImpactError> {
        components.sort();
        let value = Self { components };
        value.validate()?;
        Ok(value)
    }

    pub fn includes(&self, key: &ChangeImpactComponentKey) -> bool {
        self.components.is_empty() || self.components.binary_search(key).is_ok()
    }

    pub fn is_projection_of(&self, broader: &Self) -> bool {
        broader.components.is_empty()
            || (!self.components.is_empty()
                && self.components.iter().all(|key| broader.components.binary_search(key).is_ok()))
    }

    pub fn validate(&self) -> Result<(), ChangeImpactError> {
        validate_canonical_set("scope.components", &self.components, MAX_CHANGE_IMPACT_COMPONENTS)
    }

    pub fn digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"change-impact-scope-v1");
        hasher.field_u16(self.components.len().try_into().unwrap_or(u16::MAX));
        for key in &self.components {
            hash_component_key(&mut hasher, key);
        }
        hasher.finish()
    }
}

impl Default for ChangeImpactScope {
    fn default() -> Self {
        Self::all()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpactEvidence {
    pub id: Digest,
    #[serde(deserialize_with = "wire::deserialize_path")]
    pub path: String,
    pub state: ChangeImpactEvidenceState,
    pub content_digest: Digest,
    pub byte_start: Option<u64>,
    pub byte_end: Option<u64>,
    #[serde(deserialize_with = "wire::deserialize_evidence_roles")]
    pub roles: Vec<ChangeImpactEvidenceRole>,
    #[serde(deserialize_with = "wire::deserialize_subject_ids")]
    pub subjects: Vec<SubjectId>,
}

impl ChangeImpactEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: impl Into<String>,
        state: ChangeImpactEvidenceState,
        content_digest: Digest,
        byte_start: Option<u64>,
        byte_end: Option<u64>,
        mut roles: Vec<ChangeImpactEvidenceRole>,
        mut subjects: Vec<SubjectId>,
    ) -> Result<Self, ChangeImpactError> {
        roles.sort();
        subjects.sort();
        let mut value = Self {
            id: Digest([0; 32]),
            path: path.into(),
            state,
            content_digest,
            byte_start,
            byte_end,
            roles,
            subjects,
        };
        value.validate_shape()?;
        value.id = value.compute_id();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ChangeImpactError> {
        self.validate_shape()?;
        if self.id != self.compute_id() {
            return Err(ChangeImpactError::Digest("evidence.id"));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ChangeImpactError> {
        validate_relative_path("evidence.path", &self.path)?;
        if self.roles.is_empty() {
            return Err(ChangeImpactError::Empty("evidence.roles"));
        }
        validate_canonical_set("evidence.roles", &self.roles, 8)?;
        validate_canonical_set("evidence.subjects", &self.subjects, MAX_CHANGE_IMPACT_SUBJECTS)?;
        match (self.byte_start, self.byte_end) {
            (None, None) => {}
            (Some(start), Some(end)) if start < end => {}
            _ => return Err(ChangeImpactError::Range("evidence")),
        }
        Ok(())
    }

    fn compute_id(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"change-impact-evidence-v1");
        hasher.field_str(&self.path);
        hasher.field_u8(match self.state {
            ChangeImpactEvidenceState::Before => 0,
            ChangeImpactEvidenceState::After => 1,
        });
        hasher.field_digest(self.content_digest);
        hash_optional_u64(&mut hasher, self.byte_start);
        hash_optional_u64(&mut hasher, self.byte_end);
        for role in &self.roles {
            hasher.field_u8(evidence_role_tag(*role));
        }
        for subject in &self.subjects {
            hasher.field_digest(subject.digest());
        }
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpactAssessment {
    pub key: ChangeImpactComponentKey,
    pub authority: ChangeImpactAnalysisAuthority,
    pub disposition: ChangeImpactDisposition,
    #[serde(deserialize_with = "wire::deserialize_impact_kinds")]
    pub impact_kinds: Vec<ChangeImpactKind>,
    #[serde(deserialize_with = "wire::deserialize_text")]
    pub rationale: String,
    #[serde(deserialize_with = "wire::deserialize_digests")]
    pub evidence_ids: Vec<Digest>,
    #[serde(deserialize_with = "wire::deserialize_artifact_ids")]
    pub input_artifact_ids: Vec<ArtifactId>,
    #[serde(deserialize_with = "wire::deserialize_paths")]
    pub affected_paths: Vec<String>,
    #[serde(deserialize_with = "wire::deserialize_test_target_ids")]
    pub test_target_ids: Vec<Digest>,
    pub content_digest: Digest,
}

impl ChangeImpactAssessment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: ChangeImpactComponentKey,
        disposition: ChangeImpactDisposition,
        mut impact_kinds: Vec<ChangeImpactKind>,
        rationale: impl Into<String>,
        mut evidence_ids: Vec<Digest>,
        mut input_artifact_ids: Vec<ArtifactId>,
        mut affected_paths: Vec<String>,
        mut test_target_ids: Vec<Digest>,
    ) -> Result<Self, ChangeImpactError> {
        impact_kinds.sort();
        evidence_ids.sort();
        input_artifact_ids.sort();
        affected_paths.sort();
        test_target_ids.sort();
        let mut value = Self {
            key,
            authority: ChangeImpactAnalysisAuthority::ModelAuthored,
            disposition,
            impact_kinds,
            rationale: rationale.into(),
            evidence_ids,
            input_artifact_ids,
            affected_paths,
            test_target_ids,
            content_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.content_digest = value.compute_digest();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ChangeImpactError> {
        self.validate_shape()?;
        if self.content_digest != self.compute_digest() {
            return Err(ChangeImpactError::Digest("assessment.content_digest"));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ChangeImpactError> {
        if self.authority != ChangeImpactAnalysisAuthority::ModelAuthored {
            return Err(ChangeImpactError::Authority);
        }
        validate_text("assessment.rationale", &self.rationale, MAX_CHANGE_IMPACT_TEXT_BYTES)?;
        validate_canonical_set("assessment.impact_kinds", &self.impact_kinds, 8)?;
        validate_canonical_set(
            "assessment.evidence_ids",
            &self.evidence_ids,
            MAX_CHANGE_IMPACT_REFERENCES,
        )?;
        validate_canonical_set(
            "assessment.input_artifact_ids",
            &self.input_artifact_ids,
            MAX_CHANGE_IMPACT_INPUTS,
        )?;
        validate_canonical_set(
            "assessment.affected_paths",
            &self.affected_paths,
            MAX_CHANGE_IMPACT_REFERENCES,
        )?;
        for path in &self.affected_paths {
            validate_relative_path("assessment.affected_paths", path)?;
        }
        validate_canonical_set(
            "assessment.test_target_ids",
            &self.test_target_ids,
            MAX_CHANGE_IMPACT_TEST_TARGETS,
        )?;
        if self.disposition == ChangeImpactDisposition::Affected && self.impact_kinds.is_empty() {
            return Err(ChangeImpactError::Empty("affected assessment impact kinds"));
        }
        if self.disposition != ChangeImpactDisposition::Unknown
            && self.evidence_ids.is_empty()
            && self.input_artifact_ids.is_empty()
        {
            return Err(ChangeImpactError::Empty("conclusive assessment support"));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"change-impact-assessment-v1");
        hash_component_key(&mut hasher, &self.key);
        hasher.field_u8(disposition_tag(self.disposition));
        for kind in &self.impact_kinds {
            hasher.field_u8(impact_kind_tag(*kind));
        }
        hasher.field_normalized_lines(&self.rationale);
        for id in &self.evidence_ids {
            hasher.field_digest(*id);
        }
        for id in &self.input_artifact_ids {
            hasher.field_digest(id.digest());
        }
        for path in &self.affected_paths {
            hasher.field_str(path);
        }
        for id in &self.test_target_ids {
            hasher.field_digest(*id);
        }
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeImpact {
    pub format_revision: u16,
    #[serde(deserialize_with = "wire::deserialize_schema")]
    pub schema: String,
    pub repository_lineage: Digest,
    #[serde(deserialize_with = "wire::deserialize_identifier")]
    pub source_selector: String,
    pub change_set: ChangeImpactChangeSet,
    pub scope: ChangeImpactScope,
    pub analysis_definition_digest: Digest,
    #[serde(deserialize_with = "wire::deserialize_requirements")]
    pub requirement_universe: Vec<ChangeImpactRequirement>,
    #[serde(deserialize_with = "wire::deserialize_constraints")]
    pub constraints: Vec<ChangeImpactConstraint>,
    #[serde(deserialize_with = "wire::deserialize_subjects")]
    pub subject_universe: Vec<Subject>,
    #[serde(deserialize_with = "wire::deserialize_input_references")]
    pub accepted_inputs: Vec<ChangeImpactInputReference>,
    pub test_inventory_digest: Option<Digest>,
    pub test_inventory_validation_certificate: Option<Digest>,
    #[serde(deserialize_with = "wire::deserialize_evidence")]
    pub evidence: Vec<ChangeImpactEvidence>,
    #[serde(deserialize_with = "wire::deserialize_assessments")]
    pub assessments: Vec<ChangeImpactAssessment>,
    #[serde(deserialize_with = "wire::deserialize_gaps")]
    pub gaps: Vec<String>,
    pub content_digest: Digest,
}

impl ChangeImpact {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository_lineage: Digest,
        source_selector: impl Into<String>,
        change_set: ChangeImpactChangeSet,
        scope: ChangeImpactScope,
        analysis_definition_digest: Digest,
        mut requirement_universe: Vec<ChangeImpactRequirement>,
        mut constraints: Vec<ChangeImpactConstraint>,
        mut subject_universe: Vec<Subject>,
        mut accepted_inputs: Vec<ChangeImpactInputReference>,
        test_inventory_digest: Option<Digest>,
        test_inventory_validation_certificate: Option<Digest>,
        mut evidence: Vec<ChangeImpactEvidence>,
        mut assessments: Vec<ChangeImpactAssessment>,
        mut gaps: Vec<String>,
    ) -> Result<Self, ChangeImpactError> {
        requirement_universe.sort_by_key(|value| value.id);
        constraints.sort_by_key(|value| value.id);
        subject_universe.sort_by_key(|value| value.id);
        accepted_inputs.sort();
        evidence.sort_by_key(|value| value.id);
        assessments.sort_by_key(|value| value.key);
        gaps.sort();
        let mut value = Self {
            format_revision: CHANGE_IMPACT_FORMAT_REVISION,
            schema: CHANGE_IMPACT_SCHEMA_ID.to_owned(),
            repository_lineage,
            source_selector: source_selector.into(),
            change_set,
            scope,
            analysis_definition_digest,
            requirement_universe,
            constraints,
            subject_universe,
            accepted_inputs,
            test_inventory_digest,
            test_inventory_validation_certificate,
            evidence,
            assessments,
            gaps,
            content_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.content_digest = value.compute_digest();
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, ChangeImpactError> {
        if bytes.len() > MAX_CHANGE_IMPACT_WIRE_BYTES {
            return Err(ChangeImpactError::Bound {
                field: "change_impact.wire_bytes",
                actual: bytes.len(),
                maximum: MAX_CHANGE_IMPACT_WIRE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ChangeImpactError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ChangeImpactError> {
        self.validate_shape()?;
        if self.content_digest != self.compute_digest() {
            return Err(ChangeImpactError::Digest("change_impact.content_digest"));
        }
        Ok(())
    }

    pub fn component_universe(&self) -> Vec<ChangeImpactComponentKey> {
        component_universe(&self.requirement_universe, &self.subject_universe)
    }

    fn validate_shape(&self) -> Result<(), ChangeImpactError> {
        if self.format_revision != CHANGE_IMPACT_FORMAT_REVISION {
            return Err(ChangeImpactError::FormatRevision(self.format_revision));
        }
        if self.schema != CHANGE_IMPACT_SCHEMA_ID {
            return Err(ChangeImpactError::Schema);
        }
        validate_identifier("change_impact.source_selector", &self.source_selector)?;
        self.change_set.validate()?;
        self.scope.validate()?;
        validate_canonical_by(
            "change_impact.requirement_universe",
            &self.requirement_universe,
            MAX_CHANGE_IMPACT_REQUIREMENTS,
            |left, right| left.id < right.id,
        )?;
        validate_canonical_by(
            "change_impact.constraints",
            &self.constraints,
            MAX_CHANGE_IMPACT_CONSTRAINTS,
            |left, right| left.id < right.id,
        )?;
        validate_canonical_by(
            "change_impact.subject_universe",
            &self.subject_universe,
            MAX_CHANGE_IMPACT_SUBJECTS,
            |left, right| left.id < right.id,
        )?;
        if self.requirement_universe.is_empty() || self.subject_universe.is_empty() {
            return Err(ChangeImpactError::Empty("requirement or subject universe"));
        }
        for requirement in &self.requirement_universe {
            requirement.validate()?;
        }
        for constraint in &self.constraints {
            constraint.validate()?;
        }
        for subject in &self.subject_universe {
            validate_subject(subject, self.repository_lineage)?;
        }
        validate_canonical_set(
            "change_impact.accepted_inputs",
            &self.accepted_inputs,
            MAX_CHANGE_IMPACT_INPUTS,
        )?;
        for input in &self.accepted_inputs {
            input.validate()?;
        }
        let mut input_artifacts = BTreeSet::new();
        if self.accepted_inputs.iter().any(|input| !input_artifacts.insert(input.artifact)) {
            return Err(ChangeImpactError::Canonical("change_impact.accepted_inputs.artifact"));
        }
        if self.test_inventory_digest.is_some()
            != self.test_inventory_validation_certificate.is_some()
        {
            return Err(ChangeImpactError::Input("test inventory binding"));
        }
        validate_canonical_by(
            "change_impact.evidence",
            &self.evidence,
            MAX_CHANGE_IMPACT_EVIDENCE,
            |left, right| left.id < right.id,
        )?;
        for item in &self.evidence {
            item.validate()?;
        }
        validate_canonical_by(
            "change_impact.assessments",
            &self.assessments,
            MAX_CHANGE_IMPACT_COMPONENTS,
            |left, right| left.key < right.key,
        )?;
        validate_canonical_set("change_impact.gaps", &self.gaps, MAX_CHANGE_IMPACT_REFERENCES)?;
        for gap in &self.gaps {
            validate_text("change_impact.gaps", gap, MAX_CHANGE_IMPACT_TEXT_BYTES)?;
        }
        validate_total_text(self)?;
        self.validate_references()
    }

    fn validate_references(&self) -> Result<(), ChangeImpactError> {
        let universe = self.component_universe();
        if universe.len() > MAX_CHANGE_IMPACT_COMPONENTS {
            return Err(ChangeImpactError::Bound {
                field: "component_universe",
                actual: universe.len(),
                maximum: MAX_CHANGE_IMPACT_COMPONENTS,
            });
        }
        if self.scope.components.iter().any(|key| universe.binary_search(key).is_err()) {
            return Err(ChangeImpactError::Reference("scope.components"));
        }
        let expected =
            if self.scope.components.is_empty() { &universe } else { &self.scope.components };
        if self.assessments.iter().map(|value| value.key).collect::<Vec<_>>() != *expected {
            return Err(ChangeImpactError::Coverage);
        }
        let evidence = self.evidence.iter().map(|value| value.id).collect::<BTreeSet<_>>();
        let inputs =
            self.accepted_inputs.iter().map(|value| value.artifact).collect::<BTreeSet<_>>();
        let subjects = self.subject_universe.iter().map(|value| value.id).collect::<BTreeSet<_>>();
        let evidence_by_path =
            self.evidence.iter().map(|value| value.path.as_str()).collect::<BTreeSet<_>>();
        for item in &self.evidence {
            if item.subjects.iter().any(|subject| !subjects.contains(subject)) {
                return Err(ChangeImpactError::Reference("evidence.subjects"));
            }
        }
        for assessment in &self.assessments {
            assessment.validate()?;
            if !self.scope.includes(&assessment.key)
                || assessment.evidence_ids.iter().any(|id| !evidence.contains(id))
                || assessment.input_artifact_ids.iter().any(|id| !inputs.contains(id))
                || assessment
                    .affected_paths
                    .iter()
                    .any(|path| !evidence_by_path.contains(path.as_str()))
            {
                return Err(ChangeImpactError::Reference("assessment"));
            }
            if !assessment.test_target_ids.is_empty()
                && (self.test_inventory_digest.is_none()
                    || self.test_inventory_validation_certificate.is_none())
            {
                return Err(ChangeImpactError::Reference("assessment.test_target_ids"));
            }
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"change-impact-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_digest(self.repository_lineage);
        hasher.field_str(&self.source_selector);
        hasher.field_digest(self.change_set.digest);
        hasher.field_digest(self.scope.digest());
        hasher.field_digest(self.analysis_definition_digest);
        for value in &self.requirement_universe {
            hasher.field_digest(value.id.digest());
        }
        for value in &self.constraints {
            hasher.field_digest(value.id);
        }
        for value in &self.subject_universe {
            hasher.field_digest(value.id.digest());
        }
        for value in &self.accepted_inputs {
            hasher.field_str(&value.contract_id);
            hasher.field_u32(value.contract_revision);
            hasher.field_digest(value.artifact.digest());
            hasher.field_digest(value.validation_certificate);
            hasher.field_digest(value.definition_digest);
        }
        hash_optional_digest(&mut hasher, self.test_inventory_digest);
        hash_optional_digest(&mut hasher, self.test_inventory_validation_certificate);
        for value in &self.evidence {
            hasher.field_digest(value.id);
        }
        for value in &self.assessments {
            hasher.field_digest(value.content_digest);
        }
        for gap in &self.gaps {
            hasher.field_normalized_lines(gap);
        }
        hasher.finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ChangeImpactError {
    #[error("change impact format revision {0} is unsupported")]
    FormatRevision(u16),
    #[error("change impact schema is unsupported")]
    Schema,
    #[error("{field} contains {actual} entries or bytes; the maximum is {maximum}")]
    Bound { field: &'static str, actual: usize, maximum: usize },
    #[error("{0} must be non-empty and bounded")]
    Text(&'static str),
    #[error("{0} must be a safe repository-relative path")]
    Path(&'static str),
    #[error("{0} must be ordered and unique")]
    Canonical(&'static str),
    #[error("{0} must not be empty")]
    Empty(&'static str),
    #[error("{0} contains an unknown reference")]
    Reference(&'static str),
    #[error("{0} digest is inconsistent")]
    Digest(&'static str),
    #[error("{0} range is invalid")]
    Range(&'static str),
    #[error("change file `{0}` has an invalid operation/digest shape")]
    ChangeFile(String),
    #[error("change impact assessment authority must remain model_authored")]
    Authority,
    #[error("change impact assessments do not exactly cover the requested component scope")]
    Coverage,
    #[error("{0} is invalid")]
    Input(&'static str),
    #[error("change impact JSON is invalid: {0}")]
    Json(String),
}

fn component_universe(
    requirements: &[ChangeImpactRequirement],
    subjects: &[Subject],
) -> Vec<ChangeImpactComponentKey> {
    let mut values = Vec::with_capacity(requirements.len().saturating_mul(subjects.len()));
    for requirement in requirements {
        for subject in subjects {
            values.push(ChangeImpactComponentKey {
                requirement: requirement.id,
                subject: subject.id,
            });
        }
    }
    values.sort();
    values
}

fn validate_subject(
    subject: &Subject,
    repository_lineage: Digest,
) -> Result<(), ChangeImpactError> {
    validate_text(
        "subject.canonical_name",
        &subject.canonical_name,
        MAX_CHANGE_IMPACT_IDENTIFIER_BYTES,
    )?;
    if !subject.is_canonical() || subject.repository_lineage != repository_lineage {
        return Err(ChangeImpactError::Input("subject"));
    }
    Ok(())
}

fn validate_total_text(value: &ChangeImpact) -> Result<(), ChangeImpactError> {
    let total = value
        .requirement_universe
        .iter()
        .map(|item| item.text.len())
        .chain(value.constraints.iter().map(|item| item.text.len()))
        .chain(value.assessments.iter().map(|item| item.rationale.len()))
        .chain(value.gaps.iter().map(String::len))
        .try_fold(0usize, |total, length| total.checked_add(length))
        .unwrap_or(usize::MAX);
    if total > MAX_CHANGE_IMPACT_TOTAL_TEXT_BYTES {
        return Err(ChangeImpactError::Bound {
            field: "change_impact.total_text_bytes",
            actual: total,
            maximum: MAX_CHANGE_IMPACT_TOTAL_TEXT_BYTES,
        });
    }
    Ok(())
}

fn validate_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), ChangeImpactError> {
    if value.trim().is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(ChangeImpactError::Text(field));
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ChangeImpactError> {
    if value.is_empty()
        || value.len() > MAX_CHANGE_IMPACT_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ChangeImpactError::Text(field));
    }
    Ok(())
}

fn validate_relative_path(field: &'static str, value: &str) -> Result<(), ChangeImpactError> {
    use std::path::{Component, Path};
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > MAX_CHANGE_IMPACT_PATH_BYTES
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || path.is_absolute()
        || path.components().any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ChangeImpactError::Path(field));
    }
    Ok(())
}

fn validate_canonical_set<T: Ord>(
    field: &'static str,
    values: &[T],
    maximum: usize,
) -> Result<(), ChangeImpactError> {
    validate_canonical_by(field, values, maximum, |left, right| left < right)
}

fn validate_canonical_by<T>(
    field: &'static str,
    values: &[T],
    maximum: usize,
    ordered: impl Fn(&T, &T) -> bool,
) -> Result<(), ChangeImpactError> {
    if values.len() > maximum {
        return Err(ChangeImpactError::Bound { field, actual: values.len(), maximum });
    }
    if !values.windows(2).all(|pair| ordered(&pair[0], &pair[1])) {
        return Err(ChangeImpactError::Canonical(field));
    }
    Ok(())
}

fn hash_component_key(hasher: &mut CanonicalHasher, key: &ChangeImpactComponentKey) {
    hasher.field_digest(key.requirement.digest());
    hasher.field_digest(key.subject.digest());
}

fn hash_optional_digest(hasher: &mut CanonicalHasher, value: Option<Digest>) {
    hasher.field_u8(u8::from(value.is_some()));
    if let Some(value) = value {
        hasher.field_digest(value);
    }
}

fn hash_optional_u64(hasher: &mut CanonicalHasher, value: Option<u64>) {
    hasher.field_u8(u8::from(value.is_some()));
    if let Some(value) = value {
        hasher.field_bytes(&value.to_le_bytes());
    }
}

fn patch_operation_tag(value: PatchOperation) -> u8 {
    match value {
        PatchOperation::Create => 0,
        PatchOperation::Update => 1,
        PatchOperation::Delete => 2,
    }
}

fn evidence_role_tag(value: ChangeImpactEvidenceRole) -> u8 {
    match value {
        ChangeImpactEvidenceRole::ChangedSurface => 0,
        ChangeImpactEvidenceRole::DependencyDeclaration => 1,
        ChangeImpactEvidenceRole::Implementation => 2,
        ChangeImpactEvidenceRole::PublicBoundary => 3,
        ChangeImpactEvidenceRole::Test => 4,
        ChangeImpactEvidenceRole::Supporting => 5,
    }
}

fn disposition_tag(value: ChangeImpactDisposition) -> u8 {
    match value {
        ChangeImpactDisposition::Affected => 0,
        ChangeImpactDisposition::NoImpactIdentified => 1,
        ChangeImpactDisposition::Unknown => 2,
    }
}

fn impact_kind_tag(value: ChangeImpactKind) -> u8 {
    match value {
        ChangeImpactKind::Build => 0,
        ChangeImpactKind::RuntimeBehavior => 1,
        ChangeImpactKind::PublicApi => 2,
        ChangeImpactKind::Compatibility => 3,
        ChangeImpactKind::Test => 4,
        ChangeImpactKind::Documentation => 5,
        ChangeImpactKind::Operational => 6,
    }
}

#[cfg(test)]
mod tests;
