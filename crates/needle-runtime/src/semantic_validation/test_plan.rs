use super::{
    SemanticValidationError, contains_bytes, is_safe_relative_path, read_evidence_from_root,
};
use needle_core::{Digest, SemanticWorkerArtifact, TestCommand};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

struct TestPlanProposal<'a> {
    identifier: &'a str,
    evidence_paths: &'a [String],
}

pub(super) struct TestPlanProofFile {
    pub(super) path: String,
    bytes: Vec<u8>,
    pub(super) content_digest: Digest,
}

pub(super) struct TestPlanProof {
    pub(super) files: Vec<TestPlanProofFile>,
    pub(super) identifier_names_subject: bool,
    pub(super) subject_observed: bool,
    pub(super) identifier_observed: bool,
}

fn validate_test_plan_proposal(
    worker_artifact: &SemanticWorkerArtifact,
) -> Result<Option<TestPlanProposal<'_>>, SemanticValidationError> {
    let SemanticWorkerArtifact::TestPlan {
        runner,
        argv,
        cwd_relative,
        identifiers,
        selection,
        evidence_paths,
    } = worker_artifact
    else {
        return Ok(None);
    };
    let valid_paths = !evidence_paths.is_empty()
        && evidence_paths.len() <= 8
        && evidence_paths
            .iter()
            .all(|value| !value.is_empty() && value.len() <= 512 && is_safe_relative_path(value));
    let identifier = identifiers.first().map_or("", String::as_str);
    let command_violations =
        TestCommand::from_canonical_parts(runner, argv, identifier).err().unwrap_or_default();
    let mut rejection_reasons =
        command_violations.iter().map(|violation| violation.code()).collect::<Vec<_>>();
    if identifiers.len() != 1 {
        rejection_reasons.push("identifier_count_not_one");
    }
    if !valid_paths {
        rejection_reasons.push("bounds_or_paths");
    }
    if selection != "representative" {
        rejection_reasons.push("selection_not_representative");
    }
    if !is_safe_relative_path(cwd_relative) {
        rejection_reasons.push("cwd_not_safe_relative");
    }
    rejection_reasons.sort_unstable();
    rejection_reasons.dedup();
    if !rejection_reasons.is_empty() {
        return Err(SemanticValidationError::Evidence(format!(
            "worker-discovered test plan rejected: {}",
            rejection_reasons.join(",")
        )));
    }
    Ok(Some(TestPlanProposal { identifier, evidence_paths }))
}

pub(super) fn validate_test_plan_proof(
    worker_artifact: &SemanticWorkerArtifact,
    repository_root: &Path,
    subject: &needle_core::Subject,
) -> Result<Option<TestPlanProof>, SemanticValidationError> {
    let Some(proposal) = validate_test_plan_proposal(worker_artifact)? else {
        return Ok(None);
    };
    let root = fs::canonicalize(repository_root).map_err(|error| {
        SemanticValidationError::Evidence(format!("cannot resolve repository: {error}"))
    })?;
    let mut files = Vec::with_capacity(proposal.evidence_paths.len());
    for path in proposal.evidence_paths.iter().cloned().collect::<BTreeSet<_>>() {
        let bytes = read_evidence_from_root(&root, &path)?;
        files.push(TestPlanProofFile { path, content_digest: Digest::blake3(&bytes), bytes });
    }

    let canonical_subject = subject.canonical_name.trim_start_matches("--");
    let identifier_names_subject = proposal.identifier == subject.canonical_name
        || (!canonical_subject.is_empty() && proposal.identifier.contains(canonical_subject));
    let identifier_leaf =
        proposal.identifier.rsplit("::").next().unwrap_or(proposal.identifier).as_bytes();
    let subject_observed =
        files.iter().any(|file| contains_bytes(&file.bytes, subject.canonical_name.as_bytes()));
    let identifier_observed = files.iter().any(|file| contains_bytes(&file.bytes, identifier_leaf));
    if !identifier_observed {
        return Err(SemanticValidationError::Evidence(
            "worker-discovered test identifier is absent from declared evidence".to_owned(),
        ));
    }
    if !identifier_names_subject && !subject_observed {
        return Err(SemanticValidationError::Evidence(
            "worker-discovered test does not match the requested subject".to_owned(),
        ));
    }
    files.sort_unstable_by(|left, right| left.path.cmp(&right.path));

    Ok(Some(TestPlanProof {
        files,
        identifier_names_subject,
        subject_observed,
        identifier_observed,
    }))
}
