use super::{
    ChangeImpactRuntimeError, MAX_CHANGE_IMPACT_BLOB_FILE_BYTES, MAX_CHANGE_IMPACT_BLOB_TOTAL_BYTES,
};
use crate::store::PatchFileBlob;
use needle_core::{
    ChangeImpactChangeSet, ChangeImpactFile, Digest, MAX_CHANGE_IMPACT_FILES, PatchArtifact,
    PatchOperation,
};
use std::collections::BTreeMap;

pub fn derive_change_impact_change_set(
    patch: &PatchArtifact,
    blobs: &[PatchFileBlob],
) -> Result<ChangeImpactChangeSet, ChangeImpactRuntimeError> {
    if patch.files.is_empty()
        || patch.files.len() > MAX_CHANGE_IMPACT_FILES
        || patch.files.len() != blobs.len()
    {
        return Err(ChangeImpactRuntimeError::Patch(
            "file and blob cardinality is invalid".to_owned(),
        ));
    }
    for file in &patch.files {
        if file.path.len() > needle_core::MAX_CHANGE_IMPACT_PATH_BYTES {
            return Err(ChangeImpactRuntimeError::Patch(
                "file path exceeds the bounded maximum".to_owned(),
            ));
        }
    }
    if patch.id != PatchArtifact::compute_id(patch.source_snapshot, &patch.files) {
        return Err(ChangeImpactRuntimeError::Patch(
            "patch id does not match its filesystem manifest".to_owned(),
        ));
    }

    let blob_map = bound_blob_map(patch, blobs)?;
    let mut files = Vec::with_capacity(patch.files.len());
    for file in &patch.files {
        let blob = blob_map.get(file.path.as_str()).ok_or_else(|| {
            ChangeImpactRuntimeError::Patch(format!("blob is missing for `{}`", file.path))
        })?;
        let before_digest = blob.before.as_deref().map(Digest::blake3);
        let after_digest = blob.after.as_deref().map(Digest::blake3);
        let before_bytes = blob.before.as_ref().map_or(0, Vec::len) as u64;
        let after_bytes = blob.after.as_ref().map_or(0, Vec::len) as u64;
        if before_digest != file.before_digest
            || after_digest != file.after_digest
            || before_bytes != file.before_bytes
            || after_bytes != file.after_bytes
            || !blob_shape_matches(file.operation, blob)
        {
            return Err(ChangeImpactRuntimeError::Patch(format!(
                "blob does not match `{}`",
                file.path
            )));
        }
        files.push(ChangeImpactFile::new(
            file.path.clone(),
            file.operation,
            before_digest,
            after_digest,
            before_bytes,
            after_bytes,
        )?);
    }
    ChangeImpactChangeSet::new(patch.id, patch.source_snapshot, files).map_err(Into::into)
}

pub(super) fn bound_blob_map<'a>(
    patch: &'a PatchArtifact,
    blobs: &'a [PatchFileBlob],
) -> Result<BTreeMap<&'a str, &'a PatchFileBlob>, ChangeImpactRuntimeError> {
    if blobs.len() != patch.files.len() || blobs.len() > MAX_CHANGE_IMPACT_FILES {
        return Err(ChangeImpactRuntimeError::Patch(
            "blob cardinality does not match the patch".to_owned(),
        ));
    }
    let mut total = 0usize;
    let mut values = BTreeMap::new();
    for blob in blobs {
        if blob.path.len() > needle_core::MAX_CHANGE_IMPACT_PATH_BYTES {
            return Err(ChangeImpactRuntimeError::Patch(
                "blob path exceeds the bounded maximum".to_owned(),
            ));
        }
        for bytes in [&blob.before, &blob.after].into_iter().flatten() {
            if bytes.len() > MAX_CHANGE_IMPACT_BLOB_FILE_BYTES {
                return Err(ChangeImpactRuntimeError::BlobFileBound {
                    path: blob.path.clone(),
                    actual: bytes.len(),
                    maximum: MAX_CHANGE_IMPACT_BLOB_FILE_BYTES,
                });
            }
            total =
                total.checked_add(bytes.len()).ok_or(ChangeImpactRuntimeError::BlobTotalBound {
                    actual: usize::MAX,
                    maximum: MAX_CHANGE_IMPACT_BLOB_TOTAL_BYTES,
                })?;
            if total > MAX_CHANGE_IMPACT_BLOB_TOTAL_BYTES {
                return Err(ChangeImpactRuntimeError::BlobTotalBound {
                    actual: total,
                    maximum: MAX_CHANGE_IMPACT_BLOB_TOTAL_BYTES,
                });
            }
        }
        if values.insert(blob.path.as_str(), blob).is_some() {
            return Err(ChangeImpactRuntimeError::Patch("blob paths must be unique".to_owned()));
        }
    }
    Ok(values)
}

fn blob_shape_matches(operation: PatchOperation, blob: &PatchFileBlob) -> bool {
    match operation {
        PatchOperation::Create => blob.before.is_none() && blob.after.is_some(),
        PatchOperation::Update => blob.before.is_some() && blob.after.is_some(),
        PatchOperation::Delete => blob.before.is_some() && blob.after.is_none(),
    }
}
