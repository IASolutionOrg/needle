use crate::{
    ActionContractId, ArtifactId, ArtifactRequestId, ArtifactValidationCertificateId,
    CanonicalHasher, CapabilityMode, Digest, FailedRefreshMemoId, ManifestTransitionId,
    PartitionKeyMapping, PartitionManifestId, PartitionRef, RefreshAttemptId,
};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use thiserror::Error;

pub const REFRESH_ATTEMPT_FORMAT_REVISION: u16 = 1;
pub const FAILED_REFRESH_MEMO_FORMAT_REVISION: u16 = 1;
pub const MAX_REFRESH_ATTEMPT_PARTITIONS: usize = 4_096;
pub const MAX_REFRESH_EXECUTION_ATTEMPTS: usize = 16;
pub const MAX_REFRESH_ATTEMPT_WIRE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_FAILED_REFRESH_MEMO_WIRE_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshFailureClass {
    Acquisition,
    Operator,
    Reconstruction,
    Validation,
    Timeout,
    BudgetExceeded,
    RuntimeUnavailable,
    Storage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RefreshOutcome {
    Succeeded {
        reconstructed_artifact: ArtifactId,
        validation_certificate: ArtifactValidationCertificateId,
    },
    Failed {
        failure_class: RefreshFailureClass,
        failure_evidence_digest: Digest,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshAttemptInput {
    pub request: ArtifactRequestId,
    pub action_contract: ActionContractId,
    pub prior_artifact: ArtifactId,
    pub state_delta: Digest,
    pub prior_manifest: PartitionManifestId,
    pub current_manifest: PartitionManifestId,
    pub manifest_transition: ManifestTransitionId,
    pub retained_partitions: Vec<PartitionKeyMapping>,
    pub refreshed_partitions: Vec<PartitionRef>,
    pub added_partitions: Vec<PartitionRef>,
    pub removed_partitions: Vec<PartitionRef>,
    pub refresh_policy_definition_digest: Digest,
    pub operator_definition_digest: Digest,
    pub execution_scope_digest: Digest,
    pub execution_attempts: Vec<Digest>,
    pub started_unix_ms: u64,
    pub completed_unix_ms: u64,
    pub cost_microusd: Option<u64>,
    pub outcome: RefreshOutcome,
}

/// Immutable, content-addressed audit record for one selected refresh.
///
/// Revision 1 is fixed to Shadow. Persisting this record cannot make the prior
/// artifact valid and does not authorize a resolver decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshAttempt {
    pub format_revision: u16,
    pub id: RefreshAttemptId,
    pub request: ArtifactRequestId,
    pub action_contract: ActionContractId,
    pub prior_artifact: ArtifactId,
    pub state_delta: Digest,
    pub prior_manifest: PartitionManifestId,
    pub current_manifest: PartitionManifestId,
    pub manifest_transition: ManifestTransitionId,
    #[serde(deserialize_with = "deserialize_mappings")]
    pub retained_partitions: Vec<PartitionKeyMapping>,
    #[serde(deserialize_with = "deserialize_partition_refs")]
    pub refreshed_partitions: Vec<PartitionRef>,
    #[serde(deserialize_with = "deserialize_partition_refs")]
    pub added_partitions: Vec<PartitionRef>,
    #[serde(deserialize_with = "deserialize_partition_refs")]
    pub removed_partitions: Vec<PartitionRef>,
    pub refresh_policy_definition_digest: Digest,
    pub operator_definition_digest: Digest,
    pub execution_scope_digest: Digest,
    #[serde(deserialize_with = "deserialize_execution_attempts")]
    pub execution_attempts: Vec<Digest>,
    pub started_unix_ms: u64,
    pub completed_unix_ms: u64,
    pub cost_microusd: Option<u64>,
    pub outcome: RefreshOutcome,
    pub authority: CapabilityMode,
}

impl RefreshAttempt {
    pub fn new(mut input: RefreshAttemptInput) -> Result<Self, RefreshRecordError> {
        input.retained_partitions.sort_unstable();
        input.refreshed_partitions.sort_unstable();
        input.added_partitions.sort_unstable();
        input.removed_partitions.sort_unstable();
        let mut value = Self {
            format_revision: REFRESH_ATTEMPT_FORMAT_REVISION,
            id: RefreshAttemptId::new(Digest([0; 32])),
            request: input.request,
            action_contract: input.action_contract,
            prior_artifact: input.prior_artifact,
            state_delta: input.state_delta,
            prior_manifest: input.prior_manifest,
            current_manifest: input.current_manifest,
            manifest_transition: input.manifest_transition,
            retained_partitions: input.retained_partitions,
            refreshed_partitions: input.refreshed_partitions,
            added_partitions: input.added_partitions,
            removed_partitions: input.removed_partitions,
            refresh_policy_definition_digest: input.refresh_policy_definition_digest,
            operator_definition_digest: input.operator_definition_digest,
            execution_scope_digest: input.execution_scope_digest,
            execution_attempts: input.execution_attempts,
            started_unix_ms: input.started_unix_ms,
            completed_unix_ms: input.completed_unix_ms,
            cost_microusd: input.cost_microusd,
            outcome: input.outcome,
            authority: CapabilityMode::Shadow,
        };
        value.validate_shape()?;
        value.id = RefreshAttemptId::new(value.compute_digest());
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, RefreshRecordError> {
        enforce_wire_bound("refresh_attempt", bytes.len(), MAX_REFRESH_ATTEMPT_WIRE_BYTES)?;
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| RefreshRecordError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), RefreshRecordError> {
        self.validate_shape()?;
        if self.id.digest() != self.compute_digest() {
            return Err(RefreshRecordError::Digest("refresh_attempt.id"));
        }
        Ok(())
    }

    pub fn failure(&self) -> Option<(RefreshFailureClass, Digest)> {
        match self.outcome {
            RefreshOutcome::Succeeded { .. } => None,
            RefreshOutcome::Failed { failure_class, failure_evidence_digest } => {
                Some((failure_class, failure_evidence_digest))
            }
        }
    }

    fn validate_shape(&self) -> Result<(), RefreshRecordError> {
        if self.format_revision != REFRESH_ATTEMPT_FORMAT_REVISION {
            return Err(RefreshRecordError::FormatRevision {
                record: "refresh_attempt",
                actual: self.format_revision,
            });
        }
        if self.authority != CapabilityMode::Shadow {
            return Err(RefreshRecordError::Authority);
        }
        if self.prior_manifest == self.current_manifest {
            return Err(RefreshRecordError::ManifestBinding);
        }
        if self.completed_unix_ms < self.started_unix_ms {
            return Err(RefreshRecordError::Timing);
        }
        validate_canonical_set(
            "refresh_attempt.retained_partitions",
            &self.retained_partitions,
            MAX_REFRESH_ATTEMPT_PARTITIONS,
            false,
        )?;
        validate_canonical_set(
            "refresh_attempt.refreshed_partitions",
            &self.refreshed_partitions,
            MAX_REFRESH_ATTEMPT_PARTITIONS,
            true,
        )?;
        validate_canonical_set(
            "refresh_attempt.added_partitions",
            &self.added_partitions,
            MAX_REFRESH_ATTEMPT_PARTITIONS,
            true,
        )?;
        validate_canonical_set(
            "refresh_attempt.removed_partitions",
            &self.removed_partitions,
            MAX_REFRESH_ATTEMPT_PARTITIONS,
            true,
        )?;
        validate_unique_sequence(
            "refresh_attempt.execution_attempts",
            &self.execution_attempts,
            MAX_REFRESH_EXECUTION_ATTEMPTS,
        )?;
        if self.retained_partitions.is_empty()
            || self.retained_partitions.iter().any(|mapping| {
                mapping.prior.manifest != self.prior_manifest
                    || mapping.current.manifest != self.current_manifest
            })
            || self
                .refreshed_partitions
                .iter()
                .chain(&self.added_partitions)
                .any(|partition| partition.manifest != self.current_manifest)
            || self
                .removed_partitions
                .iter()
                .any(|partition| partition.manifest != self.prior_manifest)
        {
            return Err(RefreshRecordError::ManifestBinding);
        }
        let retained_current = self
            .retained_partitions
            .iter()
            .map(|mapping| mapping.current.key_digest)
            .collect::<BTreeSet<_>>();
        let refreshed =
            self.refreshed_partitions.iter().map(|value| value.key_digest).collect::<BTreeSet<_>>();
        let added =
            self.added_partitions.iter().map(|value| value.key_digest).collect::<BTreeSet<_>>();
        if !retained_current.is_disjoint(&refreshed)
            || !retained_current.is_disjoint(&added)
            || !refreshed.is_disjoint(&added)
        {
            return Err(RefreshRecordError::PartitionOverlap);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"refresh-attempt-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.request.digest());
        hasher.field_str(self.action_contract.as_str());
        hasher.field_digest(self.prior_artifact.digest());
        hasher.field_digest(self.state_delta);
        hasher.field_digest(self.prior_manifest.digest());
        hasher.field_digest(self.current_manifest.digest());
        hasher.field_digest(self.manifest_transition.digest());
        hash_mappings(&mut hasher, &self.retained_partitions);
        hash_partition_refs(&mut hasher, &self.refreshed_partitions);
        hash_partition_refs(&mut hasher, &self.added_partitions);
        hash_partition_refs(&mut hasher, &self.removed_partitions);
        hasher.field_digest(self.refresh_policy_definition_digest);
        hasher.field_digest(self.operator_definition_digest);
        hasher.field_digest(self.execution_scope_digest);
        hasher.field_u32(self.execution_attempts.len().try_into().unwrap_or(u32::MAX));
        for attempt in &self.execution_attempts {
            hasher.field_digest(*attempt);
        }
        hash_u64(&mut hasher, self.started_unix_ms);
        hash_u64(&mut hasher, self.completed_unix_ms);
        match self.cost_microusd {
            Some(cost) => {
                hasher.field_u8(1);
                hash_u64(&mut hasher, cost);
            }
            None => hasher.field_u8(0),
        }
        hash_outcome(&mut hasher, self.outcome);
        hasher.field_u8(0);
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailedRefreshMemoKey {
    pub request: ArtifactRequestId,
    pub action_contract: ActionContractId,
    pub prior_artifact: ArtifactId,
    pub state_delta: Digest,
    pub refresh_policy_definition_digest: Digest,
    pub operator_definition_digest: Digest,
    pub execution_scope_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailedRefreshMemo {
    pub format_revision: u16,
    pub id: FailedRefreshMemoId,
    pub attempt: RefreshAttemptId,
    pub request: ArtifactRequestId,
    pub action_contract: ActionContractId,
    pub prior_artifact: ArtifactId,
    pub state_delta: Digest,
    pub refresh_policy_definition_digest: Digest,
    pub operator_definition_digest: Digest,
    pub execution_scope_digest: Digest,
    pub failure_class: RefreshFailureClass,
    pub failure_evidence_digest: Digest,
    pub expires_unix_ms: Option<u64>,
}

impl FailedRefreshMemo {
    pub fn from_attempt(
        attempt: &RefreshAttempt,
        expires_unix_ms: Option<u64>,
    ) -> Result<Self, RefreshRecordError> {
        attempt.validate()?;
        let Some((failure_class, failure_evidence_digest)) = attempt.failure() else {
            return Err(RefreshRecordError::SuccessfulAttemptMemo);
        };
        if expires_unix_ms.is_some_and(|expires| expires <= attempt.completed_unix_ms) {
            return Err(RefreshRecordError::MemoExpiry);
        }
        let mut value = Self {
            format_revision: FAILED_REFRESH_MEMO_FORMAT_REVISION,
            id: FailedRefreshMemoId::new(Digest([0; 32])),
            attempt: attempt.id,
            request: attempt.request,
            action_contract: attempt.action_contract.clone(),
            prior_artifact: attempt.prior_artifact,
            state_delta: attempt.state_delta,
            refresh_policy_definition_digest: attempt.refresh_policy_definition_digest,
            operator_definition_digest: attempt.operator_definition_digest,
            execution_scope_digest: attempt.execution_scope_digest,
            failure_class,
            failure_evidence_digest,
            expires_unix_ms,
        };
        value.validate_shape()?;
        value.id = FailedRefreshMemoId::new(value.compute_digest());
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, RefreshRecordError> {
        enforce_wire_bound("failed_refresh_memo", bytes.len(), MAX_FAILED_REFRESH_MEMO_WIRE_BYTES)?;
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| RefreshRecordError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), RefreshRecordError> {
        self.validate_shape()?;
        if self.id.digest() != self.compute_digest() {
            return Err(RefreshRecordError::Digest("failed_refresh_memo.id"));
        }
        Ok(())
    }

    pub fn key(&self) -> FailedRefreshMemoKey {
        FailedRefreshMemoKey {
            request: self.request,
            action_contract: self.action_contract.clone(),
            prior_artifact: self.prior_artifact,
            state_delta: self.state_delta,
            refresh_policy_definition_digest: self.refresh_policy_definition_digest,
            operator_definition_digest: self.operator_definition_digest,
            execution_scope_digest: self.execution_scope_digest,
        }
    }

    pub fn matches_key(&self, key: &FailedRefreshMemoKey) -> bool {
        self.request == key.request
            && self.action_contract == key.action_contract
            && self.prior_artifact == key.prior_artifact
            && self.state_delta == key.state_delta
            && self.refresh_policy_definition_digest == key.refresh_policy_definition_digest
            && self.operator_definition_digest == key.operator_definition_digest
            && self.execution_scope_digest == key.execution_scope_digest
    }

    pub fn is_active_at(&self, unix_ms: u64) -> bool {
        self.expires_unix_ms.is_none_or(|expires| expires > unix_ms)
    }

    fn validate_shape(&self) -> Result<(), RefreshRecordError> {
        if self.format_revision != FAILED_REFRESH_MEMO_FORMAT_REVISION {
            return Err(RefreshRecordError::FormatRevision {
                record: "failed_refresh_memo",
                actual: self.format_revision,
            });
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"failed-refresh-memo-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.attempt.digest());
        hasher.field_digest(self.request.digest());
        hasher.field_str(self.action_contract.as_str());
        hasher.field_digest(self.prior_artifact.digest());
        hasher.field_digest(self.state_delta);
        hasher.field_digest(self.refresh_policy_definition_digest);
        hasher.field_digest(self.operator_definition_digest);
        hasher.field_digest(self.execution_scope_digest);
        hasher.field_u8(failure_class_tag(self.failure_class));
        hasher.field_digest(self.failure_evidence_digest);
        match self.expires_unix_ms {
            Some(expires) => {
                hasher.field_u8(1);
                hash_u64(&mut hasher, expires);
            }
            None => hasher.field_u8(0),
        }
        hasher.finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RefreshRecordError {
    #[error("{record} format revision {actual} is unsupported")]
    FormatRevision { record: &'static str, actual: u16 },
    #[error("{record} contains {actual} bytes; the maximum is {maximum}")]
    WireBound { record: &'static str, actual: usize, maximum: usize },
    #[error("refresh record JSON is invalid: {0}")]
    Json(String),
    #[error("{field} contains {actual} entries; the maximum is {maximum}")]
    CollectionBound { field: &'static str, actual: usize, maximum: usize },
    #[error("{0} must be strictly sorted and unique")]
    CanonicalSet(&'static str),
    #[error("{0} must not contain duplicates")]
    UniqueSequence(&'static str),
    #[error("refresh partition references do not match the prior/current manifests")]
    ManifestBinding,
    #[error("refresh partition classes overlap")]
    PartitionOverlap,
    #[error("refresh completion precedes its start")]
    Timing,
    #[error("refresh attempt authority must remain Shadow")]
    Authority,
    #[error("a successful refresh attempt cannot produce a failed-refresh memo")]
    SuccessfulAttemptMemo,
    #[error("failed-refresh memo expiry must follow attempt completion")]
    MemoExpiry,
    #[error("{0} does not match its canonical digest")]
    Digest(&'static str),
}

fn enforce_wire_bound(
    record: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), RefreshRecordError> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(RefreshRecordError::WireBound { record, actual, maximum })
    }
}

fn validate_canonical_set<T: Ord>(
    field: &'static str,
    values: &[T],
    maximum: usize,
    allow_empty: bool,
) -> Result<(), RefreshRecordError> {
    if values.len() > maximum {
        return Err(RefreshRecordError::CollectionBound { field, actual: values.len(), maximum });
    }
    if (!allow_empty && values.is_empty()) || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(RefreshRecordError::CanonicalSet(field));
    }
    Ok(())
}

fn validate_unique_sequence<T: Ord + Copy>(
    field: &'static str,
    values: &[T],
    maximum: usize,
) -> Result<(), RefreshRecordError> {
    if values.len() > maximum {
        return Err(RefreshRecordError::CollectionBound { field, actual: values.len(), maximum });
    }
    let unique = values.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(RefreshRecordError::UniqueSequence(field));
    }
    Ok(())
}

fn deserialize_mappings<'de, D>(deserializer: D) -> Result<Vec<PartitionKeyMapping>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, PartitionKeyMapping, MAX_REFRESH_ATTEMPT_PARTITIONS>(
        deserializer,
        "refresh_attempt.retained_partitions",
    )
}

fn deserialize_partition_refs<'de, D>(deserializer: D) -> Result<Vec<PartitionRef>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, PartitionRef, MAX_REFRESH_ATTEMPT_PARTITIONS>(
        deserializer,
        "refresh_attempt.partition_refs",
    )
}

fn deserialize_execution_attempts<'de, D>(deserializer: D) -> Result<Vec<Digest>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, Digest, MAX_REFRESH_EXECUTION_ATTEMPTS>(
        deserializer,
        "refresh_attempt.execution_attempts",
    )
}

fn deserialize_bounded_vec<'de, D, T, const MAX: usize>(
    deserializer: D,
    field: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T, const MAX: usize> {
        field: &'static str,
        marker: std::marker::PhantomData<T>,
    }

    impl<'de, T, const MAX: usize> Visitor<'de> for BoundedVecVisitor<T, MAX>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX} entries for {}", self.field)
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX));
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX {
                    return Err(serde::de::Error::custom(format_args!(
                        "{} exceeds the maximum of {MAX} entries",
                        self.field
                    )));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer
        .deserialize_seq(BoundedVecVisitor::<T, MAX> { field, marker: std::marker::PhantomData })
}

fn hash_mappings(hasher: &mut CanonicalHasher, values: &[PartitionKeyMapping]) {
    hasher.field_u32(values.len().try_into().unwrap_or(u32::MAX));
    for mapping in values {
        hash_partition_ref(hasher, mapping.prior);
        hash_partition_ref(hasher, mapping.current);
    }
}

fn hash_partition_refs(hasher: &mut CanonicalHasher, values: &[PartitionRef]) {
    hasher.field_u32(values.len().try_into().unwrap_or(u32::MAX));
    for value in values {
        hash_partition_ref(hasher, *value);
    }
}

fn hash_partition_ref(hasher: &mut CanonicalHasher, value: PartitionRef) {
    hasher.field_digest(value.manifest.digest());
    hasher.field_digest(value.key_digest);
}

fn hash_outcome(hasher: &mut CanonicalHasher, outcome: RefreshOutcome) {
    match outcome {
        RefreshOutcome::Succeeded { reconstructed_artifact, validation_certificate } => {
            hasher.field_u8(0);
            hasher.field_digest(reconstructed_artifact.digest());
            hasher.field_digest(validation_certificate.digest());
        }
        RefreshOutcome::Failed { failure_class, failure_evidence_digest } => {
            hasher.field_u8(1);
            hasher.field_u8(failure_class_tag(failure_class));
            hasher.field_digest(failure_evidence_digest);
        }
    }
}

fn failure_class_tag(value: RefreshFailureClass) -> u8 {
    match value {
        RefreshFailureClass::Acquisition => 0,
        RefreshFailureClass::Operator => 1,
        RefreshFailureClass::Reconstruction => 2,
        RefreshFailureClass::Validation => 3,
        RefreshFailureClass::Timeout => 4,
        RefreshFailureClass::BudgetExceeded => 5,
        RefreshFailureClass::RuntimeUnavailable => 6,
        RefreshFailureClass::Storage => 7,
    }
}

fn hash_u64(hasher: &mut CanonicalHasher, value: u64) {
    hasher.field_u32((value >> 32) as u32);
    hasher.field_u32(value as u32);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> Digest {
        Digest::blake3(label)
    }

    fn failed_attempt() -> RefreshAttempt {
        let prior = PartitionManifestId::new(digest("prior-manifest"));
        let current = PartitionManifestId::new(digest("current-manifest"));
        RefreshAttempt::new(RefreshAttemptInput {
            request: ArtifactRequestId::new(digest("request")),
            action_contract: ActionContractId::new("needle.tests.inventory").unwrap(),
            prior_artifact: ArtifactId::new(digest("prior-artifact")),
            state_delta: digest("delta"),
            prior_manifest: prior,
            current_manifest: current,
            manifest_transition: ManifestTransitionId::new(digest("transition")),
            retained_partitions: vec![PartitionKeyMapping {
                prior: PartitionRef::new(prior, digest("retained")),
                current: PartitionRef::new(current, digest("retained")),
            }],
            refreshed_partitions: vec![PartitionRef::new(current, digest("refreshed"))],
            added_partitions: vec![PartitionRef::new(current, digest("added"))],
            removed_partitions: vec![PartitionRef::new(prior, digest("removed"))],
            refresh_policy_definition_digest: digest("refresh-policy"),
            operator_definition_digest: digest("operator"),
            execution_scope_digest: digest("execution-scope"),
            execution_attempts: vec![digest("execution-attempt")],
            started_unix_ms: 10,
            completed_unix_ms: 20,
            cost_microusd: Some(7),
            outcome: RefreshOutcome::Failed {
                failure_class: RefreshFailureClass::Validation,
                failure_evidence_digest: digest("failure-evidence"),
            },
        })
        .unwrap()
    }

    #[test]
    fn attempt_and_memo_round_trip_and_detect_tampering() {
        let attempt = failed_attempt();
        let json = serde_json::to_vec(&attempt).unwrap();
        assert_eq!(RefreshAttempt::decode_json(&json).unwrap(), attempt);
        let memo = FailedRefreshMemo::from_attempt(&attempt, Some(100)).unwrap();
        let json = serde_json::to_vec(&memo).unwrap();
        assert_eq!(FailedRefreshMemo::decode_json(&json).unwrap(), memo);
        assert!(memo.matches_key(&memo.key()));
        assert!(memo.is_active_at(99));
        assert!(!memo.is_active_at(100));

        let mut tampered = attempt;
        tampered.completed_unix_ms += 1;
        assert_eq!(tampered.validate(), Err(RefreshRecordError::Digest("refresh_attempt.id")));
    }

    #[test]
    fn success_cannot_create_a_failure_memo_and_partition_overlap_is_rejected() {
        let mut input = failed_attempt();
        input.outcome = RefreshOutcome::Succeeded {
            reconstructed_artifact: ArtifactId::new(digest("result")),
            validation_certificate: ArtifactValidationCertificateId::new(digest("certificate")),
        };
        input.id = RefreshAttemptId::new(input.compute_digest());
        assert_eq!(
            FailedRefreshMemo::from_attempt(&input, Some(100)),
            Err(RefreshRecordError::SuccessfulAttemptMemo)
        );
        assert_eq!(
            FailedRefreshMemo::from_attempt(&failed_attempt(), Some(20)),
            Err(RefreshRecordError::MemoExpiry)
        );

        let current = input.current_manifest;
        input.added_partitions =
            vec![PartitionRef::new(current, input.refreshed_partitions[0].key_digest)];
        assert_eq!(input.validate(), Err(RefreshRecordError::PartitionOverlap));
    }

    #[test]
    fn bounded_deserializer_rejects_execution_attempt_overflow_before_retention() {
        let attempt = failed_attempt();
        let mut json = serde_json::to_value(&attempt).unwrap();
        json["execution_attempts"] = serde_json::Value::Array(
            (0..=MAX_REFRESH_EXECUTION_ATTEMPTS)
                .map(|index| serde_json::to_value(digest(&format!("attempt-{index}"))).unwrap())
                .collect(),
        );
        assert!(serde_json::from_value::<RefreshAttempt>(json).is_err());
    }

    #[test]
    fn execution_attempt_sequence_rejects_duplicates() {
        let attempt = failed_attempt();
        let mut json = serde_json::to_value(&attempt).unwrap();
        let repeated = serde_json::to_value(digest("execution-attempt")).unwrap();
        json["execution_attempts"] = serde_json::Value::Array(vec![repeated.clone(), repeated]);
        let decoded = serde_json::from_value::<RefreshAttempt>(json).unwrap();
        assert_eq!(
            decoded.validate(),
            Err(RefreshRecordError::UniqueSequence("refresh_attempt.execution_attempts"))
        );
    }

    #[test]
    fn refresh_record_digests_are_stable() {
        let attempt = failed_attempt();
        let memo = FailedRefreshMemo::from_attempt(&attempt, Some(100)).unwrap();
        assert_eq!(
            attempt.id.digest(),
            Digest::parse("b3:30babd4acbcf98ee8b84d05a2f787c5c236ed9230cdf8854bfa9ea6a93d93557")
                .unwrap()
        );
        assert_eq!(
            memo.id.digest(),
            Digest::parse("b3:f1b57ac72ac6d57794d7710c95f9b3e21741389e350c1861fb855ba826c5d80d")
                .unwrap()
        );
    }
}
