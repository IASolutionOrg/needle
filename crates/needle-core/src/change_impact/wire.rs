use super::*;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::marker::PhantomData;

struct BoundedStringVisitor<const MAX: usize>;

impl<const MAX: usize> Visitor<'_> for BoundedStringVisitor<MAX> {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a string containing at most {MAX} bytes")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if value.len() > MAX {
            return Err(E::custom(format!("string exceeds {MAX} bytes")));
        }
        Ok(value.to_owned())
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        if value.len() > MAX {
            return Err(E::custom(format!("string exceeds {MAX} bytes")));
        }
        Ok(value)
    }
}

fn bounded_string<'de, D: Deserializer<'de>, const MAX: usize>(
    deserializer: D,
) -> Result<String, D::Error> {
    deserializer.deserialize_string(BoundedStringVisitor::<MAX>)
}

struct BoundedVecVisitor<T, const MAX: usize>(PhantomData<T>);

impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for BoundedVecVisitor<T, MAX> {
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a sequence containing at most {MAX} entries")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX));
        while let Some(value) = sequence.next_element()? {
            if values.len() == MAX {
                return Err(de::Error::custom(format!("sequence exceeds {MAX} entries")));
            }
            values.push(value);
        }
        Ok(values)
    }
}

struct BoundedString<const MAX: usize>(String);

impl<'de, const MAX: usize> Deserialize<'de> for BoundedString<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        bounded_string::<D, MAX>(deserializer).map(Self)
    }
}

struct BoundedStringVecVisitor<const MAX_ENTRIES: usize, const MAX_BYTES: usize>;

impl<'de, const MAX_ENTRIES: usize, const MAX_BYTES: usize> Visitor<'de>
    for BoundedStringVecVisitor<MAX_ENTRIES, MAX_BYTES>
{
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {MAX_ENTRIES} strings containing at most {MAX_BYTES} bytes each")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_ENTRIES));
        while let Some(value) = sequence.next_element::<BoundedString<MAX_BYTES>>()? {
            if values.len() == MAX_ENTRIES {
                return Err(de::Error::custom(format!("sequence exceeds {MAX_ENTRIES} entries")));
            }
            values.push(value.0);
        }
        Ok(values)
    }
}

fn bounded_vec<'de, D, T, const MAX: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(BoundedVecVisitor::<T, MAX>(PhantomData))
}

pub(super) fn deserialize_text<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    bounded_string::<D, MAX_CHANGE_IMPACT_TEXT_BYTES>(deserializer)
}

pub(super) fn deserialize_path<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    bounded_string::<D, MAX_CHANGE_IMPACT_PATH_BYTES>(deserializer)
}

pub(super) fn deserialize_identifier<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    bounded_string::<D, MAX_CHANGE_IMPACT_IDENTIFIER_BYTES>(deserializer)
}

pub(super) fn deserialize_schema<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    bounded_string::<D, 64>(deserializer)
}

pub(super) fn deserialize_change_files<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ChangeImpactFile>, D::Error> {
    bounded_vec::<D, ChangeImpactFile, MAX_CHANGE_IMPACT_FILES>(deserializer)
}

pub(super) fn deserialize_component_keys<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ChangeImpactComponentKey>, D::Error> {
    bounded_vec::<D, ChangeImpactComponentKey, MAX_CHANGE_IMPACT_COMPONENTS>(deserializer)
}

pub(super) fn deserialize_evidence_roles<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ChangeImpactEvidenceRole>, D::Error> {
    bounded_vec::<D, ChangeImpactEvidenceRole, 8>(deserializer)
}

pub(super) fn deserialize_subject_ids<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<SubjectId>, D::Error> {
    bounded_vec::<D, SubjectId, MAX_CHANGE_IMPACT_SUBJECTS>(deserializer)
}

pub(super) fn deserialize_impact_kinds<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ChangeImpactKind>, D::Error> {
    bounded_vec::<D, ChangeImpactKind, 8>(deserializer)
}

pub(super) fn deserialize_digests<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Digest>, D::Error> {
    bounded_vec::<D, Digest, MAX_CHANGE_IMPACT_REFERENCES>(deserializer)
}

pub(super) fn deserialize_artifact_ids<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ArtifactId>, D::Error> {
    bounded_vec::<D, ArtifactId, MAX_CHANGE_IMPACT_INPUTS>(deserializer)
}

pub(super) fn deserialize_paths<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    deserializer.deserialize_seq(
        BoundedStringVecVisitor::<MAX_CHANGE_IMPACT_REFERENCES, MAX_CHANGE_IMPACT_PATH_BYTES>,
    )
}

pub(super) fn deserialize_test_target_ids<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Digest>, D::Error> {
    bounded_vec::<D, Digest, MAX_CHANGE_IMPACT_TEST_TARGETS>(deserializer)
}

pub(super) fn deserialize_requirements<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ChangeImpactRequirement>, D::Error> {
    bounded_vec::<D, ChangeImpactRequirement, MAX_CHANGE_IMPACT_REQUIREMENTS>(deserializer)
}

pub(super) fn deserialize_constraints<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ChangeImpactConstraint>, D::Error> {
    bounded_vec::<D, ChangeImpactConstraint, MAX_CHANGE_IMPACT_CONSTRAINTS>(deserializer)
}

pub(super) fn deserialize_subjects<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Subject>, D::Error> {
    bounded_vec::<D, Subject, MAX_CHANGE_IMPACT_SUBJECTS>(deserializer)
}

pub(super) fn deserialize_input_references<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ChangeImpactInputReference>, D::Error> {
    bounded_vec::<D, ChangeImpactInputReference, MAX_CHANGE_IMPACT_INPUTS>(deserializer)
}

pub(super) fn deserialize_evidence<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ChangeImpactEvidence>, D::Error> {
    bounded_vec::<D, ChangeImpactEvidence, MAX_CHANGE_IMPACT_EVIDENCE>(deserializer)
}

pub(super) fn deserialize_assessments<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ChangeImpactAssessment>, D::Error> {
    bounded_vec::<D, ChangeImpactAssessment, MAX_CHANGE_IMPACT_COMPONENTS>(deserializer)
}

pub(super) fn deserialize_gaps<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    deserializer.deserialize_seq(
        BoundedStringVecVisitor::<MAX_CHANGE_IMPACT_REFERENCES, MAX_CHANGE_IMPACT_TEXT_BYTES>,
    )
}
