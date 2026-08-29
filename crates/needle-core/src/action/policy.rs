use super::ACTION_FORMAT_REVISION;
use crate::{CanonicalHasher, Digest};
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use thiserror::Error;

pub const MAX_REUSE_MODE_ENTRIES: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReuseMode {
    Exact,
    Project,
    Assemble,
    Refresh,
    Never,
}

impl ReuseMode {
    const ALL: [Self; MAX_REUSE_MODE_ENTRIES] =
        [Self::Exact, Self::Project, Self::Assemble, Self::Refresh, Self::Never];

    const fn tag(self) -> u8 {
        match self {
            Self::Exact => 0,
            Self::Project => 1,
            Self::Assemble => 2,
            Self::Refresh => 3,
            Self::Never => 4,
        }
    }

    const fn bit(self) -> u8 {
        1 << self.tag()
    }
}

/// Compact canonical set of reuse modes.
///
/// Construction canonicalizes order and duplicates once. Digesting and policy
/// checks never allocate or sort.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ReuseModeSet(u8);

impl ReuseModeSet {
    pub fn new<I>(modes: I) -> Result<Self, ReuseModeSetError>
    where
        I: IntoIterator<Item = ReuseMode>,
    {
        let mut bits = 0_u8;
        let mut entries = 0_usize;
        for mode in modes {
            entries += 1;
            if entries > MAX_REUSE_MODE_ENTRIES {
                return Err(ReuseModeSetError::TooManyEntries { maximum: MAX_REUSE_MODE_ENTRIES });
            }
            bits |= mode.bit();
        }
        Self::from_bits(bits)
    }

    fn from_bits(bits: u8) -> Result<Self, ReuseModeSetError> {
        if bits == 0 {
            return Err(ReuseModeSetError::Empty);
        }
        if bits & ReuseMode::Never.bit() != 0 && bits != ReuseMode::Never.bit() {
            return Err(ReuseModeSetError::NeverExclusive);
        }
        Ok(Self(bits))
    }

    pub const fn contains(self, mode: ReuseMode) -> bool {
        self.0 & mode.bit() != 0
    }

    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn iter(self) -> impl Iterator<Item = ReuseMode> {
        ReuseMode::ALL.into_iter().filter(move |mode| self.contains(*mode))
    }

    pub(crate) const fn bits(self) -> u8 {
        self.0
    }
}

impl fmt::Debug for ReuseModeSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_set().entries(self.iter()).finish()
    }
}

impl Serialize for ReuseModeSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.len()))?;
        for mode in self.iter() {
            sequence.serialize_element(&mode)?;
        }
        sequence.end()
    }
}

struct ReuseModeSetVisitor;

impl<'de> Visitor<'de> for ReuseModeSetVisitor {
    type Value = ReuseModeSet;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a sequence of at most {MAX_REUSE_MODE_ENTRIES} reuse modes")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut bits = 0_u8;
        let mut entries = 0_usize;
        while let Some(mode) = sequence.next_element::<ReuseMode>()? {
            entries += 1;
            if entries > MAX_REUSE_MODE_ENTRIES {
                return Err(serde::de::Error::custom(ReuseModeSetError::TooManyEntries {
                    maximum: MAX_REUSE_MODE_ENTRIES,
                }));
            }
            bits |= mode.bit();
        }
        ReuseModeSet::from_bits(bits).map_err(serde::de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for ReuseModeSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(ReuseModeSetVisitor)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReuseModeSetError {
    #[error("reuse mode set must not be empty")]
    Empty,
    #[error("reuse mode set must contain at most {maximum} entries")]
    TooManyEntries { maximum: usize },
    #[error("reuse mode `never` is mutually exclusive with every completion reuse mode")]
    NeverExclusive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompletionPolicy {
    ReuseAllowed,
    ExactReuseOnly,
    FreshRequired,
}

impl CompletionPolicy {
    const fn tag(self) -> u8 {
        match self {
            Self::ReuseAllowed => 0,
            Self::ExactReuseOnly => 1,
            Self::FreshRequired => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidencePolicy {
    Standard,
    IndependentEvidenceRequired,
}

impl EvidencePolicy {
    const fn tag(self) -> u8 {
        match self {
            Self::Standard => 0,
            Self::IndependentEvidenceRequired => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PriorArtifactPolicy {
    ContractDefined,
    AdvisoryOnly,
    Forbidden,
}

impl PriorArtifactPolicy {
    const fn tag(self) -> u8 {
        match self {
            Self::ContractDefined => 0,
            Self::AdvisoryOnly => 1,
            Self::Forbidden => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PersistencePolicy {
    Persistent,
    Ephemeral,
    NoStore,
}

impl PersistencePolicy {
    const fn tag(self) -> u8 {
        match self {
            Self::Persistent => 0,
            Self::Ephemeral => 1,
            Self::NoStore => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchPolicy {
    pub completion: CompletionPolicy,
    pub evidence: EvidencePolicy,
    pub prior_artifacts: PriorArtifactPolicy,
    pub persistence: PersistencePolicy,
}

impl DispatchPolicy {
    pub fn digest(self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"action-dispatch-policy-v1");
        hasher.field_u16(ACTION_FORMAT_REVISION);
        hasher.field_u8(self.completion.tag());
        hasher.field_u8(self.evidence.tag());
        hasher.field_u8(self.prior_artifacts.tag());
        hasher.field_u8(self.persistence.tag());
        hasher.finish()
    }
}
