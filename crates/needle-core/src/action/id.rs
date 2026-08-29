use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use thiserror::Error;

pub const MAX_ACTION_CONTRACT_ID_BYTES: usize = 64;

/// Stable nominal identity for an action product contract.
///
/// Definition changes are represented by the contract digests, not by adding
/// transport, route, model, or policy data to this identifier.
#[derive(Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ActionContractId(String);

impl ActionContractId {
    pub fn new(value: impl Into<String>) -> Result<Self, ActionContractIdError> {
        let value = value.into();
        let bytes = value.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_ACTION_CONTRACT_ID_BYTES {
            return Err(ActionContractIdError::Length);
        }
        if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
            return Err(ActionContractIdError::Start);
        }
        if let Some((index, _)) = bytes.iter().enumerate().find(|(_, byte)| {
            !(byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(**byte, b'.' | b'_' | b'-'))
        }) {
            return Err(ActionContractIdError::Character(index));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ActionContractId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for ActionContractId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ActionContractId").field(&self.0).finish()
    }
}

impl fmt::Display for ActionContractId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for ActionContractId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ActionContractId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ActionContractIdError {
    #[error("action contract id must contain between 1 and 64 ASCII bytes")]
    Length,
    #[error("action contract id must start with a lowercase ASCII letter or digit")]
    Start,
    #[error("action contract id contains an invalid character at byte {0}")]
    Character(usize),
}
