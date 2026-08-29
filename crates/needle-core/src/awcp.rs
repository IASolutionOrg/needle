//! Experimental provider-neutral Agent Work Cache Protocol domain.
//!
//! Revision 1 is an offline conformance contract. It is not a public
//! compatibility promise and does not grant resolver authority.

use crate::Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod partition_manifest;
mod publication;
mod resolution;

pub use partition_manifest::*;
pub use publication::*;
pub use resolution::*;

pub const AWCP_PROTOCOL_REVISION: u16 = 1;
pub const MAX_AWCP_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_AWCP_KNOWN_DEFINITIONS: usize = 16;
pub const MAX_AWCP_ARTIFACTS: usize = 8;
pub const MAX_AWCP_MISSING_OBLIGATIONS: usize = 16;
pub const MAX_AWCP_WORKER_RESULT_BYTES: usize = 32 * 1024;
pub const MAX_AWCP_ARTIFACT_PROJECTION_BYTES: usize = 32 * 1024;
pub const MAX_AWCP_SCHEMA_ID_BYTES: usize = 96;
pub const MAX_AWCP_TICKET_TTL_MS: u64 = 5 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResolutionTicketId(Digest);

impl ResolutionTicketId {
    pub const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExecutionReportId(Digest);

impl ExecutionReportId {
    pub const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "body", rename_all = "snake_case", deny_unknown_fields)]
pub enum AwcpRequest {
    ResolveAction(Box<ResolveActionRequest>),
    PublishAction(Box<PublishActionRequest>),
    GetArtifact(GetArtifactRequest),
    ReportExecution(Box<ReportExecutionRequest>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "body", rename_all = "snake_case", deny_unknown_fields)]
pub enum AwcpResponse {
    ResolveAction(Box<ResolveActionResponse>),
    PublishAction(Box<PublishActionResponse>),
    GetArtifact(Box<GetArtifactResponse>),
    ReportExecution(ReportExecutionResponse),
    Error(AwcpErrorResponse),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AwcpErrorCode {
    MalformedMessage,
    UnsupportedRevision,
    BoundExceeded,
    UnknownAction,
    DefinitionDrift,
    CapabilityUnsupported,
    UnknownTicket,
    ForgedTicket,
    ExpiredTicket,
    ConsumedTicket,
    CallerDrift,
    SourceDrift,
    ResolutionDrift,
    DispatchDrift,
    EffectDrift,
    PublishForbidden,
    ArtifactForbidden,
    InvalidWorkerResult,
    ExecutionReportConflict,
    CapacityExceeded,
    RuntimeUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwcpErrorResponse {
    pub protocol_revision: u16,
    pub code: AwcpErrorCode,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwcpValidationError {
    #[error("AWCP protocol revision {0} is unsupported")]
    Revision(u16),
    #[error("{field} contains {actual} entries or bytes; the hard maximum is {maximum}")]
    Bound { field: &'static str, actual: usize, maximum: usize },
    #[error("{0} must be strictly sorted and unique")]
    CanonicalSet(&'static str),
    #[error("AWCP action request does not match its definition handle")]
    ActionDefinitionBinding,
    #[error("AWCP semantic input digest does not match its action request")]
    SemanticInputsDigest,
    #[error("AWCP applied limit must be non-zero")]
    ZeroLimit,
    #[error("AWCP ticket expiry is invalid or exceeds the hard TTL")]
    TicketExpiry,
    #[error("AWCP publish authority does not match refresh bindings")]
    PublishAuthorityBinding,
    #[error("AWCP artifact handles must be strictly ordered and unique")]
    ArtifactOrdering,
    #[error("worker result schema identifier is invalid")]
    WorkerResultSchema,
    #[error("worker result is not valid JSON")]
    WorkerResultJson,
    #[error("worker result JSON is not canonical compact JSON")]
    WorkerResultCanonical,
    #[error("credential-shaped material is forbidden in AWCP worker results")]
    CredentialMaterial,
    #[error("worker observation completion precedes its start")]
    ObservationTime,
    #[error("external effects require an effect receipt")]
    EffectReceipt,
    #[error("artifact projection is not valid JSON")]
    ArtifactProjectionJson,
    #[error("AWCP partition manifest projection is invalid")]
    PartitionManifestProjection,
    #[error("AWCP partition manifest projection must remain Shadow-only")]
    PartitionManifestAuthority,
    #[error("AWCP partition manifest projection digest is invalid")]
    PartitionManifestDigest,
}

pub(super) fn validate_revision(revision: u16) -> Result<(), AwcpValidationError> {
    if revision == AWCP_PROTOCOL_REVISION {
        Ok(())
    } else {
        Err(AwcpValidationError::Revision(revision))
    }
}

pub(super) fn validate_bound(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), AwcpValidationError> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(AwcpValidationError::Bound { field, actual, maximum })
    }
}

pub(super) fn validate_nonzero_bound(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), AwcpValidationError> {
    if actual == 0 {
        return Err(AwcpValidationError::ZeroLimit);
    }
    validate_bound(field, actual, maximum)
}

#[cfg(test)]
mod tests;
