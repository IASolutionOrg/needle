//! Experimental offline AWCP conformance runtime.
//!
//! This module deliberately has no live resolver, store, transport, or provider
//! wiring. It exercises the protocol authority boundary without changing which
//! production capabilities may serve results.

mod protocol;
mod simulator;

pub use simulator::{
    AuthenticatedAwcpContext, MAX_OFFLINE_AWCP_ARTIFACTS, MAX_OFFLINE_AWCP_GRANTS,
    MAX_OFFLINE_AWCP_REPORTS, MAX_OFFLINE_AWCP_RESOLUTIONS, MAX_OFFLINE_AWCP_TICKETS,
    OfflineActionResolution, OfflineArtifactProjection, OfflineAwcpError, OfflineAwcpSimulator,
};

#[cfg(test)]
pub(crate) use protocol::definition_handle;

#[cfg(test)]
mod tests;
