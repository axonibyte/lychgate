//! Grant state machine, TTL policy, and inventory schema for lychgate.
//!
//! Everything here is pure logic with injected time: expiry is a property of
//! observation (`Grant::status(now)`), so no background thread is required
//! for a lapsed grant to read as expired.

pub mod approval;
pub mod bmc;
pub mod channel;
pub mod deadman;
pub mod grant;
pub mod inventory;
pub mod proto;
pub mod registry;
pub mod snapshot;
pub mod ssh;
pub mod ttl;
pub mod vnc;

pub use approval::{
    parse_ssh_public_key, AcceptAny, AnyOf, ApprovalError, ApprovalRequest, ApprovalVerifier,
    RefuseAll, SshSigVerifier, APPROVAL_NAMESPACE,
};
pub use channel::{
    apply_channels, reestablish_channels, revert_channels, ApplyOutcome, ChannelDriver,
    ChannelState, DriverError, DriverSet, ReestablishOutcome, RevertOutcome,
};
pub use grant::{Grant, GrantError, GrantStatus, MAX_APPROVAL_WINDOW_SECS};
pub use inventory::{
    ApprovalConfig, BmcConfig, BmcMethod, BmcTls, Channel, Ed25519Approver, Host, Inventory,
    InventoryError, Os, SshConfig, VncConfig,
};
pub use registry::{ExpiredGrant, ExpiredPending, GrantRegistry, RegistryError};
pub use snapshot::{GrantRecord, SnapshotError, StateDoc, STATE_VERSION};
pub use ttl::{Ttl, TtlError, MAX_TTL_SECS, RENEWAL_WINDOW_SECS};
