//! Grant state machine, TTL policy, and inventory schema for lychgate.
//!
//! Everything here is pure logic with injected time: expiry is a property of
//! observation (`Grant::status(now)`), so no background thread is required
//! for a lapsed grant to read as expired.

pub mod approval;
pub mod authority;
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

pub use approval::{parse_ssh_public_key, ApprovalError, ApprovalRequest, APPROVAL_NAMESPACE};
pub use authority::{
    ApprovalSpec, AuthKind, Authenticator, AuthenticatorSpec, Authority, AuthorityBody,
    AuthorityError, AuthorityModel, AuthoritySpec, Factor, FactorSpec, Missing, Outcome,
    WeightedFactor,
};
pub use channel::{
    apply_channels, reestablish_channels, revert_channels, ApplyOutcome, ChannelDriver,
    ChannelState, DriverError, DriverSet, ReestablishOutcome, RevertOutcome,
};
pub use grant::{Grant, GrantError, GrantStatus, PendingView, MAX_APPROVAL_WINDOW_SECS};
pub use inventory::{
    BmcConfig, BmcMethod, BmcTls, Channel, Host, HostAccess, Inventory, InventoryError, Os,
    SshConfig, VncConfig,
};
pub use registry::{ExpiredGrant, ExpiredPending, GrantRegistry, RegistryError};
pub use snapshot::{GrantRecord, SnapshotError, StateDoc, STATE_VERSION};
pub use ttl::{Ttl, TtlError, MAX_TTL_SECS, RENEWAL_WINDOW_SECS};
