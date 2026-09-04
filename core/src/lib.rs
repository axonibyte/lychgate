//! Grant state machine, TTL policy, and inventory schema for lychgate.
//!
//! Everything here is pure logic with injected time: expiry is a property of
//! observation (`Grant::status(now)`), so no background thread is required
//! for a lapsed grant to read as expired.

pub mod channel;
pub mod deadman;
pub mod grant;
pub mod inventory;
pub mod proto;
pub mod registry;
pub mod snapshot;
pub mod ssh;
pub mod ttl;

pub use channel::{
    apply_channels, revert_channels, ApplyOutcome, ChannelDriver, ChannelState, DriverError,
    DriverSet, RevertOutcome,
};
pub use grant::{Grant, GrantError, GrantStatus};
pub use inventory::{Channel, Host, Inventory, InventoryError, Os, SshConfig};
pub use registry::{ExpiredGrant, GrantRegistry, RegistryError};
pub use snapshot::{GrantRecord, SnapshotError, StateDoc, STATE_VERSION};
pub use ttl::{Ttl, TtlError, MAX_TTL_SECS, RENEWAL_WINDOW_SECS};
