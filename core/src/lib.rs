//! Grant state machine, TTL policy, and inventory schema for lychgate.
//!
//! Everything here is pure logic with injected time: expiry is a property of
//! observation (`Grant::status(now)`), so no background thread is required
//! for a lapsed grant to read as expired.

pub mod grant;
pub mod inventory;
pub mod ttl;

pub use grant::{CloseOutcome, Grant, GrantError, GrantStatus};
pub use inventory::{Channel, Host, Inventory, InventoryError, Os};
pub use ttl::{Ttl, TtlError, MAX_TTL_SECS, RENEWAL_WINDOW_SECS};
