//! The driver seam: one implementation per access channel.
//!
//! The contract every driver signs:
//!
//! - `apply` is **atomic-or-reported**: on `Err`, the channel may be half
//!   applied and MUST be treated as needing revert. A driver never fails
//!   "cleanly" — the caller cannot tell a failure-before-touching-anything
//!   from a failure-midway, so it must not try.
//! - `revert` is **idempotent**: reverting a channel that was never applied,
//!   or reverting twice, succeeds.
//! - `verify` reads the target's **actual** state, never a cached belief.
//!
//! Orchestration lives here too, pure over the trait: apply channels in
//! declaration order and, on the first failure, revert the applied prefix in
//! reverse. What that guarantees — and all it guarantees — is that a failed
//! open can only ever present as *needs revert*, never as cleanly open.

use std::collections::BTreeMap;
use std::fmt;

use crate::inventory::{Channel, Host};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverError(pub String);

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DriverError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    Closed,
    Open,
}

pub trait ChannelDriver {
    /// Which channel this driver operates. A driver set holds at most one
    /// driver per channel.
    fn channel(&self) -> Channel;
    fn apply(&mut self, host: &Host) -> Result<(), DriverError>;
    fn revert(&mut self, host: &Host) -> Result<(), DriverError>;
    fn verify(&mut self, host: &Host) -> Result<ChannelState, DriverError>;

    /// A secret this driver's last apply produced for the operator (a BMC
    /// break-glass password), taken exactly once. Most channels have none.
    fn take_secret(&mut self) -> Option<crate::bmc::Secret> {
        None
    }
}

/// The registered drivers, keyed by channel. Until M4 the production set is
/// empty; fakes populate it in tests.
#[derive(Default)]
pub struct DriverSet {
    drivers: BTreeMap<Channel, Box<dyn ChannelDriver + Send>>,
}

impl DriverSet {
    pub fn new() -> DriverSet {
        DriverSet::default()
    }

    /// Registers a driver. A second driver for the same channel is refused:
    /// two implementations fighting over one channel is a configuration
    /// error, not a fallback mechanism.
    pub fn register(&mut self, driver: Box<dyn ChannelDriver + Send>) -> Result<(), DriverError> {
        let channel = driver.channel();
        if self.drivers.contains_key(&channel) {
            return Err(DriverError(format!(
                "a driver for channel {channel:?} is already registered"
            )));
        }
        self.drivers.insert(channel, driver);
        Ok(())
    }

    /// Drains a secret a driver produced at open, if any — the caller hands
    /// it to the operator once and drops it.
    pub fn take_secret(&mut self, channel: Channel) -> Option<crate::bmc::Secret> {
        self.drivers.get_mut(&channel).and_then(|d| d.take_secret())
    }

    /// The channels of `requested` that have a registered driver, in the
    /// requested order. What cannot be driven cannot be applied — and must
    /// not be recorded as applied.
    pub fn drivable(&self, requested: &[Channel]) -> Vec<Channel> {
        requested
            .iter()
            .copied()
            .filter(|c| self.drivers.contains_key(c))
            .collect()
    }
}

/// The outcome of an open attempt across a host's channels.
#[derive(Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Every drivable channel applied; `applied` is what revert must later
    /// undo (recorded in the grant, not re-derived from the inventory).
    Applied { applied: Vec<Channel> },
    /// A channel failed. The applied prefix was reverted in reverse order;
    /// whatever failed to revert is in `stuck` and the grant must present
    /// as needs-revert.
    Failed {
        failed: Channel,
        error: DriverError,
        reverted: Vec<Channel>,
        stuck: Vec<Channel>,
    },
}

/// Applies `channels` in order; on the first failure, reverts the applied
/// prefix in reverse. The failed channel itself is also reverted —
/// atomic-or-reported means it may be half applied.
pub fn apply_channels(set: &mut DriverSet, host: &Host, channels: &[Channel]) -> ApplyOutcome {
    let mut applied: Vec<Channel> = Vec::new();
    for &channel in channels {
        let driver = set
            .drivers
            .get_mut(&channel)
            .expect("apply_channels is called with drivable channels only");
        if let Err(error) = driver.apply(host) {
            // Unwind: the failed channel first (it may be half applied),
            // then the applied prefix in reverse order.
            let mut to_revert = vec![channel];
            to_revert.extend(applied.iter().rev().copied());
            let mut reverted = Vec::new();
            let mut stuck = Vec::new();
            for c in to_revert {
                let driver = set.drivers.get_mut(&c).expect("was drivable");
                match driver.revert(host) {
                    Ok(()) => reverted.push(c),
                    Err(_) => stuck.push(c),
                }
            }
            return ApplyOutcome::Failed {
                failed: channel,
                error,
                reverted,
                stuck,
            };
        }
        applied.push(channel);
    }
    ApplyOutcome::Applied { applied }
}

/// The outcome of reverting a grant's applied channels.
#[derive(Debug, PartialEq, Eq)]
pub enum RevertOutcome {
    Reverted,
    /// Some channels refused to revert; the grant must stay needs-revert
    /// and the caller retries. Never swallowed.
    Stuck {
        stuck: Vec<(Channel, DriverError)>,
    },
}

/// Reverts `channels` in reverse of their application order. Every channel
/// is attempted even after a failure: knowing that two are stuck is worth
/// more than knowing one is.
pub fn revert_channels(set: &mut DriverSet, host: &Host, channels: &[Channel]) -> RevertOutcome {
    let mut stuck = Vec::new();
    for &channel in channels.iter().rev() {
        match set.drivers.get_mut(&channel) {
            // A channel recorded as applied but no longer drivable cannot be
            // reverted by anyone: that is stuck, not skippable.
            None => stuck.push((
                channel,
                DriverError(format!("no driver registered for channel {channel:?}")),
            )),
            Some(driver) => {
                if let Err(e) = driver.revert(host) {
                    stuck.push((channel, e));
                }
            }
        }
    }
    if stuck.is_empty() {
        RevertOutcome::Reverted
    } else {
        RevertOutcome::Stuck { stuck }
    }
}

#[cfg(any(test, feature = "fakes"))]
pub mod fakes;
#[cfg(test)]
mod tests;
