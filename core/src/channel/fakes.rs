//! Scripted fake drivers for the error-injection tier. Compiled only under
//! cfg(test) or the `fakes` feature (dev-dependencies of sibling crates);
//! never reachable from a release binary.

use std::sync::{Arc, Mutex};

use super::{ChannelDriver, ChannelState, DriverError};
use crate::inventory::{Channel, Host};

/// What a fake does when poked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    Succeed,
    FailApply,
    FailRevert,
    FailBoth,
}

/// Every call every fake received, in order, shared across the set. This is
/// the second oracle: tests assert the registry's claim AND that the calls
/// really happened (or really did not).
pub type CallLog = Arc<Mutex<Vec<(Channel, &'static str)>>>;

pub struct FakeDriver {
    channel: Channel,
    script: Script,
    log: CallLog,
    /// Tracks what "the host" would show, so verify has real state to read.
    open: bool,
    /// An optional one-time secret this driver yields at apply, for testing
    /// the BMC password handoff without a real BMC.
    secret: Option<crate::bmc::Secret>,
    /// The ttl_secs from the last apply ctx, shared so tests can assert the
    /// context reached the driver.
    pub last_ttl_secs: std::sync::Arc<std::sync::Mutex<Option<u64>>>,
}

impl FakeDriver {
    pub fn new(channel: Channel, script: Script, log: CallLog) -> Box<FakeDriver> {
        Box::new(FakeDriver {
            channel,
            script,
            log,
            open: false,
            secret: None,
            last_ttl_secs: Default::default(),
        })
    }

    /// A fake that yields `secret` from take_secret after a successful apply.
    pub fn with_secret(channel: Channel, log: CallLog, secret: &str) -> Box<FakeDriver> {
        Box::new(FakeDriver {
            channel,
            script: Script::Succeed,
            log,
            open: false,
            secret: Some(crate::bmc::Secret::new(secret.to_string())),
            last_ttl_secs: Default::default(),
        })
    }

    /// A fake that already reads as open — models a durable resource that
    /// survived a restart, so `reestablish` (default = verify) reports Open.
    pub fn already_open(channel: Channel, script: Script, log: CallLog) -> Box<FakeDriver> {
        Box::new(FakeDriver {
            channel,
            script,
            log,
            open: true,
            last_ttl_secs: Default::default(),
            secret: None,
        })
    }
}

impl ChannelDriver for FakeDriver {
    fn channel(&self) -> Channel {
        self.channel
    }

    fn apply(&mut self, _host: &Host, ctx: &super::ApplyCtx) -> Result<(), DriverError> {
        // The ttl is recorded so tests can assert the context actually
        // arrived at the driver (the E4 device channel depends on it).
        self.last_ttl_secs.lock().unwrap().replace(ctx.ttl_secs);
        self.log.lock().unwrap().push((self.channel, "apply"));
        match self.script {
            Script::FailApply | Script::FailBoth => {
                // Atomic-or-reported: a failing apply may still have opened
                // something. Model the worst case.
                self.open = true;
                Err(DriverError(format!(
                    "scripted apply failure on {:?}",
                    self.channel
                )))
            }
            _ => {
                self.open = true;
                Ok(())
            }
        }
    }

    fn revert(&mut self, _host: &Host) -> Result<(), DriverError> {
        self.log.lock().unwrap().push((self.channel, "revert"));
        match self.script {
            Script::FailRevert | Script::FailBoth => Err(DriverError(format!(
                "scripted revert failure on {:?}",
                self.channel
            ))),
            _ => {
                self.open = false;
                Ok(())
            }
        }
    }

    fn verify(&mut self, _host: &Host) -> Result<ChannelState, DriverError> {
        self.log.lock().unwrap().push((self.channel, "verify"));
        Ok(if self.open {
            ChannelState::Open
        } else {
            ChannelState::Closed
        })
    }

    fn take_secret(&mut self) -> Option<crate::bmc::Secret> {
        self.secret.take()
    }

    fn suspend(&mut self) {
        // Models killing a daemon-held resource (the tunnel) without
        // reverting: the "host" now reads closed, but no revert ran.
        self.log.lock().unwrap().push((self.channel, "suspend"));
        self.open = false;
    }
}
