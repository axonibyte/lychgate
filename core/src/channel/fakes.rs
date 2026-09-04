//! Scripted fake drivers for the error-injection tier. Test-only: these are
//! compiled under cfg(test) and can never reach a release binary.

use std::cell::RefCell;
use std::rc::Rc;

use super::{ChannelDriver, ChannelState, DriverError};
use crate::inventory::{Channel, Host};

/// What a fake does when poked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Script {
    Succeed,
    FailApply,
    FailRevert,
    FailBoth,
}

/// Every call every fake received, in order, shared across the set. This is
/// the second oracle: tests assert the registry's claim AND that the calls
/// really happened (or really did not).
pub(crate) type CallLog = Rc<RefCell<Vec<(Channel, &'static str)>>>;

pub(crate) struct FakeDriver {
    channel: Channel,
    script: Script,
    log: CallLog,
    /// Tracks what "the host" would show, so verify has real state to read.
    open: bool,
}

impl FakeDriver {
    pub(crate) fn new(channel: Channel, script: Script, log: CallLog) -> Box<FakeDriver> {
        Box::new(FakeDriver {
            channel,
            script,
            log,
            open: false,
        })
    }
}

impl ChannelDriver for FakeDriver {
    fn channel(&self) -> Channel {
        self.channel
    }

    fn apply(&mut self, _host: &Host) -> Result<(), DriverError> {
        self.log.borrow_mut().push((self.channel, "apply"));
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
        self.log.borrow_mut().push((self.channel, "revert"));
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
        self.log.borrow_mut().push((self.channel, "verify"));
        Ok(if self.open {
            ChannelState::Open
        } else {
            ChannelState::Closed
        })
    }
}
