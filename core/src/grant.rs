//! The grant state machine.
//!
//! Time is injected: every observation takes `now`, and expiry is a property
//! of observation rather than of a background thread. The daemon's revert
//! loop acts on what `status` already reports; it does not create the truth.

use std::time::{Duration, SystemTime};

use crate::ttl::{Ttl, RENEWAL_WINDOW_SECS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantState {
    Closed,
    Open {
        opened_at: SystemTime,
        expires_at: SystemTime,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantStatus {
    Closed,
    Open {
        remaining: Duration,
    },
    /// Stored as open, observed at or past its expiry. Fail-closed: whatever
    /// the grant opened must be treated as due for revert.
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseOutcome {
    WasOpen,
    AlreadyClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantError {
    AlreadyOpen,
    NotOpen,
    /// Renewal requested with more than the renewal window remaining. Time
    /// cannot be stockpiled ahead of need.
    TooEarly {
        remaining: Duration,
    },
    /// The expiry would not fit in the clock. Refusing to open beats a grant
    /// that effectively never expires.
    ClockOverflow,
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantError::AlreadyOpen => write!(f, "grant is already open"),
            GrantError::NotOpen => write!(f, "grant is not open"),
            GrantError::TooEarly { remaining } => write!(
                f,
                "renewal refused with {}s remaining; renewal opens {}s before expiry",
                remaining.as_secs(),
                RENEWAL_WINDOW_SECS
            ),
            GrantError::ClockOverflow => write!(f, "expiry does not fit in the clock"),
        }
    }
}

impl std::error::Error for GrantError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    state: GrantState,
}

impl Grant {
    pub fn new() -> Grant {
        Grant {
            state: GrantState::Closed,
        }
    }

    pub fn status(&self, now: SystemTime) -> GrantStatus {
        match self.state {
            GrantState::Closed => GrantStatus::Closed,
            GrantState::Open { expires_at, .. } => match expires_at.duration_since(now) {
                // duration_since errs when now >= the boundary would leave
                // zero: a grant observed at the exact expiry instant is
                // expired, not open for zero more seconds.
                Ok(remaining) if !remaining.is_zero() => GrantStatus::Open { remaining },
                _ => GrantStatus::Expired,
            },
        }
    }

    /// Opens the grant. Refused only while observed open; an expired grant
    /// reopens as if it were closed. Returns the expiry instant.
    pub fn open(&mut self, now: SystemTime, ttl: &Ttl) -> Result<SystemTime, GrantError> {
        if let GrantStatus::Open { .. } = self.status(now) {
            return Err(GrantError::AlreadyOpen);
        }
        let expires_at = now
            .checked_add(ttl.duration())
            .ok_or(GrantError::ClockOverflow)?;
        self.state = GrantState::Open {
            opened_at: now,
            expires_at,
        };
        Ok(expires_at)
    }

    /// Closes the grant. Idempotent; reports whether there was anything to
    /// close.
    pub fn close(&mut self) -> CloseOutcome {
        let outcome = match self.state {
            GrantState::Open { .. } => CloseOutcome::WasOpen,
            GrantState::Closed => CloseOutcome::AlreadyClosed,
        };
        self.state = GrantState::Closed;
        outcome
    }

    /// Renews an open grant. Accepted only inside the final renewal window
    /// before expiry; the new expiry is anchored at `now`, never at the old
    /// expiry. An expired grant is refused — reopening is always explicit.
    pub fn renew(&mut self, now: SystemTime, ttl: &Ttl) -> Result<SystemTime, GrantError> {
        let remaining = match self.status(now) {
            GrantStatus::Open { remaining } => remaining,
            GrantStatus::Closed | GrantStatus::Expired => return Err(GrantError::NotOpen),
        };
        if remaining > Duration::from_secs(RENEWAL_WINDOW_SECS) {
            return Err(GrantError::TooEarly { remaining });
        }
        let expires_at = now
            .checked_add(ttl.duration())
            .ok_or(GrantError::ClockOverflow)?;
        if let GrantState::Open { opened_at, .. } = self.state {
            self.state = GrantState::Open {
                opened_at,
                expires_at,
            };
        }
        Ok(expires_at)
    }
}

impl Default for Grant {
    fn default() -> Grant {
        Grant::new()
    }
}

impl Grant {
    /// The recorded open interval, for the snapshot layer. Stored state, not
    /// an observation: an expired-but-unreaped grant still reports its
    /// interval.
    pub(crate) fn open_parts(&self) -> Option<(SystemTime, SystemTime)> {
        match self.state {
            GrantState::Open {
                opened_at,
                expires_at,
            } => Some((opened_at, expires_at)),
            GrantState::Closed => None,
        }
    }

    /// Rebuilds a grant a snapshot recorded as open. Interval sanity (order,
    /// cap) is the snapshot layer's job before this is called.
    pub(crate) fn restore_open(opened_at: SystemTime, expires_at: SystemTime) -> Grant {
        Grant {
            state: GrantState::Open {
                opened_at,
                expires_at,
            },
        }
    }
}

#[cfg(test)]
mod tests;
