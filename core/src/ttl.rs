//! TTL parsing and policy.

use std::fmt;
use std::time::Duration;

/// Break-glass access is never open-ended: no grant may live longer than a
/// day. A multi-day incident reopens explicitly.
pub const MAX_TTL_SECS: u64 = 24 * 60 * 60;

/// Renewal is only accepted this close to expiry, so time cannot be
/// stockpiled ahead of need.
pub const RENEWAL_WINDOW_SECS: u64 = 2 * 60 * 60;

/// A validated time-to-live. Invariant: `0 < secs <= MAX_TTL_SECS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ttl(Duration);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TtlError {
    /// A zero TTL is a grant that was never open; refuse it rather than let
    /// "open" mean nothing.
    Zero,
    ExceedsCap {
        secs: u64,
    },
    Unparseable(String),
    Overflow,
}

impl fmt::Display for TtlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TtlError::Zero => write!(f, "ttl must be greater than zero"),
            TtlError::ExceedsCap { secs } => write!(
                f,
                "ttl of {secs}s exceeds the {MAX_TTL_SECS}s cap; break-glass access is never open-ended"
            ),
            TtlError::Unparseable(s) => {
                write!(f, "unparseable ttl {s:?}; expected forms like 90s, 15m, 2h")
            }
            TtlError::Overflow => write!(f, "ttl does not fit in seconds"),
        }
    }
}

impl std::error::Error for TtlError {}

impl Ttl {
    pub fn from_secs(secs: u64) -> Result<Ttl, TtlError> {
        if secs == 0 {
            return Err(TtlError::Zero);
        }
        if secs > MAX_TTL_SECS {
            return Err(TtlError::ExceedsCap { secs });
        }
        Ok(Ttl(Duration::from_secs(secs)))
    }

    /// Parses `"90s"`, `"15m"`, or `"2h"`. The unit is required: a bare
    /// number is refused rather than guessed at.
    pub fn parse(s: &str) -> Result<Ttl, TtlError> {
        let unparseable = || TtlError::Unparseable(s.to_string());
        let (digits, per_unit): (&str, u64) = if let Some(d) = s.strip_suffix('s') {
            (d, 1)
        } else if let Some(d) = s.strip_suffix('m') {
            (d, 60)
        } else if let Some(d) = s.strip_suffix('h') {
            (d, 60 * 60)
        } else {
            return Err(unparseable());
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(unparseable());
        }
        let count: u64 = digits.parse().map_err(|_| TtlError::Overflow)?;
        let secs = count.checked_mul(per_unit).ok_or(TtlError::Overflow)?;
        Ttl::from_secs(secs)
    }

    pub fn duration(&self) -> Duration {
        self.0
    }
}

impl fmt::Display for Ttl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}s", self.0.as_secs())
    }
}

#[cfg(test)]
mod tests;
