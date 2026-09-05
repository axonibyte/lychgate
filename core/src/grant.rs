//! The grant state machine.
//!
//! Time is injected: every observation takes `now`, and expiry is a property
//! of observation rather than of a background thread.
//!
//! Since M3 the machine carries write-ahead intent: side effects never start
//! from unrecorded state. `Opening` is persisted before any driver runs;
//! `NeedsRevert` is the only stored path from `Open` back to `Closed`, so a
//! crash anywhere in the lifecycle restarts into a state that either retries
//! the revert or is demoted to needing one — never into a grant that quietly
//! claims more or less access than the host may really have.
//!
//! ```text
//! Closed ──begin_open──▶ Opening ──finish_open──▶ Open
//!                        Opening ──abort_open───▶ Closed        (unwound cleanly)
//!                        Opening ──fail_open────▶ NeedsRevert   (stuck channels)
//! Open ──begin_revert──▶ NeedsRevert ──finish_revert──▶ Closed
//! ```

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use crate::approval::ApprovalRequest;
use crate::inventory::Channel;
use crate::ttl::{Ttl, RENEWAL_WINDOW_SECS};

/// The longest an unapproved request may sit pending before it lapses. Raised
/// to the TTL cap (24h) so hour-scale `wait` factors are usable: a pending grant
/// must be able to live long enough to collect the weight a wait contributes. A
/// hand-edited state file claiming a longer window is refused by the snapshot
/// layer.
pub const MAX_APPROVAL_WINDOW_SECS: u64 = crate::ttl::MAX_TTL_SECS;

#[derive(Debug, Clone, PartialEq, Eq)]
enum GrantState {
    Closed,
    /// An operator approval has been requested but not yet granted. Holds no
    /// access and applied nothing; it lapses at `approval_deadline` and is
    /// reaped, fail-closed. Authenticator proofs accumulate in `satisfied` as
    /// they arrive; the daemon evaluates the resolved `profile`'s authority and,
    /// once the weighted threshold is met, carries the grant to Opening
    /// (anchoring the grant's expiry at that instant, never at request time).
    Pending {
        requested_at: SystemTime,
        approval_deadline: SystemTime,
        ttl: Ttl,
        nonce: [u8; 32],
        /// The approval profile requested at open time.
        profile: String,
        /// Authenticator ids whose proofs have verified against this request's
        /// challenge so far. Never a secret or a token — just which factors are
        /// satisfied.
        satisfied: BTreeSet<String>,
    },
    /// Persisted intent: drivers are (or were) running. A daemon that boots
    /// into this state crashed mid-open and must demote it to NeedsRevert.
    Opening {
        opened_at: SystemTime,
        expires_at: SystemTime,
        channels: Vec<Channel>,
    },
    Open {
        opened_at: SystemTime,
        expires_at: SystemTime,
        /// What was actually applied at open time — what revert must undo,
        /// regardless of what the inventory says later.
        channels: Vec<Channel>,
    },
    NeedsRevert {
        channels: Vec<Channel>,
        since: SystemTime,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantStatus {
    Closed,
    /// A request awaiting operator approval, within its window.
    AwaitingApproval {
        remaining: Duration,
    },
    /// A pending request observed at/after its approval deadline. Fail-closed:
    /// it approves nothing now and is reaped.
    ApprovalExpired,
    /// Mid-open: drivers in flight, or a crash left the intent behind.
    Opening,
    Open {
        remaining: Duration,
    },
    /// Stored as open, observed at or past its expiry. Fail-closed: whatever
    /// the grant opened must be treated as due for revert.
    Expired,
    /// Channels are (or may be) applied on the host and must be reverted;
    /// retried until empty.
    NeedsRevert {
        channels: Vec<Channel>,
    },
}

/// What the daemon reads from a pending grant to evaluate its authority: the
/// requested profile, the accumulated satisfied authenticator ids, and the time
/// elapsed since the request (for `wait` factors).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingView {
    pub profile: String,
    pub satisfied: BTreeSet<String>,
    pub requested_at: SystemTime,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantError {
    AlreadyOpen,
    NotOpen,
    /// The grant is mid-open; resolve that before anything else.
    MidOpen,
    /// A request is already awaiting approval for this host.
    AlreadyPending,
    /// The grant is not awaiting approval (nothing to approve/cancel).
    NotPending,
    /// The approval window elapsed before the token arrived; reopen explicitly.
    ApprovalWindowElapsed,
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
            GrantError::MidOpen => write!(f, "grant is mid-open; retry shortly"),
            GrantError::AlreadyPending => {
                write!(f, "a request is already awaiting approval for this host")
            }
            GrantError::NotPending => write!(f, "grant is not awaiting approval"),
            GrantError::ApprovalWindowElapsed => write!(
                f,
                "the approval window elapsed before the token arrived; reopen to try again"
            ),
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
        match &self.state {
            GrantState::Closed => GrantStatus::Closed,
            GrantState::Pending {
                approval_deadline, ..
            } => match approval_deadline.duration_since(now) {
                // Observed at the exact deadline instant: expired, not "zero
                // seconds left" — the same rule as an open grant's expiry.
                Ok(remaining) if !remaining.is_zero() => {
                    GrantStatus::AwaitingApproval { remaining }
                }
                _ => GrantStatus::ApprovalExpired,
            },
            GrantState::Opening { .. } => GrantStatus::Opening,
            GrantState::NeedsRevert { channels, .. } => GrantStatus::NeedsRevert {
                channels: channels.clone(),
            },
            GrantState::Open { expires_at, .. } => match expires_at.duration_since(now) {
                // duration_since errs when now >= the boundary would leave
                // zero: a grant observed at the exact expiry instant is
                // expired, not open for zero more seconds.
                Ok(remaining) if !remaining.is_zero() => GrantStatus::Open { remaining },
                _ => GrantStatus::Expired,
            },
        }
    }

    /// Records the intent to open, before any driver runs. Only a Closed
    /// grant may begin opening: an expired or needs-revert grant holds
    /// channels that must be reverted first — reopening over them would
    /// lose track of what is applied on the host.
    pub fn begin_open(
        &mut self,
        now: SystemTime,
        ttl: &Ttl,
        channels: Vec<Channel>,
    ) -> Result<SystemTime, GrantError> {
        match self.status(now) {
            GrantStatus::Closed => {}
            GrantStatus::Opening => return Err(GrantError::MidOpen),
            _ => return Err(GrantError::AlreadyOpen),
        }
        let expires_at = now
            .checked_add(ttl.duration())
            .ok_or(GrantError::ClockOverflow)?;
        self.state = GrantState::Opening {
            opened_at: now,
            expires_at,
            channels,
        };
        Ok(expires_at)
    }

    /// Every drivable channel applied: the grant is open, and its recorded
    /// channels are exactly what was applied.
    pub fn finish_open(&mut self) -> Result<(), GrantError> {
        match &self.state {
            GrantState::Opening {
                opened_at,
                expires_at,
                channels,
            } => {
                self.state = GrantState::Open {
                    opened_at: *opened_at,
                    expires_at: *expires_at,
                    channels: channels.clone(),
                };
                Ok(())
            }
            _ => Err(GrantError::NotOpen),
        }
    }

    /// The apply failed and the unwind reverted everything: back to Closed,
    /// cleanly refused.
    pub fn abort_open(&mut self) -> Result<(), GrantError> {
        match &self.state {
            GrantState::Opening { .. } => {
                self.state = GrantState::Closed;
                Ok(())
            }
            _ => Err(GrantError::NotOpen),
        }
    }

    /// The apply failed and `stuck` channels could not be unwound: they are
    /// (or may be) applied on the host and must be reverted.
    pub fn fail_open(&mut self, stuck: Vec<Channel>, now: SystemTime) -> Result<(), GrantError> {
        match &self.state {
            GrantState::Opening { .. } => {
                self.state = GrantState::NeedsRevert {
                    channels: stuck,
                    since: now,
                };
                Ok(())
            }
            _ => Err(GrantError::NotOpen),
        }
    }

    /// Records that this grant must end up closed (operator close or expiry)
    /// before any revert runs. Idempotent from NeedsRevert — a retry changes
    /// nothing. Returns the channels to revert.
    pub fn begin_revert(&mut self, now: SystemTime) -> Result<Vec<Channel>, GrantError> {
        match &self.state {
            GrantState::Open { channels, .. } => {
                let channels = channels.clone();
                self.state = GrantState::NeedsRevert {
                    channels: channels.clone(),
                    since: now,
                };
                Ok(channels)
            }
            GrantState::NeedsRevert { channels, .. } => Ok(channels.clone()),
            GrantState::Opening { .. } => Err(GrantError::MidOpen),
            // A pending grant is cancelled, not reverted (it applied nothing);
            // close routes there instead of here.
            GrantState::Pending { .. } => Err(GrantError::NotPending),
            GrantState::Closed => Err(GrantError::NotOpen),
        }
    }

    /// Some channels reverted, these did not. Returns true if the stuck set
    /// changed (worth journaling), false on an identical retry.
    pub fn retain_stuck(&mut self, stuck: Vec<Channel>) -> Result<bool, GrantError> {
        match &mut self.state {
            GrantState::NeedsRevert { channels, .. } => {
                let changed = *channels != stuck;
                *channels = stuck;
                Ok(changed)
            }
            _ => Err(GrantError::NotOpen),
        }
    }

    /// Everything reverted: closed for real.
    pub fn finish_revert(&mut self) -> Result<(), GrantError> {
        match &self.state {
            GrantState::NeedsRevert { .. } => {
                self.state = GrantState::Closed;
                Ok(())
            }
            _ => Err(GrantError::NotOpen),
        }
    }

    /// Renews an open grant. Accepted only inside the final renewal window
    /// before expiry; the new expiry is anchored at `now`, never at the old
    /// expiry. Expired, mid-open, and needs-revert grants are refused —
    /// renewal never resurrects anything.
    pub fn renew(&mut self, now: SystemTime, ttl: &Ttl) -> Result<SystemTime, GrantError> {
        let remaining = match self.status(now) {
            GrantStatus::Open { remaining } => remaining,
            _ => return Err(GrantError::NotOpen),
        };
        if remaining > Duration::from_secs(RENEWAL_WINDOW_SECS) {
            return Err(GrantError::TooEarly { remaining });
        }
        let expires_at = now
            .checked_add(ttl.duration())
            .ok_or(GrantError::ClockOverflow)?;
        if let GrantState::Open {
            opened_at,
            channels,
            ..
        } = &self.state
        {
            self.state = GrantState::Open {
                opened_at: *opened_at,
                expires_at,
                channels: channels.clone(),
            };
        }
        Ok(expires_at)
    }

    /// Records a pending approval request, before any driver runs and before
    /// the grant may open. Only a Closed grant may begin: a pending or open
    /// grant already holds a request or access.
    pub fn begin_pending(
        &mut self,
        now: SystemTime,
        approval_deadline: SystemTime,
        ttl: Ttl,
        nonce: [u8; 32],
        profile: String,
    ) -> Result<(), GrantError> {
        match self.status(now) {
            GrantStatus::Closed => {}
            GrantStatus::Opening => return Err(GrantError::MidOpen),
            GrantStatus::AwaitingApproval { .. } | GrantStatus::ApprovalExpired => {
                return Err(GrantError::AlreadyPending)
            }
            _ => return Err(GrantError::AlreadyOpen),
        }
        self.state = GrantState::Pending {
            requested_at: now,
            approval_deadline,
            ttl,
            nonce,
            profile,
            satisfied: BTreeSet::new(),
        };
        Ok(())
    }

    /// Record that authenticator `id`'s proof has verified against this
    /// request's challenge. Only a request still within its window accepts
    /// proofs; a lapsed one is refused (the reaper will clean it up). Returns
    /// whether the id was newly added (worth journaling) versus a re-submission.
    pub fn add_satisfied(&mut self, now: SystemTime, id: String) -> Result<bool, GrantError> {
        match self.status(now) {
            GrantStatus::AwaitingApproval { .. } => {}
            GrantStatus::ApprovalExpired => return Err(GrantError::ApprovalWindowElapsed),
            _ => return Err(GrantError::NotPending),
        }
        match &mut self.state {
            GrantState::Pending { satisfied, .. } => Ok(satisfied.insert(id)),
            _ => Err(GrantError::NotPending),
        }
    }

    /// The pending request's profile, its accumulated satisfied authenticator
    /// ids, and the time elapsed since it was requested — what the daemon needs
    /// to evaluate the resolved authority. A lapsed window is refused.
    pub fn pending_view(&self, now: SystemTime) -> Result<PendingView, GrantError> {
        match self.status(now) {
            GrantStatus::AwaitingApproval { .. } => {}
            GrantStatus::ApprovalExpired => return Err(GrantError::ApprovalWindowElapsed),
            _ => return Err(GrantError::NotPending),
        }
        match &self.state {
            GrantState::Pending {
                requested_at,
                profile,
                satisfied,
                ..
            } => Ok(PendingView {
                profile: profile.clone(),
                satisfied: satisfied.clone(),
                requested_at: *requested_at,
                elapsed: now.duration_since(*requested_at).unwrap_or_default(),
            }),
            _ => Err(GrantError::NotPending),
        }
    }

    /// The challenge for a request awaiting approval, for the verifier. A
    /// lapsed window is refused (the reaper will clean it up).
    pub(crate) fn pending_request(
        &self,
        host: &str,
        now: SystemTime,
    ) -> Result<ApprovalRequest, GrantError> {
        match self.status(now) {
            GrantStatus::AwaitingApproval { .. } => {}
            GrantStatus::ApprovalExpired => return Err(GrantError::ApprovalWindowElapsed),
            _ => return Err(GrantError::NotPending),
        }
        match &self.state {
            GrantState::Pending {
                requested_at,
                ttl,
                nonce,
                ..
            } => Ok(ApprovalRequest::new(
                *nonce,
                host.to_string(),
                ttl.duration().as_secs(),
                *requested_at,
            )),
            _ => Err(GrantError::NotPending),
        }
    }

    /// A verified approval carries a pending request to Opening, anchoring the
    /// grant's expiry at `now` (never at request time — time is not
    /// stockpiled while awaiting approval). A lapsed window is refused.
    pub fn approve_to_opening(
        &mut self,
        now: SystemTime,
        channels: Vec<Channel>,
    ) -> Result<SystemTime, GrantError> {
        let ttl = match self.status(now) {
            GrantStatus::AwaitingApproval { .. } => match &self.state {
                GrantState::Pending { ttl, .. } => *ttl,
                _ => return Err(GrantError::NotPending),
            },
            GrantStatus::ApprovalExpired => return Err(GrantError::ApprovalWindowElapsed),
            _ => return Err(GrantError::NotPending),
        };
        let expires_at = now
            .checked_add(ttl.duration())
            .ok_or(GrantError::ClockOverflow)?;
        self.state = GrantState::Opening {
            opened_at: now,
            expires_at,
            channels,
        };
        Ok(expires_at)
    }

    /// Cancels a pending request (an operator close, or the reaper aging out a
    /// lapsed window). Nothing was applied, so there is nothing to revert.
    pub fn cancel_pending(&mut self) -> Result<(), GrantError> {
        match &self.state {
            GrantState::Pending { .. } => {
                self.state = GrantState::Closed;
                Ok(())
            }
            _ => Err(GrantError::NotPending),
        }
    }
}

impl Default for Grant {
    fn default() -> Grant {
        Grant::new()
    }
}

/// The stored shape, mirrored by the snapshot layer. Interval sanity is the
/// snapshot layer's job before restore is called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GrantParts {
    Pending {
        requested_at: SystemTime,
        approval_deadline: SystemTime,
        ttl: Ttl,
        nonce: [u8; 32],
        profile: String,
        satisfied: BTreeSet<String>,
    },
    Opening {
        opened_at: SystemTime,
        expires_at: SystemTime,
        channels: Vec<Channel>,
    },
    Open {
        opened_at: SystemTime,
        expires_at: SystemTime,
        channels: Vec<Channel>,
    },
    NeedsRevert {
        channels: Vec<Channel>,
        since: SystemTime,
    },
}

impl Grant {
    /// Stored state, not an observation: an expired-but-unreaped grant
    /// still reports its open interval. Closed is None (absence).
    pub(crate) fn parts(&self) -> Option<GrantParts> {
        match &self.state {
            GrantState::Closed => None,
            GrantState::Pending {
                requested_at,
                approval_deadline,
                ttl,
                nonce,
                profile,
                satisfied,
            } => Some(GrantParts::Pending {
                requested_at: *requested_at,
                approval_deadline: *approval_deadline,
                ttl: *ttl,
                nonce: *nonce,
                profile: profile.clone(),
                satisfied: satisfied.clone(),
            }),
            GrantState::Opening {
                opened_at,
                expires_at,
                channels,
            } => Some(GrantParts::Opening {
                opened_at: *opened_at,
                expires_at: *expires_at,
                channels: channels.clone(),
            }),
            GrantState::Open {
                opened_at,
                expires_at,
                channels,
            } => Some(GrantParts::Open {
                opened_at: *opened_at,
                expires_at: *expires_at,
                channels: channels.clone(),
            }),
            GrantState::NeedsRevert { channels, since } => Some(GrantParts::NeedsRevert {
                channels: channels.clone(),
                since: *since,
            }),
        }
    }

    pub(crate) fn restore(parts: GrantParts) -> Grant {
        let state = match parts {
            GrantParts::Pending {
                requested_at,
                approval_deadline,
                ttl,
                nonce,
                profile,
                satisfied,
            } => GrantState::Pending {
                requested_at,
                approval_deadline,
                ttl,
                nonce,
                profile,
                satisfied,
            },
            GrantParts::Opening {
                opened_at,
                expires_at,
                channels,
            } => GrantState::Opening {
                opened_at,
                expires_at,
                channels,
            },
            GrantParts::Open {
                opened_at,
                expires_at,
                channels,
            } => GrantState::Open {
                opened_at,
                expires_at,
                channels,
            },
            GrantParts::NeedsRevert { channels, since } => {
                GrantState::NeedsRevert { channels, since }
            }
        };
        Grant { state }
    }
}

#[cfg(test)]
mod tests;
