//! The grant registry: one grant per inventory host.
//!
//! Fail-closed at the boundary: lychgate refuses to track hosts it was never
//! told about, so a typo'd host name is an error, not a fresh implicit grant.
//! The lifecycle methods mirror `Grant`'s write-ahead transitions; the
//! daemon persists between each step.

use std::collections::BTreeMap;
use std::fmt;
use std::time::SystemTime;

use crate::approval::ApprovalRequest;
use crate::grant::{Grant, GrantError, GrantStatus};
use crate::inventory::{Channel, Inventory};
use crate::ttl::Ttl;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// Fail-closed: lychgate refuses hosts it was never told about.
    UnknownHost(String),
    Grant(GrantError),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::UnknownHost(host) => {
                write!(f, "host {host:?} is not in the inventory")
            }
            RegistryError::Grant(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for RegistryError {}

/// A grant that was observed expired and transitioned to needs-revert, with
/// what the journal's expire event needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredGrant {
    pub host: String,
    pub opened_at: SystemTime,
    pub expires_at: SystemTime,
    pub channels: Vec<Channel>,
}

/// A pending request whose approval window lapsed unapproved, reaped to closed.
/// No nonce (a challenge) or token is carried into the audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredPending {
    pub host: String,
    pub requested_at: SystemTime,
    pub approval_deadline: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRegistry {
    grants: BTreeMap<String, Grant>,
}

impl GrantRegistry {
    /// Every inventory host starts with a closed grant.
    pub fn new(inventory: &Inventory) -> GrantRegistry {
        GrantRegistry {
            grants: inventory
                .hosts
                .iter()
                .map(|h| (h.name.clone(), Grant::new()))
                .collect(),
        }
    }

    fn grant_mut(&mut self, host: &str) -> Result<&mut Grant, RegistryError> {
        self.grants
            .get_mut(host)
            .ok_or_else(|| RegistryError::UnknownHost(host.to_string()))
    }

    pub fn begin_open(
        &mut self,
        host: &str,
        now: SystemTime,
        ttl: &Ttl,
        channels: Vec<Channel>,
    ) -> Result<SystemTime, RegistryError> {
        self.grant_mut(host)?
            .begin_open(now, ttl, channels)
            .map_err(RegistryError::Grant)
    }

    pub fn finish_open(&mut self, host: &str) -> Result<(), RegistryError> {
        self.grant_mut(host)?
            .finish_open()
            .map_err(RegistryError::Grant)
    }

    pub fn abort_open(&mut self, host: &str) -> Result<(), RegistryError> {
        self.grant_mut(host)?
            .abort_open()
            .map_err(RegistryError::Grant)
    }

    pub fn fail_open(
        &mut self,
        host: &str,
        stuck: Vec<Channel>,
        now: SystemTime,
    ) -> Result<(), RegistryError> {
        self.grant_mut(host)?
            .fail_open(stuck, now)
            .map_err(RegistryError::Grant)
    }

    pub fn begin_revert(
        &mut self,
        host: &str,
        now: SystemTime,
    ) -> Result<Vec<Channel>, RegistryError> {
        self.grant_mut(host)?
            .begin_revert(now)
            .map_err(RegistryError::Grant)
    }

    pub fn retain_stuck(&mut self, host: &str, stuck: Vec<Channel>) -> Result<bool, RegistryError> {
        self.grant_mut(host)?
            .retain_stuck(stuck)
            .map_err(RegistryError::Grant)
    }

    pub fn finish_revert(&mut self, host: &str) -> Result<(), RegistryError> {
        self.grant_mut(host)?
            .finish_revert()
            .map_err(RegistryError::Grant)
    }

    pub fn renew(
        &mut self,
        host: &str,
        now: SystemTime,
        ttl: &Ttl,
    ) -> Result<SystemTime, RegistryError> {
        self.grant_mut(host)?
            .renew(now, ttl)
            .map_err(RegistryError::Grant)
    }

    pub fn begin_pending(
        &mut self,
        host: &str,
        now: SystemTime,
        approval_deadline: SystemTime,
        ttl: Ttl,
        nonce: [u8; 32],
        profile: String,
    ) -> Result<(), RegistryError> {
        self.grant_mut(host)?
            .begin_pending(now, approval_deadline, ttl, nonce, profile)
            .map_err(RegistryError::Grant)
    }

    /// Record that authenticator `id`'s proof verified against `host`'s pending
    /// request. Returns whether it was newly added.
    pub fn add_satisfied(
        &mut self,
        host: &str,
        now: SystemTime,
        id: String,
    ) -> Result<bool, RegistryError> {
        self.grant_mut(host)?
            .add_satisfied(now, id)
            .map_err(RegistryError::Grant)
    }

    /// The pending request's profile, accumulated satisfied ids, and elapsed
    /// time — what the daemon evaluates the resolved authority against.
    pub fn pending_view(
        &self,
        host: &str,
        now: SystemTime,
    ) -> Result<crate::grant::PendingView, RegistryError> {
        self.grants
            .get(host)
            .ok_or_else(|| RegistryError::UnknownHost(host.to_string()))?
            .pending_view(now)
            .map_err(RegistryError::Grant)
    }

    /// Hosts observed awaiting approval right now, in name order — the reap
    /// loop's list to re-evaluate as `wait` factors accrue.
    pub fn awaiting_approval(&self, now: SystemTime) -> Vec<String> {
        self.grants
            .iter()
            .filter_map(|(name, g)| match g.status(now) {
                GrantStatus::AwaitingApproval { .. } => Some(name.clone()),
                _ => None,
            })
            .collect()
    }

    /// The challenge for a host's pending request, for the verifier.
    pub fn pending(&self, host: &str, now: SystemTime) -> Result<ApprovalRequest, RegistryError> {
        self.grants
            .get(host)
            .ok_or_else(|| RegistryError::UnknownHost(host.to_string()))?
            .pending_request(host, now)
            .map_err(RegistryError::Grant)
    }

    pub fn approve_to_opening(
        &mut self,
        host: &str,
        now: SystemTime,
        channels: Vec<Channel>,
    ) -> Result<SystemTime, RegistryError> {
        self.grant_mut(host)?
            .approve_to_opening(now, channels)
            .map_err(RegistryError::Grant)
    }

    pub fn cancel_pending(&mut self, host: &str) -> Result<(), RegistryError> {
        self.grant_mut(host)?
            .cancel_pending()
            .map_err(RegistryError::Grant)
    }

    pub fn status(&self, host: &str, now: SystemTime) -> Result<GrantStatus, RegistryError> {
        self.grants
            .get(host)
            .map(|g| g.status(now))
            .ok_or_else(|| RegistryError::UnknownHost(host.to_string()))
    }

    /// Every host's status, in name order.
    pub fn statuses(&self, now: SystemTime) -> Vec<(&str, GrantStatus)> {
        self.grants
            .iter()
            .map(|(name, g)| (name.as_str(), g.status(now)))
            .collect()
    }

    /// Transitions every observed-Expired grant to needs-revert and returns
    /// what the expire journal events need, in name order. Journal-once: the
    /// grants are needs-revert afterwards, so a second reap at the same
    /// instant returns nothing.
    pub fn reap_to_revert(&mut self, now: SystemTime) -> Vec<ExpiredGrant> {
        let mut expired = Vec::new();
        for (name, grant) in self.grants.iter_mut() {
            if grant.status(now) != GrantStatus::Expired {
                continue;
            }
            let (opened_at, expires_at) = match grant.parts() {
                Some(crate::grant::GrantParts::Open {
                    opened_at,
                    expires_at,
                    ..
                }) => (opened_at, expires_at),
                _ => unreachable!("only stored-open grants observe as expired"),
            };
            let channels = grant
                .begin_revert(now)
                .expect("an expired grant can always begin revert");
            expired.push(ExpiredGrant {
                host: name.clone(),
                opened_at,
                expires_at,
                channels,
            });
        }
        expired
    }

    /// Cancels every pending request observed past its approval window and
    /// returns what the journal needs, in name order. Journal-once: the grants
    /// are Closed afterwards. Nothing is reverted — a pending request applied
    /// nothing.
    pub fn reap_expired_pending(&mut self, now: SystemTime) -> Vec<ExpiredPending> {
        let mut expired = Vec::new();
        for (name, grant) in self.grants.iter_mut() {
            if grant.status(now) != GrantStatus::ApprovalExpired {
                continue;
            }
            let (requested_at, approval_deadline) = match grant.parts() {
                Some(crate::grant::GrantParts::Pending {
                    requested_at,
                    approval_deadline,
                    ..
                }) => (requested_at, approval_deadline),
                _ => unreachable!("only pending grants observe as approval-expired"),
            };
            grant
                .cancel_pending()
                .expect("an approval-expired grant is pending");
            expired.push(ExpiredPending {
                host: name.clone(),
                requested_at,
                approval_deadline,
            });
        }
        expired
    }

    /// Hosts whose grants currently need revert, with their stuck channels,
    /// in name order. The retry list for every pass.
    pub fn needing_revert(&self, now: SystemTime) -> Vec<(String, Vec<Channel>)> {
        self.grants
            .iter()
            .filter_map(|(name, g)| match g.status(now) {
                GrantStatus::NeedsRevert { channels } => Some((name.clone(), channels)),
                _ => None,
            })
            .collect()
    }

    /// Hosts observed open right now, with the channels they applied, in name
    /// order. Used at boot to re-establish daemon-held resources (the vnc
    /// tunnel) for grants that outlived a daemon restart. Expired grants are
    /// omitted — the reap loop handles those.
    pub fn open_channels(&self, now: SystemTime) -> Vec<(String, Vec<Channel>)> {
        self.grants
            .iter()
            .filter_map(|(name, g)| match g.status(now) {
                GrantStatus::Open { .. } => match g.parts() {
                    Some(crate::grant::GrantParts::Open { channels, .. }) => {
                        Some((name.clone(), channels))
                    }
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    /// Boot-time demotion: a stored Opening means a daemon died mid-apply,
    /// and nobody knows how far it got — every intended channel must be
    /// treated as possibly applied. Only callable when nothing can be
    /// legitimately in flight (before the listener starts).
    pub fn demote_opening(&mut self, now: SystemTime) -> Vec<(String, Vec<Channel>)> {
        let mut demoted = Vec::new();
        for (name, grant) in self.grants.iter_mut() {
            if grant.status(now) != GrantStatus::Opening {
                continue;
            }
            let channels = match grant.parts() {
                Some(crate::grant::GrantParts::Opening { channels, .. }) => channels,
                _ => unreachable!("status said opening"),
            };
            grant
                .fail_open(channels.clone(), now)
                .expect("an opening grant can always be failed");
            demoted.push((name.clone(), channels));
        }
        demoted
    }

    /// For the snapshot layer: stored grants in name order.
    pub(crate) fn grants(&self) -> impl Iterator<Item = (&str, &Grant)> {
        self.grants.iter().map(|(name, g)| (name.as_str(), g))
    }

    /// For the snapshot layer: whether this host is in the inventory the
    /// registry was built from.
    pub(crate) fn knows(&self, host: &str) -> bool {
        self.grants.contains_key(host)
    }

    /// For the snapshot layer: replace a known host's grant with restored
    /// state. Membership is checked by the caller before this runs.
    pub(crate) fn restore(&mut self, host: &str, grant: Grant) {
        if let Some(slot) = self.grants.get_mut(host) {
            *slot = grant;
        }
    }
}

#[cfg(test)]
mod tests;
