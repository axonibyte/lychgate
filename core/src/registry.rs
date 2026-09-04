//! The grant registry: one grant per inventory host.
//!
//! Fail-closed at the boundary: lychgate refuses to track hosts it was never
//! told about, so a typo'd host name is an error, not a fresh implicit grant.

use std::collections::BTreeMap;
use std::fmt;
use std::time::SystemTime;

use crate::grant::{CloseOutcome, Grant, GrantError, GrantStatus};
use crate::inventory::Inventory;
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

    pub fn open(
        &mut self,
        host: &str,
        now: SystemTime,
        ttl: &Ttl,
    ) -> Result<SystemTime, RegistryError> {
        self.grant_mut(host)?
            .open(now, ttl)
            .map_err(RegistryError::Grant)
    }

    pub fn close(&mut self, host: &str) -> Result<CloseOutcome, RegistryError> {
        Ok(self.grant_mut(host)?.close())
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

    /// Transitions every observed-Expired grant to Closed and returns the
    /// host names, in name order. Journal-once: a second reap at the same
    /// instant returns nothing. (M3+: revert slots in before the close.)
    pub fn reap(&mut self, now: SystemTime) -> Vec<String> {
        let mut reaped = Vec::new();
        for (name, grant) in self.grants.iter_mut() {
            if grant.status(now) == GrantStatus::Expired {
                grant.close();
                reaped.push(name.clone());
            }
        }
        reaped
    }
}

#[cfg(test)]
mod tests;
