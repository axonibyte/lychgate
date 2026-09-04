//! The registry's on-disk shape.
//!
//! Snapshots are observation-free: they record stored state, never
//! `status(now)`. A grant that is stored open but observed expired persists
//! as open across a restart, so the restarted daemon observes the expiry and
//! journals it — journal-once survives a death between expiry and
//! observation.
//!
//! Versioned from the first commit, because the alternative is guessing
//! later what an unversioned file meant. The version *check* lives in the
//! daemon's store, which owns the file path the refusal must name.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::grant::Grant;
use crate::inventory::Inventory;
use crate::registry::GrantRegistry;
use crate::ttl::MAX_TTL_SECS;

pub const STATE_VERSION: u32 = 1;

/// Unlike reaper's state document, this one refuses unknown fields: the file
/// is machine-written but hand-editable, and a stray edit to break-glass
/// state must fail at load, consistent with the inventory's ethos.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateDoc {
    pub version: u32,
    /// Absence means closed; only open grants are recorded.
    pub open_grants: BTreeMap<String, OpenGrant>,
}

impl Default for StateDoc {
    fn default() -> StateDoc {
        StateDoc {
            version: STATE_VERSION,
            open_grants: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenGrant {
    #[serde(with = "epoch")]
    pub opened_at: SystemTime,
    #[serde(with = "epoch")]
    pub expires_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// All offenders at once, so one refusal names every host that must be
    /// resolved. Fail-closed: removing a host from the inventory while it
    /// holds an open grant must not silently drop the grant.
    UnknownHosts(Vec<String>),
    /// Impossible via open(), so the file was edited or corrupted.
    ExpiryNotAfterOpening { host: String },
    /// A span over the TTL cap is a cap bypass, however it got there.
    ExceedsCap { host: String, secs: u64 },
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::UnknownHosts(hosts) => write!(
                f,
                "state records open grants for hosts not in the inventory: {hosts:?}; \
                 a host cannot leave the inventory while its grant is open"
            ),
            SnapshotError::ExpiryNotAfterOpening { host } => {
                write!(f, "state for host {host:?} expires at or before it opened")
            }
            SnapshotError::ExceedsCap { host, secs } => write!(
                f,
                "state for host {host:?} spans {secs}s, over the {MAX_TTL_SECS}s cap"
            ),
        }
    }
}

impl std::error::Error for SnapshotError {}

/// Times are stored as whole seconds since the epoch: this file is read by
/// people during incidents, and a number they can paste into date(1) is
/// worth more than nanoseconds.
mod epoch {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(
            t.duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
        let secs = u64::deserialize(d)?;
        from_secs_checked(secs)
            .ok_or_else(|| serde::de::Error::custom("epoch seconds overflow SystemTime"))
    }
}

/// Checked, because this arrives from a file: a value that overflows
/// SystemTime must surface as a load error, not a panic.
fn from_secs_checked(secs: u64) -> Option<SystemTime> {
    UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

impl GrantRegistry {
    /// Observation-free: records stored state, not `status(now)`.
    pub fn snapshot(&self) -> StateDoc {
        StateDoc {
            version: STATE_VERSION,
            open_grants: self
                .grants()
                .filter_map(|(name, grant)| {
                    grant.open_parts().map(|(opened_at, expires_at)| {
                        (
                            name.to_string(),
                            OpenGrant {
                                opened_at,
                                expires_at,
                            },
                        )
                    })
                })
                .collect(),
        }
    }

    /// Rebuilds a registry from the inventory and a state document. A past
    /// expiry is accepted — that is the normal restart-past-expiry case; the
    /// reload observes it.
    pub fn from_parts(
        inventory: &Inventory,
        doc: &StateDoc,
    ) -> Result<GrantRegistry, SnapshotError> {
        let mut registry = GrantRegistry::new(inventory);

        let unknown: Vec<String> = doc
            .open_grants
            .keys()
            .filter(|host| !registry.knows(host))
            .cloned()
            .collect();
        if !unknown.is_empty() {
            return Err(SnapshotError::UnknownHosts(unknown));
        }

        for (host, open) in &doc.open_grants {
            let span = match open.expires_at.duration_since(open.opened_at) {
                Ok(span) if !span.is_zero() => span,
                _ => return Err(SnapshotError::ExpiryNotAfterOpening { host: host.clone() }),
            };
            if span.as_secs() > MAX_TTL_SECS {
                return Err(SnapshotError::ExceedsCap {
                    host: host.clone(),
                    secs: span.as_secs(),
                });
            }
            registry.restore(host, Grant::restore_open(open.opened_at, open.expires_at));
        }

        Ok(registry)
    }
}

#[cfg(test)]
mod tests;
