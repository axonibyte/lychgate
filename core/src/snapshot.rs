//! The registry's on-disk shape, version 2.
//!
//! Snapshots are observation-free: they record stored state, never
//! `status(now)`. A grant that is stored open but observed expired persists
//! as open across a restart, so the restarted daemon observes the expiry and
//! journals it. A stored `Opening` survives too — boot demotes it.
//!
//! Version 2 (M3) records the lifecycle states: absence is Closed;
//! `opening`, `open`, and `needs-revert` carry their channels. Version 1
//! files are refused by the store's version check; there are no released
//! versions to migrate.
//!
//! The wire shape is decoded through a flat permissive-fields struct and
//! validated by hand rather than serde-tagged enums: every wrong field
//! combination gets a refusal naming the host and the problem, and the
//! validation code is mutation-killable.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::grant::{Grant, GrantParts};
use crate::inventory::{Channel, Inventory};
use crate::registry::GrantRegistry;
use crate::ttl::MAX_TTL_SECS;

pub const STATE_VERSION: u32 = 2;

/// Unlike reaper's state document, this one refuses unknown fields: the file
/// is machine-written but hand-editable, and a stray edit to break-glass
/// state must fail at load, consistent with the inventory's ethos.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateDoc {
    pub version: u32,
    /// Absence means closed; only lifecycle states are recorded.
    pub grants: BTreeMap<String, GrantRecord>,
}

impl Default for StateDoc {
    fn default() -> StateDoc {
        StateDoc {
            version: STATE_VERSION,
            grants: BTreeMap::new(),
        }
    }
}

/// One grant's stored state. Flat on disk: `state` names the shape, the
/// other fields belong to it, and `validate` refuses every combination the
/// daemon would never write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRecord {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none", default, with = "epoch_opt")]
    pub opened_at: Option<SystemTime>,
    #[serde(skip_serializing_if = "Option::is_none", default, with = "epoch_opt")]
    pub expires_at: Option<SystemTime>,
    #[serde(skip_serializing_if = "Option::is_none", default, with = "epoch_opt")]
    pub since: Option<SystemTime>,
    pub channels: Vec<Channel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// All offenders at once, so one refusal names every host that must be
    /// resolved. Fail-closed: removing a host from the inventory while it
    /// holds a live grant must not silently drop the grant.
    UnknownHosts(Vec<String>),
    /// Impossible via the lifecycle, so the file was edited or corrupted.
    ExpiryNotAfterOpening { host: String },
    /// A span over the TTL cap is a cap bypass, however it got there.
    ExceedsCap { host: String, secs: u64 },
    /// Wrong state name or a field combination the daemon never writes.
    Malformed { host: String, message: String },
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::UnknownHosts(hosts) => write!(
                f,
                "state records grants for hosts not in the inventory: {hosts:?}; \
                 a host cannot leave the inventory while its grant is live"
            ),
            SnapshotError::ExpiryNotAfterOpening { host } => {
                write!(f, "state for host {host:?} expires at or before it opened")
            }
            SnapshotError::ExceedsCap { host, secs } => write!(
                f,
                "state for host {host:?} spans {secs}s, over the {MAX_TTL_SECS}s cap"
            ),
            SnapshotError::Malformed { host, message } => {
                write!(f, "state for host {host:?} is malformed: {message}")
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

/// Times are stored as whole seconds since the epoch: this file is read by
/// people during incidents, and a number they can paste into date(1) is
/// worth more than nanoseconds.
mod epoch_opt {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(t: &Option<SystemTime>, s: S) -> Result<S::Ok, S::Error> {
        match t {
            Some(t) => s.serialize_u64(
                t.duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            ),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SystemTime>, D::Error> {
        let secs = Option::<u64>::deserialize(d)?;
        secs.map(|s| {
            from_secs_checked(s)
                .ok_or_else(|| serde::de::Error::custom("epoch seconds overflow SystemTime"))
        })
        .transpose()
    }
}

/// Checked, because this arrives from a file: a value that overflows
/// SystemTime must surface as a load error, not a panic.
fn from_secs_checked(secs: u64) -> Option<SystemTime> {
    UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

fn record_of(parts: GrantParts) -> GrantRecord {
    match parts {
        GrantParts::Opening {
            opened_at,
            expires_at,
            channels,
        } => GrantRecord {
            state: "opening".to_string(),
            opened_at: Some(opened_at),
            expires_at: Some(expires_at),
            since: None,
            channels,
        },
        GrantParts::Open {
            opened_at,
            expires_at,
            channels,
        } => GrantRecord {
            state: "open".to_string(),
            opened_at: Some(opened_at),
            expires_at: Some(expires_at),
            since: None,
            channels,
        },
        GrantParts::NeedsRevert { channels, since } => GrantRecord {
            state: "needs-revert".to_string(),
            opened_at: None,
            expires_at: None,
            since: Some(since),
            channels,
        },
    }
}

fn parts_of(host: &str, record: &GrantRecord) -> Result<GrantParts, SnapshotError> {
    let malformed = |message: &str| SnapshotError::Malformed {
        host: host.to_string(),
        message: message.to_string(),
    };
    let interval = || -> Result<(SystemTime, SystemTime), SnapshotError> {
        let opened_at = record
            .opened_at
            .ok_or_else(|| malformed("missing opened_at"))?;
        let expires_at = record
            .expires_at
            .ok_or_else(|| malformed("missing expires_at"))?;
        if record.since.is_some() {
            return Err(malformed("\"since\" belongs to needs-revert only"));
        }
        let span = match expires_at.duration_since(opened_at) {
            Ok(span) if !span.is_zero() => span,
            _ => {
                return Err(SnapshotError::ExpiryNotAfterOpening {
                    host: host.to_string(),
                })
            }
        };
        if span.as_secs() > MAX_TTL_SECS {
            return Err(SnapshotError::ExceedsCap {
                host: host.to_string(),
                secs: span.as_secs(),
            });
        }
        Ok((opened_at, expires_at))
    };

    match record.state.as_str() {
        "opening" => {
            let (opened_at, expires_at) = interval()?;
            Ok(GrantParts::Opening {
                opened_at,
                expires_at,
                channels: record.channels.clone(),
            })
        }
        "open" => {
            let (opened_at, expires_at) = interval()?;
            Ok(GrantParts::Open {
                opened_at,
                expires_at,
                channels: record.channels.clone(),
            })
        }
        "needs-revert" => {
            if record.opened_at.is_some() || record.expires_at.is_some() {
                return Err(malformed(
                    "needs-revert carries only \"since\" and channels",
                ));
            }
            let since = record.since.ok_or_else(|| malformed("missing since"))?;
            // An empty channel set is a legitimate transient: a grant with no
            // drivable channels (or one whose reverts all cleared) is
            // needs-revert with nothing left to do, and the next pass closes
            // it. The daemon writes exactly this during a driverless close.
            Ok(GrantParts::NeedsRevert {
                channels: record.channels.clone(),
                since,
            })
        }
        other => Err(malformed(&format!("unknown state {other:?}"))),
    }
}

impl GrantRegistry {
    /// Observation-free: records stored state, not `status(now)`.
    pub fn snapshot(&self) -> StateDoc {
        StateDoc {
            version: STATE_VERSION,
            grants: self
                .grants()
                .filter_map(|(name, grant)| {
                    grant
                        .parts()
                        .map(|parts| (name.to_string(), record_of(parts)))
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
            .grants
            .keys()
            .filter(|host| !registry.knows(host))
            .cloned()
            .collect();
        if !unknown.is_empty() {
            return Err(SnapshotError::UnknownHosts(unknown));
        }

        for (host, record) in &doc.grants {
            let parts = parts_of(host, record)?;
            registry.restore(host, Grant::restore(parts));
        }

        Ok(registry)
    }
}

#[cfg(test)]
mod tests;
