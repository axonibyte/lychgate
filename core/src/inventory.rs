//! The host inventory: which machines lychgate may touch, and through which
//! channels. The schema is strict — an unrecognized field is a refusal, not a
//! shrug — because a typo in a break-glass config must fail at load, not at
//! 03:00 when the grant it silently disabled is needed.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    #[serde(default)]
    pub hosts: Vec<Host>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub name: String,
    pub address: String,
    pub os: Os,
    pub channels: Vec<Channel>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Os {
    Freebsd,
    Linux,
}

// Serialize too: the daemon's audit journal writes channel names, and they
// must be the same kebab-case vocabulary the inventory reads.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Channel {
    Ssh,
    AuthorizedKeys,
    Bmc,
    Vnc,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InventoryError {
    Toml(String),
    EmptyHostName,
    DuplicateHostName(String),
    EmptyAddress { host: String },
    NoChannels { host: String },
    DuplicateChannel { host: String },
}

impl fmt::Display for InventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InventoryError::Toml(e) => write!(f, "inventory is not valid: {e}"),
            InventoryError::EmptyHostName => write!(f, "a host has an empty name"),
            InventoryError::DuplicateHostName(name) => {
                write!(f, "host name {name:?} appears more than once")
            }
            InventoryError::EmptyAddress { host } => {
                write!(f, "host {host:?} has an empty address")
            }
            InventoryError::NoChannels { host } => {
                write!(f, "host {host:?} declares no channels; a host lychgate may not touch does not belong in the inventory")
            }
            InventoryError::DuplicateChannel { host } => {
                write!(f, "host {host:?} lists the same channel more than once")
            }
        }
    }
}

impl std::error::Error for InventoryError {}

impl Inventory {
    pub fn parse(toml_text: &str) -> Result<Inventory, InventoryError> {
        let inventory: Inventory =
            toml::from_str(toml_text).map_err(|e| InventoryError::Toml(e.to_string()))?;
        inventory.validate()?;
        Ok(inventory)
    }

    fn validate(&self) -> Result<(), InventoryError> {
        let mut names = BTreeSet::new();
        for host in &self.hosts {
            if host.name.is_empty() {
                return Err(InventoryError::EmptyHostName);
            }
            if !names.insert(&host.name) {
                return Err(InventoryError::DuplicateHostName(host.name.clone()));
            }
            if host.address.is_empty() {
                return Err(InventoryError::EmptyAddress {
                    host: host.name.clone(),
                });
            }
            if host.channels.is_empty() {
                return Err(InventoryError::NoChannels {
                    host: host.name.clone(),
                });
            }
            let unique: BTreeSet<Channel> = host.channels.iter().copied().collect();
            if unique.len() != host.channels.len() {
                return Err(InventoryError::DuplicateChannel {
                    host: host.name.clone(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
