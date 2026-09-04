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
    /// Required exactly when the host declares an `ssh` or
    /// `authorized-keys` channel; refused otherwise (dead config is a typo).
    #[serde(default)]
    pub ssh: Option<SshConfig>,
}

fn default_ssh_port() -> u16 {
    22
}

fn default_authorized_keys_path() -> String {
    "/root/.ssh/authorized_keys".to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SshConfig {
    /// The unprivileged account the daemon connects as. Whatever rights it
    /// needs (writing the drop-in, reloading sshd, editing authorized_keys)
    /// come from `become_cmd`, or from the account itself being root.
    pub agent_user: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// What PermitRootLogin must be when no grant is open. Revert verifies
    /// the host's effective value equals this — drift is a loud stuck
    /// revert, not silence.
    pub root_posture_default: crate::ssh::Posture,
    /// What the ssh channel sets while a grant is open.
    pub root_posture_emergency: crate::ssh::Posture,
    #[serde(default = "default_authorized_keys_path")]
    pub authorized_keys_path: String,
    /// authorized_keys lines installed inside the lychgate fence while a
    /// grant is open. Required (non-empty) when the authorized-keys channel
    /// is declared.
    #[serde(default)]
    pub emergency_keys: Vec<String>,
    /// Passed to ssh -i when set; otherwise the client's own config decides.
    #[serde(default)]
    pub identity_file: Option<String>,
    /// Privilege prefix for remote commands, e.g. "doas" or "sudo -n".
    /// Absent means the agent account already has the rights it needs.
    #[serde(default)]
    pub become_cmd: Option<String>,
    /// Overrides the per-OS default sshd reload command.
    #[serde(default)]
    pub reload_cmd: Option<String>,
    /// Overrides the per-OS default drop-in path.
    #[serde(default)]
    pub dropin_path: Option<String>,
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
    EmptyAddress {
        host: String,
    },
    NoChannels {
        host: String,
    },
    DuplicateChannel {
        host: String,
    },
    /// ssh/authorized-keys channels need [hosts.ssh]; and vice versa.
    SshConfigMissing {
        host: String,
    },
    SshConfigUnused {
        host: String,
    },
    NoEmergencyKeys {
        host: String,
    },
    /// The ssh channel would set the posture to what it already must be.
    PostureUnchanged {
        host: String,
    },
    BadEmergencyKey {
        host: String,
        message: String,
    },
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
            InventoryError::SshConfigMissing { host } => write!(
                f,
                "host {host:?} declares an ssh or authorized-keys channel but has no [hosts.ssh] config"
            ),
            InventoryError::SshConfigUnused { host } => write!(
                f,
                "host {host:?} has [hosts.ssh] config but declares neither the ssh nor the authorized-keys channel; dead config is a typo"
            ),
            InventoryError::NoEmergencyKeys { host } => write!(
                f,
                "host {host:?} declares the authorized-keys channel but [hosts.ssh] lists no emergency_keys"
            ),
            InventoryError::PostureUnchanged { host } => write!(
                f,
                "host {host:?}: root_posture_emergency equals root_posture_default, so the ssh channel would change nothing; drop the ssh channel or change a posture"
            ),
            InventoryError::BadEmergencyKey { host, message } => {
                write!(f, "host {host:?}: {message}")
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

            let wants_ssh = host.channels.contains(&Channel::Ssh)
                || host.channels.contains(&Channel::AuthorizedKeys);
            match (&host.ssh, wants_ssh) {
                (None, true) => {
                    return Err(InventoryError::SshConfigMissing {
                        host: host.name.clone(),
                    })
                }
                (Some(_), false) => {
                    return Err(InventoryError::SshConfigUnused {
                        host: host.name.clone(),
                    })
                }
                (Some(ssh), true) => {
                    if host.channels.contains(&Channel::Ssh)
                        && ssh.root_posture_default == ssh.root_posture_emergency
                    {
                        return Err(InventoryError::PostureUnchanged {
                            host: host.name.clone(),
                        });
                    }
                    if host.channels.contains(&Channel::AuthorizedKeys)
                        && ssh.emergency_keys.is_empty()
                    {
                        return Err(InventoryError::NoEmergencyKeys {
                            host: host.name.clone(),
                        });
                    }
                    for key in &ssh.emergency_keys {
                        // The same refusals the fence enforces, moved to
                        // load time: a bad key must fail here, not at 03:00.
                        if let Err(e) = crate::ssh::validate_key_line(key) {
                            return Err(InventoryError::BadEmergencyKey {
                                host: host.name.clone(),
                                message: e.to_string(),
                            });
                        }
                    }
                }
                (None, false) => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
