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
    /// Deployment-wide operator-approval policy. When present, opening any
    /// grant requires a token from one of the configured approvers. Absent, a
    /// daemon must decide its own default (lychgated refuses to serve without
    /// an approver unless --dry-run) — see the daemon, not the schema.
    #[serde(default)]
    pub approval: Option<ApprovalConfig>,
}

/// The approvers a deployment accepts. Any one of them may approve (the
/// fail-closed `AnyOf` composite); an empty table is refused at load. TOTP and
/// FIDO2 approver lists land in later sub-milestones.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConfig {
    #[serde(default)]
    pub ed25519: Vec<Ed25519Approver>,
}

/// One SSHSIG Ed25519 approver: an identity and the OpenSSH public key whose
/// `ssh-keygen -Y sign -n lychgate-approval` signatures are accepted. The key
/// is public, so it is inline (unlike a secret, which is always a file path).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Ed25519Approver {
    pub key_id: String,
    pub public_key: String,
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
    /// Required exactly when the host declares a `bmc` channel.
    #[serde(default)]
    pub bmc: Option<BmcConfig>,
    /// Required exactly when the host declares a `vnc` channel.
    #[serde(default)]
    pub vnc: Option<VncConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BmcMethod {
    Redfish,
    Racadm,
    Ipmitool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum BmcTls {
    /// Verify the endpoint's certificate against this CA bundle.
    CaFile { path: String },
    /// Skip verification. Must be spelled out in the inventory; never the
    /// default, because a break-glass control channel over unverified TLS is
    /// a decision an operator makes on purpose, not one lychgate makes for
    /// them.
    Insecure,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BmcConfig {
    /// The Redfish base URL, e.g. "https://10.0.9.5".
    pub endpoint: String,
    pub method: BmcMethod,
    /// The break-glass account's username and its AccountService slot id.
    pub account_user: String,
    pub account_id: String,
    /// How the daemon authenticates to the BMC to drive AccountService.
    pub auth_user: String,
    /// Path to a file holding the auth password (never inline in the
    /// inventory — the inventory is world-readable config, not a secret store).
    pub auth_password_file: String,
    pub tls: BmcTls,
}

fn default_ssh_port() -> u16 {
    22
}

fn default_rfb_host() -> String {
    "127.0.0.1".to_string()
}

fn default_vnc_password_len() -> usize {
    // Classic RFB VNC-Auth (DES challenge-response) truncates the password to
    // 8 bytes; a longer value buys nothing on such servers. 8 is the honest
    // default. See TESTING.md.
    8
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

/// The `vnc` channel's config: how to reach the hypervisor, where the VM's
/// RFB server listens on it, which local port lychgated forwards, and the
/// agnostic commands that set and clear the VM's VNC password. The connection
/// fields are the channel's own (not `[hosts.ssh]`): a vnc-only host should
/// not have to declare an ssh channel — which mutates PermitRootLogin — merely
/// to reach cbsd.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VncConfig {
    /// The account lychgated connects to the hypervisor as.
    pub agent_user: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// Passed to ssh -i when set.
    #[serde(default)]
    pub identity_file: Option<String>,
    /// Privilege prefix for the password commands, e.g. "doas".
    #[serde(default)]
    pub become_cmd: Option<String>,
    /// Where the VM's RFB server binds on the hypervisor — the tunnel's remote
    /// side. Defaults to loopback: RFB should never be world-exposed.
    #[serde(default = "default_rfb_host")]
    pub rfb_host: String,
    /// The RFB port on the hypervisor (the tunnel's remote side).
    pub rfb_port: u16,
    /// The port lychgated forwards on the daemon host (the tunnel's local
    /// side). Fixed per host so verify and boot re-establishment can find it
    /// without remembering a pid; unique across hosts.
    pub local_port: u16,
    /// The VM identifier handed to the password commands as `{target}`.
    pub target: String,
    /// Command that sets the VM's VNC password. Must reference
    /// `{password_file}` (where lychgate stages the fresh password) and may
    /// reference `{target}`. Validated at load; see `crate::vnc`.
    pub set_password_cmd: String,
    /// Command that clears/rotates away the VNC password on revert. May
    /// reference `{target}`; never `{password_file}`.
    pub clear_password_cmd: String,
    #[serde(default = "default_vnc_password_len")]
    pub password_len: usize,
    /// Where on the hypervisor lychgate stages the one-time password (mode
    /// 600, removed immediately after the set command). Substituted as
    /// `{password_file}`.
    #[serde(default)]
    pub password_file: Option<String>,
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
    BmcConfigMissing {
        host: String,
    },
    BmcConfigUnused {
        host: String,
    },
    /// A method named in the schema but not implemented yet.
    BmcMethodUnimplemented {
        host: String,
        method: String,
    },
    /// vnc channel needs [hosts.vnc]; and vice versa.
    VncConfigMissing {
        host: String,
    },
    VncConfigUnused {
        host: String,
    },
    /// A password command template lychgate could not render safely.
    VncCommandQuoted {
        host: String,
        which: &'static str,
    },
    VncMissingPasswordFile {
        host: String,
    },
    VncClearHasPasswordFile {
        host: String,
    },
    VncUnknownPlaceholder {
        host: String,
        which: &'static str,
        placeholder: String,
    },
    /// A zero port or password length — no auth, or nowhere to forward.
    VncBadPort {
        host: String,
        field: &'static str,
    },
    VncBadPasswordLen {
        host: String,
    },
    /// Two hosts forward the same daemon-local port; only one can own it.
    VncLocalPortConflict {
        host: String,
        other: String,
        port: u16,
    },
    /// An [approval] table with no approvers — fail-closed: nothing could ever
    /// approve a grant.
    ApprovalNoApprovers,
    ApprovalEmptyKeyId,
    ApprovalDuplicateKeyId(String),
    /// A configured approver public key does not parse.
    ApprovalBadPublicKey {
        id: String,
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
            InventoryError::BmcConfigMissing { host } => write!(
                f,
                "host {host:?} declares a bmc channel but has no [hosts.bmc] config"
            ),
            InventoryError::BmcConfigUnused { host } => write!(
                f,
                "host {host:?} has [hosts.bmc] config but declares no bmc channel; dead config is a typo"
            ),
            InventoryError::BmcMethodUnimplemented { host, method } => write!(
                f,
                "host {host:?}: bmc method {method:?} is not implemented yet; only redfish is"
            ),
            InventoryError::VncConfigMissing { host } => write!(
                f,
                "host {host:?} declares a vnc channel but has no [hosts.vnc] config"
            ),
            InventoryError::VncConfigUnused { host } => write!(
                f,
                "host {host:?} has [hosts.vnc] config but declares no vnc channel; dead config is a typo"
            ),
            InventoryError::VncCommandQuoted { host, which } => write!(
                f,
                "host {host:?}: {which} contains a single quote; lychgate must own the shell quoting, so a template that quotes its own arguments is refused"
            ),
            InventoryError::VncMissingPasswordFile { host } => write!(
                f,
                "host {host:?}: set_password_cmd never references {{password_file}}, so the generated password would never reach the target"
            ),
            InventoryError::VncClearHasPasswordFile { host } => write!(
                f,
                "host {host:?}: clear_password_cmd references {{password_file}}, but the clear command is never handed a password"
            ),
            InventoryError::VncUnknownPlaceholder { host, which, placeholder } => write!(
                f,
                "host {host:?}: {which} references unknown placeholder {{{placeholder}}}; lychgate would leave it in the command literally"
            ),
            InventoryError::VncBadPort { host, field } => write!(
                f,
                "host {host:?}: vnc {field} is zero"
            ),
            InventoryError::VncBadPasswordLen { host } => write!(
                f,
                "host {host:?}: vnc password_len is zero, which is no password at all"
            ),
            InventoryError::VncLocalPortConflict { host, other, port } => write!(
                f,
                "host {host:?}: local_port {port} is also forwarded by host {other:?}; two hosts cannot share one daemon-local forward port"
            ),
            InventoryError::ApprovalNoApprovers => write!(
                f,
                "[approval] is present but lists no approvers; opening a grant could never be approved (fail-closed)"
            ),
            InventoryError::ApprovalEmptyKeyId => {
                write!(f, "an [[approval.ed25519]] entry has an empty key-id")
            }
            InventoryError::ApprovalDuplicateKeyId(id) => {
                write!(f, "approver key-id {id:?} appears more than once")
            }
            InventoryError::ApprovalBadPublicKey { id, message } => write!(
                f,
                "approver {id:?}: public-key does not parse: {message}"
            ),
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
        // local_port is a daemon-host resource: two hosts forwarding the same
        // one would collide, so ownership must be unique across the inventory.
        let mut local_ports: std::collections::BTreeMap<u16, String> =
            std::collections::BTreeMap::new();
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

            let wants_bmc = host.channels.contains(&Channel::Bmc);
            match (&host.bmc, wants_bmc) {
                (None, true) => {
                    return Err(InventoryError::BmcConfigMissing {
                        host: host.name.clone(),
                    })
                }
                (Some(_), false) => {
                    return Err(InventoryError::BmcConfigUnused {
                        host: host.name.clone(),
                    })
                }
                (Some(bmc), true) => {
                    // Reserve the vocabulary without pretending: racadm and
                    // ipmitool parse but are refused at load until they exist.
                    if bmc.method != BmcMethod::Redfish {
                        return Err(InventoryError::BmcMethodUnimplemented {
                            host: host.name.clone(),
                            method: format!("{:?}", bmc.method).to_lowercase(),
                        });
                    }
                }
                (None, false) => {}
            }

            let wants_vnc = host.channels.contains(&Channel::Vnc);
            match (&host.vnc, wants_vnc) {
                (None, true) => {
                    return Err(InventoryError::VncConfigMissing {
                        host: host.name.clone(),
                    })
                }
                (Some(_), false) => {
                    return Err(InventoryError::VncConfigUnused {
                        host: host.name.clone(),
                    })
                }
                (Some(vnc), true) => {
                    if vnc.rfb_port == 0 {
                        return Err(InventoryError::VncBadPort {
                            host: host.name.clone(),
                            field: "rfb_port",
                        });
                    }
                    if vnc.local_port == 0 {
                        return Err(InventoryError::VncBadPort {
                            host: host.name.clone(),
                            field: "local_port",
                        });
                    }
                    if vnc.password_len == 0 {
                        return Err(InventoryError::VncBadPasswordLen {
                            host: host.name.clone(),
                        });
                    }
                    // The password commands are refused here, not at 03:00, if
                    // lychgate could not render them safely.
                    if let Err(e) = crate::vnc::check_set_command(&vnc.set_password_cmd) {
                        return Err(vnc_template_error(&host.name, "set_password_cmd", e));
                    }
                    if let Err(e) = crate::vnc::check_clear_command(&vnc.clear_password_cmd) {
                        return Err(vnc_template_error(&host.name, "clear_password_cmd", e));
                    }
                    // Fixed per host, unique across the inventory.
                    if let Some(other) = local_ports.insert(vnc.local_port, host.name.clone()) {
                        return Err(InventoryError::VncLocalPortConflict {
                            host: host.name.clone(),
                            other,
                            port: vnc.local_port,
                        });
                    }
                }
                (None, false) => {}
            }
        }

        // Deployment-wide approval policy (not per-host).
        if let Some(approval) = &self.approval {
            if approval.ed25519.is_empty() {
                return Err(InventoryError::ApprovalNoApprovers);
            }
            let mut ids = BTreeSet::new();
            for e in &approval.ed25519 {
                if e.key_id.is_empty() {
                    return Err(InventoryError::ApprovalEmptyKeyId);
                }
                if !ids.insert(&e.key_id) {
                    return Err(InventoryError::ApprovalDuplicateKeyId(e.key_id.clone()));
                }
                // A bad approver key must fail at load, not at 03:00.
                if let Err(err) = crate::approval::parse_ssh_public_key(&e.public_key) {
                    return Err(InventoryError::ApprovalBadPublicKey {
                        id: e.key_id.clone(),
                        message: err.to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Maps a template refusal from `crate::vnc` onto the inventory error that
/// names the host and the offending field.
fn vnc_template_error(
    host: &str,
    which: &'static str,
    e: crate::vnc::VncTemplateError,
) -> InventoryError {
    use crate::vnc::VncTemplateError::*;
    match e {
        Quoted => InventoryError::VncCommandQuoted {
            host: host.to_string(),
            which,
        },
        MissingPasswordFile => InventoryError::VncMissingPasswordFile {
            host: host.to_string(),
        },
        ClearHasPasswordFile => InventoryError::VncClearHasPasswordFile {
            host: host.to_string(),
        },
        UnknownPlaceholder(placeholder) => InventoryError::VncUnknownPlaceholder {
            host: host.to_string(),
            which,
            placeholder,
        },
    }
}

#[cfg(test)]
mod tests;
