//! The host inventory: which machines lychgate may touch, and through which
//! channels. The schema is strict — an unrecognized field is a refusal, not a
//! shrug — because a typo in a break-glass config must fail at load, not at
//! 03:00 when the grant it silently disabled is needed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::authority::{ApprovalSpec, AuthorityBody, AuthorityError, AuthorityModel};

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    #[serde(default)]
    pub hosts: Vec<Host>,
    /// Deployment-wide operator-approval policy: the weighted-threshold
    /// authorities (authenticators, groups, profiles) that gate opening a grant.
    /// When present, an open must satisfy the resolved profile's authority.
    /// Absent, the daemon decides its own default (lychgated refuses to serve
    /// without an approval policy unless --dry-run). See `crate::authority`.
    #[serde(default)]
    pub approval: Option<ApprovalSpec>,
}

/// Which approval profiles a host permits, and any per-profile authority
/// overrides for it. A host with no `[hosts.access]` permits every global
/// profile at its default authority.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostAccess {
    /// The global profiles that may be opened on this host (non-empty).
    pub profiles: Vec<String>,
    /// Per-profile authority overrides, keyed by profile id: this host requires
    /// the override's authority for that profile instead of the global one.
    #[serde(default, rename = "override")]
    pub overrides: BTreeMap<String, AuthorityBody>,
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
    /// Required exactly when the host declares an `http` channel.
    #[serde(default)]
    pub http: Option<HttpConfig>,
    /// Required exactly when the host declares an `mqtt` channel.
    #[serde(default)]
    pub mqtt: Option<MqttConfig>,
    /// Required exactly when the host declares a `serial` channel.
    #[serde(default)]
    pub serial: Option<SerialConfig>,
    /// Which approval profiles may be opened on this host, and any per-profile
    /// overrides. Absent: the host permits every global profile at its default
    /// authority. Meaningful only when [approval] is configured.
    #[serde(default)]
    pub access: Option<HostAccess>,
    /// Whether this host is a drill **canary**: a designated throwaway host that
    /// `lychgate drill` may open-and-revert as a standing self-test, bypassing
    /// the approval gate. Default false — only a canary is drillable, and a real
    /// host never is. See the daemon's drill path and TESTING.md.
    #[serde(default)]
    pub drill: bool,
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

/// A verify posture for a generic channel: either a probe spec, or the
/// literal string `"none"` — an explicit, named narrowing (the daemon is then
/// the sole oracle for this channel's state, and the open response says so).
/// The field is required: silence about verification is not an option.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum VerifyMode<T> {
    /// Must be exactly `"none"`; any other string is refused at load.
    None(String),
    Probe(T),
}

/// One HTTP request the http channel makes (open, revert, or verify),
/// executed against the host's `endpoint`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestSpec {
    /// HTTP method, e.g. "GET"/"POST"/"PUT".
    pub method: String,
    /// Path appended to the endpoint, e.g. "/api/maintenance".
    pub path: String,
    #[serde(default)]
    pub body: Option<String>,
    /// The exact status the response must carry; anything else is a driver
    /// error, never silently accepted.
    pub expect_status: u16,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpVerifySpec {
    pub method: String,
    pub path: String,
    pub expect_status: u16,
    /// Substring markers mapping the response body onto the channel state.
    /// Matching neither (or both) is an error, never a guessed state.
    pub open_marker: String,
    pub closed_marker: String,
}

/// `[hosts.http]` — drive a device's HTTP management surface (curl-exec
/// transport, like the bmc channel's). The daemon is the sole TTL enforcer
/// here; there is no dead-man on the device (see docs/EMBEDDED.md §2a).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpConfig {
    /// Base URL, e.g. "https://10.0.9.31:8443".
    pub endpoint: String,
    pub tls: BmcTls,
    /// Optional basic-auth pair; the password lives in a file (never inline,
    /// never on argv — it reaches curl over stdin).
    #[serde(default)]
    pub auth_user: Option<String>,
    #[serde(default)]
    pub auth_password_file: Option<String>,
    pub open: HttpRequestSpec,
    pub revert: HttpRequestSpec,
    pub verify: VerifyMode<HttpVerifySpec>,
}

/// How the daemon authenticates to the MQTT broker.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum MqttAuth {
    /// Mutual TLS: the daemon presents a client certificate.
    TlsClientCert {
        certfile: String,
        keyfile: String,
        cafile: String,
    },
    /// Named in the vocabulary but refused at load: mosquitto_pub takes a
    /// password only via argv or a world-readable -P file handed to every
    /// invocation, and a secret on argv is a refusal, not a trade-off.
    Password { username: String },
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MqttMessageSpec {
    pub topic: String,
    pub payload: String,
}

fn default_mqtt_timeout_secs() -> u64 {
    5
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MqttVerifySpec {
    /// Topic subscribed for one message (a retained state topic is the
    /// natural fit). No message within `timeout_secs` is *unverified* — an
    /// error, never a state.
    pub topic: String,
    pub open_marker: String,
    pub closed_marker: String,
    #[serde(default = "default_mqtt_timeout_secs")]
    pub timeout_secs: u64,
}

/// `[hosts.mqtt]` — drive a device through an MQTT broker
/// (mosquitto_pub/mosquitto_sub exec transport). Broker auth is anonymous or
/// TLS client-cert; password auth is refused at load (argv leak).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MqttConfig {
    /// "host:port" of the broker.
    pub broker: String,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub auth: Option<MqttAuth>,
    pub open: MqttMessageSpec,
    pub revert: MqttMessageSpec,
    pub verify: VerifyMode<MqttVerifySpec>,
}

fn default_serial_timeout_secs() -> u64 {
    5
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SerialCmdSpec {
    /// Bytes written to the port (include the newline if the device wants one).
    pub send: String,
    /// Substring the response must contain.
    pub expect: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SerialVerifySpec {
    pub send: String,
    pub open_marker: String,
    pub closed_marker: String,
}

/// `[hosts.serial]` — drive a device over a local serial port (direct fd,
/// raw termios). `baud` is optional: absent leaves the port's speed alone,
/// and setting it on a pty is a tolerated no-op, so the same config drives
/// real ttys and the test simulator.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SerialConfig {
    /// The tty device path, e.g. "/dev/cuaU0".
    pub device: String,
    #[serde(default)]
    pub baud: Option<u32>,
    /// Per-transaction reply budget; running out is a transport error.
    #[serde(default = "default_serial_timeout_secs")]
    pub timeout_secs: u64,
    pub open: SerialCmdSpec,
    pub revert: SerialCmdSpec,
    pub verify: VerifyMode<SerialVerifySpec>,
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
    /// A firmware-class device: no shell, no cron, no filesystem lychgate can
    /// reach. Load-time rule: an embedded host may declare only the channels
    /// that need none of those (http, mqtt, serial, bmc) — the shell-borne
    /// channels are refused, which is what keeps the `Os` match sites that
    /// render shell commands unreachable for embedded hosts.
    Embedded,
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
    Http,
    Mqtt,
    Serial,
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
    /// A generic channel (http/mqtt/serial) declared without its config table,
    /// or vice versa.
    GenericConfigMissing {
        host: String,
        channel: &'static str,
    },
    GenericConfigUnused {
        host: String,
        channel: &'static str,
    },
    /// `verify = "<something>"` where only the literal "none" is meaningful.
    GenericVerifyNotNone {
        host: String,
        channel: &'static str,
        got: String,
    },
    /// A `{placeholder}` in a template that substitutes nothing.
    GenericPlaceholder {
        host: String,
        channel: &'static str,
        field: &'static str,
        message: String,
    },
    /// An expect_status outside 100..=599.
    GenericBadStatus {
        host: String,
        which: &'static str,
    },
    /// A zero timeout would make every transaction fail instantly.
    GenericZeroTimeout {
        host: String,
        channel: &'static str,
    },
    /// Password broker auth would put the secret on mosquitto's argv.
    MqttPasswordAuth {
        host: String,
    },
    /// An embedded host declaring a shell-borne channel (ssh, authorized-keys,
    /// vnc): a device with no shell cannot carry them, and the load rule is
    /// what keeps the shell-rendering Os match sites unreachable.
    EmbeddedChannelUnsupported {
        host: String,
        channel: String,
    },
    /// The [approval] policy is malformed (dangling reference, cycle,
    /// unsatisfiable threshold, unimplemented authenticator kind, …).
    Approval(AuthorityError),
    /// A host declares [hosts.access] but the inventory has no [approval] policy.
    AccessWithoutApproval {
        host: String,
    },
    /// A host's [hosts.access] permits no profiles — it could never be opened.
    AccessNoProfiles {
        host: String,
    },
    /// A host permits, or overrides, a profile that is not defined.
    UnknownProfile {
        host: String,
        profile: String,
    },
    /// A host overrides a profile it does not permit — dead config.
    OverrideForUnpermittedProfile {
        host: String,
        profile: String,
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
            InventoryError::GenericConfigMissing { host, channel } => write!(
                f,
                "host {host:?} declares a {channel} channel but has no [hosts.{channel}] config"
            ),
            InventoryError::GenericConfigUnused { host, channel } => write!(
                f,
                "host {host:?} has [hosts.{channel}] config but declares no {channel} channel; dead config is a typo"
            ),
            InventoryError::GenericVerifyNotNone { host, channel, got } => write!(
                f,
                "host {host:?}: [hosts.{channel}] verify = {got:?}; only the literal \"none\" (an explicit narrowing) or a verify table is meaningful"
            ),
            InventoryError::GenericPlaceholder { host, channel, field, message } => write!(
                f,
                "host {host:?}: [hosts.{channel}] {field} {message}"
            ),
            InventoryError::GenericBadStatus { host, which } => write!(
                f,
                "host {host:?}: {which} expect_status is not an HTTP status (100..=599)"
            ),
            InventoryError::GenericZeroTimeout { host, channel } => write!(
                f,
                "host {host:?}: [hosts.{channel}] timeout_secs is zero, so every transaction would fail instantly"
            ),
            InventoryError::MqttPasswordAuth { host } => write!(
                f,
                "host {host:?}: mqtt password auth is refused — mosquitto clients take the password on argv, where every process on the daemon host can read it; use TLS client certificates or an anonymous listener"
            ),
            InventoryError::EmbeddedChannelUnsupported { host, channel } => write!(
                f,
                "host {host:?} is os = \"embedded\" but declares the {channel} channel, which needs a shell on the target; embedded hosts may declare only http, mqtt, serial, and bmc"
            ),
            InventoryError::Approval(e) => write!(f, "[approval] policy is invalid: {e}"),
            InventoryError::AccessWithoutApproval { host } => write!(
                f,
                "host {host:?} declares [hosts.access] but the inventory has no [approval] policy; access profiles are meaningless without one"
            ),
            InventoryError::AccessNoProfiles { host } => write!(
                f,
                "host {host:?} declares [hosts.access] permitting no profiles; it could never be opened (fail-closed)"
            ),
            InventoryError::UnknownProfile { host, profile } => write!(
                f,
                "host {host:?} references approval profile {profile:?}, which is not defined in [approval]"
            ),
            InventoryError::OverrideForUnpermittedProfile { host, profile } => write!(
                f,
                "host {host:?} overrides profile {profile:?} but does not permit it; dead config is a typo"
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

    /// The generic-channel (http/mqtt/serial) rules for one host: paired
    /// config-vs-channel presence, template placeholder refusals, status and
    /// timeout sanity, the verify-XOR-"none" rule, and the mqtt password-auth
    /// refusal.
    fn validate_generic(&self, host: &Host) -> Result<(), InventoryError> {
        let err_missing = |channel| InventoryError::GenericConfigMissing {
            host: host.name.clone(),
            channel,
        };
        let err_unused = |channel| InventoryError::GenericConfigUnused {
            host: host.name.clone(),
            channel,
        };
        let check_verify_none = |channel: &'static str, s: &str| {
            if s == "none" {
                Ok(())
            } else {
                Err(InventoryError::GenericVerifyNotNone {
                    host: host.name.clone(),
                    channel,
                    got: s.to_string(),
                })
            }
        };
        let check_template = |channel: &'static str, field: &'static str, template: &str| {
            crate::generic::forbid_placeholders(template).map_err(|e| {
                InventoryError::GenericPlaceholder {
                    host: host.name.clone(),
                    channel,
                    field,
                    message: e.to_string(),
                }
            })
        };
        let check_status = |which: &'static str, status: u16| {
            if (100..=599).contains(&status) {
                Ok(())
            } else {
                Err(InventoryError::GenericBadStatus {
                    host: host.name.clone(),
                    which,
                })
            }
        };

        match (&host.http, host.channels.contains(&Channel::Http)) {
            (None, true) => return Err(err_missing("http")),
            (Some(_), false) => return Err(err_unused("http")),
            (Some(http), true) => {
                for (which, req) in [("open", &http.open), ("revert", &http.revert)] {
                    check_status(which, req.expect_status)?;
                    check_template("http", "path", &req.path)?;
                    if let Some(body) = &req.body {
                        check_template("http", "body", body)?;
                    }
                }
                match &http.verify {
                    VerifyMode::None(s) => check_verify_none("http", s)?,
                    VerifyMode::Probe(v) => {
                        check_status("verify", v.expect_status)?;
                        check_template("http", "path", &v.path)?;
                    }
                }
            }
            (None, false) => {}
        }

        match (&host.mqtt, host.channels.contains(&Channel::Mqtt)) {
            (None, true) => return Err(err_missing("mqtt")),
            (Some(_), false) => return Err(err_unused("mqtt")),
            (Some(mqtt), true) => {
                if let Some(MqttAuth::Password { .. }) = &mqtt.auth {
                    return Err(InventoryError::MqttPasswordAuth {
                        host: host.name.clone(),
                    });
                }
                for (field, spec) in [("open", &mqtt.open), ("revert", &mqtt.revert)] {
                    let _ = field;
                    check_template("mqtt", "topic", &spec.topic)?;
                    check_template("mqtt", "payload", &spec.payload)?;
                }
                match &mqtt.verify {
                    VerifyMode::None(s) => check_verify_none("mqtt", s)?,
                    VerifyMode::Probe(v) => {
                        check_template("mqtt", "topic", &v.topic)?;
                        if v.timeout_secs == 0 {
                            return Err(InventoryError::GenericZeroTimeout {
                                host: host.name.clone(),
                                channel: "mqtt",
                            });
                        }
                    }
                }
            }
            (None, false) => {}
        }

        match (&host.serial, host.channels.contains(&Channel::Serial)) {
            (None, true) => return Err(err_missing("serial")),
            (Some(_), false) => return Err(err_unused("serial")),
            (Some(serial), true) => {
                if serial.timeout_secs == 0 {
                    return Err(InventoryError::GenericZeroTimeout {
                        host: host.name.clone(),
                        channel: "serial",
                    });
                }
                for spec in [&serial.open, &serial.revert] {
                    check_template("serial", "send", &spec.send)?;
                }
                match &serial.verify {
                    VerifyMode::None(s) => check_verify_none("serial", s)?,
                    VerifyMode::Probe(v) => check_template("serial", "send", &v.send)?,
                }
            }
            (None, false) => {}
        }

        Ok(())
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

            self.validate_generic(host)?;

            if host.os == Os::Embedded {
                for ch in &host.channels {
                    if matches!(ch, Channel::Ssh | Channel::AuthorizedKeys | Channel::Vnc) {
                        let name = match ch {
                            Channel::Ssh => "ssh",
                            Channel::AuthorizedKeys => "authorized-keys",
                            Channel::Vnc => "vnc",
                            _ => unreachable!(),
                        };
                        return Err(InventoryError::EmbeddedChannelUnsupported {
                            host: host.name.clone(),
                            channel: name.to_string(),
                        });
                    }
                }
            }
        }

        // Deployment-wide approval policy (not per-host): build and fully
        // validate the authority model, then check each host's access against it.
        let model = self.approval_model()?;
        for host in &self.hosts {
            let Some(access) = &host.access else {
                continue;
            };
            let Some(model) = &model else {
                return Err(InventoryError::AccessWithoutApproval {
                    host: host.name.clone(),
                });
            };
            if access.profiles.is_empty() {
                return Err(InventoryError::AccessNoProfiles {
                    host: host.name.clone(),
                });
            }
            let permitted: BTreeSet<&str> = access.profiles.iter().map(|s| s.as_str()).collect();
            for profile in &access.profiles {
                if model.profile(profile).is_none() {
                    return Err(InventoryError::UnknownProfile {
                        host: host.name.clone(),
                        profile: profile.clone(),
                    });
                }
            }
            for (profile, body) in &access.overrides {
                if !permitted.contains(profile.as_str()) {
                    return Err(InventoryError::OverrideForUnpermittedProfile {
                        host: host.name.clone(),
                        profile: profile.clone(),
                    });
                }
                model
                    .resolve_override(profile, body)
                    .map_err(InventoryError::Approval)?;
            }
        }
        Ok(())
    }

    /// Build the deployment's approval model, or `None` if no `[approval]` policy
    /// is configured. All structural validation (references, cycles,
    /// satisfiability, unimplemented kinds) happens here, so this is both what
    /// `validate` checks and what the daemon builds to serve.
    pub fn approval_model(&self) -> Result<Option<AuthorityModel>, InventoryError> {
        match &self.approval {
            Some(spec) => AuthorityModel::from_spec(spec)
                .map(Some)
                .map_err(InventoryError::Approval),
            None => Ok(None),
        }
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
