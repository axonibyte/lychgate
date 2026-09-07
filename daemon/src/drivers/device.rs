//! The device channel driver: grants enforced BY the device.
//!
//! "Open" here does not flip remote state the daemon must later flip back —
//! it delivers a signed lgcap. capability token, and the device anchors the
//! TTL on its own uptime clock. The daemon still reverts eagerly (a signed
//! lgrvk. revocation at close), but the device's own deadline is the real
//! guarantee: this is the ssh channel's daemon/dead-man split with the roles
//! swapped, and it survives daemon death, network partition, and operator
//! absence. See docs/EMBEDDED.md §3.
//!
//! Two seams: `TokenSigner` (the daemon's signing keys + the seq ledger —
//! the sequence number is reserved DURABLY before a token exists, so a crash
//! wastes a number and never reuses one) and `DeviceTransport` (one line-
//! protocol transaction over whichever wire the host's config names). The
//! line protocol itself lives in lychgate-wire, shared verbatim with the
//! device engine, so the two ends cannot drift.

use lychgate_core::{
    ActuatorSpec, ApplyCtx, Channel, ChannelDriver, ChannelState, DeviceAlg, DeviceConfig,
    DriverError, FailStatePolicy, Host,
};
use lychgate_wire::line::{self, Command, Reply};

use crate::device_state::DeviceState;

/// Signs capability/revocation tokens for a device, reserving each sequence
/// number durably before the token exists.
pub trait TokenSigner: Send {
    fn next_cap(
        &mut self,
        device: &DeviceConfig,
        nonce: [u8; 16],
        ttl_secs: u32,
    ) -> Result<String, DriverError>;

    fn next_rvk(&mut self, device: &DeviceConfig, nonce: [u8; 16]) -> Result<String, DriverError>;
}

/// One line-protocol transaction: send a command line, return the reply line.
pub trait DeviceTransport: Send {
    fn transact(
        &mut self,
        host: &Host,
        device: &DeviceConfig,
        command: &str,
    ) -> Result<String, DriverError>;
}

/// Fresh randomness for grant nonces (a seam so tests are deterministic).
pub trait NonceSource: Send {
    fn nonce(&mut self) -> [u8; 16];
}

/// Production nonces from the OS CSPRNG.
pub struct UrandomNonces;

impl NonceSource for UrandomNonces {
    fn nonce(&mut self) -> [u8; 16] {
        use std::io::Read;
        let mut bytes = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .expect("/dev/urandom is readable on every supported platform");
        bytes
    }
}

pub struct DeviceDriver {
    transport: Box<dyn DeviceTransport>,
    signer: Box<dyn TokenSigner>,
    nonces: Box<dyn NonceSource>,
    state: DeviceState,
}

impl DeviceDriver {
    pub fn new(
        transport: Box<dyn DeviceTransport>,
        signer: Box<dyn TokenSigner>,
        nonces: Box<dyn NonceSource>,
        state: DeviceState,
    ) -> Box<DeviceDriver> {
        Box::new(DeviceDriver {
            transport,
            signer,
            nonces,
            state,
        })
    }

    fn config(host: &Host) -> Result<&DeviceConfig, DriverError> {
        host.device.as_ref().ok_or_else(|| {
            DriverError(format!("host {:?} has no [hosts.device] config", host.name))
        })
    }

    fn device_id(device: &DeviceConfig) -> [u8; 16] {
        device
            .device_id_bytes()
            .expect("device_id was validated at inventory load")
    }

    fn send(
        &mut self,
        host: &Host,
        device: &DeviceConfig,
        cmd: &Command<'_>,
    ) -> Result<String, DriverError> {
        let mut buf = [0u8; line::MAX_LINE_LEN];
        let rendered = line::render_command(cmd, &mut buf)
            .map_err(|e| DriverError(format!("rendering device command: {e}")))?;
        self.transport.transact(host, device, rendered)
    }

    fn report(&mut self, host: &Host, device: &DeviceConfig) -> Result<line::Report, DriverError> {
        let reply = self.send(host, device, &Command::Status)?;
        match line::parse_reply(&reply) {
            Ok(Reply::State(report)) => Ok(report),
            Ok(Reply::Nak(reason)) => Err(DriverError(format!(
                "device {:?} refused STAT: {reason}",
                host.name
            ))),
            Ok(other) => Err(DriverError(format!(
                "device {:?} answered STAT with {other:?}",
                host.name
            ))),
            Err(e) => Err(DriverError(format!(
                "device {:?} STAT reply unparseable ({e}): {:?}",
                host.name,
                reply.trim()
            ))),
        }
    }

    /// Deliver a capability and hold the device to it: the ACK must echo our
    /// nonce, and the remaining time must be sane against the ttl we sent.
    fn deliver_cap(
        &mut self,
        host: &Host,
        device: &DeviceConfig,
        nonce: [u8; 16],
        ttl_secs: u32,
    ) -> Result<(), DriverError> {
        let token = self.signer.next_cap(device, nonce, ttl_secs)?;
        let reply = self.send(host, device, &Command::Token(&token))?;
        match line::parse_reply(&reply) {
            Ok(Reply::AckOpen {
                nonce: echoed,
                remaining_secs,
            }) => {
                if echoed != nonce {
                    return Err(DriverError(format!(
                        "device {:?} acknowledged a DIFFERENT grant nonce than the one \
                         delivered — refusing to treat someone else's grant as ours",
                        host.name
                    )));
                }
                if remaining_secs == 0 || remaining_secs > u64::from(ttl_secs) {
                    return Err(DriverError(format!(
                        "device {:?} anchored an implausible remaining time ({remaining_secs}s \
                         against a {ttl_secs}s ttl)",
                        host.name
                    )));
                }
                Ok(())
            }
            Ok(Reply::Nak(reason)) => Err(DriverError(format!(
                "device {:?} refused the capability: {reason}",
                host.name
            ))),
            Ok(other) => Err(DriverError(format!(
                "device {:?} answered TOK with {other:?}",
                host.name
            ))),
            Err(e) => Err(DriverError(format!(
                "device {:?} TOK reply unparseable ({e}): {:?}",
                host.name,
                reply.trim()
            ))),
        }
    }
}

/// The actuator second oracle (docs/EMBEDDED.md §7): when the inventory
/// declares an actuator, "switch commanded" is not enough — the reported
/// fail-state must match the declaration (config drift is a loud error),
/// a promised current sensor must actually report, and the load must agree
/// with the grant, with exactly one named exception: a fail-energized
/// actuator that just BOOTED legitimately reads load=on while closed (the
/// don't-hard-down-the-server case — checked, not shrugged at).
fn check_actuator(
    actuator: &ActuatorSpec,
    report: &line::Report,
    expect_open: bool,
    host: &str,
) -> Result<(), DriverError> {
    let declared = match actuator.fail_state {
        FailStatePolicy::Energized => line::FailState::Energized,
        FailStatePolicy::DeEnergized => line::FailState::DeEnergized,
    };
    match report.fail {
        Some(reported) if reported == declared => {}
        Some(_) => {
            return Err(DriverError(format!(
                "device {host:?} reports a DIFFERENT fail-state than the inventory declares — the actuator's failure behavior has drifted from policy"
            )))
        }
        None => {
            return Err(DriverError(format!(
                "device {host:?} is declared an actuator but reports no fail-state"
            )))
        }
    }
    let load = match (actuator.current_sense, report.load) {
        (true, None) => {
            return Err(DriverError(format!(
                "device {host:?} promises current sense but its STATE carries no load reading"
            )))
        }
        (_, load) => load,
    };
    if let Some(load) = load {
        let boot_energized = report.reason == Some(line::CloseReason::Boot)
            && actuator.fail_state == FailStatePolicy::Energized;
        match (expect_open, load) {
            (true, true) | (false, false) => {}
            (false, true) if boot_energized => {} // the named exception
            (true, false) => {
                return Err(DriverError(format!(
                    "device {host:?}: the grant is open but the load reads OFF — the actuator did not actually actuate"
                )))
            }
            (false, true) => {
                return Err(DriverError(format!(
                    "device {host:?}: the grant is closed but the load reads ON — the revert did not actually revert (stuck relay?)"
                )))
            }
        }
    }
    Ok(())
}

impl ChannelDriver for DeviceDriver {
    fn channel(&self) -> Channel {
        Channel::Device
    }

    fn apply(&mut self, host: &Host, ctx: &ApplyCtx) -> Result<(), DriverError> {
        let device = Self::config(host)?.clone();
        let device_id = Self::device_id(&device);
        let ttl_secs = u32::try_from(ctx.ttl_secs)
            .map_err(|_| DriverError(format!("ttl {}s exceeds the wire format", ctx.ttl_secs)))?;

        let nonce = self.nonces.nonce();
        // Persist the nonce BEFORE delivery: if we crash after the device
        // accepts, the restarted daemon must know which grant is ours.
        self.state
            .set_open_nonce(&device_id, &nonce)
            .map_err(|e| DriverError(format!("persisting grant nonce: {e}")))?;

        self.deliver_cap(host, &device, nonce, ttl_secs)?;

        // Verify against actual device state, not the ACK alone.
        let report = self.report(host, &device)?;
        if let Some(actuator) = &device.actuator {
            check_actuator(actuator, &report, true, &host.name)?;
        }
        match report.open {
            Some((n, remaining)) if n == nonce && remaining > 0 => Ok(()),
            Some((n, _)) if n != nonce => Err(DriverError(format!(
                "device {:?} reports a different grant open after delivery",
                host.name
            ))),
            _ => Err(DriverError(format!(
                "device {:?} did not read back open after accepting the capability",
                host.name
            ))),
        }
    }

    fn renew(&mut self, host: &Host, ctx: &ApplyCtx) -> Result<(), DriverError> {
        let device = Self::config(host)?.clone();
        let device_id = Self::device_id(&device);
        let ttl_secs = u32::try_from(ctx.ttl_secs)
            .map_err(|_| DriverError(format!("ttl {}s exceeds the wire format", ctx.ttl_secs)))?;
        let nonce = self
            .state
            .open_nonce(&device_id)
            .map_err(|e| DriverError(format!("reading grant nonce: {e}")))?
            .ok_or_else(|| {
                DriverError(format!(
                    "no grant nonce recorded for device {:?}; cannot renew what was never \
                     delivered",
                    host.name
                ))
            })?;
        // Same nonce, fresh seq, new ttl: the device re-anchors idempotently.
        self.deliver_cap(host, &device, nonce, ttl_secs)
    }

    fn revert(&mut self, host: &Host) -> Result<(), DriverError> {
        let device = Self::config(host)?.clone();
        let device_id = Self::device_id(&device);

        // Our recorded nonce, else whatever the device says is open (a
        // revocation must name the grant), else the device is already closed.
        let nonce = match self
            .state
            .open_nonce(&device_id)
            .map_err(|e| DriverError(format!("reading grant nonce: {e}")))?
        {
            Some(n) => Some(n),
            None => self.report(host, &device)?.open.map(|(n, _)| n),
        };
        let Some(nonce) = nonce else {
            return Ok(()); // Idempotent: nothing open anywhere.
        };

        let token = self.signer.next_rvk(&device, nonce)?;
        let reply = self.send(host, &device, &Command::Revoke(&token))?;
        match line::parse_reply(&reply) {
            Ok(Reply::AckClosed) => {}
            Ok(Reply::Nak(reason)) => {
                return Err(DriverError(format!(
                    "device {:?} refused the revocation: {reason}",
                    host.name
                )))
            }
            Ok(other) => {
                return Err(DriverError(format!(
                    "device {:?} answered RVK with {other:?}",
                    host.name
                )))
            }
            Err(e) => {
                return Err(DriverError(format!(
                    "device {:?} RVK reply unparseable ({e})",
                    host.name
                )))
            }
        }
        // Read the actual state back before believing it.
        let report = self.report(host, &device)?;
        if let Some(actuator) = &device.actuator {
            check_actuator(actuator, &report, false, &host.name)?;
        }
        if report.open.is_some() {
            return Err(DriverError(format!(
                "device {:?} still reports open after the revocation",
                host.name
            )));
        }
        self.state
            .clear_open_nonce(&device_id)
            .map_err(|e| DriverError(format!("clearing grant nonce: {e}")))?;
        Ok(())
    }

    fn verify(&mut self, host: &Host) -> Result<ChannelState, DriverError> {
        let device = Self::config(host)?.clone();
        let device_id = Self::device_id(&device);
        let ours = self
            .state
            .open_nonce(&device_id)
            .map_err(|e| DriverError(format!("reading grant nonce: {e}")))?;
        let report = self.report(host, &device)?;
        if let Some(actuator) = &device.actuator {
            check_actuator(actuator, &report, report.open.is_some(), &host.name)?;
        }
        match (report.open, ours) {
            (None, _) => Ok(ChannelState::Closed),
            (Some((n, _)), Some(mine)) if n == mine => Ok(ChannelState::Open),
            // Open under a nonce that is not ours: NEVER report Closed (that
            // would let a revert path shrug at a live foreign grant).
            (Some(_), _) => Err(DriverError(format!(
                "device {:?} is open under a grant this daemon did not record — refusing to \
 report a state for someone else's grant",
                host.name
            ))),
        }
    }

    fn reestablish(&mut self, host: &Host) -> Result<ChannelState, DriverError> {
        // After a restart: the grant is ours iff the device holds OUR
        // recorded nonce with time remaining. Anything else — closed, a
        // foreign nonce, no record — reads Closed, which routes into the
        // existing Lost/retract path (reachability we cannot confirm, we
        // retract; the revocation then names whatever nonce the device
        // reports, so a foreign grant is closed too rather than adopted).
        let device = Self::config(host)?.clone();
        let device_id = Self::device_id(&device);
        let ours = self
            .state
            .open_nonce(&device_id)
            .map_err(|e| DriverError(format!("reading grant nonce: {e}")))?;
        let report = self.report(host, &device)?;
        Ok(match (report.open, ours) {
            (Some((n, remaining)), Some(mine)) if n == mine && remaining > 0 => ChannelState::Open,
            _ => ChannelState::Closed,
        })
    }
}

/// The production signer: the [signing] keys plus the seq ledger.
pub struct ProductionSigner {
    pub ed25519_seed: Option<[u8; 32]>,
    pub p256_scalar: Option<[u8; 32]>,
    pub state: DeviceState,
}

impl ProductionSigner {
    fn key(&self, alg: DeviceAlg) -> Result<lychgate_wire::SigningKey<'_>, DriverError> {
        match alg {
            DeviceAlg::Ed25519 => self
                .ed25519_seed
                .as_ref()
                .map(lychgate_wire::SigningKey::Ed25519Seed)
                .ok_or_else(|| DriverError("no [signing] key_file loaded".into())),
            DeviceAlg::P256 => self
                .p256_scalar
                .as_ref()
                .map(lychgate_wire::SigningKey::P256Scalar)
                .ok_or_else(|| DriverError("no [signing] p256_key_file loaded".into())),
        }
    }

    fn ver(alg: DeviceAlg) -> u8 {
        match alg {
            DeviceAlg::Ed25519 => lychgate_wire::VER_ED25519,
            DeviceAlg::P256 => lychgate_wire::VER_P256,
        }
    }

    /// Reserve a sequence number durably BEFORE any token exists: a crash
    /// here wastes a number, never reuses one.
    fn reserve(&mut self, device_id: &[u8; 16]) -> Result<u64, DriverError> {
        self.state
            .reserve_seq(device_id)
            .map_err(|e| DriverError(format!("reserving token seq: {e}")))
    }
}

impl TokenSigner for ProductionSigner {
    fn next_cap(
        &mut self,
        device: &DeviceConfig,
        nonce: [u8; 16],
        ttl_secs: u32,
    ) -> Result<String, DriverError> {
        let device_id = DeviceDriver::device_id(device);
        let seq = self.reserve(&device_id)?;
        let cap = lychgate_wire::Capability {
            ver: Self::ver(device.alg),
            device_id,
            grant_nonce: nonce,
            capability: device.capability,
            ttl_secs,
            issued_seq: seq,
        };
        lychgate_wire::sign_capability_token(&self.key(device.alg)?, &cap)
            .map_err(|e| DriverError(format!("signing capability token: {e}")))
    }

    fn next_rvk(&mut self, device: &DeviceConfig, nonce: [u8; 16]) -> Result<String, DriverError> {
        let device_id = DeviceDriver::device_id(device);
        let seq = self.reserve(&device_id)?;
        let rvk = lychgate_wire::Revocation {
            ver: Self::ver(device.alg),
            device_id,
            grant_nonce: nonce,
            issued_seq: seq,
        };
        lychgate_wire::sign_revocation_token(&self.key(device.alg)?, &rvk)
            .map_err(|e| DriverError(format!("signing revocation token: {e}")))
    }
}

/// The production transport: dispatches per the host's configured wire.
/// Serial and http ride the generic channels' raw helpers; the device-mqtt
/// transport is refused at inventory load (named unimplemented — an exec'd
/// subscribe-then-publish round trip cannot be made race-free, so it waits
/// for a real implementation rather than shipping one that mostly works).
pub struct ExecDeviceTransport;

impl DeviceTransport for ExecDeviceTransport {
    fn transact(
        &mut self,
        host: &Host,
        device: &DeviceConfig,
        command: &str,
    ) -> Result<String, DriverError> {
        let framed = format!("{command}\n");
        if let Some(serial) = &device.serial {
            let reply = crate::drivers::serial::fd_transact(
                &serial.device,
                serial.baud,
                serial.timeout_secs,
                &framed,
                &crate::drivers::serial::Until(vec!["\n".to_string()]),
            )?;
            return Ok(reply.lines().next().unwrap_or("").to_string());
        }
        if let Some(http) = &device.http {
            let (status, body) = crate::drivers::http::curl_request(
                &http.endpoint,
                &http.tls,
                http.auth_user.as_deref(),
                http.auth_password_file.as_deref(),
                "POST",
                "/lychgate/cmd",
                Some(command),
            )?;
            if status != 200 {
                return Err(DriverError(format!(
                    "device {:?} command endpoint returned HTTP {status}",
                    host.name
                )));
            }
            return Ok(body.trim_end().to_string());
        }
        Err(DriverError(format!(
            "device {:?} has no usable transport (validated at load; this is a bug)",
            host.name
        )))
    }
}

#[cfg(test)]
mod tests;
