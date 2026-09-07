//! The device-side grant engine: everything a cooperative lychgate device
//! must get right, behind three small traits its firmware implements.
//!
//! The rules this crate owns (docs/EMBEDDED.md §3 is the narrative):
//!
//! - **A reboot closes the grant.** Grant state lives in RAM only; the gate
//!   is driven closed in `DeviceEngine::new`, before any protocol handling.
//!   Power-cycling a device revokes access, never extends it.
//! - **TTL on the uptime clock.** The deadline anchors at token acceptance
//!   on `UptimeClock::uptime_ms`; expiry is a property of observation (any
//!   command, or `tick()`, notices it) and drops the gate.
//! - **Sequence anti-replay.** `issued_seq` must strictly advance past the
//!   `SeqStore` mark, which is persisted BEFORE a token takes effect — the
//!   only device-side state that survives a reboot, so a captured token is
//!   dead once superseded even across a power cycle.
//! - **Single grant, idempotent redelivery.** The same nonce at the SAME seq
//!   is re-acknowledged without re-anchoring (a replayed still-current token
//!   must not extend the deadline); the same nonce at a HIGHER seq is a
//!   renewal and re-anchors; a new nonce while open is refused busy.
//! - **Policy bounds.** A ttl over `lychgate_wire::MAX_TTL_SECS` is refused
//!   here — the wire format deliberately parses it; the device is where the
//!   bound bites.
//!
//! Firmware implements `UptimeClock` (a monotonic ms counter), `SeqStore`
//! (a small persistent record — flash, NVS, an SE counter), and `Gate` (the
//! thing access actually flows through: a GPIO, a relay, a port enable),
//! then feeds lines to `handle_line` and calls `tick()` from its main loop.
//! The reference ESP32-C3 firmware and the e2e device simulator are both
//! thin wrappers around this engine, so they cannot drift from each other.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

use lychgate_wire::line::{self, CloseReason, Command, Reply, Report};
use lychgate_wire::{PublicKey, WireError};

/// A monotonic milliseconds-since-boot clock. Wall time is deliberately
/// absent from the whole design — the device has no trusted source of it.
pub trait UptimeClock {
    fn uptime_ms(&self) -> u64;
}

/// The persistent anti-replay mark. `store` must be durable before it
/// returns (flash write-through, not a cache): it is the one thing a reboot
/// must not lose.
pub trait SeqStore {
    fn load(&mut self) -> Result<u64, StoreError>;
    fn store(&mut self, seq: u64) -> Result<(), StoreError>;
}

/// The access being gated. `set_open(false)` must always be safe to call —
/// it is invoked unconditionally at boot and on every close.
pub trait Gate {
    fn set_open(&mut self, open: bool);
}

/// A storage failure. The engine fails CLOSED on it: a token whose seq
/// cannot be recorded is refused, because accepting it would leave the
/// replay mark behind the tokens in the wild.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreError;

/// The device's provisioned verifying key, owned (no_std, no alloc).
#[derive(Debug, Clone, Copy)]
pub enum TrustRoot {
    Ed25519([u8; 32]),
    /// Uncompressed SEC1 point (0x04 || x || y).
    P256([u8; 65]),
}

impl TrustRoot {
    fn key(&self) -> PublicKey<'_> {
        match self {
            TrustRoot::Ed25519(k) => PublicKey::Ed25519(k),
            TrustRoot::P256(k) => PublicKey::P256Sec1(&k[..]),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Grant {
    nonce: [u8; 16],
    expires_at_ms: u64,
}

/// The engine. Generic over the three HAL traits so firmware pays no
/// dynamic dispatch and tests inject fakes.
pub struct DeviceEngine<C, S, G> {
    clock: C,
    seq: S,
    gate: G,
    device_id: [u8; 16],
    trust: TrustRoot,
    grant: Option<Grant>,
    last_close: Option<CloseReason>,
}

impl<C: UptimeClock, S: SeqStore, G: Gate> DeviceEngine<C, S, G> {
    /// Boot. The gate is driven CLOSED here, before any line is handled —
    /// the reboot-revokes rule is enforced by construction, not convention.
    pub fn new(device_id: [u8; 16], trust: TrustRoot, clock: C, seq: S, mut gate: G) -> Self {
        gate.set_open(false);
        DeviceEngine {
            clock,
            seq,
            gate,
            device_id,
            trust,
            grant: None,
            last_close: Some(CloseReason::Boot),
        }
    }

    /// Drop the gate if the deadline has passed. Call from the main loop;
    /// `handle_line` also calls it, so expiry is a property of observation.
    pub fn tick(&mut self) {
        if let Some(grant) = &self.grant {
            if self.clock.uptime_ms() >= grant.expires_at_ms {
                self.close(CloseReason::Expiry);
            }
        }
    }

    fn close(&mut self, reason: CloseReason) {
        self.grant = None;
        self.gate.set_open(false);
        self.last_close = Some(reason);
    }

    fn remaining_secs(&self, grant: &Grant) -> u64 {
        grant
            .expires_at_ms
            .saturating_sub(self.clock.uptime_ms())
            .div_ceil(1000)
    }

    /// Handle one protocol line, rendering the reply into `buf`.
    pub fn handle_line<'b>(
        &mut self,
        input: &str,
        buf: &'b mut [u8; line::MAX_LINE_LEN],
    ) -> &'b str {
        self.tick();
        let reply = match line::parse_command(input) {
            Ok(Command::Token(token)) => self.accept_token(token),
            Ok(Command::Revoke(token)) => self.accept_revocation(token),
            Ok(Command::Status) => Reply::State(self.report()),
            Ok(Command::SePubkey) | Ok(Command::SeSign(_)) => Reply::Nak("unsupported"),
            Err(_) => Reply::Nak("bad-command"),
        };
        line::render_reply(&reply, buf).expect("replies fit MAX_LINE_LEN")
    }

    fn report(&mut self) -> Report {
        // The report is best-effort about the mark (a read failure shows 0
        // rather than hiding the whole report); acceptance itself still
        // fails closed through the store path.
        let seq = self.seq.load().unwrap_or(0);
        Report {
            open: self
                .grant
                .as_ref()
                .map(|g| (g.nonce, self.remaining_secs(g))),
            seq,
            load: None,
            fail: None,
            reason: if self.grant.is_none() {
                self.last_close
            } else {
                None
            },
        }
    }

    fn accept_token(&mut self, token: &str) -> Reply<'static> {
        let cap = match lychgate_wire::verify_capability(&self.trust.key(), token) {
            Ok(cap) => cap,
            Err(WireError::VersionKeyMismatch) => return Reply::Nak("wrong-alg"),
            Err(_) => return Reply::Nak("bad-token"),
        };
        if cap.device_id != self.device_id {
            return Reply::Nak("wrong-device");
        }
        let stored = match self.seq.load() {
            Ok(s) => s,
            Err(_) => return Reply::Nak("store-failed"),
        };

        // Idempotent redelivery: the SAME token (same nonce, same seq as the
        // one that set the mark) is re-acknowledged WITHOUT re-anchoring — a
        // replayed still-current token must not extend the deadline.
        if let Some(grant) = self.grant {
            if grant.nonce == cap.grant_nonce && cap.issued_seq == stored {
                return Reply::AckOpen {
                    nonce: grant.nonce,
                    remaining_secs: self.remaining_secs(&grant),
                };
            }
            if grant.nonce != cap.grant_nonce {
                // A new grant while one is open: refused whether its seq is
                // fresh or stale (per-device single-grant, the daemon's own
                // model).
                return Reply::Nak("busy");
            }
        }

        if cap.issued_seq <= stored {
            return Reply::Nak("replay");
        }
        if cap.ttl_secs > lychgate_wire::MAX_TTL_SECS {
            return Reply::Nak("ttl");
        }
        // The mark is durable BEFORE the grant takes effect: fail closed on
        // a store error rather than accept a token we could not retire.
        if self.seq.store(cap.issued_seq).is_err() {
            return Reply::Nak("store-failed");
        }

        let expires_at_ms = self
            .clock
            .uptime_ms()
            .saturating_add(u64::from(cap.ttl_secs).saturating_mul(1000));
        let grant = Grant {
            nonce: cap.grant_nonce,
            expires_at_ms,
        };
        self.grant = Some(grant);
        self.last_close = None;
        self.gate.set_open(true);
        Reply::AckOpen {
            nonce: grant.nonce,
            remaining_secs: self.remaining_secs(&grant),
        }
    }

    fn accept_revocation(&mut self, token: &str) -> Reply<'static> {
        let rvk = match lychgate_wire::verify_revocation(&self.trust.key(), token) {
            Ok(rvk) => rvk,
            Err(WireError::VersionKeyMismatch) => return Reply::Nak("wrong-alg"),
            Err(_) => return Reply::Nak("bad-token"),
        };
        if rvk.device_id != self.device_id {
            return Reply::Nak("wrong-device");
        }
        let stored = match self.seq.load() {
            Ok(s) => s,
            Err(_) => return Reply::Nak("store-failed"),
        };
        // A stale revocation (an old capture) must not close a NEWER grant:
        // seq ordering is the staleness oracle.
        if rvk.issued_seq <= stored {
            return Reply::Nak("replay");
        }
        if self.seq.store(rvk.issued_seq).is_err() {
            return Reply::Nak("store-failed");
        }
        match &self.grant {
            None => Reply::AckClosed, // Idempotent.
            Some(grant) if grant.nonce == rvk.grant_nonce => {
                self.close(CloseReason::Revert);
                Reply::AckClosed
            }
            // Fresh seq but naming a grant we do not hold: refuse rather
            // than close the wrong thing.
            Some(_) => Reply::Nak("wrong-grant"),
        }
    }
}

#[cfg(test)]
mod tests;
