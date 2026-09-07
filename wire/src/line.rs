//! The device line protocol: newline-delimited ASCII between the daemon's
//! device channel and a cooperative device.
//!
//! One implementation for BOTH sides, on purpose: the daemon renders
//! commands and parses replies, the device (firmware, the e2e simulator)
//! parses commands and renders replies — all through this module, so the two
//! ends cannot drift. The grammar (normative copy in docs/EMBEDDED.md):
//!
//! ```text
//! daemon -> device                 device -> daemon
//! TOK <lgcap-token>                ACK <nonce-hex32> <remaining_secs> | NAK <reason>
//! RVK <lgrvk-token>                ACK closed                         | NAK <reason>
//! STAT                             STATE open <nonce-hex32> <remaining_secs> seq=<n> [trailers]
//!                                  STATE closed seq=<n> [trailers]
//! SE-PUBKEY?                       PUBKEY <hex>                       | NAK <reason>
//! SE-SIGN <challenge>              SIG <lgtpm-token>                  | NAK <reason>
//! ```
//!
//! Trailers are `key=value` words: `load=on|off` (actuator load sense),
//! `fail=energized|de-energized` (the device's configured fail-state), and
//! `reason=revert|expiry|boot` (why the grant last closed). Unknown trailers
//! are refused — a device speaking a newer dialect must not be half
//! understood.

use crate::WireError;

/// Enough for any command or reply: the longest is `TOK ` + a max-length
/// token + newline slack.
pub const MAX_LINE_LEN: usize = 4 + crate::MAX_TOKEN_LEN + 16;

/// A daemon-to-device command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command<'a> {
    /// Deliver a capability token.
    Token(&'a str),
    /// Deliver a revocation token.
    Revoke(&'a str),
    /// Read the device's state report.
    Status,
    /// Read the secure element's public key (E5).
    SePubkey,
    /// Have the secure element sign an approval challenge (E5).
    SeSign(&'a str),
}

/// Why the grant last closed, as the device reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Revert,
    Expiry,
    Boot,
}

/// The device's configured fail-state (actuators; see docs/EMBEDDED.md §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailState {
    Energized,
    DeEnergized,
}

/// A parsed `STATE ...` report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// `Some((grant_nonce, remaining_secs))` when open.
    pub open: Option<([u8; 16], u64)>,
    /// The device's stored anti-replay sequence number.
    pub seq: u64,
    /// Actuator load sense, when the device carries one.
    pub load: Option<bool>,
    /// The device's configured fail-state, when it reports one.
    pub fail: Option<FailState>,
    /// Why the grant last closed, when the device remembers.
    pub reason: Option<CloseReason>,
}

/// A device-to-daemon reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply<'a> {
    /// A capability was accepted (or idempotently re-accepted).
    AckOpen {
        nonce: [u8; 16],
        remaining_secs: u64,
    },
    /// A revocation was applied (or the grant was already closed).
    AckClosed,
    /// A refusal; the reason word is the device's own.
    Nak(&'a str),
    State(Report),
    Pubkey(&'a str),
    Sig(&'a str),
}

fn hex_nonce(nonce: &[u8; 16], out: &mut [u8; 32]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in nonce.iter().enumerate() {
        out[2 * i] = HEX[(b >> 4) as usize];
        out[2 * i + 1] = HEX[(b & 0x0f) as usize];
    }
}

fn parse_hex_nonce(s: &str) -> Result<[u8; 16], WireError> {
    let bytes = s.as_bytes();
    if bytes.len() != 32 {
        return Err(WireError::Malformed("nonce is not 32 hex chars"));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = (bytes[2 * i] as char)
            .to_digit(16)
            .ok_or(WireError::Malformed("nonce is not hex"))?;
        let lo = (bytes[2 * i + 1] as char)
            .to_digit(16)
            .ok_or(WireError::Malformed("nonce is not hex"))?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

/// A fixed-buffer line writer (no_std, zero-alloc).
struct Line<'b> {
    buf: &'b mut [u8],
    len: usize,
}

impl<'b> Line<'b> {
    fn push(&mut self, s: &str) -> Result<(), WireError> {
        let b = s.as_bytes();
        if self.len + b.len() > self.buf.len() {
            return Err(WireError::BufferTooSmall);
        }
        self.buf[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
        Ok(())
    }

    fn push_u64(&mut self, mut n: u64) -> Result<(), WireError> {
        let mut digits = [0u8; 20];
        let mut i = digits.len();
        loop {
            i -= 1;
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        let s = core::str::from_utf8(&digits[i..]).expect("ascii digits");
        self.push(s)
    }

    fn finish(self) -> &'b str {
        core::str::from_utf8(&self.buf[..self.len]).expect("lines are pure ASCII")
    }
}

/// Render a command into `buf` (no trailing newline; transports frame).
pub fn render_command<'b>(
    cmd: &Command<'_>,
    buf: &'b mut [u8; MAX_LINE_LEN],
) -> Result<&'b str, WireError> {
    let mut line = Line { buf, len: 0 };
    match cmd {
        Command::Token(t) => {
            line.push("TOK ")?;
            line.push(t)?;
        }
        Command::Revoke(t) => {
            line.push("RVK ")?;
            line.push(t)?;
        }
        Command::Status => line.push("STAT")?,
        Command::SePubkey => line.push("SE-PUBKEY?")?,
        Command::SeSign(c) => {
            line.push("SE-SIGN ")?;
            line.push(c)?;
        }
    }
    Ok(line.finish())
}

/// Render a reply into `buf`.
pub fn render_reply<'b>(
    reply: &Reply<'_>,
    buf: &'b mut [u8; MAX_LINE_LEN],
) -> Result<&'b str, WireError> {
    let mut line = Line { buf, len: 0 };
    match reply {
        Reply::AckOpen {
            nonce,
            remaining_secs,
        } => {
            let mut hexed = [0u8; 32];
            hex_nonce(nonce, &mut hexed);
            line.push("ACK ")?;
            line.push(core::str::from_utf8(&hexed).expect("hex is ascii"))?;
            line.push(" ")?;
            line.push_u64(*remaining_secs)?;
        }
        Reply::AckClosed => line.push("ACK closed")?,
        Reply::Nak(reason) => {
            line.push("NAK ")?;
            line.push(reason)?;
        }
        Reply::State(report) => {
            line.push("STATE ")?;
            match &report.open {
                Some((nonce, remaining)) => {
                    let mut hexed = [0u8; 32];
                    hex_nonce(nonce, &mut hexed);
                    line.push("open ")?;
                    line.push(core::str::from_utf8(&hexed).expect("hex is ascii"))?;
                    line.push(" ")?;
                    line.push_u64(*remaining)?;
                }
                None => line.push("closed")?,
            }
            line.push(" seq=")?;
            line.push_u64(report.seq)?;
            if let Some(load) = report.load {
                line.push(if load { " load=on" } else { " load=off" })?;
            }
            if let Some(fail) = report.fail {
                line.push(match fail {
                    FailState::Energized => " fail=energized",
                    FailState::DeEnergized => " fail=de-energized",
                })?;
            }
            if let Some(reason) = report.reason {
                line.push(match reason {
                    CloseReason::Revert => " reason=revert",
                    CloseReason::Expiry => " reason=expiry",
                    CloseReason::Boot => " reason=boot",
                })?;
            }
        }
        Reply::Pubkey(hex) => {
            line.push("PUBKEY ")?;
            line.push(hex)?;
        }
        Reply::Sig(token) => {
            line.push("SIG ")?;
            line.push(token)?;
        }
    }
    Ok(line.finish())
}

/// Parse a daemon-to-device command line (the device side).
pub fn parse_command(line: &str) -> Result<Command<'_>, WireError> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line == "STAT" {
        return Ok(Command::Status);
    }
    if line == "SE-PUBKEY?" {
        return Ok(Command::SePubkey);
    }
    if let Some(rest) = line.strip_prefix("TOK ") {
        return Ok(Command::Token(rest));
    }
    if let Some(rest) = line.strip_prefix("RVK ") {
        return Ok(Command::Revoke(rest));
    }
    if let Some(rest) = line.strip_prefix("SE-SIGN ") {
        return Ok(Command::SeSign(rest));
    }
    Err(WireError::Malformed("unknown command"))
}

fn parse_u64(s: &str, what: &'static str) -> Result<u64, WireError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WireError::Malformed(what));
    }
    s.parse().map_err(|_| WireError::Malformed(what))
}

fn parse_state(rest: &str) -> Result<Report, WireError> {
    let mut words = rest.split(' ').filter(|w| !w.is_empty());
    let open = match words.next() {
        Some("open") => {
            let nonce = parse_hex_nonce(
                words
                    .next()
                    .ok_or(WireError::Malformed("STATE open lacks a nonce"))?,
            )?;
            let remaining = parse_u64(
                words
                    .next()
                    .ok_or(WireError::Malformed("STATE open lacks remaining_secs"))?,
                "remaining_secs is not a number",
            )?;
            Some((nonce, remaining))
        }
        Some("closed") => None,
        _ => return Err(WireError::Malformed("STATE is neither open nor closed")),
    };
    let mut report = Report {
        open,
        seq: 0,
        load: None,
        fail: None,
        reason: None,
    };
    let mut saw_seq = false;
    for word in words {
        let (key, value) = word
            .split_once('=')
            .ok_or(WireError::Malformed("trailer is not key=value"))?;
        match key {
            "seq" => {
                report.seq = parse_u64(value, "seq is not a number")?;
                saw_seq = true;
            }
            "load" => {
                report.load = Some(match value {
                    "on" => true,
                    "off" => false,
                    _ => return Err(WireError::Malformed("load is neither on nor off")),
                })
            }
            "fail" => {
                report.fail = Some(match value {
                    "energized" => FailState::Energized,
                    "de-energized" => FailState::DeEnergized,
                    _ => return Err(WireError::Malformed("unknown fail state")),
                })
            }
            "reason" => {
                report.reason = Some(match value {
                    "revert" => CloseReason::Revert,
                    "expiry" => CloseReason::Expiry,
                    "boot" => CloseReason::Boot,
                    _ => return Err(WireError::Malformed("unknown close reason")),
                })
            }
            // A newer dialect must not be half-understood.
            _ => return Err(WireError::Malformed("unknown trailer")),
        }
    }
    if !saw_seq {
        return Err(WireError::Malformed("STATE lacks seq="));
    }
    Ok(report)
}

/// Parse a device-to-daemon reply line (the daemon side).
pub fn parse_reply(line: &str) -> Result<Reply<'_>, WireError> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line == "ACK closed" {
        return Ok(Reply::AckClosed);
    }
    if let Some(rest) = line.strip_prefix("ACK ") {
        let (nonce_s, remaining_s) = rest
            .split_once(' ')
            .ok_or(WireError::Malformed("ACK lacks remaining_secs"))?;
        return Ok(Reply::AckOpen {
            nonce: parse_hex_nonce(nonce_s)?,
            remaining_secs: parse_u64(remaining_s, "remaining_secs is not a number")?,
        });
    }
    if let Some(rest) = line.strip_prefix("NAK ") {
        return Ok(Reply::Nak(rest));
    }
    if let Some(rest) = line.strip_prefix("STATE ") {
        return Ok(Reply::State(parse_state(rest)?));
    }
    if let Some(rest) = line.strip_prefix("PUBKEY ") {
        return Ok(Reply::Pubkey(rest));
    }
    if let Some(rest) = line.strip_prefix("SIG ") {
        return Ok(Reply::Sig(rest));
    }
    Err(WireError::Malformed("unknown reply"))
}
