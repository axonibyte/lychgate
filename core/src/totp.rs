//! RFC 6238 TOTP verification — pure, injected-time, no I/O.
//!
//! An authenticator app (Google Authenticator, Authy, a hardware TOTP token)
//! shares a base32 secret with lychgate and shows a rolling 6-digit code. This
//! module turns a secret + a counter into that code (RFC 4226 §5.3 dynamic
//! truncation over HMAC-SHA1, the crypto from RustCrypto) and checks a submitted
//! code against a small window of counters, returning the matched counter so the
//! daemon can spend it once against its single-use ledger.
//!
//! The parameters are the near-universal authenticator-app defaults — SHA-1, a
//! 30-second step, 6 digits — so any standard app interoperates without
//! configuration.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// The RFC 6238 step (seconds) and code length. Fixed to the app defaults.
const STEP_SECS: u64 = 30;
const DIGITS: u32 = 6;

/// A TOTP shared secret. Redacted in Debug/Display so it cannot leak through a
/// stray `{:?}`; the bytes are used only by this module's HMAC. Parsed from
/// base32 — what authenticator apps display and encode in their QR codes.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpSecret(Vec<u8>);

#[derive(Debug, PartialEq, Eq)]
pub enum TotpError {
    /// The configured secret is not valid base32.
    BadBase32,
    /// The secret decoded to nothing — no secret at all.
    Empty,
}

impl fmt::Display for TotpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TotpError::BadBase32 => write!(f, "totp secret is not valid base32"),
            TotpError::Empty => write!(f, "totp secret is empty"),
        }
    }
}

impl std::error::Error for TotpError {}

impl TotpSecret {
    /// Parse a base32 secret (RFC 4648), tolerant of the whitespace, case and
    /// padding that authenticator apps and config files vary on: apps show
    /// grouped uppercase, some emit `=` padding, some do not.
    pub fn from_base32(s: &str) -> Result<TotpSecret, TotpError> {
        let cleaned: String = s
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_uppercase();
        let unpadded = cleaned.trim_end_matches('=');
        let bytes = data_encoding::BASE32_NOPAD
            .decode(unpadded.as_bytes())
            .map_err(|_| TotpError::BadBase32)?;
        if bytes.is_empty() {
            return Err(TotpError::Empty);
        }
        Ok(TotpSecret(bytes))
    }
}

impl fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpSecret(redacted)")
    }
}

impl fmt::Display for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// The time step (counter) for an instant. Before the epoch (impossible on a
/// sane clock) counts as step 0.
fn counter_at(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / STEP_SECS)
        .unwrap_or(0)
}

/// The RFC 6238 code for `secret` at `counter`: HMAC-SHA1 of the big-endian
/// counter, then RFC 4226 §5.3 dynamic truncation to `DIGITS` zero-padded
/// digits. This is HOTP(secret, counter); TOTP is HOTP over the time step.
pub fn code_at(secret: &TotpSecret, counter: u64) -> String {
    // HMAC accepts a key of any length, so new_from_slice never errs here.
    let mut mac = HmacSha1::new_from_slice(&secret.0).expect("hmac accepts any key length");
    mac.update(&counter.to_be_bytes());
    let hs = mac.finalize().into_bytes(); // 20 bytes
    let offset = (hs[19] & 0x0f) as usize;
    let bin = ((hs[offset] as u32 & 0x7f) << 24)
        | ((hs[offset + 1] as u32) << 16)
        | ((hs[offset + 2] as u32) << 8)
        | (hs[offset + 3] as u32);
    let modulo = 10u32.pow(DIGITS);
    format!("{:0width$}", bin % modulo, width = DIGITS as usize)
}

/// Whether `code` is a valid TOTP for `secret` at `now`, within `±skew_steps`
/// time steps (clock drift tolerance). Returns the matched counter so the daemon
/// can spend it exactly once against its ledger; `None` if nothing in the window
/// matches. The window is scanned in full with a constant-time compare and no
/// early return, so neither a near-miss nor which step matched leaks via timing.
pub fn matches(secret: &TotpSecret, code: &str, now: SystemTime, skew_steps: u64) -> Option<u64> {
    let code = code.trim();
    // A well-formed code is exactly DIGITS ASCII digits — a format check, not a
    // secret comparison, so an early return here leaks nothing.
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let center = counter_at(now);
    let lo = center.saturating_sub(skew_steps);
    let hi = center.saturating_add(skew_steps);
    let mut found = None;
    for counter in lo..=hi {
        if ct_eq(code_at(secret, counter).as_bytes(), code.as_bytes()) {
            found = Some(counter);
        }
    }
    found
}

/// Constant-time equality for equal-length byte slices. Not crypto — a
/// comparison primitive — but kept constant-time so a code check leaks no timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests;
