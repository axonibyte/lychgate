//! The `hmac` authenticator kind: HMAC-SHA256 over the approval challenge.
//!
//! The tier-A story (docs/EMBEDDED.md §6, path 2): SHA-256 fits a classic
//! AVR where curve crypto does not, so a low-end device with no secure
//! element can still be an approval factor. Deliberately the SYMMETRIC,
//! honestly-weak kind: the daemon holds the same 32-byte secret (a mode-600
//! secret-file, sealable via --tpm-unseal like every other secret file), so
//! compromise of the daemon host forges this factor — the runbook prices it
//! at low weight, composed with an asymmetric human factor, exactly the
//! password kind's positioning. Challenge-bound, so no single-use ledger:
//! the per-request nonce is the anti-replay, as with fido2/tpm.
//!
//! Token: `lghmac.<base64url-nopad(HMAC-SHA256(secret, challenge))>`.
//! (The module is named hmac_factor to keep clear of the `hmac` crate.)

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// The dispatch discriminator, like `lgfido2.`/`lgtpm.`.
pub const TOKEN_PREFIX: &str = "lghmac.";

/// Secrets are exactly 32 bytes (hex in the secret-file): enough for the
/// full HMAC-SHA256 security level, small enough for tier-A flash.
pub const SECRET_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HmacError {
    /// The token is not `lghmac.` + base64url of a 32-byte MAC.
    Malformed,
    /// The MAC did not verify (constant-time compare inside the hmac crate).
    Mismatch,
    /// The secret-file's content is not 64 hex characters.
    BadSecret,
}

impl fmt::Display for HmacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HmacError::Malformed => write!(
                f,
                "not an lghmac token (expected {TOKEN_PREFIX}<base64url of a 32-byte MAC>)"
            ),
            HmacError::Mismatch => write!(f, "hmac verification failed"),
            HmacError::BadSecret => write!(
                f,
                "hmac secret must be exactly {SECRET_LEN} bytes as hex ({} characters)",
                SECRET_LEN * 2
            ),
        }
    }
}

impl std::error::Error for HmacError {}

/// Parse and validate a secret-file's content at daemon startup (fail at
/// start, not at 03:00).
pub fn check_secret(text: &str) -> Result<Vec<u8>, HmacError> {
    let hex = text.trim();
    if hex.len() != SECRET_LEN * 2 {
        return Err(HmacError::BadSecret);
    }
    (0..SECRET_LEN)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| HmacError::BadSecret))
        .collect()
}

/// The device/test signer: deterministic, so a low-end device (or this
/// crate's own KAT) computes the identical token.
pub fn sign(secret: &[u8], challenge: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(challenge.as_bytes());
    format!(
        "{TOKEN_PREFIX}{}",
        data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes())
    )
}

/// Verify a token against the challenge it must be bound to. The MAC compare
/// is the hmac crate's constant-time `verify_slice`; a wrong-length MAC is
/// `Malformed`, never a silent false.
pub fn verify(secret: &[u8], token: &str, challenge: &str) -> Result<(), HmacError> {
    let b64 = token
        .strip_prefix(TOKEN_PREFIX)
        .ok_or(HmacError::Malformed)?;
    let presented = data_encoding::BASE64URL_NOPAD
        .decode(b64.as_bytes())
        .map_err(|_| HmacError::Malformed)?;
    if presented.len() != 32 {
        return Err(HmacError::Malformed);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(challenge.as_bytes());
    mac.verify_slice(&presented)
        .map_err(|_| HmacError::Mismatch)
}

#[cfg(test)]
mod tests;
