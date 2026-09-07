//! The lychgate wire contract: `lgcap.` capability tokens and `lgrvk.`
//! revocation tokens, as exchanged between the daemon (signer) and a
//! cooperative device (verifier).
//!
//! This crate is deliberately tiny and `no_std`: it is compiled into device
//! firmware, the e2e device simulator, the daemon, an AVR-facing C reference
//! implementation (by contract, not by linking), and an FPGA soft-core image.
//! The committed vectors under `vectors/` are the cross-language contract —
//! a port that passes them speaks the protocol, and a vector change is a
//! breaking change by definition. See docs/EMBEDDED.md for the normative
//! byte-level description.
//!
//! Token grammar (ASCII): `lgcap.<b64url(payload)>.<b64url(signature)>` and
//! `lgrvk.<b64url(payload)>.<b64url(signature)>`, base64url without padding.
//! The payload is a deterministic-CBOR-subset map (see `cbor`); the signature
//! covers the ASCII prefix concatenated with the payload bytes, so a
//! revocation signature can never verify as a capability (domain separation).
//! Two schemes, selected by the payload's `ver` field:
//!
//! * `ver = 1` — Ed25519 (RFC 8032), 64-byte signature.
//! * `ver = 2` — ECDSA P-256 over SHA-256, raw `r || s` 64-byte signature —
//!   the ATECC608's native format, so tier-A devices verify by hashing on-MCU
//!   and delegating the curve check to the secure element.
//!
//! Policy stays out of this crate: `MAX_TTL_SECS` is exported for consumers
//! (the device refuses a longer TTL, the daemon never issues one), but a
//! larger value deliberately *parses* — a committed vector pins that, so
//! every port agrees on where policy lives.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

mod cbor;
pub mod line;
mod token;

pub use token::{
    decode_capability, decode_revocation, encode_capability, encode_revocation,
    sign_capability_into, sign_revocation_into, verify_capability, verify_revocation, Capability,
    PublicKey, Revocation, SigningKey, CAP_PREFIX, MAX_PAYLOAD_LEN, MAX_TOKEN_LEN, RVK_PREFIX,
    SIG_LEN, VER_ED25519, VER_P256,
};

#[cfg(feature = "std")]
pub use token::{sign_capability_token, sign_revocation_token};

/// The TTL ceiling consumers enforce (24 hours, matching the daemon's grant
/// cap). Enforcement is deliberately NOT in the decoder: the device refuses,
/// the daemon caps, and the wire format stays policy-free.
pub const MAX_TTL_SECS: u32 = 86_400;

/// Everything that can go wrong verifying or decoding a token. `Malformed`
/// carries a static reason so ports and tests can name the exact refusal
/// without allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The token does not start with the expected `lgcap.` / `lgrvk.` prefix.
    BadPrefix,
    /// A base64url segment failed to decode (or padding was present).
    BadBase64,
    /// The CBOR payload violates the deterministic subset; the reason names
    /// the first rule broken.
    Malformed(&'static str),
    /// The payload parsed but its `ver` is not one this crate knows.
    UnknownVersion,
    /// The payload's `ver` does not match the kind of key supplied.
    VersionKeyMismatch,
    /// The public key bytes are not a valid key for the selected scheme.
    BadKey,
    /// The signature check failed.
    BadSignature,
    /// An output buffer was too small (signing/encoding only).
    BufferTooSmall,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireError::BadPrefix => write!(f, "not a lychgate token (bad prefix)"),
            WireError::BadBase64 => write!(f, "base64url segment failed to decode"),
            WireError::Malformed(why) => write!(f, "malformed payload: {why}"),
            WireError::UnknownVersion => write!(f, "unknown token version"),
            WireError::VersionKeyMismatch => {
                write!(f, "token version does not match the supplied key kind")
            }
            WireError::BadKey => write!(f, "invalid public key for the token's scheme"),
            WireError::BadSignature => write!(f, "signature verification failed"),
            WireError::BufferTooSmall => write!(f, "output buffer too small"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WireError {}

#[cfg(test)]
mod tests;
