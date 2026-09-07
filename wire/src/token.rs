//! lgcap./lgrvk. assembly, parsing, signing and verification.
//!
//! Everything here is zero-alloc and `no_std`; the `std` feature adds
//! String-returning signer conveniences only. The signed message is always
//! the ASCII token prefix concatenated with the payload bytes — domain
//! separation between capabilities and revocations at the signature level.

use crate::cbor::{Reader, Writer};
use crate::WireError;
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::Verifier as _;
use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use p256::ecdsa::signature::Signer as _;

/// Capability-token prefix; part of the signed message.
pub const CAP_PREFIX: &str = "lgcap.";
/// Revocation-token prefix; part of the signed message.
pub const RVK_PREFIX: &str = "lgrvk.";

/// `ver` for Ed25519-signed tokens.
pub const VER_ED25519: u8 = 1;
/// `ver` for P-256-signed tokens (raw `r || s` signatures — the ATECC608's
/// native Verify format).
pub const VER_P256: u8 = 2;

/// Both schemes emit 64-byte signatures.
pub const SIG_LEN: usize = 64;

/// The largest payload either token kind can encode (the capability map with
/// every integer at maximum width).
pub const MAX_PAYLOAD_LEN: usize = 61;

/// The largest token either kind can produce: prefix + b64url(payload) +
/// '.' + b64url(signature). Fixed buffers of this size always suffice.
pub const MAX_TOKEN_LEN: usize = 6 + 82 + 1 + 86;

/// A capability: "hold `capability` open on device `device_id` for
/// `ttl_secs`, anchored at your own acceptance instant". See docs/EMBEDDED.md
/// for the field semantics (nonce idempotency, seq anti-replay).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub ver: u8,
    pub device_id: [u8; 16],
    pub grant_nonce: [u8; 16],
    pub capability: u32,
    pub ttl_secs: u32,
    pub issued_seq: u64,
}

/// A revocation: "close the grant `grant_nonce` on device `device_id` now".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revocation {
    pub ver: u8,
    pub device_id: [u8; 16],
    pub grant_nonce: [u8; 16],
    pub issued_seq: u64,
}

/// The device's provisioned trust root: exactly one key, of the kind matching
/// the `ver` its tokens are signed under.
#[derive(Debug, Clone, Copy)]
pub enum PublicKey<'a> {
    /// 32-byte Ed25519 public key (`ver = 1`).
    Ed25519(&'a [u8; 32]),
    /// SEC1-encoded P-256 point, compressed (33 bytes) or uncompressed (65)
    /// (`ver = 2`).
    P256Sec1(&'a [u8]),
}

impl PublicKey<'_> {
    fn ver(&self) -> u8 {
        match self {
            PublicKey::Ed25519(_) => VER_ED25519,
            PublicKey::P256Sec1(_) => VER_P256,
        }
    }
}

/// The daemon's signing key material.
#[derive(Debug, Clone, Copy)]
pub enum SigningKey<'a> {
    /// 32-byte Ed25519 seed (`ver = 1`).
    Ed25519Seed(&'a [u8; 32]),
    /// 32-byte big-endian P-256 scalar (`ver = 2`). Signing is deterministic
    /// (RFC 6979), so tokens are KAT-stable.
    P256Scalar(&'a [u8; 32]),
}

impl SigningKey<'_> {
    fn ver(&self) -> u8 {
        match self {
            SigningKey::Ed25519Seed(_) => VER_ED25519,
            SigningKey::P256Scalar(_) => VER_P256,
        }
    }
}

// --- payload codec ---------------------------------------------------------

/// Encode a capability payload into `out`, returning the byte length.
pub fn encode_capability(cap: &Capability, out: &mut [u8]) -> Result<usize, WireError> {
    let mut w = Writer::new(out);
    w.map(6)?;
    w.uint_entry(0, u64::from(cap.ver))?;
    w.bstr_entry(1, &cap.device_id)?;
    w.bstr_entry(2, &cap.grant_nonce)?;
    w.uint_entry(3, u64::from(cap.capability))?;
    w.uint_entry(4, u64::from(cap.ttl_secs))?;
    w.uint_entry(5, cap.issued_seq)?;
    Ok(w.finish())
}

/// Encode a revocation payload into `out`, returning the byte length.
pub fn encode_revocation(rvk: &Revocation, out: &mut [u8]) -> Result<usize, WireError> {
    let mut w = Writer::new(out);
    w.map(4)?;
    w.uint_entry(0, u64::from(rvk.ver))?;
    w.bstr_entry(1, &rvk.device_id)?;
    w.bstr_entry(2, &rvk.grant_nonce)?;
    w.uint_entry(3, rvk.issued_seq)?;
    Ok(w.finish())
}

fn read_ver(r: &mut Reader<'_>) -> Result<u8, WireError> {
    let ver = r.uint_entry(0, "expected an unsigned integer")?;
    match u8::try_from(ver) {
        Ok(v @ (VER_ED25519 | VER_P256)) => Ok(v),
        _ => Err(WireError::UnknownVersion),
    }
}

/// Decode a capability payload. Structural checks only — signature
/// verification and every policy decision live with the caller.
pub fn decode_capability(payload: &[u8]) -> Result<Capability, WireError> {
    let mut r = Reader::new(payload);
    r.map(6)?;
    let ver = read_ver(&mut r)?;
    let device_id = r.bstr16_entry(1)?;
    let grant_nonce = r.bstr16_entry(2)?;
    let capability = r.uint_entry_u32(3)?;
    let ttl_secs = r.uint_entry_u32(4)?;
    let issued_seq = r.uint_entry(5, "expected an unsigned integer")?;
    r.end()?;
    Ok(Capability {
        ver,
        device_id,
        grant_nonce,
        capability,
        ttl_secs,
        issued_seq,
    })
}

/// Decode a revocation payload (structural checks only).
pub fn decode_revocation(payload: &[u8]) -> Result<Revocation, WireError> {
    let mut r = Reader::new(payload);
    r.map(4)?;
    let ver = read_ver(&mut r)?;
    let device_id = r.bstr16_entry(1)?;
    let grant_nonce = r.bstr16_entry(2)?;
    let issued_seq = r.uint_entry(3, "expected an unsigned integer")?;
    r.end()?;
    Ok(Revocation {
        ver,
        device_id,
        grant_nonce,
        issued_seq,
    })
}

// --- token assembly / verification -----------------------------------------

/// b64url-decode `seg` into `out`, refusing padding and junk.
fn b64_decode(seg: &[u8], out: &mut [u8]) -> Result<usize, WireError> {
    let len = BASE64URL_NOPAD
        .decode_len(seg.len())
        .map_err(|_| WireError::BadBase64)?;
    if len > out.len() {
        return Err(WireError::BadBase64);
    }
    BASE64URL_NOPAD
        .decode_mut(seg, &mut out[..len])
        .map_err(|_| WireError::BadBase64)?;
    Ok(len)
}

/// The message both schemes sign: `prefix ++ payload`.
fn signed_message(prefix: &str, payload: &[u8], buf: &mut [u8]) -> usize {
    let p = prefix.as_bytes();
    buf[..p.len()].copy_from_slice(p);
    buf[p.len()..p.len() + payload.len()].copy_from_slice(payload);
    p.len() + payload.len()
}

fn verify_sig(key: &PublicKey<'_>, message: &[u8], sig: &[u8; SIG_LEN]) -> Result<(), WireError> {
    match key {
        PublicKey::Ed25519(pk) => {
            let vk = ed25519_dalek::VerifyingKey::from_bytes(pk).map_err(|_| WireError::BadKey)?;
            let sig = ed25519_dalek::Signature::from_bytes(sig);
            vk.verify(message, &sig)
                .map_err(|_| WireError::BadSignature)
        }
        PublicKey::P256Sec1(sec1) => {
            let vk =
                p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1).map_err(|_| WireError::BadKey)?;
            let sig =
                p256::ecdsa::Signature::from_slice(sig).map_err(|_| WireError::BadSignature)?;
            // Hash here rather than through the Verifier trait so the digest
            // is the explicit SHA-256(prefix ++ payload) the ATECC608 path
            // computes on-MCU.
            use sha2::{Digest as _, Sha256};
            let digest = Sha256::digest(message);
            vk.verify_prehash(&digest, &sig)
                .map_err(|_| WireError::BadSignature)
        }
    }
}

/// Split, decode and verify a token of the given kind; returns the raw
/// payload bytes' length after writing them into `payload_out`.
fn open_token(
    prefix: &str,
    key: &PublicKey<'_>,
    token: &str,
    payload_out: &mut [u8; MAX_PAYLOAD_LEN],
) -> Result<usize, WireError> {
    let rest = token.strip_prefix(prefix).ok_or(WireError::BadPrefix)?;
    let dot = rest.find('.').ok_or(WireError::BadBase64)?;
    let (payload_b64, sig_b64) = (&rest[..dot], &rest[dot + 1..]);

    let payload_len = b64_decode(payload_b64.as_bytes(), payload_out)?;

    let mut sig = [0u8; SIG_LEN];
    let sig_len = b64_decode(sig_b64.as_bytes(), &mut sig)?;
    if sig_len != SIG_LEN {
        return Err(WireError::BadSignature);
    }

    let mut msg = [0u8; CAP_PREFIX.len() + MAX_PAYLOAD_LEN];
    let msg_len = signed_message(prefix, &payload_out[..payload_len], &mut msg);
    verify_sig(key, &msg[..msg_len], &sig)?;
    Ok(payload_len)
}

/// Verify a capability token end to end: prefix, base64, signature over
/// `prefix ++ payload`, structural payload decode, and ver-vs-key agreement.
pub fn verify_capability(key: &PublicKey<'_>, token: &str) -> Result<Capability, WireError> {
    let mut payload = [0u8; MAX_PAYLOAD_LEN];
    let len = open_token(CAP_PREFIX, key, token, &mut payload)?;
    let cap = decode_capability(&payload[..len])?;
    if cap.ver != key.ver() {
        return Err(WireError::VersionKeyMismatch);
    }
    Ok(cap)
}

/// Verify a revocation token end to end (same checks as `verify_capability`).
pub fn verify_revocation(key: &PublicKey<'_>, token: &str) -> Result<Revocation, WireError> {
    let mut payload = [0u8; MAX_PAYLOAD_LEN];
    let len = open_token(RVK_PREFIX, key, token, &mut payload)?;
    let rvk = decode_revocation(&payload[..len])?;
    if rvk.ver != key.ver() {
        return Err(WireError::VersionKeyMismatch);
    }
    Ok(rvk)
}

fn sign_message(key: &SigningKey<'_>, message: &[u8]) -> Result<[u8; SIG_LEN], WireError> {
    match key {
        SigningKey::Ed25519Seed(seed) => {
            let sk = ed25519_dalek::SigningKey::from_bytes(seed);
            Ok(ed25519_dalek::Signer::sign(&sk, message).to_bytes())
        }
        SigningKey::P256Scalar(scalar) => {
            let sk =
                p256::ecdsa::SigningKey::from_slice(&scalar[..]).map_err(|_| WireError::BadKey)?;
            let sig: p256::ecdsa::Signature = sk.sign(message);
            let mut out = [0u8; SIG_LEN];
            out.copy_from_slice(&sig.to_bytes());
            Ok(out)
        }
    }
}

fn assemble<'b>(
    prefix: &str,
    key: &SigningKey<'_>,
    payload: &[u8],
    buf: &'b mut [u8; MAX_TOKEN_LEN],
) -> Result<&'b str, WireError> {
    let mut msg = [0u8; CAP_PREFIX.len() + MAX_PAYLOAD_LEN];
    let msg_len = signed_message(prefix, payload, &mut msg);
    let sig = sign_message(key, &msg[..msg_len])?;

    let payload_b64_len = BASE64URL_NOPAD.encode_len(payload.len());
    let sig_b64_len = BASE64URL_NOPAD.encode_len(SIG_LEN);
    let total = prefix.len() + payload_b64_len + 1 + sig_b64_len;
    if total > buf.len() {
        return Err(WireError::BufferTooSmall);
    }

    let (head, rest) = buf.split_at_mut(prefix.len());
    head.copy_from_slice(prefix.as_bytes());
    let (pseg, rest) = rest.split_at_mut(payload_b64_len);
    BASE64URL_NOPAD.encode_mut(payload, pseg);
    rest[0] = b'.';
    BASE64URL_NOPAD.encode_mut(&sig, &mut rest[1..1 + sig_b64_len]);

    // Everything written is ASCII by construction.
    core::str::from_utf8(&buf[..total]).map_err(|_| WireError::BadBase64)
}

/// Sign a capability into a fixed buffer (no_std). `cap.ver` must match the
/// key kind — a mismatched pair is refused rather than silently rewritten.
pub fn sign_capability_into<'b>(
    key: &SigningKey<'_>,
    cap: &Capability,
    buf: &'b mut [u8; MAX_TOKEN_LEN],
) -> Result<&'b str, WireError> {
    if cap.ver != key.ver() {
        return Err(WireError::VersionKeyMismatch);
    }
    let mut payload = [0u8; MAX_PAYLOAD_LEN];
    let len = encode_capability(cap, &mut payload)?;
    assemble(CAP_PREFIX, key, &payload[..len], buf)
}

/// Sign a revocation into a fixed buffer (no_std).
pub fn sign_revocation_into<'b>(
    key: &SigningKey<'_>,
    rvk: &Revocation,
    buf: &'b mut [u8; MAX_TOKEN_LEN],
) -> Result<&'b str, WireError> {
    if rvk.ver != key.ver() {
        return Err(WireError::VersionKeyMismatch);
    }
    let mut payload = [0u8; MAX_PAYLOAD_LEN];
    let len = encode_revocation(rvk, &mut payload)?;
    assemble(RVK_PREFIX, key, &payload[..len], buf)
}

/// Sign a capability, returning an owned token (std convenience).
#[cfg(feature = "std")]
pub fn sign_capability_token(key: &SigningKey<'_>, cap: &Capability) -> Result<String, WireError> {
    let mut buf = [0u8; MAX_TOKEN_LEN];
    sign_capability_into(key, cap, &mut buf).map(str::to_owned)
}

/// Sign a revocation, returning an owned token (std convenience).
#[cfg(feature = "std")]
pub fn sign_revocation_token(key: &SigningKey<'_>, rvk: &Revocation) -> Result<String, WireError> {
    let mut buf = [0u8; MAX_TOKEN_LEN];
    sign_revocation_into(key, rvk, &mut buf).map(str::to_owned)
}
