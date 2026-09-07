//! Raw `r || s` P-256 signature → DER, as pure byte formatting.
//!
//! Secure elements (the ATECC608's Sign command) emit 64-byte raw
//! signatures; lychgate's `lgtpm.` approval tokens carry DER (what
//! `core::tpm::verify` parses). This transform is the only bridge a
//! device-side signer needs, and it deliberately has NO curve dependency —
//! DER `INTEGER`s are minimal-length two's-complement, so each 32-byte half
//! drops leading zero bytes and gains a `0x00` prefix when its high bit is
//! set. Maximum output: 72 bytes.

use crate::WireError;

/// The largest possible DER encoding of a P-256 signature.
pub const MAX_P256_DER_LEN: usize = 72;

fn integer_len(half: &[u8]) -> usize {
    let significant = half.iter().position(|&b| b != 0).map_or(0, |i| 32 - i);
    if significant == 0 {
        1 // INTEGER 0 encodes as a single 0x00 byte.
    } else if half[32 - significant] & 0x80 != 0 {
        significant + 1 // High bit set: a 0x00 prefix keeps it positive.
    } else {
        significant
    }
}

fn write_integer(half: &[u8], out: &mut [u8], mut pos: usize) -> usize {
    let len = integer_len(half);
    out[pos] = 0x02;
    out[pos + 1] = len as u8;
    pos += 2;
    let significant = half.iter().position(|&b| b != 0).map_or(0, |i| 32 - i);
    if significant == 0 {
        out[pos] = 0x00;
        return pos + 1;
    }
    if half[32 - significant] & 0x80 != 0 {
        out[pos] = 0x00;
        pos += 1;
    }
    out[pos..pos + significant].copy_from_slice(&half[32 - significant..]);
    pos + significant
}

/// Encode a raw `r || s` signature as DER, returning the byte length
/// written into `out`.
pub fn p256_raw_sig_to_der(
    rs: &[u8; 64],
    out: &mut [u8; MAX_P256_DER_LEN],
) -> Result<usize, WireError> {
    let (r, s) = rs.split_at(32);
    let body = 2 + integer_len(r) + 2 + integer_len(s);
    if 2 + body > out.len() {
        return Err(WireError::BufferTooSmall);
    }
    out[0] = 0x30; // SEQUENCE
    out[1] = body as u8;
    let pos = write_integer(r, out, 2);
    let end = write_integer(s, out, pos);
    debug_assert_eq!(end, 2 + body);
    Ok(end)
}
