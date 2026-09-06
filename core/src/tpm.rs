//! TPM factor verification — pure — and a software signer for tests.
//!
//! A `tpm` authenticator is a P-256 ECDSA key whose private half lives
//! non-exportable inside a TPM 2.0; its proof is a signature over the request's
//! challenge. On the wire that is `lgtpm.<base64url(DER ECDSA signature)>` —
//! the TPM-ness is an *operational* property (the key cannot leave the chip),
//! not a wire property, so this module verifies plain ECDSA with the registered
//! public key and knows nothing about TPMs. The hardware ceremony (TCTI, key
//! creation, TPM2_Sign) lives behind the CLI's `tpm-client` feature, not here.
//!
//! `sign` is the software signer used by the tests and the e2e so both speak
//! the exact bytes `verify` accepts (the fido2 software-authenticator pattern);
//! RustCrypto's ECDSA is RFC 6979 deterministic, so the KAT vectors are stable
//! and the core stays randomness-free.

use std::fmt;

/// The proof token prefix — the dispatch discriminator, like `lgfido2.`.
pub const TOKEN_PREFIX: &str = "lgtpm.";

#[derive(Debug, PartialEq, Eq)]
pub enum TpmError {
    Malformed(String),
    /// The signature did not verify over this request's challenge.
    BadSignature,
    /// The configured public key is not a usable P-256 key.
    UnsupportedKey(String),
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TpmError::Malformed(m) => write!(f, "malformed TPM token: {m}"),
            TpmError::BadSignature => {
                write!(f, "TPM signature did not verify over the challenge")
            }
            TpmError::UnsupportedKey(m) => write!(f, "unusable TPM public key: {m}"),
        }
    }
}

impl std::error::Error for TpmError {}

/// Verify a `lgtpm.` token against a registered public key (SEC1 uncompressed
/// P-256) and the request's challenge. The signature is DER-encoded ECDSA over
/// the challenge string's bytes (SHA-256 inside ECDSA), which is exactly what
/// TPM2_Sign produces for a digest of those bytes.
pub fn verify(public_key: &[u8], token: &str, challenge: &str) -> Result<(), TpmError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    let payload = token
        .strip_prefix(TOKEN_PREFIX)
        .ok_or_else(|| TpmError::Malformed("not an lgtpm token".to_string()))?;
    let der = data_encoding::BASE64URL_NOPAD
        .decode(payload.trim().as_bytes())
        .map_err(|_| TpmError::Malformed("token is not base64url".to_string()))?;
    let vk = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| TpmError::UnsupportedKey(format!("p256 key: {e}")))?;
    let sig =
        Signature::from_der(&der).map_err(|e| TpmError::Malformed(format!("signature: {e}")))?;
    vk.verify(challenge.as_bytes(), &sig)
        .map_err(|_| TpmError::BadSignature)
}

/// Check that `public_key` parses as a P-256 key — the inventory's load-time
/// validation, so a bad credential fails at load, not at 03:00.
pub fn check_public_key(public_key: &[u8]) -> Result<(), TpmError> {
    p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
        .map(|_| ())
        .map_err(|e| TpmError::UnsupportedKey(format!("p256 key: {e}")))
}

/// The public key for a raw P-256 scalar, in the storage form `verify` expects
/// (SEC1 uncompressed) — for the software signer's registration in tests.
pub fn public_key(private_key: &[u8]) -> Result<Vec<u8>, TpmError> {
    use p256::ecdsa::SigningKey;
    let sk = SigningKey::from_slice(private_key)
        .map_err(|e| TpmError::UnsupportedKey(format!("p256 private key: {e}")))?;
    Ok(sk
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec())
}

/// The software signer: produce a valid `lgtpm.` token from a raw private key.
/// Used by the tests and the e2e so they speak the exact bytes `verify`
/// accepts; a real deployment signs inside the TPM (`lychgate tpm-sign`).
/// Deterministic (RFC 6979) — no randomness in core.
pub fn sign(private_key: &[u8], challenge: &str) -> Result<String, TpmError> {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    let sk = SigningKey::from_slice(private_key)
        .map_err(|e| TpmError::UnsupportedKey(format!("p256 private key: {e}")))?;
    let sig: Signature = sk.sign(challenge.as_bytes());
    Ok(assemble_token(sig.to_der().as_bytes()))
}

/// Assemble an `lgtpm.` token from a DER ECDSA signature — shared by the
/// software signer and the `tpm-client` hardware path, so there is one wire
/// format.
pub fn assemble_token(signature_der: &[u8]) -> String {
    format!(
        "{TOKEN_PREFIX}{}",
        data_encoding::BASE64URL_NOPAD.encode(signature_der)
    )
}

#[cfg(test)]
mod tests;
