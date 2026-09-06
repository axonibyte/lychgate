//! FIDO2 / WebAuthn assertion verification — pure — and a software authenticator.
//!
//! A FIDO2 hardware key is the strongest factor: like an SSHSIG it *binds to the
//! challenge*, so an assertion cannot be phished or replayed for another request.
//! During registration the credential's public key and id are recorded (public,
//! inline in the inventory); an assertion is the key's signature over
//! `authenticatorData ‖ SHA-256(clientDataJSON)`, where clientDataJSON carries
//! the challenge and authenticatorData carries the relying-party hash and flags.
//!
//! This module verifies that assertion (ES256 = ECDSA-P256, or EdDSA = Ed25519)
//! and — for tests and the CLI's software mode — constructs one from a private
//! key. Signing is deterministic (ECDSA-P256 via RFC 6979, Ed25519 by
//! construction), so it stays randomness-free and the KAT vectors are stable.
//! The crypto is RustCrypto's; nothing is hand-rolled. The hardware ceremony
//! (CTAP2 over USB/HID) lives behind the CLI's `fido2-client` feature, not here.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The relying-party id every lychgate assertion is bound to: authData's
/// rpIdHash must be `SHA-256(RP_ID)`, so an assertion made for another rp is
/// refused here.
pub const RP_ID: &str = "lychgate";

/// The proof token prefix — the dispatch discriminator (like SSHSIG's BEGIN
/// line): `lgfido2.<base64url(json)>`.
pub const TOKEN_PREFIX: &str = "lgfido2.";

/// authenticatorData flag: user present.
const FLAG_UP: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    /// ECDSA over NIST P-256 with SHA-256 (COSE alg -7).
    Es256,
    /// Ed25519 (COSE alg -8).
    EdDsa,
}

/// A registered credential: how to verify its assertions.
#[derive(Debug, Clone)]
pub struct Fido2Credential {
    pub alg: Alg,
    pub credential_id: Vec<u8>,
    /// ES256: a SEC1 point (uncompressed, 65 bytes). EdDSA: the 32-byte key.
    pub public_key: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Fido2Error {
    Malformed(String),
    /// The assertion names a different credential than the configured one.
    WrongCredential,
    /// clientDataJSON's challenge is not this request's.
    ChallengeMismatch,
    /// authenticatorData's rpIdHash is not lychgate's.
    WrongRelyingParty,
    /// The user-present flag is clear — no user touched the key.
    UserNotPresent,
    /// The signature did not verify over the signed data.
    BadSignature,
    /// The configured public key is not usable for its algorithm.
    UnsupportedKey(String),
}

impl fmt::Display for Fido2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fido2Error::Malformed(m) => write!(f, "malformed FIDO2 assertion: {m}"),
            Fido2Error::WrongCredential => {
                write!(f, "assertion is for a different credential than configured")
            }
            Fido2Error::ChallengeMismatch => {
                write!(f, "assertion's challenge does not match the request")
            }
            Fido2Error::WrongRelyingParty => {
                write!(f, "assertion is for a different relying party")
            }
            Fido2Error::UserNotPresent => write!(f, "assertion has no user-present flag"),
            Fido2Error::BadSignature => write!(f, "assertion signature did not verify"),
            Fido2Error::UnsupportedKey(m) => write!(f, "unusable credential key: {m}"),
        }
    }
}

impl std::error::Error for Fido2Error {}

/// The `lgfido2.` token payload: a WebAuthn assertion, each field base64url.
#[derive(Debug, Serialize, Deserialize)]
struct AssertionToken {
    #[serde(rename = "credentialId")]
    credential_id: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    signature: String,
}

#[derive(Deserialize)]
struct ClientDataIn {
    #[serde(rename = "type")]
    ty: String,
    challenge: String,
}

#[derive(Serialize)]
struct ClientDataOut<'a> {
    #[serde(rename = "type")]
    ty: &'a str,
    challenge: String,
    origin: &'a str,
}

fn b64(bytes: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(bytes)
}

/// `SHA-256(RP_ID)` — the rpIdHash a lychgate assertion's authenticatorData must
/// carry. A hardware client passes `RP_ID` as the relying-party id to its key;
/// this is what the daemon checks the returned authData against.
pub fn rp_id_hash() -> [u8; 32] {
    Sha256::digest(RP_ID.as_bytes()).into()
}

/// The canonical `clientDataJSON` bytes for a challenge — exactly what `verify`
/// re-hashes and parses. Both authenticators (software and the CTAP2 hardware
/// client) build the assertion over *these* bytes, so the format has one source
/// of truth: the hardware client hashes this to the clientDataHash it hands the
/// key, then puts these same bytes in the token.
pub fn client_data_json(challenge: &str) -> Vec<u8> {
    let cd = ClientDataOut {
        ty: "webauthn.get",
        challenge: b64(challenge.as_bytes()),
        origin: RP_ID,
    };
    // ClientDataOut serialises infallibly (only owned/borrowed strings).
    serde_json::to_vec(&cd).expect("clientDataJSON serialises")
}

/// `SHA-256(clientDataJSON)` — the clientDataHash a WebAuthn client hands the
/// authenticator to sign (with authenticatorData) during getAssertion.
pub fn client_data_hash(challenge: &str) -> [u8; 32] {
    Sha256::digest(client_data_json(challenge)).into()
}

/// Assemble an `lgfido2.` token from the four assertion fields — used by the
/// software authenticator and by the CTAP2 hardware client, so both emit the
/// exact bytes `verify` accepts. For ES256 the signature is DER-encoded ECDSA
/// (as CTAP2 returns); for EdDSA it is the raw 64-byte signature.
pub fn assemble_token(
    credential_id: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> String {
    let tok = AssertionToken {
        credential_id: b64(credential_id),
        authenticator_data: b64(authenticator_data),
        client_data_json: b64(client_data_json),
        signature: b64(signature),
    };
    // AssertionToken serialises infallibly (four owned strings).
    let outer = serde_json::to_vec(&tok).expect("assertion token serialises");
    format!("{TOKEN_PREFIX}{}", b64(&outer))
}

fn unb64(s: &str, what: &str) -> Result<Vec<u8>, Fido2Error> {
    data_encoding::BASE64URL_NOPAD
        .decode(s.trim().as_bytes())
        .map_err(|_| Fido2Error::Malformed(format!("{what} is not base64url")))
}

/// Verify a FIDO2 assertion token against a registered credential and the
/// request's challenge. Returns `Ok(())` when the assertion is valid, bound to
/// this challenge and to lychgate as the relying party.
pub fn verify(cred: &Fido2Credential, token: &str, challenge: &str) -> Result<(), Fido2Error> {
    let payload = token
        .strip_prefix(TOKEN_PREFIX)
        .ok_or_else(|| Fido2Error::Malformed("not an lgfido2 token".to_string()))?;
    let raw = unb64(payload, "token")?;
    let tok: AssertionToken = serde_json::from_slice(&raw)
        .map_err(|e| Fido2Error::Malformed(format!("token json: {e}")))?;

    if unb64(&tok.credential_id, "credentialId")? != cred.credential_id {
        return Err(Fido2Error::WrongCredential);
    }
    let auth_data = unb64(&tok.authenticator_data, "authenticatorData")?;
    let client_data = unb64(&tok.client_data_json, "clientDataJSON")?;
    let signature = unb64(&tok.signature, "signature")?;

    let cd: ClientDataIn = serde_json::from_slice(&client_data)
        .map_err(|e| Fido2Error::Malformed(format!("clientDataJSON: {e}")))?;
    if cd.ty != "webauthn.get" {
        return Err(Fido2Error::Malformed(format!(
            "clientData type is {:?}, not \"webauthn.get\"",
            cd.ty
        )));
    }
    if cd.challenge != b64(challenge.as_bytes()) {
        return Err(Fido2Error::ChallengeMismatch);
    }

    if auth_data.len() < 37 {
        return Err(Fido2Error::Malformed(
            "authenticatorData too short".to_string(),
        ));
    }
    if auth_data[0..32] != Sha256::digest(RP_ID.as_bytes())[..] {
        return Err(Fido2Error::WrongRelyingParty);
    }
    if auth_data[32] & FLAG_UP == 0 {
        return Err(Fido2Error::UserNotPresent);
    }

    // The signed message: authenticatorData ‖ SHA-256(clientDataJSON).
    let mut signed = auth_data;
    signed.extend_from_slice(&Sha256::digest(&client_data));
    verify_signature(cred, &signed, &signature)
}

fn verify_signature(
    cred: &Fido2Credential,
    signed: &[u8],
    signature: &[u8],
) -> Result<(), Fido2Error> {
    match cred.alg {
        Alg::Es256 => {
            use p256::ecdsa::signature::Verifier;
            use p256::ecdsa::{Signature, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(&cred.public_key)
                .map_err(|e| Fido2Error::UnsupportedKey(format!("es256 key: {e}")))?;
            let sig = Signature::from_der(signature)
                .map_err(|e| Fido2Error::Malformed(format!("es256 signature: {e}")))?;
            vk.verify(signed, &sig)
                .map_err(|_| Fido2Error::BadSignature)
        }
        Alg::EdDsa => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let key: [u8; 32] =
                cred.public_key.as_slice().try_into().map_err(|_| {
                    Fido2Error::UnsupportedKey("eddsa key is not 32 bytes".to_string())
                })?;
            let vk = VerifyingKey::from_bytes(&key)
                .map_err(|e| Fido2Error::UnsupportedKey(format!("eddsa key: {e}")))?;
            let sig = Signature::from_slice(signature)
                .map_err(|e| Fido2Error::Malformed(format!("eddsa signature: {e}")))?;
            vk.verify(signed, &sig)
                .map_err(|_| Fido2Error::BadSignature)
        }
    }
}

/// The public key for a private key, in the storage form `verify` expects
/// (SEC1 uncompressed for ES256, raw 32 bytes for EdDSA) — for registration.
pub fn public_key(alg: Alg, private_key: &[u8]) -> Result<Vec<u8>, Fido2Error> {
    match alg {
        Alg::Es256 => {
            use p256::ecdsa::SigningKey;
            let sk = SigningKey::from_slice(private_key)
                .map_err(|e| Fido2Error::UnsupportedKey(format!("es256 private key: {e}")))?;
            Ok(sk
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec())
        }
        Alg::EdDsa => {
            use ed25519_dalek::SigningKey;
            let key: [u8; 32] = private_key.try_into().map_err(|_| {
                Fido2Error::UnsupportedKey("eddsa private key is not 32 bytes".to_string())
            })?;
            Ok(SigningKey::from_bytes(&key)
                .verifying_key()
                .to_bytes()
                .to_vec())
        }
    }
}

/// Check that `public_key` is a usable public key for `alg` — for the
/// inventory's load-time validation, so a bad credential fails at load, not at
/// 03:00. Does not verify anything, only that the key parses.
pub fn check_public_key(alg: Alg, public_key: &[u8]) -> Result<(), Fido2Error> {
    match alg {
        Alg::Es256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
            .map(|_| ())
            .map_err(|e| Fido2Error::UnsupportedKey(format!("es256 key: {e}"))),
        Alg::EdDsa => {
            let key: [u8; 32] = public_key
                .try_into()
                .map_err(|_| Fido2Error::UnsupportedKey("eddsa key is not 32 bytes".to_string()))?;
            ed25519_dalek::VerifyingKey::from_bytes(&key)
                .map(|_| ())
                .map_err(|e| Fido2Error::UnsupportedKey(format!("eddsa key: {e}")))
        }
    }
}

/// The signature counter carried in an assertion token's authenticatorData
/// (bytes 33..37, big-endian). The daemon reads it AFTER `verify` accepts the
/// same token, to feed its per-credential counter ledger (clone detection): a
/// counter that goes backwards means two devices are signing with one
/// credential. Zero means the authenticator does not implement counters.
pub fn token_counter(token: &str) -> Result<u32, Fido2Error> {
    let payload = token
        .strip_prefix(TOKEN_PREFIX)
        .ok_or_else(|| Fido2Error::Malformed("not an lgfido2 token".to_string()))?;
    let raw = unb64(payload, "token")?;
    let tok: AssertionToken = serde_json::from_slice(&raw)
        .map_err(|e| Fido2Error::Malformed(format!("token json: {e}")))?;
    let auth_data = unb64(&tok.authenticator_data, "authenticatorData")?;
    if auth_data.len() < 37 {
        return Err(Fido2Error::Malformed(
            "authenticatorData too short".to_string(),
        ));
    }
    Ok(u32::from_be_bytes([
        auth_data[33],
        auth_data[34],
        auth_data[35],
        auth_data[36],
    ]))
}

/// The software authenticator: construct a valid assertion token from a private
/// key. Used by the CLI's `--software-key` mode and by the tests, so both speak
/// the exact bytes `verify` accepts. Deterministic — no randomness. The counter
/// is 0 (no counter support), like most software credentials.
pub fn build_assertion(
    alg: Alg,
    private_key: &[u8],
    credential_id: &[u8],
    challenge: &str,
) -> Result<String, Fido2Error> {
    build_assertion_with_counter(alg, private_key, credential_id, challenge, 0)
}

/// `build_assertion` with an explicit signature counter — for the daemon tier's
/// counter-ledger tests, which need assertions whose counters they control.
pub fn build_assertion_with_counter(
    alg: Alg,
    private_key: &[u8],
    credential_id: &[u8],
    challenge: &str,
    counter: u32,
) -> Result<String, Fido2Error> {
    let client_data = client_data_json(challenge);

    let mut auth_data = Vec::with_capacity(37);
    auth_data.extend_from_slice(&rp_id_hash());
    auth_data.push(FLAG_UP);
    auth_data.extend_from_slice(&counter.to_be_bytes());

    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));
    let signature = sign(alg, private_key, &signed)?;

    Ok(assemble_token(
        credential_id,
        &auth_data,
        &client_data,
        &signature,
    ))
}

fn sign(alg: Alg, private_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Fido2Error> {
    match alg {
        Alg::Es256 => {
            use p256::ecdsa::signature::Signer;
            use p256::ecdsa::{Signature, SigningKey};
            let sk = SigningKey::from_slice(private_key)
                .map_err(|e| Fido2Error::UnsupportedKey(format!("es256 private key: {e}")))?;
            let sig: Signature = sk.sign(msg);
            Ok(sig.to_der().as_bytes().to_vec())
        }
        Alg::EdDsa => {
            use ed25519_dalek::{Signature, Signer, SigningKey};
            let key: [u8; 32] = private_key.try_into().map_err(|_| {
                Fido2Error::UnsupportedKey("eddsa private key is not 32 bytes".to_string())
            })?;
            let sk = SigningKey::from_bytes(&key);
            let sig: Signature = sk.sign(msg);
            Ok(sig.to_bytes().to_vec())
        }
    }
}

#[cfg(test)]
mod tests;
