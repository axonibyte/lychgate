//! Password approval: Argon2id hashing and constant-time verification, pure.
//!
//! A password is the weakest factor — a reusable shared secret with no challenge
//! binding and no single-use ledger — so it earns little weight and is meant to
//! be combined with stronger factors. What this module protects is the password
//! *at rest*: the inventory stores an Argon2id PHC hash in a mode-600 file, so a
//! leaked file is not a trivial recovery, and the daemon verifies a typed
//! password against that hash in constant time.
//!
//! The KDF and the compare are RustCrypto's `argon2`; nothing is hand-rolled.
//! Hashing takes an injected salt so this stays randomness-free (the CLI's
//! `hash-password` supplies salt bytes from the OS CSPRNG), consistent with how
//! the challenge nonce and TOTP time are injected.

use std::fmt;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

#[derive(Debug, PartialEq, Eq)]
pub enum PasswordError {
    /// A stored hash string that is not a valid PHC / Argon2 hash.
    BadHash(String),
    /// Hashing failed (a salt that will not encode, an internal KDF error).
    Hashing(String),
}

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PasswordError::BadHash(m) => write!(f, "invalid password hash: {m}"),
            PasswordError::Hashing(m) => write!(f, "password hashing failed: {m}"),
        }
    }
}

impl std::error::Error for PasswordError {}

/// Hash `password` with Argon2id (default params) over the given `salt` bytes,
/// returning a self-describing PHC string (`$argon2id$…`) to store in the
/// mode-600 hash file. The salt is injected (the caller supplies OS randomness),
/// so this is deterministic and pure.
pub fn hash(password: &str, salt: &[u8]) -> Result<String, PasswordError> {
    let salt =
        SaltString::encode_b64(salt).map_err(|e| PasswordError::Hashing(format!("salt: {e}")))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| PasswordError::Hashing(e.to_string()))
}

/// Parse a stored hash string, requiring an actual digest — `PasswordHash::new`
/// alone accepts a bare algorithm ident (e.g. `$argon2id$garbage`) with no
/// digest, which would then verify nothing; that is a malformed hash, refused
/// here rather than left as an authenticator that silently always fails.
fn parse(phc: &str) -> Result<PasswordHash<'_>, PasswordError> {
    let parsed = PasswordHash::new(phc).map_err(|e| PasswordError::BadHash(e.to_string()))?;
    if parsed.hash.is_none() {
        return Err(PasswordError::BadHash(
            "hash string carries no digest".to_string(),
        ));
    }
    Ok(parsed)
}

/// Verify a typed `password` against a stored PHC hash string. A malformed hash
/// is an error (not `false`) — the daemon refuses to serve one rather than treat
/// every password as wrong. The compare is Argon2's constant-time verify.
pub fn verify(phc: &str, password: &str) -> Result<bool, PasswordError> {
    let parsed = parse(phc)?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(PasswordError::BadHash(e.to_string())),
    }
}

/// Parse-only check that a stored hash is well-formed (and carries a digest),
/// for the daemon's fail-closed startup validation.
pub fn validate_hash(phc: &str) -> Result<(), PasswordError> {
    parse(phc).map(|_| ())
}

#[cfg(test)]
mod tests;
