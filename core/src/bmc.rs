//! Pure logic for the BMC channel: the Redfish AccountService requests that
//! enable and disable a break-glass account and set its password, the
//! parsing of the responses, and break-glass password generation. No I/O —
//! the daemon's driver runs these over a transport that shells out to curl.
//!
//! The break-glass account is a fixture on the iDRAC: lychgate rotates its
//! password and toggles its `Enabled` flag, never creating or deleting it,
//! because account-slot management races the BMC's own.

use std::fmt;

use serde::Serialize;

/// A password never written to the journal or logs. Its Debug and Display
/// redact, so it cannot leak through a stray `{:?}`; the real bytes are only
/// reachable through `reveal`, called on exactly one path — the CLI open
/// response.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Secret {
        Secret(value)
    }

    /// The one deliberate way out. Named so every call site is greppable.
    pub fn reveal(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(redacted)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Generates break-glass passwords. Production reads the OS CSPRNG; tests use
/// a seeded stub so request-body assertions are deterministic.
pub trait PasswordGen: Send {
    fn generate(&mut self) -> Secret;
}

/// The character set: iDRAC rejects some punctuation in passwords, so this
/// stays within a broadly-accepted alphanumeric-plus-safe-symbols set while
/// keeping ~6 bits per character.
pub const PASSWORD_ALPHABET: &[u8] =
    b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789-_.@";
pub const PASSWORD_LEN: usize = 20;

/// Maps arbitrary random bytes onto the alphabet. Shared by the production
/// generator and the test stub so both produce valid passwords.
pub fn password_from_bytes(bytes: &[u8]) -> Secret {
    let mut out = String::with_capacity(bytes.len());
    for b in bytes {
        out.push(PASSWORD_ALPHABET[(*b as usize) % PASSWORD_ALPHABET.len()] as char);
    }
    Secret(out)
}

/// The AccountService member path for a break-glass account slot, e.g.
/// `/redfish/v1/AccountService/Accounts/3`.
pub fn account_path(account_id: &str) -> String {
    format!("/redfish/v1/AccountService/Accounts/{account_id}")
}

/// The PATCH body that enables the account, sets its username, and rotates
/// its password in one request.
pub fn enable_body(username: &str, password: &Secret) -> String {
    #[derive(Serialize)]
    struct Enable<'a> {
        #[serde(rename = "UserName")]
        user_name: &'a str,
        #[serde(rename = "Password")]
        password: &'a str,
        #[serde(rename = "Enabled")]
        enabled: bool,
    }
    // Infallible for this shape (all string/bool fields).
    serde_json::to_string(&Enable {
        user_name: username,
        password: password.reveal(),
        enabled: true,
    })
    .expect("enable body always serializes")
}

/// The PATCH body that disables the account. The password is not touched on
/// disable — the next open rotates it.
pub fn disable_body() -> String {
    r#"{"Enabled":false}"#.to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountState {
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BmcError {
    /// The account GET came back as something other than a recognizable
    /// AccountService member.
    Unparseable(String),
    /// A well-formed account, but a different user than the inventory names
    /// occupies the slot — refusing beats rotating a stranger's password.
    WrongAccount { expected: String, found: String },
}

impl fmt::Display for BmcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BmcError::Unparseable(m) => write!(f, "unparseable AccountService response: {m}"),
            BmcError::WrongAccount { expected, found } => write!(
                f,
                "account slot holds user {found:?}, not the expected break-glass user {expected:?}"
            ),
        }
    }
}

impl std::error::Error for BmcError {}

/// Reads the account's enabled state from a Redfish account GET, verifying
/// the slot holds the expected user. UserName mismatch is refused; an empty
/// UserName (an unused slot) is accepted so a first open can claim it.
pub fn parse_account(body: &str, expected_user: &str) -> Result<AccountState, BmcError> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| BmcError::Unparseable(e.to_string()))?;

    let enabled = value
        .get("Enabled")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| BmcError::Unparseable("no boolean Enabled field".to_string()))?;

    if let Some(user) = value.get("UserName").and_then(|v| v.as_str()) {
        if !user.is_empty() && user != expected_user {
            return Err(BmcError::WrongAccount {
                expected: expected_user.to_string(),
                found: user.to_string(),
            });
        }
    }

    Ok(if enabled {
        AccountState::Enabled
    } else {
        AccountState::Disabled
    })
}

#[cfg(test)]
mod tests;
