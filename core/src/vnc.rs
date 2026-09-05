//! Pure validation for the VNC channel's configurable password commands.
//!
//! The `vnc` channel rotates a one-time password on the target through an
//! operator-supplied command template, agnostic to the platform (cbsd is the
//! pilot; anything that can set a VNC password works). lychgate substitutes
//! placeholders into the template and runs the result over ssh on the
//! hypervisor:
//!
//! - `{target}` — the VM identifier, in both the set and clear commands;
//! - `{password_file}` — a path lychgate writes the fresh password to (mode
//!   600) and removes immediately after; the set command only.
//!
//! lychgate is the sole authority on shell quoting: it single-quotes each
//! substituted value before the remote shell sees it (see the daemon's
//! transport). So a template carrying its own single quote is refused rather
//! than rendered — the same discipline as `deadman::render_script`, and for
//! the same reason: lychgate must own every quote in the command it runs. All
//! of these refusals fire at load, not at 03:00.

use std::fmt;

/// Placeholders the set command may reference. `{password_file}` is required
/// there — without it the generated password would never reach the target.
pub const SET_PLACEHOLDERS: &[&str] = &["target", "password_file"];
/// Placeholders the clear command may reference. It never receives a password.
pub const CLEAR_PLACEHOLDERS: &[&str] = &["target"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VncTemplateError {
    /// A single quote in the template. lychgate owns the shell quoting, so a
    /// template that quotes its own arguments is refused rather than corrupted.
    Quoted,
    /// The set command never references `{password_file}`, so the generated
    /// password would have nowhere to land.
    MissingPasswordFile,
    /// The clear command references `{password_file}`, but no password is
    /// generated on revert — a sign the wrong template was pasted.
    ClearHasPasswordFile,
    /// A `{placeholder}` outside the allowed set: lychgate would leave it in
    /// the command literally, so it is almost certainly a typo.
    UnknownPlaceholder(String),
}

impl fmt::Display for VncTemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VncTemplateError::Quoted => write!(
                f,
                "contains a single quote; lychgate owns the shell quoting, so a template that \
                 quotes its own arguments is refused"
            ),
            VncTemplateError::MissingPasswordFile => write!(
                f,
                "never references {{password_file}}, so the generated password would never reach \
                 the target"
            ),
            VncTemplateError::ClearHasPasswordFile => write!(
                f,
                "references {{password_file}}, but the clear command is never handed a password"
            ),
            VncTemplateError::UnknownPlaceholder(p) => write!(
                f,
                "references unknown placeholder {{{p}}}; lychgate would leave it in the command \
                 literally"
            ),
        }
    }
}

impl std::error::Error for VncTemplateError {}

/// Extracts lychgate's placeholder tokens — a `{name}` run where `name` is one
/// or more of `[A-Za-z_]`. A `${name}` shell variable expansion is skipped
/// (the `$` guard), and anything that is not a clean `{name}` run — brace
/// expansion like `{a,b}`, `{1..3}`, an empty `{}` — is left for the shell.
fn placeholders(template: &str) -> Vec<String> {
    let bytes = template.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' && (i == 0 || bytes[i - 1] != b'$') {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && (bytes[j].is_ascii_alphabetic() || bytes[j] == b'_') {
                j += 1;
            }
            if j > start && j < bytes.len() && bytes[j] == b'}' {
                out.push(template[start..j].to_string());
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn refuse_quotes(template: &str) -> Result<(), VncTemplateError> {
    if template.contains('\'') {
        Err(VncTemplateError::Quoted)
    } else {
        Ok(())
    }
}

/// Validates the set-password command template. Refuses embedded quotes and
/// unknown placeholders, and requires `{password_file}`.
pub fn check_set_command(template: &str) -> Result<(), VncTemplateError> {
    refuse_quotes(template)?;
    let found = placeholders(template);
    for ph in &found {
        if !SET_PLACEHOLDERS.contains(&ph.as_str()) {
            return Err(VncTemplateError::UnknownPlaceholder(ph.clone()));
        }
    }
    if !found.iter().any(|p| p == "password_file") {
        return Err(VncTemplateError::MissingPasswordFile);
    }
    Ok(())
}

/// Validates the clear-password command template. Refuses embedded quotes, a
/// stray `{password_file}` (caught precisely, before the generic unknown-
/// placeholder check), and any other unknown placeholder.
pub fn check_clear_command(template: &str) -> Result<(), VncTemplateError> {
    refuse_quotes(template)?;
    for ph in placeholders(template) {
        if ph == "password_file" {
            return Err(VncTemplateError::ClearHasPasswordFile);
        }
        if !CLEAR_PLACEHOLDERS.contains(&ph.as_str()) {
            return Err(VncTemplateError::UnknownPlaceholder(ph));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
