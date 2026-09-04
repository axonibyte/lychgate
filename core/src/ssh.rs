//! Pure string logic for the SSH channel: the root-posture vocabulary, the
//! lychgate-owned sshd_config drop-in, the fenced authorized_keys block, and
//! `sshd -T` output parsing. No I/O here — the daemon's driver runs these
//! transforms over its transport.

use std::fmt;

use serde::{Deserialize, Serialize};

/// PermitRootLogin values lychgate will set or expect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Posture {
    No,
    ProhibitPassword,
    Yes,
}

impl Posture {
    /// The token written into sshd_config.
    pub fn sshd_token(&self) -> &'static str {
        match self {
            Posture::No => "no",
            Posture::ProhibitPassword => "prohibit-password",
            Posture::Yes => "yes",
        }
    }

    /// Parses sshd's own vocabulary, including the legacy spelling of
    /// prohibit-password that older configs and some sshd -T outputs use.
    pub fn from_sshd_token(token: &str) -> Option<Posture> {
        match token {
            "no" => Some(Posture::No),
            "prohibit-password" | "without-password" => Some(Posture::ProhibitPassword),
            "yes" => Some(Posture::Yes),
            _ => None,
        }
    }
}

impl fmt::Display for Posture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.sshd_token())
    }
}

/// The drop-in lychgate writes. Owned wholly by lychgate: removed on revert,
/// never merged with anything.
pub fn render_dropin(posture: Posture) -> String {
    format!(
        "# Managed by lychgated; do not edit. Removed when the grant closes.\n\
         PermitRootLogin {}\n",
        posture.sshd_token()
    )
}

/// Extracts the effective PermitRootLogin from `sshd -T` output.
pub fn parse_effective_posture(sshd_t_output: &str) -> Option<Posture> {
    sshd_t_output.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        match (words.next(), words.next(), words.next()) {
            (Some(key), Some(value), None) if key.eq_ignore_ascii_case("permitrootlogin") => {
                Posture::from_sshd_token(value)
            }
            _ => None,
        }
    })
}

/// Sorts first among drop-ins on purpose: sshd honors the FIRST obtained
/// value for a keyword, so within the include directory an early name wins.
/// (Whether drop-ins beat the main config at all depends on where its
/// Include line sits — which is why the driver verifies instead of
/// trusting.)
pub const DEFAULT_DROPIN: &str = "/etc/ssh/sshd_config.d/00-lychgate.conf";

/// The shell command that reloads sshd on this host: the per-host override,
/// or the per-OS default. One truth shared by the driver and the rendered
/// dead-man script.
pub fn reload_command(host: &crate::inventory::Host, ssh: &crate::inventory::SshConfig) -> String {
    match &ssh.reload_cmd {
        Some(cmd) => cmd.clone(),
        None => match host.os {
            crate::inventory::Os::Freebsd => "service sshd reload".to_string(),
            crate::inventory::Os::Linux => {
                "systemctl reload sshd 2>/dev/null || systemctl reload ssh".to_string()
            }
        },
    }
}

pub const FENCE_BEGIN: &str = "# --- LYCHGATE BEGIN break-glass keys; do not edit this block ---";
pub const FENCE_END: &str = "# --- LYCHGATE END ---";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceError {
    /// Markers unbalanced, duplicated, or out of order: somebody edited the
    /// fence. Reported, never clobbered.
    Malformed(String),
    /// A key line that could corrupt the file or the fence itself.
    BadKey { key: String, message: String },
}

impl fmt::Display for FenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FenceError::Malformed(m) => {
                write!(
                    f,
                    "authorized_keys fence is malformed: {m}; refusing to touch the file"
                )
            }
            FenceError::BadKey { key, message } => {
                write!(f, "refusing emergency key {key:?}: {message}")
            }
        }
    }
}

impl std::error::Error for FenceError {}

/// Refuses key material that would corrupt the file or the fence. Applied
/// to every key before it is ever written.
pub fn validate_key_line(key: &str) -> Result<(), FenceError> {
    let bad = |message: &str| FenceError::BadKey {
        key: key.to_string(),
        message: message.to_string(),
    };
    if key.trim().is_empty() {
        return Err(bad("empty"));
    }
    if key.contains('\n') || key.contains('\r') {
        return Err(bad("contains a line break"));
    }
    if key.contains("LYCHGATE") {
        return Err(bad("contains fence marker text"));
    }
    Ok(())
}

fn positions(lines: &[&str], marker: &str) -> Vec<usize> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| if *l == marker { Some(i) } else { None })
        .collect()
}

/// Where the fence sits in a file, as line indices.
fn locate_fence(lines: &[&str]) -> Result<Option<(usize, usize)>, FenceError> {
    let begins = positions(lines, FENCE_BEGIN);
    let ends = positions(lines, FENCE_END);
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => Ok(None),
        ([b], [e]) if b < e => Ok(Some((*b, *e))),
        ([b], [e]) => Err(FenceError::Malformed(format!(
            "END marker (line {}) precedes BEGIN (line {})",
            e + 1,
            b + 1
        ))),
        ([], _) => Err(FenceError::Malformed(
            "END marker without BEGIN".to_string(),
        )),
        (_, []) => Err(FenceError::Malformed(
            "BEGIN marker without END".to_string(),
        )),
        _ => Err(FenceError::Malformed("duplicated markers".to_string())),
    }
}

/// Inserts or replaces the lychgate fence with `keys`, preserving every
/// byte outside it. The file always ends with a newline afterwards.
pub fn fence_upsert(existing: &str, keys: &[String]) -> Result<String, FenceError> {
    for key in keys {
        validate_key_line(key)?;
    }
    let lines: Vec<&str> = existing.lines().collect();
    let fence = locate_fence(&lines)?;

    let mut block = vec![FENCE_BEGIN.to_string()];
    block.extend(keys.iter().cloned());
    block.push(FENCE_END.to_string());

    let mut out: Vec<String> = Vec::new();
    match fence {
        Some((b, e)) => {
            out.extend(lines[..b].iter().map(|l| l.to_string()));
            out.extend(block);
            out.extend(lines[e + 1..].iter().map(|l| l.to_string()));
        }
        None => {
            out.extend(lines.iter().map(|l| l.to_string()));
            out.extend(block);
        }
    }
    Ok(out.join("\n") + "\n")
}

/// Removes the lychgate fence wholly, preserving every byte outside it. A
/// file with no fence is returned unchanged (idempotent revert).
pub fn fence_remove(existing: &str) -> Result<String, FenceError> {
    let lines: Vec<&str> = existing.lines().collect();
    match locate_fence(&lines)? {
        None => Ok(existing.to_string()),
        Some((b, e)) => {
            let mut out: Vec<&str> = Vec::new();
            out.extend(&lines[..b]);
            out.extend(&lines[e + 1..]);
            if out.is_empty() {
                Ok(String::new())
            } else {
                Ok(out.join("\n") + "\n")
            }
        }
    }
}

#[cfg(test)]
mod tests;
