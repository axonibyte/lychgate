//! The dead-man backstop, rendered: a self-contained POSIX sh script
//! installed on the target at grant open, driven by one marked line in
//! root's crontab, reverting break-glass access at the deadline with no
//! daemon participation. Rendering is pure and lives here; installing it is
//! the daemon's job over the transport.
//!
//! Files on the target:
//! - the script (0700), whose revert knowledge is baked in at render time;
//! - the deadline file (epoch seconds) — renew rewrites only this;
//! - the fired marker, left behind for the daemon to find and journal.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::inventory::Host;
use crate::ssh::{reload_command, FENCE_BEGIN, FENCE_END};

pub const SCRIPT_PATH: &str = "/etc/lychgate.deadman.sh";
pub const DEADLINE_PATH: &str = "/etc/lychgate.deadman.deadline";
pub const FIRED_PATH: &str = "/etc/lychgate.deadman.fired";

/// The whole-line tag on the crontab entry, managed like the
/// authorized_keys fence: lychgate owns lines carrying it, nothing else.
pub const CRON_MARKER: &str = "# LYCHGATE-DEADMAN";

/// The every-minute check. Cron's granularity bounds how late the backstop
/// fires (about a minute past the deadline, plus the script's own runtime).
pub fn cron_line() -> String {
    format!("* * * * * /bin/sh {SCRIPT_PATH} {CRON_MARKER}")
}

pub fn render_deadline(expires_at: SystemTime) -> String {
    let secs = expires_at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}\n")
}

/// Adds the dead-man line to a crontab if no line carries the marker;
/// idempotent. Every byte of the existing crontab is preserved.
pub fn crontab_with_deadman(existing: &str) -> String {
    if existing.lines().any(|l| l.contains(CRON_MARKER)) {
        return existing.to_string();
    }
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&cron_line());
    out.push('\n');
    out
}

/// Drops every line carrying the marker (matching the script's own
/// `grep -v` cleanup); everything else is preserved.
pub fn crontab_without_deadman(existing: &str) -> String {
    let kept: Vec<&str> = existing
        .lines()
        .filter(|l| !l.contains(CRON_MARKER))
        .collect();
    if kept.is_empty() {
        String::new()
    } else {
        kept.join("\n") + "\n"
    }
}

/// Renders the script for one host. Everything the revert needs is baked in
/// — the script must work with the daemon dead and the network gone.
pub fn render_script(host: &Host) -> Option<String> {
    let ssh = host.ssh.as_ref()?;
    let dropin = ssh
        .dropin_path
        .clone()
        .unwrap_or_else(|| crate::ssh::DEFAULT_DROPIN.to_string());
    let akeys = &ssh.authorized_keys_path;
    let reload = reload_command(host, ssh);

    // The fence markers and paths are embedded single-quoted; none of them
    // may contain a single quote. The markers are constants (asserted in
    // tests); the paths come from the inventory and are refused here rather
    // than silently corrupting the script.
    for value in [dropin.as_str(), akeys.as_str()] {
        if value.contains('\'') {
            return None;
        }
    }

    Some(format!(
        r#"#!/bin/sh
# Rendered by lychgated for host {host_name}. The dead-man backstop:
# reverts break-glass access at the deadline with no daemon participation.
# Removed when the grant closes; do not edit.
set -u
deadline="$(cat {DEADLINE_PATH} 2>/dev/null)" || exit 0
[ -n "${{deadline}}" ] || exit 0
now="$(date +%s)"
[ "${{now}}" -ge "${{deadline}}" ] || exit 0

rm -f '{dropin}'
{reload} || true

akeys='{akeys}'
if [ -f "${{akeys}}" ]; then
    awk -v b='{begin}' -v e='{end}' \
        '$0==b {{ skip=1; next }} $0==e {{ skip=0; next }} !skip {{ print }}' \
        "${{akeys}}" > "${{akeys}}.lychgate-tmp" && \
        mv "${{akeys}}.lychgate-tmp" "${{akeys}}"
fi

: > {FIRED_PATH}
logger -t lychgate-deadman 'deadline passed; break-glass access reverted' || true
( crontab -l 2>/dev/null | grep -v 'LYCHGATE-DEADMAN' | crontab - ) || true
rm -f {DEADLINE_PATH}
exit 0
"#,
        host_name = host.name,
        begin = FENCE_BEGIN,
        end = FENCE_END,
    ))
}

#[cfg(test)]
mod tests;
