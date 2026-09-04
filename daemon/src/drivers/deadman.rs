//! Installing, rescheduling and removing the dead-man backstop on a target.
//! Rendering lives in core; this is the transport side.

use std::time::SystemTime;

use lychgate_core::deadman::{
    crontab_with_deadman, crontab_without_deadman, render_deadline, render_script, CRON_MARKER,
    DEADLINE_PATH, FIRED_PATH, SCRIPT_PATH,
};
use lychgate_core::{DriverError, Host};

use crate::drivers::remote::Remote;
use crate::transport::SshTransport;

pub trait DeadmanControl: Send {
    /// Installs (or refreshes — idempotent) the backstop: the script, the
    /// deadline, and the crontab line.
    fn install(&mut self, host: &Host, expires_at: SystemTime) -> Result<(), DriverError>;

    /// Moves the deadline. Delegates to install: the schedule and script are
    /// re-asserted rather than assumed present.
    fn reschedule(&mut self, host: &Host, expires_at: SystemTime) -> Result<(), DriverError> {
        self.install(host, expires_at)
    }

    /// Removes the backstop wholly; returns whether the fired marker was
    /// found (and clears it) — the daemon journals that.
    fn remove(&mut self, host: &Host) -> Result<bool, DriverError>;
}

pub struct ExecDeadman {
    transport: Box<dyn SshTransport>,
}

impl ExecDeadman {
    pub fn new(transport: Box<dyn SshTransport>) -> Box<ExecDeadman> {
        Box::new(ExecDeadman { transport })
    }
}

impl DeadmanControl for ExecDeadman {
    fn install(&mut self, host: &Host, expires_at: SystemTime) -> Result<(), DriverError> {
        let ssh = host
            .ssh
            .as_ref()
            .ok_or_else(|| DriverError(format!("host {:?} has no ssh config", host.name)))?;
        let script = render_script(host).ok_or_else(|| {
            DriverError(format!(
                "cannot render a dead-man script for {:?} (a path contains a single quote?)",
                host.name
            ))
        })?;
        let mut remote = Remote {
            transport: self.transport.as_mut(),
        };
        remote.write_file(host, ssh, SCRIPT_PATH, &script)?;
        remote.write_file(host, ssh, DEADLINE_PATH, &render_deadline(expires_at))?;

        // Read-modify-write of root's crontab, preserving every non-marker
        // byte; the upsert is idempotent.
        let current = remote.run_ok(
            host,
            ssh,
            vec![
                "sh".into(),
                "-c".into(),
                "crontab -l 2>/dev/null || true".into(),
            ],
            None,
            "reading crontab",
        )?;
        let wanted = crontab_with_deadman(&current);
        if wanted != current {
            remote.run_ok(
                host,
                ssh,
                vec!["crontab".into(), "-".into()],
                Some(&wanted),
                "writing crontab",
            )?;
        }

        // Verify: the claim is about the host's state. The schedule line
        // must be there, and the deadline must read back as written.
        let landed = remote.run_ok(
            host,
            ssh,
            vec![
                "sh".into(),
                "-c".into(),
                "crontab -l 2>/dev/null || true".into(),
            ],
            None,
            "verifying crontab",
        )?;
        if !landed.lines().any(|l| l.contains(CRON_MARKER)) {
            return Err(DriverError(format!(
                "dead-man schedule verify failed on {:?}: the crontab line did not land",
                host.name
            )));
        }
        let deadline = remote.read_file(host, ssh, DEADLINE_PATH)?;
        if deadline != render_deadline(expires_at) {
            return Err(DriverError(format!(
                "dead-man deadline verify failed on {:?}: read back {deadline:?}",
                host.name
            )));
        }
        Ok(())
    }

    fn remove(&mut self, host: &Host) -> Result<bool, DriverError> {
        let ssh = host
            .ssh
            .as_ref()
            .ok_or_else(|| DriverError(format!("host {:?} has no ssh config", host.name)))?;
        let mut remote = Remote {
            transport: self.transport.as_mut(),
        };

        let current = remote.run_ok(
            host,
            ssh,
            vec![
                "sh".into(),
                "-c".into(),
                "crontab -l 2>/dev/null || true".into(),
            ],
            None,
            "reading crontab",
        )?;
        let wanted = crontab_without_deadman(&current);
        if wanted != current {
            remote.run_ok(
                host,
                ssh,
                vec!["crontab".into(), "-".into()],
                Some(&wanted),
                "writing crontab",
            )?;
        }

        // One round trip: report the fired marker, then clear everything.
        let script = format!(
            "if test -f {FIRED_PATH}; then echo fired; fi; \
             rm -f {FIRED_PATH} {SCRIPT_PATH} {DEADLINE_PATH}"
        );
        let out = remote.run_ok(
            host,
            ssh,
            vec!["sh".into(), "-c".into(), script],
            None,
            "removing dead-man files",
        )?;
        Ok(out.contains("fired"))
    }
}

#[cfg(test)]
mod tests;
