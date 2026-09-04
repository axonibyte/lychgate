//! Shared plumbing every SSH-borne driver uses to reach a host.

use lychgate_core::ssh::{parse_effective_posture, reload_command, Posture};
use lychgate_core::{DriverError, Host, SshConfig};

use crate::transport::SshTransport;

fn reload_argv(host: &Host, ssh: &SshConfig) -> Vec<String> {
    vec!["sh".into(), "-c".into(), reload_command(host, ssh)]
}

/// Prepends the become prefix (e.g. "doas", "sudo -n") when configured.
fn with_become(ssh: &SshConfig, argv: Vec<String>) -> Vec<String> {
    match &ssh.become_cmd {
        None => argv,
        Some(prefix) => {
            let mut out: Vec<String> = prefix.split_whitespace().map(String::from).collect();
            out.extend(argv);
            out
        }
    }
}

/// Shared plumbing over the transport.
pub(crate) struct Remote<'a> {
    pub(crate) transport: &'a mut dyn SshTransport,
}

impl Remote<'_> {
    pub(crate) fn run_ok(
        &mut self,
        host: &Host,
        ssh: &SshConfig,
        argv: Vec<String>,
        stdin: Option<&str>,
        doing: &str,
    ) -> Result<String, DriverError> {
        let argv = with_become(ssh, argv);
        let out = self.transport.run(host, &argv, stdin)?;
        if out.status != 0 {
            return Err(DriverError(format!(
                "{doing} on {:?} exited {}: {}",
                host.name,
                out.status,
                out.stderr.trim()
            )));
        }
        Ok(out.stdout)
    }

    pub(crate) fn read_file(
        &mut self,
        host: &Host,
        ssh: &SshConfig,
        path: &str,
    ) -> Result<String, DriverError> {
        // An absent file reads as empty: authorized_keys may not exist yet.
        let script = format!(
            "if test -f {p}; then cat {p}; fi",
            p = crate::transport::shell_quote(path)
        );
        self.run_ok(
            host,
            ssh,
            vec!["sh".into(), "-c".into(), script],
            None,
            "reading",
        )
    }

    pub(crate) fn write_file(
        &mut self,
        host: &Host,
        ssh: &SshConfig,
        path: &str,
        content: &str,
    ) -> Result<(), DriverError> {
        // Replacement, never in place: same discipline as the local store.
        let q = crate::transport::shell_quote(path);
        let script = format!("umask 077 && cat > {q}.lychgate-tmp && mv {q}.lychgate-tmp {q}");
        self.run_ok(
            host,
            ssh,
            vec!["sh".into(), "-c".into(), script],
            Some(content),
            "writing",
        )?;
        Ok(())
    }

    pub(crate) fn remove_file(
        &mut self,
        host: &Host,
        ssh: &SshConfig,
        path: &str,
    ) -> Result<(), DriverError> {
        let script = format!("rm -f {}", crate::transport::shell_quote(path));
        self.run_ok(
            host,
            ssh,
            vec!["sh".into(), "-c".into(), script],
            None,
            "removing",
        )?;
        Ok(())
    }

    pub(crate) fn effective_posture(
        &mut self,
        host: &Host,
        ssh: &SshConfig,
    ) -> Result<Posture, DriverError> {
        let output = self.run_ok(
            host,
            ssh,
            vec!["sshd".into(), "-T".into()],
            None,
            "querying sshd -T",
        )?;
        parse_effective_posture(&output).ok_or_else(|| {
            DriverError(format!(
                "sshd -T on {:?} did not report a recognizable permitrootlogin",
                host.name
            ))
        })
    }

    pub(crate) fn reload_sshd(&mut self, host: &Host, ssh: &SshConfig) -> Result<(), DriverError> {
        self.run_ok(host, ssh, reload_argv(host, ssh), None, "reloading sshd")?;
        Ok(())
    }

    /// The post-reload posture check. A reload briefly closes sshd's
    /// listener while it re-executes (FreeBSD's SIGHUP restart window —
    /// found by the acceptance run, invisible to the fakes), so connection
    /// failures are retried for a bounded interval. A successful query that
    /// reports the wrong posture fails immediately: once sshd answers, its
    /// config is current.
    pub(crate) fn effective_posture_after_reload(
        &mut self,
        host: &Host,
        ssh: &SshConfig,
    ) -> Result<Posture, DriverError> {
        let mut last = None;
        for attempt in 0..20 {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            match self.effective_posture(host, ssh) {
                Ok(posture) => return Ok(posture),
                Err(e) => last = Some(e),
            }
        }
        Err(last.expect("twenty attempts produce at least one error"))
    }
}
