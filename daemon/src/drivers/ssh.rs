//! The SSH-borne drivers: root posture via a lychgate-owned sshd_config
//! drop-in, and break-glass keys inside the authorized_keys fence.
//!
//! Both verify after every mutation — `sshd -T` for the effective posture, a
//! read-back for the keys file — because a driver's claim is about the
//! host's actual state, not about the commands it sent. A verify that
//! disagrees is a failed apply (unwound by the lifecycle) or a stuck revert
//! (retried loudly), never a shrug.

use lychgate_core::ssh::{
    fence_remove, fence_upsert, parse_effective_posture, render_dropin, Posture, FENCE_BEGIN,
};
use lychgate_core::{Channel, ChannelDriver, ChannelState, DriverError, Host, Os, SshConfig};

use crate::transport::SshTransport;

/// Sorts first among drop-ins on purpose: sshd honors the FIRST obtained
/// value for a keyword, so within the include directory an early name wins.
/// (Whether drop-ins beat the main config at all depends on where its
/// Include line sits — which is why apply verifies instead of trusting.)
const DEFAULT_DROPIN: &str = "/etc/ssh/sshd_config.d/00-lychgate.conf";

fn ssh_of(host: &Host) -> Result<&SshConfig, DriverError> {
    host.ssh
        .as_ref()
        .ok_or_else(|| DriverError(format!("host {:?} has no [hosts.ssh] config", host.name)))
}

fn dropin_path(ssh: &SshConfig) -> String {
    ssh.dropin_path
        .clone()
        .unwrap_or_else(|| DEFAULT_DROPIN.to_string())
}

fn reload_argv(host: &Host, ssh: &SshConfig) -> Vec<String> {
    match &ssh.reload_cmd {
        Some(cmd) => vec!["sh".into(), "-c".into(), cmd.clone()],
        None => match host.os {
            Os::Freebsd => vec!["service".into(), "sshd".into(), "reload".into()],
            Os::Linux => vec![
                "sh".into(),
                "-c".into(),
                "systemctl reload sshd 2>/dev/null || systemctl reload ssh".into(),
            ],
        },
    }
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
struct Remote<'a> {
    transport: &'a mut dyn SshTransport,
}

impl Remote<'_> {
    fn run_ok(
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

    fn read_file(
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

    fn write_file(
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

    fn remove_file(&mut self, host: &Host, ssh: &SshConfig, path: &str) -> Result<(), DriverError> {
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

    fn effective_posture(&mut self, host: &Host, ssh: &SshConfig) -> Result<Posture, DriverError> {
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

    fn reload_sshd(&mut self, host: &Host, ssh: &SshConfig) -> Result<(), DriverError> {
        self.run_ok(host, ssh, reload_argv(host, ssh), None, "reloading sshd")?;
        Ok(())
    }
}

/// The `ssh` channel: PermitRootLogin posture via the drop-in.
pub struct SshPostureDriver {
    transport: Box<dyn SshTransport>,
}

impl SshPostureDriver {
    pub fn new(transport: Box<dyn SshTransport>) -> Box<SshPostureDriver> {
        Box::new(SshPostureDriver { transport })
    }
}

impl ChannelDriver for SshPostureDriver {
    fn channel(&self) -> Channel {
        Channel::Ssh
    }

    fn apply(&mut self, host: &Host) -> Result<(), DriverError> {
        let ssh = ssh_of(host)?;
        let mut remote = Remote {
            transport: self.transport.as_mut(),
        };
        remote.write_file(
            host,
            ssh,
            &dropin_path(ssh),
            &render_dropin(ssh.root_posture_emergency),
        )?;
        remote.reload_sshd(host, ssh)?;
        let effective = remote.effective_posture(host, ssh)?;
        if effective != ssh.root_posture_emergency {
            return Err(DriverError(format!(
                "posture verify failed on {:?}: effective {effective}, wanted {}; \
                 does the main sshd_config Include the drop-in directory?",
                host.name, ssh.root_posture_emergency
            )));
        }
        Ok(())
    }

    fn revert(&mut self, host: &Host) -> Result<(), DriverError> {
        let ssh = ssh_of(host)?;
        let mut remote = Remote {
            transport: self.transport.as_mut(),
        };
        remote.remove_file(host, ssh, &dropin_path(ssh))?;
        remote.reload_sshd(host, ssh)?;
        let effective = remote.effective_posture(host, ssh)?;
        if effective != ssh.root_posture_default {
            return Err(DriverError(format!(
                "posture verify failed on {:?} after revert: effective {effective}, but the \
                 inventory declares default {}; the host's own config has drifted",
                host.name, ssh.root_posture_default
            )));
        }
        Ok(())
    }

    fn verify(&mut self, host: &Host) -> Result<ChannelState, DriverError> {
        let ssh = ssh_of(host)?;
        let mut remote = Remote {
            transport: self.transport.as_mut(),
        };
        let effective = remote.effective_posture(host, ssh)?;
        Ok(if effective == ssh.root_posture_emergency {
            ChannelState::Open
        } else {
            ChannelState::Closed
        })
    }
}

/// The `authorized-keys` channel: break-glass keys inside the fence.
pub struct AuthorizedKeysDriver {
    transport: Box<dyn SshTransport>,
}

impl AuthorizedKeysDriver {
    pub fn new(transport: Box<dyn SshTransport>) -> Box<AuthorizedKeysDriver> {
        Box::new(AuthorizedKeysDriver { transport })
    }
}

impl ChannelDriver for AuthorizedKeysDriver {
    fn channel(&self) -> Channel {
        Channel::AuthorizedKeys
    }

    fn apply(&mut self, host: &Host) -> Result<(), DriverError> {
        let ssh = ssh_of(host)?;
        let mut remote = Remote {
            transport: self.transport.as_mut(),
        };
        let current = remote.read_file(host, ssh, &ssh.authorized_keys_path)?;
        let updated =
            fence_upsert(&current, &ssh.emergency_keys).map_err(|e| DriverError(e.to_string()))?;
        remote.write_file(host, ssh, &ssh.authorized_keys_path, &updated)?;
        // Read back: the claim is about the file on the host, not the write.
        let landed = remote.read_file(host, ssh, &ssh.authorized_keys_path)?;
        if landed != updated {
            return Err(DriverError(format!(
                "authorized_keys verify failed on {:?}: the file read back differs from what was written",
                host.name
            )));
        }
        Ok(())
    }

    fn revert(&mut self, host: &Host) -> Result<(), DriverError> {
        let ssh = ssh_of(host)?;
        let mut remote = Remote {
            transport: self.transport.as_mut(),
        };
        let current = remote.read_file(host, ssh, &ssh.authorized_keys_path)?;
        let updated = fence_remove(&current).map_err(|e| DriverError(e.to_string()))?;
        if updated != current {
            remote.write_file(host, ssh, &ssh.authorized_keys_path, &updated)?;
        }
        let landed = remote.read_file(host, ssh, &ssh.authorized_keys_path)?;
        if landed.contains(FENCE_BEGIN) {
            return Err(DriverError(format!(
                "authorized_keys verify failed on {:?}: the fence is still present after revert",
                host.name
            )));
        }
        Ok(())
    }

    fn verify(&mut self, host: &Host) -> Result<ChannelState, DriverError> {
        let ssh = ssh_of(host)?;
        let mut remote = Remote {
            transport: self.transport.as_mut(),
        };
        let current = remote.read_file(host, ssh, &ssh.authorized_keys_path)?;
        Ok(if current.contains(FENCE_BEGIN) {
            ChannelState::Open
        } else {
            ChannelState::Closed
        })
    }
}

#[cfg(test)]
mod tests;
