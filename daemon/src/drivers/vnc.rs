//! The VNC driver: temporary console access to a bhyve/cbsd VM as a grant.
//!
//! Two halves, both for the grant window:
//! - a rotated one-time VNC password, set on the target through an
//!   operator-supplied, platform-agnostic command (cbsd is the pilot) — the
//!   command consumes a password *file* lychgate stages (mode 600) and removes
//!   at once, so the plaintext is never on an argv;
//! - an `ssh -L` tunnel from the daemon host to the VM's RFB port, held for
//!   the grant's life (see `tunnel`).
//!
//! apply rotates the password then brings the tunnel up; revert takes the
//! tunnel down then clears the password; verify reads the one genuinely
//! re-readable half — is the local forward listening. The one-time password
//! reaches the operator through the open response and is never journaled.
//!
//! Like bmc, there is no host-side dead-man: the tunnel dies with the daemon
//! (its own backstop), and the rotated password's expiry is the reap loop's
//! alone — a documented residual (README, TESTING).

use lychgate_core::bmc::{password_from_bytes, PasswordGen, Secret};
use lychgate_core::{Channel, ChannelDriver, ChannelState, DriverError, Host, VncConfig};

use crate::drivers::tunnel::TunnelControl;
use crate::transport::{shell_quote, CommandOutput};

/// Runs a command on the hypervisor over ssh. Its own seam (not the ssh
/// channel's `SshTransport`, which reads `host.ssh`): a vnc-only host has no
/// `[hosts.ssh]`, and the vnc connection fields are its own.
pub trait VncTransport: Send {
    fn run(
        &mut self,
        vnc: &VncConfig,
        host: &Host,
        argv: &[String],
        stdin: Option<&str>,
    ) -> Result<CommandOutput, DriverError>;
}

/// The production password generator: `password_len` characters from the OS
/// CSPRNG mapped onto the safe alphabet.
pub struct UrandomVncPasswords;

impl PasswordGen for UrandomVncPasswords {
    fn generate(&mut self) -> Secret {
        // The vnc length is per-host; the driver always calls generate_len.
        self.generate_len(lychgate_core::bmc::PASSWORD_LEN)
    }

    fn generate_len(&mut self, len: usize) -> Secret {
        use std::io::Read;
        let mut bytes = vec![0u8; len];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .expect("/dev/urandom is readable on every supported platform");
        password_from_bytes(&bytes)
    }
}

pub struct VncDriver {
    transport: Box<dyn VncTransport>,
    passwords: Box<dyn PasswordGen>,
    tunnel: Box<dyn TunnelControl>,
    /// The password from the most recent successful apply, handed to the
    /// operator once by the lifecycle. Redacted in Debug; cleared when taken.
    last_password: Option<Secret>,
}

impl VncDriver {
    pub fn new(
        transport: Box<dyn VncTransport>,
        passwords: Box<dyn PasswordGen>,
        tunnel: Box<dyn TunnelControl>,
    ) -> Box<VncDriver> {
        Box::new(VncDriver {
            transport,
            passwords,
            tunnel,
            last_password: None,
        })
    }

    fn vnc(host: &Host) -> Result<&VncConfig, DriverError> {
        host.vnc
            .as_ref()
            .ok_or_else(|| DriverError(format!("host {:?} has no [hosts.vnc] config", host.name)))
    }

    fn password_file_path(host: &Host, vnc: &VncConfig) -> String {
        vnc.password_file
            .clone()
            .unwrap_or_else(|| format!("/tmp/.lychgate-vnc-{}.pw", host.name))
    }

    /// Substitutes lychgate's placeholders, each shell-quoted so the remote
    /// shell sees exactly the intended argument. The template was proven
    /// quote-free at load, so the only quotes in the result are these.
    fn render(template: &str, target: &str, password_file: Option<&str>) -> String {
        let mut out = template.replace("{target}", &shell_quote(target));
        if let Some(pf) = password_file {
            out = out.replace("{password_file}", &shell_quote(pf));
        }
        out
    }

    fn with_become(vnc: &VncConfig, argv: Vec<String>) -> Vec<String> {
        match &vnc.become_cmd {
            None => argv,
            Some(prefix) => {
                let mut out: Vec<String> = prefix.split_whitespace().map(String::from).collect();
                out.extend(argv);
                out
            }
        }
    }

    fn run_ok(
        &mut self,
        vnc: &VncConfig,
        host: &Host,
        argv: Vec<String>,
        stdin: Option<&str>,
        doing: &str,
    ) -> Result<String, DriverError> {
        let argv = Self::with_become(vnc, argv);
        let out = self.transport.run(vnc, host, &argv, stdin)?;
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

    /// Stages the fresh password on the hypervisor, mode 600, replacement not
    /// in place — the content travels via stdin, never an argv.
    fn write_password_file(
        &mut self,
        vnc: &VncConfig,
        host: &Host,
        path: &str,
        password: &Secret,
    ) -> Result<(), DriverError> {
        let q = shell_quote(path);
        let script = format!("umask 077 && cat > {q}.lychgate-tmp && mv {q}.lychgate-tmp {q}");
        self.run_ok(
            vnc,
            host,
            vec!["sh".into(), "-c".into(), script],
            Some(password.reveal()),
            "staging the vnc password",
        )?;
        Ok(())
    }

    fn remove_password_file(
        &mut self,
        vnc: &VncConfig,
        host: &Host,
        path: &str,
    ) -> Result<(), DriverError> {
        let script = format!("rm -f {}", shell_quote(path));
        self.run_ok(
            vnc,
            host,
            vec!["sh".into(), "-c".into(), script],
            None,
            "removing the staged vnc password",
        )?;
        Ok(())
    }
}

impl ChannelDriver for VncDriver {
    fn channel(&self) -> Channel {
        Channel::Vnc
    }

    fn apply(&mut self, host: &Host) -> Result<(), DriverError> {
        let vnc = Self::vnc(host)?.clone();
        let pw_path = Self::password_file_path(host, &vnc);

        // Rotate the password: stage it, run the set command, then remove the
        // staged file whether or not the command succeeded.
        let password = self.passwords.generate_len(vnc.password_len);
        self.write_password_file(&vnc, host, &pw_path, &password)?;
        let set = Self::render(&vnc.set_password_cmd, &vnc.target, Some(&pw_path));
        let set_result = self.run_ok(
            &vnc,
            host,
            vec!["sh".into(), "-c".into(), set],
            None,
            "setting the vnc password",
        );
        let _ = self.remove_password_file(&vnc, host, &pw_path);
        set_result?;

        // Bring up reachability, then verify against the actual local port.
        self.tunnel.up(host)?;
        if !self.tunnel.listening(host)? {
            return Err(DriverError(format!(
                "vnc verify failed on {:?}: the local forward is not listening after apply",
                host.name
            )));
        }
        self.last_password = Some(password);
        Ok(())
    }

    fn revert(&mut self, host: &Host) -> Result<(), DriverError> {
        let vnc = Self::vnc(host)?.clone();
        // Reachability down first, then auth cleared — the reverse of apply.
        self.tunnel.down(host)?;
        let clear = Self::render(&vnc.clear_password_cmd, &vnc.target, None);
        self.run_ok(
            &vnc,
            host,
            vec!["sh".into(), "-c".into(), clear],
            None,
            "clearing the vnc password",
        )?;
        // A crashed apply may have left a staged file behind; rm -f tolerates
        // its absence.
        let _ = self.remove_password_file(&vnc, host, &Self::password_file_path(host, &vnc));
        if self.tunnel.listening(host)? {
            return Err(DriverError(format!(
                "vnc verify failed on {:?} after revert: the local forward is still listening",
                host.name
            )));
        }
        Ok(())
    }

    fn verify(&mut self, host: &Host) -> Result<ChannelState, DriverError> {
        Ok(if self.tunnel.listening(host)? {
            ChannelState::Open
        } else {
            ChannelState::Closed
        })
    }

    /// After a restart, re-assert reachability only — never re-run apply, so
    /// the password the operator already holds is not rotated out from under
    /// them.
    fn reestablish(&mut self, host: &Host) -> Result<ChannelState, DriverError> {
        self.tunnel.up(host)?;
        Ok(if self.tunnel.listening(host)? {
            ChannelState::Open
        } else {
            ChannelState::Closed
        })
    }

    fn suspend(&mut self) {
        self.tunnel.suspend();
    }

    /// The one-time VNC password from the last apply, handed off once.
    fn take_secret(&mut self) -> Option<Secret> {
        self.last_password.take()
    }
}

/// The production transport: ssh to the hypervisor using the vnc config's own
/// connection fields. File content travels via stdin, never an argv.
pub struct ExecSshVncTransport;

impl VncTransport for ExecSshVncTransport {
    fn run(
        &mut self,
        vnc: &VncConfig,
        host: &Host,
        argv: &[String],
        stdin: Option<&str>,
    ) -> Result<CommandOutput, DriverError> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let remote: String = argv
            .iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" ");

        let mut cmd = Command::new("ssh");
        cmd.arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("ConnectTimeout=10")
            .arg("-p")
            .arg(vnc.port.to_string())
            .arg("-l")
            .arg(&vnc.agent_user);
        if let Some(identity) = &vnc.identity_file {
            cmd.arg("-i")
                .arg(identity)
                .arg("-o")
                .arg("IdentitiesOnly=yes");
        }
        cmd.arg(&host.address).arg("--").arg(remote);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| DriverError(format!("spawning ssh for {:?}: {e}", host.name)))?;
        if let Some(content) = stdin {
            let mut pipe = child.stdin.take().expect("stdin was piped");
            pipe.write_all(content.as_bytes())
                .map_err(|e| DriverError(format!("feeding ssh stdin for {:?}: {e}", host.name)))?;
        } else {
            drop(child.stdin.take());
        }
        let output = child
            .wait_with_output()
            .map_err(|e| DriverError(format!("waiting on ssh for {:?}: {e}", host.name)))?;
        Ok(CommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[cfg(test)]
mod tests;
