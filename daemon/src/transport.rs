//! The SSH transport seam: how a driver reaches a host.
//!
//! The production implementation shells out to ssh(1) — BatchMode, the
//! inventory's agent account and port, an optional identity file — with the
//! remote command built from an argv whose every element is shell-quoted
//! client-side, and file content travelling via stdin, never embedded in a
//! command line. Tests script the seam instead; that is where mid-operation
//! failures come from.

use std::io::Write;
use std::process::{Command, Stdio};

use lychgate_core::{DriverError, Host};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

#[cfg(test)]
impl CommandOutput {
    /// Test convenience: a clean exit with this stdout.
    pub fn ok(stdout: &str) -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }
}

pub trait SshTransport: Send {
    /// Runs `argv` on the host, exactly as given (quoting is the
    /// transport's job), feeding `stdin` if present. An Err means the
    /// transport itself failed (unreachable host, dropped connection); a
    /// remote command that ran and failed comes back as a CommandOutput
    /// with a nonzero status.
    fn run(
        &mut self,
        host: &Host,
        argv: &[String],
        stdin: Option<&str>,
    ) -> Result<CommandOutput, DriverError>;
}

/// Wraps a string in single quotes for a POSIX shell, escaping embedded
/// single quotes, so the remote shell sees exactly the intended argument.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub struct ExecSshTransport;

impl SshTransport for ExecSshTransport {
    fn run(
        &mut self,
        host: &Host,
        argv: &[String],
        stdin: Option<&str>,
    ) -> Result<CommandOutput, DriverError> {
        let ssh = host
            .ssh
            .as_ref()
            .ok_or_else(|| DriverError(format!("host {:?} has no ssh config", host.name)))?;

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
            .arg(ssh.port.to_string())
            .arg("-l")
            .arg(&ssh.agent_user);
        if let Some(identity) = &ssh.identity_file {
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
            // Dropping the pipe closes it, letting the remote cat finish.
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
