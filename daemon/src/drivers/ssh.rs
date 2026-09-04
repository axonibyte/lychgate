//! The SSH-borne drivers: root posture via a lychgate-owned sshd_config
//! drop-in, and break-glass keys inside the authorized_keys fence.
//!
//! Both verify after every mutation — `sshd -T` for the effective posture, a
//! read-back for the keys file — because a driver's claim is about the
//! host's actual state, not about the commands it sent. A verify that
//! disagrees is a failed apply (unwound by the lifecycle) or a stuck revert
//! (retried loudly), never a shrug.

use lychgate_core::ssh::{fence_remove, fence_upsert, render_dropin, DEFAULT_DROPIN, FENCE_BEGIN};
use lychgate_core::{Channel, ChannelDriver, ChannelState, DriverError, Host, SshConfig};

use crate::drivers::remote::Remote;
use crate::transport::SshTransport;

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
        let effective = remote.effective_posture_after_reload(host, ssh)?;
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
        let effective = remote.effective_posture_after_reload(host, ssh)?;
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
