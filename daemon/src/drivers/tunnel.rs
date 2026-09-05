//! The VNC console tunnel: a daemon-held `ssh -L` forward from the daemon
//! host to a bhyve/cbsd VM's RFB port on its hypervisor.
//!
//! Unlike every other channel's effect, this is not host-side state — it is a
//! live child process the daemon owns. That makes it inherently fail-closed:
//! when lychgated dies, the forward must die with it, so no reachability
//! outlives the daemon that authorized it. That is NOT automatic — an orphaned
//! child is reparented to init and keeps running — so `ExecTunnelSpawner` arms
//! `PR_SET_PDEATHSIG` (Linux) / `PROC_PDEATHSIG_CTL` (FreeBSD) in the forked
//! child, the daemon tears tunnels down explicitly on a graceful stop, and a
//! stray on a host's fixed port is caught on the next boot (a re-bind fails,
//! or a teardown finds the port still held).
//!
//! The spawn is behind a `TunnelSpawner` seam so the lifecycle — readiness
//! probe, teardown, stray detection — is testable without a real ssh: the
//! fake binds a real local socket, so the port probes see reality.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use lychgate_core::{DriverError, Host};

/// Everything a tunnel needs, derived from the inventory — never persisted.
/// A fixed `local_port` is what lets verify and boot re-establishment find the
/// forward again without remembering a pid.
pub struct TunnelSpec {
    pub local_port: u16,
    pub rfb_host: String,
    pub rfb_port: u16,
    pub address: String,
    pub ssh_port: u16,
    pub agent_user: String,
    pub identity_file: Option<String>,
}

impl TunnelSpec {
    fn from_host(host: &Host) -> Result<TunnelSpec, DriverError> {
        let vnc = host.vnc.as_ref().ok_or_else(|| {
            DriverError(format!("host {:?} has no [hosts.vnc] config", host.name))
        })?;
        Ok(TunnelSpec {
            local_port: vnc.local_port,
            rfb_host: vnc.rfb_host.clone(),
            rfb_port: vnc.rfb_port,
            address: host.address.clone(),
            ssh_port: vnc.port,
            agent_user: vnc.agent_user.clone(),
            identity_file: vnc.identity_file.clone(),
        })
    }
}

/// A running forward. The handle owns the child; dropping it kills the child,
/// so a spawned-but-unretained tunnel never leaks.
pub trait TunnelHandle: Send {
    /// Still running? Reaps a child that has exited.
    fn is_alive(&mut self) -> bool;
    /// Kill and reap. Idempotent — killing an already-dead child is fine.
    fn stop(&mut self) -> Result<(), DriverError>;
}

/// Spawns a forward. The production impl runs `ssh -L`; the test fake binds a
/// real local socket so the readiness and teardown probes are exercised.
pub trait TunnelSpawner: Send {
    fn spawn(&mut self, spec: &TunnelSpec) -> Result<Box<dyn TunnelHandle>, DriverError>;
}

/// The driver-facing seam the vnc driver calls. `TunnelSet` is the production
/// implementation; tests substitute a fake.
pub trait TunnelControl: Send {
    /// Bring the forward up and confirm it accepts. Atomic-or-reported: on any
    /// failure nothing is retained and the port is left as it was found.
    fn up(&mut self, host: &Host) -> Result<(), DriverError>;
    /// Tear the forward down. Idempotent. A port still bound after we drop our
    /// child is not ours to kill — reported as stuck, never killed by port.
    fn down(&mut self, host: &Host) -> Result<(), DriverError>;
    /// Is our forward actually accepting on the local port right now?
    fn listening(&mut self, host: &Host) -> Result<bool, DriverError>;
    /// Kill every held forward without reverting or probing — a graceful
    /// daemon shutdown. The grants stay open on disk and are restored on boot.
    fn suspend(&mut self);
}

/// True if something accepts a TCP connection on 127.0.0.1:`port`.
fn port_open(port: u16) -> bool {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

/// The live tunnels, keyed by host name, plus the spawner. Held by the vnc
/// driver for the daemon's lifetime.
pub struct TunnelSet {
    spawner: Box<dyn TunnelSpawner>,
    live: BTreeMap<String, Box<dyn TunnelHandle>>,
    /// Readiness-probe budget: attempts × interval.
    probe_attempts: u32,
    probe_interval: Duration,
}

impl TunnelSet {
    pub fn new(spawner: Box<dyn TunnelSpawner>) -> TunnelSet {
        TunnelSet {
            spawner,
            live: BTreeMap::new(),
            // ssh -L handshake + forward setup: bounded, generous.
            probe_attempts: 100,
            probe_interval: Duration::from_millis(100),
        }
    }

    #[cfg(test)]
    fn with_probe(spawner: Box<dyn TunnelSpawner>, attempts: u32, interval: Duration) -> TunnelSet {
        TunnelSet {
            spawner,
            live: BTreeMap::new(),
            probe_attempts: attempts,
            probe_interval: interval,
        }
    }
}

impl TunnelControl for TunnelSet {
    fn up(&mut self, host: &Host) -> Result<(), DriverError> {
        let spec = TunnelSpec::from_host(host)?;
        let handle = self.spawner.spawn(&spec)?;
        self.live.insert(host.name.clone(), handle);

        for attempt in 0..self.probe_attempts {
            if attempt > 0 {
                std::thread::sleep(self.probe_interval);
            }
            // A child that exited (ExitOnForwardFailure fired, host
            // unreachable) will never listen: stop probing.
            let alive = self
                .live
                .get_mut(&host.name)
                .map(|h| h.is_alive())
                .unwrap_or(false);
            if !alive {
                break;
            }
            if port_open(spec.local_port) {
                return Ok(());
            }
        }

        // Missed: retain nothing, leave the port as we found it.
        if let Some(mut h) = self.live.remove(&host.name) {
            let _ = h.stop();
        }
        Err(DriverError(format!(
            "vnc tunnel for {:?} did not come up: 127.0.0.1:{} never accepted",
            host.name, spec.local_port
        )))
    }

    fn down(&mut self, host: &Host) -> Result<(), DriverError> {
        let spec = TunnelSpec::from_host(host)?;
        if let Some(mut h) = self.live.remove(&host.name) {
            h.stop()?;
        }
        // The forward should close as soon as the child is reaped; give it a
        // brief window. A port still bound after that is a stray we do not own
        // — report it stuck rather than kill an arbitrary process by port.
        for attempt in 0..10 {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(100));
            }
            if !port_open(spec.local_port) {
                return Ok(());
            }
        }
        Err(DriverError(format!(
            "vnc tunnel port 127.0.0.1:{} on {:?} is still bound after teardown; a stray process \
             holds it",
            spec.local_port, host.name
        )))
    }

    fn listening(&mut self, host: &Host) -> Result<bool, DriverError> {
        let spec = TunnelSpec::from_host(host)?;
        let alive = self
            .live
            .get_mut(&host.name)
            .map(|h| h.is_alive())
            .unwrap_or(false);
        Ok(alive && port_open(spec.local_port))
    }

    fn suspend(&mut self) {
        for (_host, mut handle) in std::mem::take(&mut self.live) {
            let _ = handle.stop();
        }
    }
}

/// The production spawner: `ssh -N -L …`, with the parent-death signal armed
/// so the forward dies with the daemon.
pub struct ExecTunnelSpawner;

struct ChildTunnel {
    child: std::process::Child,
}

impl TunnelHandle for ChildTunnel {
    fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn stop(&mut self) -> Result<(), DriverError> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        Ok(())
    }
}

impl Drop for ChildTunnel {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl TunnelSpawner for ExecTunnelSpawner {
    fn spawn(&mut self, spec: &TunnelSpec) -> Result<Box<dyn TunnelHandle>, DriverError> {
        use std::process::{Command, Stdio};

        let mut cmd = Command::new("ssh");
        cmd.arg("-N")
            .arg("-o")
            .arg("BatchMode=yes")
            // The forward must bind or ssh must not background: a failed bind
            // is a fast child exit, never a silently-wrong forward.
            .arg("-o")
            .arg("ExitOnForwardFailure=yes")
            .arg("-o")
            .arg("ServerAliveInterval=15")
            .arg("-o")
            .arg("ServerAliveCountMax=3")
            .arg("-o")
            .arg("ConnectTimeout=10")
            .arg("-L")
            .arg(format!(
                "{}:{}:{}",
                spec.local_port, spec.rfb_host, spec.rfb_port
            ))
            .arg("-p")
            .arg(spec.ssh_port.to_string())
            .arg("-l")
            .arg(&spec.agent_user);
        if let Some(identity) = &spec.identity_file {
            cmd.arg("-i")
                .arg(identity)
                .arg("-o")
                .arg("IdentitiesOnly=yes");
        }
        cmd.arg(&spec.address);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        arm_pdeathsig_on(&mut cmd);

        let child = cmd
            .spawn()
            .map_err(|e| DriverError(format!("spawning ssh -L for the vnc tunnel: {e}")))?;
        Ok(Box::new(ChildTunnel { child }))
    }
}

/// Arms "die when the parent (this daemon) dies" on the child. The closure
/// runs in the forked child before exec, so it must be async-signal-safe: it
/// makes exactly one syscall and nothing else.
fn arm_pdeathsig_on(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: pre_exec's closure runs post-fork/pre-exec. It only calls
    // prctl/procctl (a single syscall) — no allocation, no locks.
    unsafe {
        cmd.pre_exec(|| {
            arm_pdeathsig();
            Ok(())
        });
    }
}

#[cfg(target_os = "linux")]
fn arm_pdeathsig() {
    // SAFETY: a single prctl syscall, async-signal-safe.
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
    }
}

#[cfg(target_os = "freebsd")]
fn arm_pdeathsig() {
    // SAFETY: a single procctl syscall, async-signal-safe.
    unsafe {
        let mut sig: libc::c_int = libc::SIGKILL;
        libc::procctl(
            libc::P_PID,
            0,
            libc::PROC_PDEATHSIG_CTL,
            &mut sig as *mut libc::c_int as *mut libc::c_void,
        );
    }
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn arm_pdeathsig() {}

#[cfg(test)]
mod tests;
