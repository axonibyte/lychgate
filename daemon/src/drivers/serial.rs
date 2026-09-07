//! The generic serial channel driver: open/revert/verify a device over a
//! local tty from inventory-supplied send/expect command specs.
//!
//! The transport is a direct fd — open(2) the device, raw termios, write the
//! command, read until the expectation appears or the budget runs out. No
//! socat, no helper processes: the daemon host owns the port. Setting the
//! baud on a pty is a tolerated no-op, so the same driver serves real ttys
//! and the pty-backed test mock/simulator.
//!
//! Semantics mirror the http driver: apply runs the open command and holds
//! the reply to its `expect`, then requires the verify probe to read Open;
//! revert is idempotent and requires Closed; `verify = "none"` degrades
//! honestly (apply/revert trust their own expectation — the surfaced
//! narrowing — and standalone verify refuses rather than guesses). No
//! dead-man: expiry enforcement is the daemon's alone (documented residual).

use lychgate_core::generic::match_state;
use lychgate_core::{
    ApplyCtx, Channel, ChannelDriver, ChannelState, DriverError, Host, SerialCmdSpec, SerialConfig,
    VerifyMode,
};

/// One serial transaction: write `send`, collect the reply until `until`
/// matches within the budget. Returns everything read.
pub trait SerialTransport: Send {
    fn transact(
        &mut self,
        serial: &SerialConfig,
        send: &str,
        until: &Until,
    ) -> Result<String, DriverError>;
}

/// What ends a read: any of these substrings appearing in the collected
/// reply. (The driver always knows the possible answers, so the transport
/// can return as soon as one lands instead of always burning the budget.)
pub struct Until(pub Vec<String>);

pub struct SerialDriver {
    transport: Box<dyn SerialTransport>,
}

impl SerialDriver {
    pub fn new(transport: Box<dyn SerialTransport>) -> Box<SerialDriver> {
        Box::new(SerialDriver { transport })
    }

    fn config(host: &Host) -> Result<&SerialConfig, DriverError> {
        host.serial.as_ref().ok_or_else(|| {
            DriverError(format!("host {:?} has no [hosts.serial] config", host.name))
        })
    }

    fn run(
        &mut self,
        host: &Host,
        serial: &SerialConfig,
        which: &str,
        spec: &SerialCmdSpec,
    ) -> Result<(), DriverError> {
        let reply =
            self.transport
                .transact(serial, &spec.send, &Until(vec![spec.expect.clone()]))?;
        if !reply.contains(&spec.expect) {
            return Err(DriverError(format!(
                "serial {which} on {:?}: reply {:?} does not contain expected {:?}",
                host.name,
                reply.trim(),
                spec.expect
            )));
        }
        Ok(())
    }

    fn probe(&mut self, host: &Host, serial: &SerialConfig) -> Result<ChannelState, DriverError> {
        let v = match &serial.verify {
            VerifyMode::Probe(v) => v,
            VerifyMode::None(_) => {
                return Err(DriverError(format!(
                    "serial state on {:?} is unverifiable: the inventory says verify = \"none\"",
                    host.name
                )))
            }
        };
        let reply = self.transport.transact(
            serial,
            &v.send,
            &Until(vec![v.open_marker.clone(), v.closed_marker.clone()]),
        )?;
        match_state(&reply, &v.open_marker, &v.closed_marker)
            .map_err(|e| DriverError(format!("serial verify on {:?}: {e}", host.name)))
    }
}

impl ChannelDriver for SerialDriver {
    fn channel(&self) -> Channel {
        Channel::Serial
    }

    fn apply(&mut self, host: &Host, _ctx: &ApplyCtx) -> Result<(), DriverError> {
        let serial = Self::config(host)?.clone();
        self.run(host, &serial, "open", &serial.open)?;
        if matches!(serial.verify, VerifyMode::Probe(_))
            && self.probe(host, &serial)? != ChannelState::Open
        {
            return Err(DriverError(format!(
                "serial verify failed on {:?}: the device did not read back open",
                host.name
            )));
        }
        Ok(())
    }

    fn revert(&mut self, host: &Host) -> Result<(), DriverError> {
        let serial = Self::config(host)?.clone();
        self.run(host, &serial, "revert", &serial.revert)?;
        if matches!(serial.verify, VerifyMode::Probe(_))
            && self.probe(host, &serial)? != ChannelState::Closed
        {
            return Err(DriverError(format!(
                "serial verify failed on {:?}: the device did not read back closed",
                host.name
            )));
        }
        Ok(())
    }

    fn verify(&mut self, host: &Host) -> Result<ChannelState, DriverError> {
        let serial = Self::config(host)?.clone();
        self.probe(host, &serial)
    }
}

/// The production transport: open the tty, raw termios, deadline-bounded
/// short reads. Every syscall failure names the device.
pub struct FdSerialTransport;

impl SerialTransport for FdSerialTransport {
    fn transact(
        &mut self,
        serial: &SerialConfig,
        send: &str,
        until: &Until,
    ) -> Result<String, DriverError> {
        fd_transact(
            &serial.device,
            serial.baud,
            serial.timeout_secs,
            send,
            until,
        )
    }
}

/// The raw fd transaction, shared with the device channel's serial
/// transport: open, raw termios, write, deadline-bounded short reads.
pub(crate) fn fd_transact(
    dev: &str,
    baud: Option<u32>,
    timeout_secs: u64,
    send: &str,
    until: &Until,
) -> Result<String, DriverError> {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev)
        .map_err(|e| DriverError(format!("opening {dev}: {e}")))?;

    configure_port(&file, dev, baud)?;

    file.write_all(send.as_bytes())
        .and_then(|()| file.flush())
        .map_err(|e| DriverError(format!("writing to {dev}: {e}")))?;

    // Deadline loop over short reads: VMIN=0/VTIME=1 makes each read(2)
    // return within ~100ms, so the overall budget is honored without
    // blocking forever on a silent device.
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut reply = String::new();
    let mut buf = [0u8; 256];
    loop {
        if until.0.iter().any(|m| reply.contains(m)) {
            return Ok(reply);
        }
        if Instant::now() >= deadline {
            return Err(DriverError(format!(
                "no expected reply from {dev} within {timeout_secs}s (got {:?})",
                reply.trim()
            )));
        }
        match file.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => reply.push_str(&String::from_utf8_lossy(&buf[..n])),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(DriverError(format!("reading {dev}: {e}"))),
        }
    }
}

/// Raw mode + optional baud. A pty accepts the raw flags and ignores the
/// speed — deliberately tolerated, so the simulator path is identical.
fn configure_port(file: &std::fs::File, dev: &str, baud: Option<u32>) -> Result<(), DriverError> {
    use std::os::fd::AsRawFd;
    let fd = file.as_raw_fd();

    // SAFETY-free zone: all through libc's safe-ish FFI with checked returns.
    let mut tio = std::mem::MaybeUninit::<libc::termios>::uninit();
    if unsafe { libc::tcgetattr(fd, tio.as_mut_ptr()) } != 0 {
        return Err(DriverError(format!(
            "tcgetattr on {dev}: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut tio = unsafe { tio.assume_init() };
    unsafe { libc::cfmakeraw(&mut tio) };
    // VMIN=0, VTIME=1: reads return within ~100ms with whatever arrived.
    tio.c_cc[libc::VMIN] = 0;
    tio.c_cc[libc::VTIME] = 1;
    if let Some(baud) = baud {
        let speed = baud_constant(baud)
            .ok_or_else(|| DriverError(format!("unsupported baud rate {baud} for {dev}")))?;
        // Setting the speed on a pty is a no-op; on a real tty it must stick.
        unsafe {
            libc::cfsetispeed(&mut tio, speed);
            libc::cfsetospeed(&mut tio, speed);
        }
    }
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &tio) } != 0 {
        return Err(DriverError(format!(
            "tcsetattr on {dev}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn baud_constant(baud: u32) -> Option<libc::speed_t> {
    Some(match baud {
        9600 => libc::B9600,
        19200 => libc::B19200,
        38400 => libc::B38400,
        57600 => libc::B57600,
        115_200 => libc::B115200,
        _ => return None,
    })
}

#[cfg(test)]
mod tests;
