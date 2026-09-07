use super::*;
use std::sync::{Arc, Mutex};

// Mutation notes (each observed failing): drop run()'s expect check →
// a_reply_without_the_expectation_fails; drop apply's probe requirement →
// apply_refuses_when_the_probe_does_not_read_open; make the fd transport's
// deadline loop return Ok(reply) on timeout instead of Err →
// the_fd_transport_honors_its_budget_against_a_silent_pty.

struct FakeTransport {
    replies: Vec<String>,
    log: Arc<Mutex<Vec<String>>>,
}

impl SerialTransport for FakeTransport {
    fn transact(
        &mut self,
        _serial: &SerialConfig,
        send: &str,
        _until: &Until,
    ) -> Result<String, DriverError> {
        self.log.lock().unwrap().push(send.to_string());
        if self.replies.is_empty() {
            return Err(DriverError("unexpected extra transaction".into()));
        }
        Ok(self.replies.remove(0))
    }
}

fn host(verify: &str) -> Host {
    let toml = format!(
        r#"
        [[hosts]]
        name = "bench-1"
        address = "n/a-serial"
        os = "embedded"
        channels = ["serial"]
        [hosts.serial]
        device = "/dev/nonexistent-lychgate-test"
        timeout_secs = 1
        {inline}
        [hosts.serial.open]
        send = "maint on\n"
        expect = "OK ON"
        [hosts.serial.revert]
        send = "maint off\n"
        expect = "OK OFF"
        {table}
    "#,
        inline = if verify == "none" {
            r#"verify = "none""#
        } else {
            ""
        },
        table = if verify == "probe" {
            r#"
            [hosts.serial.verify]
            send = "maint?\n"
            open_marker = "MAINT ON"
            closed_marker = "MAINT OFF"
        "#
        } else {
            ""
        },
    );
    lychgate_core::Inventory::parse(&toml)
        .unwrap()
        .hosts
        .remove(0)
}

fn driver(replies: &[&str]) -> (Box<SerialDriver>, Arc<Mutex<Vec<String>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let transport = FakeTransport {
        replies: replies.iter().map(|s| s.to_string()).collect(),
        log: Arc::clone(&log),
    };
    (SerialDriver::new(Box::new(transport)), log)
}

#[test]
fn apply_sends_open_then_requires_the_probe_to_read_open() {
    let (mut d, log) = driver(&["OK ON", "MAINT ON"]);
    d.apply(&host("probe")).unwrap();
    assert_eq!(*log.lock().unwrap(), vec!["maint on\n", "maint?\n"]);
}

#[test]
fn apply_refuses_when_the_probe_does_not_read_open() {
    let (mut d, _) = driver(&["OK ON", "MAINT OFF"]);
    let err = d.apply(&host("probe")).unwrap_err();
    assert!(err.0.contains("did not read back open"), "{err:?}");
}

#[test]
fn a_reply_without_the_expectation_fails() {
    let (mut d, _) = driver(&["ERR BUSY"]);
    let err = d.apply(&host("probe")).unwrap_err();
    assert!(err.0.contains("does not contain expected"), "{err:?}");
}

#[test]
fn apply_with_verify_none_runs_exactly_one_transaction() {
    let (mut d, log) = driver(&["OK ON"]);
    d.apply(&host("none")).unwrap();
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[test]
fn revert_is_idempotent_and_requires_closed_back() {
    let (mut d, _) = driver(&["OK OFF", "MAINT OFF", "OK OFF", "MAINT OFF"]);
    let h = host("probe");
    d.revert(&h).unwrap();
    d.revert(&h).unwrap();
}

#[test]
fn verify_maps_markers_and_verify_none_refuses_to_guess() {
    let (mut d, _) = driver(&["MAINT ON"]);
    assert_eq!(d.verify(&host("probe")).unwrap(), ChannelState::Open);
    let (mut d, log) = driver(&[]);
    let err = d.verify(&host("none")).unwrap_err();
    assert!(err.0.contains("unverifiable"), "{err:?}");
    assert!(log.lock().unwrap().is_empty());
}

// --- the real fd transport against a pty -----------------------------------

/// Open a pty pair via libc (posix_openpt). Returns (master file, slave path).
fn open_pty() -> (std::fs::File, String) {
    use std::os::fd::FromRawFd;
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0, "posix_openpt failed");
        assert_eq!(libc::grantpt(master), 0);
        assert_eq!(libc::unlockpt(master), 0);
        let name = libc::ptsname(master);
        assert!(!name.is_null());
        let path = std::ffi::CStr::from_ptr(name)
            .to_string_lossy()
            .into_owned();
        (std::fs::File::from_raw_fd(master), path)
    }
}

fn serial_config(device: &str, timeout_secs: u64) -> SerialConfig {
    let toml = format!(
        r#"
        [[hosts]]
        name = "bench-1"
        address = "n/a"
        os = "embedded"
        channels = ["serial"]
        [hosts.serial]
        device = "{device}"
        baud = 115200
        timeout_secs = {timeout_secs}
        verify = "none"
        [hosts.serial.open]
        send = "x"
        expect = "y"
        [hosts.serial.revert]
        send = "x"
        expect = "y"
    "#
    );
    lychgate_core::Inventory::parse(&toml)
        .unwrap()
        .hosts
        .remove(0)
        .serial
        .unwrap()
}

#[test]
fn the_fd_transport_talks_to_a_pty_responder() {
    use std::io::{Read, Write};
    let (mut master, pts) = open_pty();
    // A thread plays the device: read the command off the master side, echo
    // the reply. This is the REAL production code path — fd open, termios raw
    // (baud on a pty: tolerated no-op), deadline reads — against a real pty.
    let responder = std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        let mut got = String::new();
        loop {
            let n = master.read(&mut buf).unwrap();
            got.push_str(&String::from_utf8_lossy(&buf[..n]));
            if got.contains('\n') {
                break;
            }
        }
        assert_eq!(got, "status?\n");
        master.write_all(b"STATE OK\n").unwrap();
        // Hold the master open until the reader is done with it.
        std::thread::sleep(std::time::Duration::from_millis(300));
    });
    let cfg = serial_config(&pts, 5);
    let reply = FdSerialTransport
        .transact(&cfg, "status?\n", &Until(vec!["STATE OK".into()]))
        .unwrap();
    assert!(reply.contains("STATE OK"));
    responder.join().unwrap();
}

#[test]
fn the_fd_transport_honors_its_budget_against_a_silent_pty() {
    // Assert the absence with time allowed to pass: a device that never
    // answers must produce a timeout ERROR naming the budget — never an Ok
    // with whatever partial reply accumulated.
    let (_master, pts) = open_pty();
    let cfg = serial_config(&pts, 1);
    let start = std::time::Instant::now();
    let err = FdSerialTransport
        .transact(&cfg, "hello\n", &Until(vec!["NEVER".into()]))
        .unwrap_err();
    assert!(err.0.contains("within 1s"), "{err:?}");
    assert!(
        start.elapsed() >= std::time::Duration::from_secs(1),
        "the budget must actually elapse"
    );
}
