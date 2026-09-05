use super::*;

use std::sync::{Arc, Mutex};

use lychgate_core::Inventory;

const PW: &str = "FIXEDPW-not-random";

struct FixedPassword;
impl PasswordGen for FixedPassword {
    fn generate(&mut self) -> Secret {
        Secret::new(PW.to_string())
    }
}

#[derive(Default)]
struct Calls {
    /// (argv, stdin) of every transport run, in order.
    runs: Vec<(Vec<String>, Option<String>)>,
}

struct FakeVnc {
    calls: Arc<Mutex<Calls>>,
    fail_set: bool,
    fail_write: bool,
}

impl VncTransport for FakeVnc {
    fn run(
        &mut self,
        _vnc: &VncConfig,
        _host: &Host,
        argv: &[String],
        stdin: Option<&str>,
    ) -> Result<CommandOutput, DriverError> {
        self.calls
            .lock()
            .unwrap()
            .runs
            .push((argv.to_vec(), stdin.map(|s| s.to_string())));
        let script = argv.join(" ");
        if self.fail_write && script.contains("umask 077") {
            return Err(DriverError("scripted transport failure on write".into()));
        }
        if self.fail_set && script.contains("setpw") {
            return Ok(CommandOutput {
                status: 1,
                stdout: String::new(),
                stderr: "scripted set failure".into(),
            });
        }
        Ok(CommandOutput::ok(""))
    }
}

#[derive(Default)]
struct TunnelState {
    up: u32,
    down: u32,
    suspend: u32,
    listening: bool,
    fail_up: bool,
}

struct FakeTunnel(Arc<Mutex<TunnelState>>);

impl TunnelControl for FakeTunnel {
    fn up(&mut self, _host: &Host) -> Result<(), DriverError> {
        let mut s = self.0.lock().unwrap();
        if s.fail_up {
            return Err(DriverError("scripted tunnel up failure".into()));
        }
        s.up += 1;
        s.listening = true;
        Ok(())
    }
    fn down(&mut self, _host: &Host) -> Result<(), DriverError> {
        let mut s = self.0.lock().unwrap();
        s.down += 1;
        s.listening = false;
        Ok(())
    }
    fn listening(&mut self, _host: &Host) -> Result<bool, DriverError> {
        Ok(self.0.lock().unwrap().listening)
    }
    fn suspend(&mut self) {
        self.0.lock().unwrap().suspend += 1;
    }
}

fn host() -> Host {
    Inventory::parse(
        r#"
[[hosts]]
name = "hv"
address = "10.0.5.20"
os = "freebsd"
channels = ["vnc"]

[hosts.vnc]
agent_user = "lychgate"
rfb_port = 5900
local_port = 5959
target = "guest-01"
set_password_cmd = "setpw {target} {password_file}"
clear_password_cmd = "clearpw {target}"
"#,
    )
    .unwrap()
    .hosts
    .remove(0)
}

fn kinds(calls: &Calls) -> Vec<&'static str> {
    calls
        .runs
        .iter()
        .map(|(argv, _)| {
            let s = argv.join(" ");
            if s.contains("umask 077") {
                "write"
            } else if s.contains("setpw") {
                "set"
            } else if s.contains("rm -f") {
                "remove"
            } else if s.contains("clearpw") {
                "clear"
            } else {
                "?"
            }
        })
        .collect()
}

/// The password appears on no argv of any run — the driver's core security
/// claim, and the in-process counterpart of the acceptance's journal grep.
fn password_off_every_argv(calls: &Calls) -> bool {
    calls
        .runs
        .iter()
        .all(|(argv, _)| !argv.iter().any(|a| a.contains(PW)))
}

fn driver(fake: FakeVnc, tunnel: Arc<Mutex<TunnelState>>) -> Box<VncDriver> {
    VncDriver::new(
        Box::new(fake),
        Box::new(FixedPassword),
        Box::new(FakeTunnel(tunnel)),
    )
}

#[test]
fn apply_stages_the_password_runs_set_removes_it_then_brings_the_tunnel_up() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let tunnel = Arc::new(Mutex::new(TunnelState::default()));
    let mut d = driver(
        FakeVnc {
            calls: Arc::clone(&calls),
            fail_set: false,
            fail_write: false,
        },
        Arc::clone(&tunnel),
    );

    d.apply(&host()).unwrap();

    let calls = calls.lock().unwrap();
    // Order: stage the password, run the set command, remove the staged file.
    assert_eq!(kinds(&calls), vec!["write", "set", "remove"]);
    // The password reached the target via stdin of the write, and nowhere else.
    assert_eq!(calls.runs[0].1.as_deref(), Some(PW));
    assert!(
        password_off_every_argv(&calls),
        "password leaked onto an argv: {:?}",
        calls.runs
    );
    // The set command carries the substituted target and staging path, no
    // literal placeholders.
    let set = calls.runs[1].0.join(" ");
    assert!(set.contains("'guest-01'"), "{set}");
    assert!(
        !set.contains("{target}") && !set.contains("{password_file}"),
        "{set}"
    );
    // The tunnel came up after the password was set.
    assert_eq!(tunnel.lock().unwrap().up, 1);
}

#[test]
fn apply_removes_the_staged_file_and_drives_no_tunnel_when_the_set_fails() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let tunnel = Arc::new(Mutex::new(TunnelState::default()));
    let mut d = driver(
        FakeVnc {
            calls: Arc::clone(&calls),
            fail_set: true,
            fail_write: false,
        },
        Arc::clone(&tunnel),
    );

    assert!(d.apply(&host()).is_err());
    let calls = calls.lock().unwrap();
    // The staged file is removed even though the set failed.
    assert_eq!(kinds(&calls), vec!["write", "set", "remove"]);
    // No tunnel was brought up, and no secret is offered.
    assert_eq!(tunnel.lock().unwrap().up, 0);
    drop(calls);
    assert!(d.take_secret().is_none());
}

#[test]
fn apply_fails_when_the_tunnel_will_not_come_up_and_offers_no_secret() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let tunnel = Arc::new(Mutex::new(TunnelState {
        fail_up: true,
        ..TunnelState::default()
    }));
    let mut d = driver(
        FakeVnc {
            calls: Arc::clone(&calls),
            fail_set: false,
            fail_write: false,
        },
        Arc::clone(&tunnel),
    );
    let err = d.apply(&host()).unwrap_err();
    assert!(err.to_string().contains("tunnel up"), "{err}");
    assert!(d.take_secret().is_none());
}

#[test]
fn a_transport_failure_on_the_write_fails_the_apply() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let tunnel = Arc::new(Mutex::new(TunnelState::default()));
    let mut d = driver(
        FakeVnc {
            calls: Arc::clone(&calls),
            fail_set: false,
            fail_write: true,
        },
        Arc::clone(&tunnel),
    );
    assert!(d.apply(&host()).is_err());
    assert_eq!(tunnel.lock().unwrap().up, 0);
}

#[test]
fn the_one_time_password_is_handed_off_exactly_once() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let tunnel = Arc::new(Mutex::new(TunnelState::default()));
    let mut d = driver(
        FakeVnc {
            calls,
            fail_set: false,
            fail_write: false,
        },
        tunnel,
    );
    d.apply(&host()).unwrap();
    assert_eq!(
        d.take_secret().map(|s| s.reveal().to_string()),
        Some(PW.to_string())
    );
    assert!(d.take_secret().is_none());
}

#[test]
fn revert_takes_the_tunnel_down_then_clears_the_password() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let tunnel = Arc::new(Mutex::new(TunnelState {
        listening: true,
        up: 1,
        ..TunnelState::default()
    }));
    let mut d = driver(
        FakeVnc {
            calls: Arc::clone(&calls),
            fail_set: false,
            fail_write: false,
        },
        Arc::clone(&tunnel),
    );

    d.revert(&host()).unwrap();
    // Down happened (listening went false), and the clear ran after it.
    assert_eq!(tunnel.lock().unwrap().down, 1);
    let calls = calls.lock().unwrap();
    assert_eq!(kinds(&calls), vec!["clear", "remove"]);
    // The clear command carries no password: no stdin on any run, no PW argv.
    assert!(calls.runs.iter().all(|(_, stdin)| stdin.is_none()));
    assert!(password_off_every_argv(&calls));
}

#[test]
fn revert_is_idempotent_on_a_never_applied_host() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let tunnel = Arc::new(Mutex::new(TunnelState::default()));
    let mut d = driver(
        FakeVnc {
            calls,
            fail_set: false,
            fail_write: false,
        },
        Arc::clone(&tunnel),
    );
    d.revert(&host()).unwrap();
    d.revert(&host()).unwrap();
    // Down was attempted each time; nothing errored.
    assert_eq!(tunnel.lock().unwrap().down, 2);
}

#[test]
fn verify_reads_the_tunnel_listening_state() {
    let tunnel = Arc::new(Mutex::new(TunnelState::default()));
    let mut d = driver(
        FakeVnc {
            calls: Arc::new(Mutex::new(Calls::default())),
            fail_set: false,
            fail_write: false,
        },
        Arc::clone(&tunnel),
    );
    assert_eq!(d.verify(&host()).unwrap(), ChannelState::Closed);
    tunnel.lock().unwrap().listening = true;
    assert_eq!(d.verify(&host()).unwrap(), ChannelState::Open);
}

#[test]
fn reestablish_brings_the_tunnel_up_without_touching_the_password() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let tunnel = Arc::new(Mutex::new(TunnelState::default()));
    let mut d = driver(
        FakeVnc {
            calls: Arc::clone(&calls),
            fail_set: false,
            fail_write: false,
        },
        Arc::clone(&tunnel),
    );
    assert_eq!(d.reestablish(&host()).unwrap(), ChannelState::Open);
    assert_eq!(tunnel.lock().unwrap().up, 1);
    // The password is untouched: no transport run at all (no set, no write).
    assert!(
        calls.lock().unwrap().runs.is_empty(),
        "reestablish ran a password command: {:?}",
        calls.lock().unwrap().runs
    );
}

#[test]
fn suspend_suspends_the_tunnel() {
    let tunnel = Arc::new(Mutex::new(TunnelState::default()));
    let mut d = driver(
        FakeVnc {
            calls: Arc::new(Mutex::new(Calls::default())),
            fail_set: false,
            fail_write: false,
        },
        Arc::clone(&tunnel),
    );
    d.suspend();
    assert_eq!(tunnel.lock().unwrap().suspend, 1);
}
