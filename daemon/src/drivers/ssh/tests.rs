//! The SSH drivers against a scripted transport: what commands really go
//! over the wire, and what happens when the wire lies or dies mid-operation.

use super::*;
use crate::transport::{CommandOutput, SshTransport};

use std::sync::{Arc, Mutex};

use lychgate_core::Inventory;

const INVENTORY: &str = r#"
[[hosts]]
name = "db-01"
address = "10.0.4.11"
os = "freebsd"
channels = ["ssh", "authorized-keys"]

[hosts.ssh]
agent_user = "lychgate"
root_posture_default = "no"
root_posture_emergency = "prohibit-password"
authorized_keys_path = "/root/.ssh/authorized_keys"
emergency_keys = ["ssh-ed25519 EMERG claude-breakglass"]
"#;

fn host() -> Host {
    Inventory::parse(INVENTORY).unwrap().hosts.remove(0)
}

type Call = (Vec<String>, Option<String>);
type Responder =
    Box<dyn FnMut(&[String], Option<&str>) -> Result<CommandOutput, DriverError> + Send>;

/// Scripted seam: a closure decides every response; every call is logged.
struct Scripted {
    log: Arc<Mutex<Vec<Call>>>,
    respond: Responder,
}

impl Scripted {
    fn new(respond: Responder) -> (Box<Scripted>, Arc<Mutex<Vec<Call>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        (
            Box::new(Scripted {
                log: Arc::clone(&log),
                respond,
            }),
            log,
        )
    }
}

impl SshTransport for Scripted {
    fn run(
        &mut self,
        _host: &Host,
        argv: &[String],
        stdin: Option<&str>,
    ) -> Result<CommandOutput, DriverError> {
        self.log
            .lock()
            .unwrap()
            .push((argv.to_vec(), stdin.map(String::from)));
        (self.respond)(argv, stdin)
    }
}

fn joined(argv: &[String]) -> String {
    argv.join(" ")
}

/// A remote host simulated well enough for both drivers: sshd -T reflects
/// whether the drop-in "exists", and the keys file holds real content.
fn fake_host_responder(include_works: bool) -> (Responder, Arc<Mutex<String>>, Arc<Mutex<String>>) {
    let dropin = Arc::new(Mutex::new(String::new()));
    let keys = Arc::new(Mutex::new(String::from("human@key A\n")));
    let d = Arc::clone(&dropin);
    let k = Arc::clone(&keys);
    let responder: Responder = Box::new(move |argv, stdin| {
        let cmd = joined(argv);
        if cmd == "sshd -T" {
            let dropin = d.lock().unwrap();
            let effective = if include_works && dropin.contains("prohibit-password") {
                "prohibit-password"
            } else {
                "no"
            };
            return Ok(CommandOutput::ok(&format!("permitrootlogin {effective}\n")));
        }
        if cmd.contains("00-lychgate.conf") && cmd.contains("cat >") {
            *d.lock().unwrap() = stdin.unwrap_or_default().to_string();
            return Ok(CommandOutput::ok(""));
        }
        if cmd.contains("rm -f") && cmd.contains("00-lychgate.conf") {
            d.lock().unwrap().clear();
            return Ok(CommandOutput::ok(""));
        }
        if cmd.contains("service sshd reload") || cmd.contains("systemctl") {
            return Ok(CommandOutput::ok(""));
        }
        if cmd.contains("authorized_keys") && cmd.contains("cat >") {
            *k.lock().unwrap() = stdin.unwrap_or_default().to_string();
            return Ok(CommandOutput::ok(""));
        }
        if cmd.contains("authorized_keys") && cmd.contains("cat ") {
            return Ok(CommandOutput::ok(&k.lock().unwrap().clone()));
        }
        Err(DriverError(format!("unexpected command: {cmd}")))
    });
    (responder, dropin, keys)
}

// --- posture driver --------------------------------------------------------

#[test]
fn posture_apply_writes_the_dropin_reloads_and_verifies_the_effective_value() {
    let (responder, dropin, _keys) = fake_host_responder(true);
    let (transport, log) = Scripted::new(responder);
    let mut driver = SshPostureDriver::new(transport);
    driver.apply(&host()).unwrap();

    // The drop-in landed with the emergency posture.
    assert!(dropin
        .lock()
        .unwrap()
        .contains("PermitRootLogin prohibit-password"));
    // Order: write, reload, verify — asserted from the transport log.
    let cmds: Vec<String> = log.lock().unwrap().iter().map(|(a, _)| joined(a)).collect();
    assert!(cmds[0].contains("00-lychgate.conf"), "{cmds:?}");
    assert!(cmds[1].contains("service sshd reload"), "{cmds:?}");
    assert_eq!(cmds[2], "sshd -T", "{cmds:?}");
}

#[test]
fn posture_apply_fails_loudly_when_the_dropin_has_no_effect() {
    // The Include directive is missing: the drop-in is written but sshd -T
    // still reports the old posture. Apply must fail (and the lifecycle
    // will unwind), pointing at the likely cause.
    let (responder, _dropin, _keys) = fake_host_responder(false);
    let (transport, _log) = Scripted::new(responder);
    let mut driver = SshPostureDriver::new(transport);
    let err = driver.apply(&host()).unwrap_err();
    assert!(err.to_string().contains("Include"), "{err}");
}

#[test]
fn posture_revert_removes_the_dropin_and_verifies_the_declared_default() {
    let (responder, dropin, _keys) = fake_host_responder(true);
    let (transport, _log) = Scripted::new(responder);
    let mut driver = SshPostureDriver::new(transport);
    driver.apply(&host()).unwrap();
    driver.revert(&host()).unwrap();
    assert!(dropin.lock().unwrap().is_empty(), "drop-in survived revert");
}

#[test]
fn posture_revert_reports_drift_when_the_host_default_disagrees_with_the_inventory() {
    // Remove works, but sshd -T reports "yes" — the host's own config has
    // drifted from the inventory's declared default of "no".
    let responder: Responder = Box::new(|argv, _| {
        let cmd = argv.join(" ");
        if cmd == "sshd -T" {
            return Ok(CommandOutput::ok("permitrootlogin yes\n"));
        }
        Ok(CommandOutput::ok(""))
    });
    let (transport, _log) = Scripted::new(responder);
    let mut driver = SshPostureDriver::new(transport);
    let err = driver.revert(&host()).unwrap_err();
    assert!(err.to_string().contains("drifted"), "{err}");
}

#[test]
fn a_transport_that_dies_mid_apply_fails_the_apply() {
    let responder: Responder =
        Box::new(|_, _| Err(DriverError("connection dropped mid-write".into())));
    let (transport, _log) = Scripted::new(responder);
    let mut driver = SshPostureDriver::new(transport);
    let err = driver.apply(&host()).unwrap_err();
    assert!(err.to_string().contains("dropped"), "{err}");
}

#[test]
fn a_remote_command_that_exits_nonzero_fails_with_its_stderr() {
    let responder: Responder = Box::new(|_, _| {
        Ok(CommandOutput {
            status: 1,
            stdout: String::new(),
            stderr: "permission denied".into(),
        })
    });
    let (transport, _log) = Scripted::new(responder);
    let mut driver = SshPostureDriver::new(transport);
    let err = driver.apply(&host()).unwrap_err();
    assert!(err.to_string().contains("permission denied"), "{err}");
}

#[test]
fn posture_verify_reads_the_actual_effective_state() {
    let (responder, dropin, _keys) = fake_host_responder(true);
    let (transport, _log) = Scripted::new(responder);
    let mut driver = SshPostureDriver::new(transport);
    assert_eq!(driver.verify(&host()).unwrap(), ChannelState::Closed);
    dropin
        .lock()
        .unwrap()
        .push_str("PermitRootLogin prohibit-password\n");
    assert_eq!(driver.verify(&host()).unwrap(), ChannelState::Open);
}

// --- authorized-keys driver ------------------------------------------------

#[test]
fn keys_apply_installs_the_fence_and_verifies_the_readback() {
    let (responder, _dropin, keys) = fake_host_responder(true);
    let (transport, _log) = Scripted::new(responder);
    let mut driver = AuthorizedKeysDriver::new(transport);
    driver.apply(&host()).unwrap();
    let file = keys.lock().unwrap().clone();
    assert!(
        file.starts_with("human@key A\n"),
        "human bytes moved:\n{file}"
    );
    assert!(file.contains("ssh-ed25519 EMERG claude-breakglass"));
    assert!(file.contains(FENCE_BEGIN));
}

#[test]
fn keys_revert_strips_the_fence_and_restores_the_human_file() {
    let (responder, _dropin, keys) = fake_host_responder(true);
    let (transport, _log) = Scripted::new(responder);
    let mut driver = AuthorizedKeysDriver::new(transport);
    driver.apply(&host()).unwrap();
    driver.revert(&host()).unwrap();
    assert_eq!(*keys.lock().unwrap(), "human@key A\n");
}

#[test]
fn keys_apply_refuses_a_malformed_fence_without_writing() {
    let (responder, _dropin, keys) = fake_host_responder(true);
    *keys.lock().unwrap() = format!("{FENCE_BEGIN}\norphaned begin, no end\n");
    let (transport, log) = Scripted::new(responder);
    let mut driver = AuthorizedKeysDriver::new(transport);
    let err = driver.apply(&host()).unwrap_err();
    assert!(err.to_string().contains("malformed"), "{err}");
    // Absence oracle: no write ever went over the wire.
    let wrote: Vec<String> = log
        .lock()
        .unwrap()
        .iter()
        .map(|(a, _)| joined(a))
        .filter(|c| c.contains("cat >"))
        .collect();
    assert_eq!(wrote, Vec::<String>::new());
}

#[test]
fn a_write_the_host_silently_lost_fails_the_keys_apply() {
    // The write "succeeds" but the readback still shows the old file: the
    // claim is about the host's state, and the host says no.
    let keys = Arc::new(Mutex::new(String::from("human@key A\n")));
    let k = Arc::clone(&keys);
    let responder: Responder = Box::new(move |argv, _stdin| {
        let cmd = argv.join(" ");
        if cmd.contains("cat >") {
            return Ok(CommandOutput::ok("")); // pretends to write; drops it
        }
        Ok(CommandOutput::ok(&k.lock().unwrap().clone()))
    });
    let (transport, _log) = Scripted::new(responder);
    let mut driver = AuthorizedKeysDriver::new(transport);
    let err = driver.apply(&host()).unwrap_err();
    assert!(err.to_string().contains("read back"), "{err}");
}

#[test]
fn an_absent_authorized_keys_file_reads_as_empty_and_gets_created() {
    let keys = Arc::new(Mutex::new(String::new()));
    let k = Arc::clone(&keys);
    let responder: Responder = Box::new(move |argv, stdin| {
        let cmd = argv.join(" ");
        if cmd.contains("cat >") {
            *k.lock().unwrap() = stdin.unwrap_or_default().to_string();
            return Ok(CommandOutput::ok(""));
        }
        Ok(CommandOutput::ok(&k.lock().unwrap().clone()))
    });
    let (transport, _log) = Scripted::new(responder);
    let mut driver = AuthorizedKeysDriver::new(transport);
    driver.apply(&host()).unwrap();
    let file = keys.lock().unwrap().clone();
    assert!(file.starts_with(FENCE_BEGIN));
}

// --- plumbing --------------------------------------------------------------

#[test]
fn the_become_prefix_precedes_every_remote_command_when_configured() {
    let mut h = host();
    h.ssh.as_mut().unwrap().become_cmd = Some("doas".into());
    let responder: Responder = Box::new(|argv, _| {
        Ok(CommandOutput::ok(if argv.join(" ").ends_with("sshd -T") {
            "permitrootlogin no\n"
        } else {
            ""
        }))
    });
    let (transport, log) = Scripted::new(responder);
    let mut driver = SshPostureDriver::new(transport);
    let _ = driver.verify(&h).unwrap();
    for (argv, _) in log.lock().unwrap().iter() {
        assert_eq!(argv[0], "doas", "{argv:?}");
    }
}

#[test]
fn shell_quoting_survives_spaces_and_embedded_quotes() {
    use crate::transport::shell_quote;
    assert_eq!(shell_quote("plain"), "'plain'");
    assert_eq!(shell_quote("with space"), "'with space'");
    assert_eq!(shell_quote("it's"), r#"'it'\''s'"#);
}
