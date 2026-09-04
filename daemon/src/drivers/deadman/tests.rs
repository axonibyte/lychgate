use super::*;
use crate::transport::{CommandOutput, SshTransport};

use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use lychgate_core::Inventory;

const INVENTORY: &str = r#"
[[hosts]]
name = "db-01"
address = "10.0.4.11"
os = "freebsd"
channels = ["ssh", "authorized-keys"]

[hosts.ssh]
agent_user = "root"
root_posture_default = "no"
root_posture_emergency = "yes"
emergency_keys = ["ssh-ed25519 EMERG breakglass"]
"#;

fn host() -> Host {
    Inventory::parse(INVENTORY).unwrap().hosts.remove(0)
}

fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// A remote host simulated for the dead-man: files and a crontab.
struct FakeTarget {
    files: Arc<Mutex<std::collections::BTreeMap<String, String>>>,
    crontab: Arc<Mutex<String>>,
}

impl FakeTarget {
    fn new(crontab: &str) -> (Box<Scripted>, FakeTarget) {
        let files = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
        let crontab = Arc::new(Mutex::new(crontab.to_string()));
        let f = Arc::clone(&files);
        let c = Arc::clone(&crontab);
        let transport = Box::new(Scripted {
            respond: Box::new(move |argv: &[String], stdin: Option<&str>| {
                let cmd = argv.join(" ");
                if cmd == "crontab -" {
                    *c.lock().unwrap() = stdin.unwrap_or_default().to_string();
                    return Ok(CommandOutput::ok(""));
                }
                if cmd.contains("crontab -l") {
                    return Ok(CommandOutput::ok(&c.lock().unwrap().clone()));
                }
                if cmd.contains("cat >") {
                    let path = cmd.split('\'').nth(1).unwrap_or_default().to_string();
                    f.lock()
                        .unwrap()
                        .insert(path, stdin.unwrap_or_default().to_string());
                    return Ok(CommandOutput::ok(""));
                }
                if cmd.contains("if test -f") && cmd.contains("cat") {
                    let path = cmd.split('\'').nth(1).unwrap_or_default();
                    let files = f.lock().unwrap();
                    return Ok(CommandOutput::ok(
                        files.get(path).map(String::as_str).unwrap_or(""),
                    ));
                }
                if cmd.contains("echo fired") {
                    let mut files = f.lock().unwrap();
                    let fired = files.remove(FIRED_PATH).is_some();
                    files.remove(SCRIPT_PATH);
                    files.remove(DEADLINE_PATH);
                    return Ok(CommandOutput::ok(if fired { "fired\n" } else { "" }));
                }
                Err(DriverError(format!("unexpected command: {cmd}")))
            }),
        });
        (transport, FakeTarget { files, crontab })
    }
}

type Responder =
    Box<dyn FnMut(&[String], Option<&str>) -> Result<CommandOutput, DriverError> + Send>;

struct Scripted {
    respond: Responder,
}

impl SshTransport for Scripted {
    fn run(
        &mut self,
        _host: &Host,
        argv: &[String],
        stdin: Option<&str>,
    ) -> Result<CommandOutput, DriverError> {
        (self.respond)(argv, stdin)
    }
}

#[test]
fn install_lands_the_script_deadline_and_schedule_preserving_the_crontab() {
    let (transport, target) = FakeTarget::new("0 3 * * * backup\n");
    let mut deadman = ExecDeadman { transport };
    deadman.install(&host(), t(1_700_000_000)).unwrap();

    let files = target.files.lock().unwrap();
    assert!(files[SCRIPT_PATH].contains("dead-man backstop"));
    assert_eq!(files[DEADLINE_PATH], "1700000000\n");
    let crontab = target.crontab.lock().unwrap();
    assert!(crontab.starts_with("0 3 * * * backup\n"), "{crontab}");
    assert!(crontab.contains(CRON_MARKER));
}

#[test]
fn install_rewrites_a_stale_deadline() {
    let (transport, target) = FakeTarget::new("");
    let files = Arc::clone(&target.files);
    let mut deadman = ExecDeadman { transport };
    deadman.install(&host(), t(1_700_000_000)).unwrap();
    files
        .lock()
        .unwrap()
        .insert(DEADLINE_PATH.to_string(), "stale\n".to_string());
    deadman.install(&host(), t(1_700_000_555)).unwrap();
    assert_eq!(files.lock().unwrap()[DEADLINE_PATH], "1700000555\n");
}

#[test]
fn install_fails_when_the_schedule_does_not_land() {
    // A target whose crontab writes vanish: the verify must refuse.
    let transport = Box::new(Scripted {
        respond: Box::new(|argv: &[String], stdin: Option<&str>| {
            let cmd = argv.join(" ");
            let _ = stdin;
            if cmd.contains("crontab -l") {
                return Ok(CommandOutput::ok("")); // writes never stick
            }
            Ok(CommandOutput::ok(""))
        }),
    });
    let mut deadman = ExecDeadman { transport };
    let err = deadman.install(&host(), t(1_000)).unwrap_err();
    assert!(err.to_string().contains("did not land"), "{err}");
}

#[test]
fn reschedule_moves_the_deadline_and_keeps_one_schedule_line() {
    let (transport, target) = FakeTarget::new("");
    let mut deadman = ExecDeadman { transport };
    deadman.install(&host(), t(1_000)).unwrap();
    deadman.reschedule(&host(), t(9_000)).unwrap();
    assert_eq!(target.files.lock().unwrap()[DEADLINE_PATH], "9000\n");
    assert_eq!(
        target.crontab.lock().unwrap().matches(CRON_MARKER).count(),
        1
    );
}

#[test]
fn remove_clears_everything_and_reports_an_unfired_backstop() {
    let (transport, target) = FakeTarget::new("0 1 * * * job\n");
    let mut deadman = ExecDeadman { transport };
    deadman.install(&host(), t(1_000)).unwrap();
    let fired = deadman.remove(&host()).unwrap();
    assert!(!fired);
    let files = target.files.lock().unwrap();
    assert!(!files.contains_key(SCRIPT_PATH));
    assert!(!files.contains_key(DEADLINE_PATH));
    let crontab = target.crontab.lock().unwrap();
    assert_eq!(*crontab, "0 1 * * * job\n", "human entries must survive");
}

#[test]
fn remove_reports_and_clears_a_fired_backstop() {
    let (transport, target) = FakeTarget::new("");
    target
        .files
        .lock()
        .unwrap()
        .insert(FIRED_PATH.to_string(), String::new());
    let mut deadman = ExecDeadman { transport };
    let fired = deadman.remove(&host()).unwrap();
    assert!(fired, "the fired marker must be reported");
    assert!(!target.files.lock().unwrap().contains_key(FIRED_PATH));
}
