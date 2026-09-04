//! End-to-end battery: the real lychgated binary as a subprocess.
//!
//! These are the M1 acceptance tests. What they do NOT prove: no access is
//! opened or reverted anywhere — "expired" here changes a JSON file and a
//! journal line, not sshd. See TESTING.md.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// A temporary directory that removes itself, however the test ends. (Same
/// shape as the crate-internal scratch module; integration tests compile as
/// their own crate, so the guard is duplicated here deliberately.)
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Scratch {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "lychgated-e2e-test-{}-{}-{label}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }
}

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const INVENTORY: &str = r#"
[[hosts]]
name = "db-01"
address = "10.0.4.11"
os = "freebsd"
channels = ["ssh", "authorized-keys"]

[[hosts]]
name = "web-02"
address = "10.0.4.12"
os = "linux"
channels = ["vnc"]
"#;

fn write_inventory(dir: &Path) -> PathBuf {
    let path = dir.join("inventory.toml");
    std::fs::write(&path, INVENTORY).unwrap();
    path
}

fn state_with(dir: &Path, body: &str) -> PathBuf {
    let state_dir = dir.join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("grants.json"), body).unwrap();
    state_dir
}

fn run_once(inventory: &Path, state_dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lychgated"))
        .args(["--inventory"])
        .arg(inventory)
        .arg("--state-dir")
        .arg(state_dir)
        .arg("--once")
        .output()
        .expect("spawn lychgated")
}

fn journal_lines(state_dir: &Path) -> Vec<serde_json::Value> {
    let path = state_dir.join("journal.jsonl");
    if !path.exists() {
        return Vec::new();
    }
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("journal line parses"))
        .collect()
}

fn grants_doc(state_dir: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(state_dir.join("grants.json")).unwrap()).unwrap()
}

#[test]
fn a_single_pass_reaps_an_expired_grant_and_journals_it_before_exiting() {
    let dir = Scratch::new("reap");
    let inv = write_inventory(&dir);
    // Opened at epoch second 1000, expired at 1600: long past by any real
    // clock this test runs under.
    let state_dir = state_with(
        &dir,
        r#"{"version":1,"open_grants":{"db-01":{"opened_at":1000,"expires_at":1600}}}"#,
    );

    let out = run_once(&inv, &state_dir);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // State rewritten: the grant is closed (absent), the version intact.
    let doc = grants_doc(&state_dir);
    assert_eq!(doc["version"], 1);
    assert_eq!(doc["open_grants"], serde_json::json!({}));

    // Journal: start, expire (with the interval and the host's channels),
    // stop — seq counting from zero.
    let lines = journal_lines(&state_dir);
    let events: Vec<&str> = lines.iter().map(|l| l["event"].as_str().unwrap()).collect();
    assert_eq!(events, ["daemon-start", "expire", "daemon-stop"]);
    let seqs: Vec<u64> = lines.iter().map(|l| l["seq"].as_u64().unwrap()).collect();
    assert_eq!(seqs, [0, 1, 2]);
    let expire = &lines[1];
    assert_eq!(expire["host"], "db-01");
    assert_eq!(
        expire["channels"],
        serde_json::json!(["ssh", "authorized-keys"])
    );
    assert_eq!(expire["opened_at"], 1000);
    assert_eq!(expire["expires_at"], 1600);

    // The operator is told the truth about what "expired" means today.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("nothing was reverted"), "{stdout}");
}

#[test]
fn a_kill_and_restart_observes_the_same_truth() {
    let dir = Scratch::new("killrestart");
    let inv = write_inventory(&dir);
    // A legal open interval (2h span, well under the cap) expiring an hour
    // from now, so no pass may reap it while the test runs.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (opened_at, expires_at) = (now - 3_600, now + 3_600);
    let future = format!(
        r#"{{"version":1,"open_grants":{{"db-01":{{"opened_at":{opened_at},"expires_at":{expires_at}}}}}}}"#
    );
    let state_dir = state_with(&dir, &future);

    // Pass 1: the open grant must come through byte-identical (a pass must
    // never re-anchor an open grant it merely observed).
    let out = run_once(&inv, &state_dir);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc = grants_doc(&state_dir);
    assert_eq!(doc["open_grants"]["db-01"]["opened_at"], opened_at);
    assert_eq!(doc["open_grants"]["db-01"]["expires_at"], expires_at);

    // Kill a running daemon mid-flight (SIGKILL: no handler, no cleanup)...
    let mut child = Command::new(env!("CARGO_BIN_EXE_lychgated"))
        .args(["--inventory"])
        .arg(&inv)
        .arg("--state-dir")
        .arg(&state_dir)
        .args(["--interval", "1"])
        .spawn()
        .expect("spawn lychgated");
    std::thread::sleep(Duration::from_millis(500));
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGKILL);
    }
    child.wait().unwrap();

    // ...and the restart observes the same truth: same interval, store
    // readable, no refusal.
    let out = run_once(&inv, &state_dir);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc = grants_doc(&state_dir);
    assert_eq!(doc["open_grants"]["db-01"]["opened_at"], opened_at);
    assert_eq!(doc["open_grants"]["db-01"]["expires_at"], expires_at);
}

#[test]
fn a_hand_corrupted_store_is_a_refusal_naming_the_file() {
    let dir = Scratch::new("corrupt");
    let inv = write_inventory(&dir);
    let state_dir = state_with(&dir, "{ this is not json");

    let out = run_once(&inv, &state_dir);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("grants.json"), "{stderr}");
    assert!(stderr.contains("unreadable"), "{stderr}");
    // Refusals journal nothing.
    assert_eq!(journal_lines(&state_dir).len(), 0);
}

#[test]
fn a_store_from_a_newer_version_is_refused_quoting_both_versions() {
    let dir = Scratch::new("newer");
    let inv = write_inventory(&dir);
    let state_dir = state_with(&dir, r#"{"version":99,"open_grants":{}}"#);

    let out = run_once(&inv, &state_dir);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("99") && stderr.contains('1'), "{stderr}");
}

#[test]
fn a_store_naming_a_host_absent_from_the_inventory_is_refused_and_journals_nothing() {
    let dir = Scratch::new("unknownhost");
    let inv = write_inventory(&dir);
    let state_dir = state_with(
        &dir,
        r#"{"version":1,"open_grants":{"ghost":{"opened_at":1000,"expires_at":1600}}}"#,
    );

    let out = run_once(&inv, &state_dir);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ghost"), "{stderr}");
    assert_eq!(journal_lines(&state_dir).len(), 0);
    // Fail-closed: the refusal must not have rewritten the state either.
    assert!(grants_doc(&state_dir)["open_grants"]["ghost"].is_object());
}

#[test]
fn an_absent_store_is_a_fresh_start_not_an_error() {
    let dir = Scratch::new("fresh");
    let inv = write_inventory(&dir);
    let state_dir = dir.join("state");
    std::fs::create_dir_all(&state_dir).unwrap();

    let out = run_once(&inv, &state_dir);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let events: Vec<String> = journal_lines(&state_dir)
        .iter()
        .map(|l| l["event"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(events, ["daemon-start", "daemon-stop"]);
}

#[test]
fn a_zero_interval_is_refused() {
    let dir = Scratch::new("zerointerval");
    let inv = write_inventory(&dir);
    let state_dir = dir.join("state");
    std::fs::create_dir_all(&state_dir).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_lychgated"))
        .args(["--inventory"])
        .arg(&inv)
        .arg("--state-dir")
        .arg(&state_dir)
        .args(["--interval", "0"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("spin"));
    // Refused before any journal line.
    assert_eq!(journal_lines(&state_dir).len(), 0);
}

#[test]
fn sigterm_ends_the_loop_with_a_daemon_stop_entry() {
    let dir = Scratch::new("sigterm");
    let inv = write_inventory(&dir);
    let state_dir = dir.join("state");
    std::fs::create_dir_all(&state_dir).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_lychgated"))
        .args(["--inventory"])
        .arg(&inv)
        .arg("--state-dir")
        .arg(&state_dir)
        .args(["--interval", "600"])
        .spawn()
        .expect("spawn lychgated");
    // Let it get through boot and the first pass. Assert the precondition
    // (it journaled its start) before asserting anything about the stop.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while journal_lines(&state_dir).is_empty() {
        assert!(std::time::Instant::now() < deadline, "daemon never started");
        std::thread::sleep(Duration::from_millis(100));
    }

    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let status = child.wait().unwrap();
    assert!(status.success(), "SIGTERM must end the loop cleanly");

    let lines = journal_lines(&state_dir);
    let last = lines.last().expect("journal has entries");
    assert_eq!(last["event"], "daemon-stop");
}
