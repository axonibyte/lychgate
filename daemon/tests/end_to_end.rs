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
        r#"{"version":2,"grants":{"db-01":{"state":"open","opened_at":1000,"expires_at":1600,"channels":[]}}}"#,
    );

    let out = run_once(&inv, &state_dir);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // State rewritten: the grant reverted to closed (absent), version intact.
    let doc = grants_doc(&state_dir);
    assert_eq!(doc["version"], 2);
    assert_eq!(doc["grants"], serde_json::json!({}));

    // Journal: the grant is observed expired (expire), then — with an empty
    // driver set, nothing to revert — closed in the same pass (close). Seq
    // counts from zero.
    let lines = journal_lines(&state_dir);
    let events: Vec<&str> = lines.iter().map(|l| l["event"].as_str().unwrap()).collect();
    assert_eq!(events, ["daemon-start", "expire", "close", "daemon-stop"]);
    let seqs: Vec<u64> = lines.iter().map(|l| l["seq"].as_u64().unwrap()).collect();
    assert_eq!(seqs, [0, 1, 2, 3]);
    let expire = &lines[1];
    assert_eq!(expire["host"], "db-01");
    // The stored grant recorded no applied channels (none were driven), so
    // that is what the expire event carries.
    assert_eq!(expire["channels"], serde_json::json!([]));
    assert_eq!(expire["opened_at"], 1000);
    assert_eq!(expire["expires_at"], 1600);
    assert_eq!(lines[2]["host"], "db-01");
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
        r#"{{"version":2,"grants":{{"db-01":{{"state":"open","opened_at":{opened_at},"expires_at":{expires_at},"channels":[]}}}}}}"#
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
    assert_eq!(doc["grants"]["db-01"]["opened_at"], opened_at);
    assert_eq!(doc["grants"]["db-01"]["expires_at"], expires_at);

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
    assert_eq!(doc["grants"]["db-01"]["opened_at"], opened_at);
    assert_eq!(doc["grants"]["db-01"]["expires_at"], expires_at);
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
    let state_dir = state_with(&dir, r#"{"version":99,"grants":{}}"#);

    let out = run_once(&inv, &state_dir);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Both versions named: the file's (99) and the one this binary speaks (2).
    assert!(stderr.contains("99") && stderr.contains('2'), "{stderr}");
}

#[test]
fn a_store_naming_a_host_absent_from_the_inventory_is_refused_and_journals_nothing() {
    let dir = Scratch::new("unknownhost");
    let inv = write_inventory(&dir);
    let state_dir = state_with(
        &dir,
        r#"{"version":2,"grants":{"ghost":{"state":"open","opened_at":1000,"expires_at":1600,"channels":[]}}}"#,
    );

    let out = run_once(&inv, &state_dir);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ghost"), "{stderr}");
    assert_eq!(journal_lines(&state_dir).len(), 0);
    // Fail-closed: the refusal must not have rewritten the state either.
    assert!(grants_doc(&state_dir)["grants"]["ghost"].is_object());
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

// --- M2: the control socket and the operator flow --------------------------

/// The lychgate CLI binary, which lives beside lychgated in the target dir.
/// Integration tests only guarantee same-package binaries, so build it if a
/// narrower test invocation (cargo test -p lychgated) has not.
fn lychgate_bin() -> PathBuf {
    let path = Path::new(env!("CARGO_BIN_EXE_lychgated")).with_file_name("lychgate");
    if !path.exists() {
        let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["build", "-p", "lychgate"])
            .status()
            .expect("spawn cargo build");
        assert!(status.success(), "building the lychgate CLI failed");
    }
    path
}

struct Daemon {
    child: std::process::Child,
    socket: PathBuf,
}

impl Daemon {
    fn start(inv: &Path, state_dir: &Path) -> Daemon {
        let socket = state_dir.join("lychgated.sock");
        let child = Command::new(env!("CARGO_BIN_EXE_lychgated"))
            .args(["--inventory"])
            .arg(inv)
            .arg("--state-dir")
            .arg(state_dir)
            .args(["--interval", "600"])
            .spawn()
            .expect("spawn lychgated");
        // Precondition asserted before anything else: the daemon is up and
        // its socket *accepts* — existence alone is not enough, because a
        // stale socket file from a prior daemon can already be present.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
                panic!("daemon never accepted on {}", socket.display());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Daemon { child, socket }
    }

    fn stop(mut self) {
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
        }
        let status = self.child.wait().unwrap();
        assert!(status.success(), "daemon did not stop cleanly");
    }
}

fn cli(socket: &Path, args: &[&str]) -> Output {
    Command::new(lychgate_bin())
        .arg("--socket")
        .arg(socket)
        .args(args)
        .output()
        .expect("spawn lychgate")
}

#[test]
fn the_operator_flow_works_end_to_end_through_both_binaries() {
    let dir = Scratch::new("operatorflow");
    let inv = write_inventory(&dir);
    let state_dir = dir.join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let daemon = Daemon::start(&inv, &state_dir);

    // Open for 4 hours.
    let out = cli(&daemon.socket, &["open", "--host", "db-01", "--ttl", "4h"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("grant open on db-01 until epoch"),
        "{stdout}"
    );

    // Status shows it open.
    let out = cli(&daemon.socket, &["status"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("db-01\topen"), "{stdout}");
    assert!(stdout.contains("web-02\tclosed"), "{stdout}");

    // Renewing with ~4h remaining is too early, refused in core's words,
    // verbatim through the wire.
    let out = cli(&daemon.socket, &["renew", "--host", "db-01", "--ttl", "4h"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("renewal refused with"), "{stderr}");

    // A second open is refused, not silently extended.
    let out = cli(&daemon.socket, &["open", "--host", "db-01", "--ttl", "1h"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already open"));

    // Unknown hosts are refused by name, daemon-side.
    let out = cli(&daemon.socket, &["open", "--host", "ghost", "--ttl", "1h"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("ghost"));

    // Close, then close again: idempotent, with the outcome named.
    let out = cli(&daemon.socket, &["close", "--host", "db-01"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("grant on db-01 closed"));
    let out = cli(&daemon.socket, &["close", "--host", "db-01"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("already closed"));

    daemon.stop();

    // The journal recorded every transition and nothing else: refusals and
    // status reads leave no line, and the already-closed close does not
    // either.
    let events: Vec<String> = journal_lines(&state_dir)
        .iter()
        .map(|l| l["event"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(events, ["daemon-start", "open", "close", "daemon-stop"]);
    let lines = journal_lines(&state_dir);
    let open = &lines[1];
    assert_eq!(open["host"], "db-01");
    assert_eq!(open["ttl_secs"], 4 * 3600);
    // No drivers yet: nothing was applied, but the declared channels are
    // recorded so the audit trail shows what a grant reaches for.
    assert_eq!(open["applied"], serde_json::json!([]));
    assert_eq!(
        open["declared"],
        serde_json::json!(["ssh", "authorized-keys"])
    );
    assert!(open["expires_at"].is_u64());
    assert_eq!(lines[2]["host"], "db-01");
}

#[test]
fn a_grant_near_expiry_can_be_renewed_and_the_renewal_is_journaled() {
    let dir = Scratch::new("renewflow");
    let inv = write_inventory(&dir);
    let state_dir = dir.join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let daemon = Daemon::start(&inv, &state_dir);

    // 90 seconds remaining is inside the 2-hour renewal window.
    let out = cli(&daemon.socket, &["open", "--host", "db-01", "--ttl", "90s"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = cli(&daemon.socket, &["renew", "--host", "db-01", "--ttl", "2h"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("renewed until epoch"));

    daemon.stop();
    let events: Vec<String> = journal_lines(&state_dir)
        .iter()
        .map(|l| l["event"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(events, ["daemon-start", "open", "renew", "daemon-stop"]);
}

#[test]
fn a_request_from_a_future_protocol_is_refused_over_the_socket() {
    use std::io::{BufRead, BufReader, Write};
    let dir = Scratch::new("futureproto");
    let inv = write_inventory(&dir);
    let state_dir = dir.join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let daemon = Daemon::start(&inv, &state_dir);

    let mut stream = std::os::unix::net::UnixStream::connect(&daemon.socket).unwrap();
    stream
        .write_all(b"{\"proto\":9,\"op\":\"status\",\"nonce\":\"zzz\"}\n")
        .unwrap();
    let mut reply = String::new();
    BufReader::new(&stream).read_line(&mut reply).unwrap();
    let v: serde_json::Value = serde_json::from_str(reply.trim()).unwrap();
    assert_eq!(v["result"], "refused");
    let err = v["error"].as_str().unwrap();
    assert!(err.contains("protocol 9") && err.contains('2'), "{err}");

    daemon.stop();
}

#[test]
fn an_oversized_request_is_refused_and_the_daemon_survives_it() {
    use std::io::{BufRead, BufReader, Write};
    let dir = Scratch::new("oversized");
    let inv = write_inventory(&dir);
    let state_dir = dir.join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let daemon = Daemon::start(&inv, &state_dir);

    let mut stream = std::os::unix::net::UnixStream::connect(&daemon.socket).unwrap();
    let big = format!("{{\"proto\":1,\"op\":\"{}\"}}\n", "x".repeat(80 * 1024));
    stream.write_all(big.as_bytes()).unwrap();
    let mut reply = String::new();
    BufReader::new(&stream).read_line(&mut reply).unwrap();
    let v: serde_json::Value = serde_json::from_str(reply.trim()).unwrap();
    assert_eq!(v["result"], "refused");
    assert!(v["error"].as_str().unwrap().contains("cap"));

    // Still alive: the precondition (refusal) came first, now the proof.
    let out = cli(&daemon.socket, &["status"]);
    assert!(out.status.success());
    daemon.stop();
}

#[test]
fn the_control_socket_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new("socketperms");
    let inv = write_inventory(&dir);
    let state_dir = dir.join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let daemon = Daemon::start(&inv, &state_dir);

    let mode = std::fs::metadata(&daemon.socket)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "socket mode {mode:o}, wanted 600");
    daemon.stop();
}

#[test]
fn a_second_daemon_is_refused_while_the_first_listens_and_a_stale_socket_is_not() {
    let dir = Scratch::new("singleton");
    let inv = write_inventory(&dir);
    let state_dir = dir.join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let daemon = Daemon::start(&inv, &state_dir);

    // Live socket: the second daemon must refuse to start.
    let out = Command::new(env!("CARGO_BIN_EXE_lychgated"))
        .args(["--inventory"])
        .arg(&inv)
        .arg("--state-dir")
        .arg(&state_dir)
        .args(["--interval", "600"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already listening"));

    // SIGKILL the first daemon so its socket file is left behind stale...
    let pid = daemon.child.id();
    let mut child = daemon.child;
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    child.wait().unwrap();
    assert!(
        daemon.socket.exists(),
        "SIGKILL should leave the socket file"
    );

    // ...and a fresh daemon replaces the stale socket rather than wedging.
    let replacement = Daemon::start(&inv, &state_dir);
    let out = cli(&replacement.socket, &["status"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    replacement.stop();
}

#[test]
fn the_cli_reports_a_missing_daemon_rather_than_hanging() {
    let dir = Scratch::new("nodaemon");
    let socket = dir.join("nothing-listens-here.sock");
    let out = cli(&socket, &["status"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("connecting to"));
}

#[test]
fn the_cli_enforces_ttl_policy_before_touching_the_socket() {
    let dir = Scratch::new("clittl");
    // No daemon anywhere near this socket: if the refusal is the cap error
    // and not a connection error, the client checked policy first.
    let socket = dir.join("nothing-listens-here.sock");
    let out = cli(&socket, &["open", "--host", "db-01", "--ttl", "25h"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cap"), "{stderr}");
    assert!(!stderr.contains("connecting to"), "{stderr}");
}
