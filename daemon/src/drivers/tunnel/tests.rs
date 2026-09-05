use super::*;

use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use lychgate_core::Inventory;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn vnc_host(local_port: u16) -> Host {
    Inventory::parse(&format!(
        r#"
[[hosts]]
name = "hv"
address = "127.0.0.1"
os = "freebsd"
channels = ["vnc"]

[hosts.vnc]
agent_user = "lychgate"
rfb_port = 5900
local_port = {local_port}
target = "vm"
set_password_cmd = "set {{target}} {{password_file}}"
clear_password_cmd = "clear {{target}}"
"#
    ))
    .unwrap()
    .hosts
    .remove(0)
}

enum Mode {
    /// Bind a real socket on the spec's port — a forward that comes up.
    Listen,
    /// Alive, but never binds the port — a forward that never comes up.
    DontListen,
    /// Spawn itself fails.
    FailSpawn,
}

/// A spawner whose "tunnel" is a real local socket, so `TunnelSet`'s port
/// probes see reality. The `alive` flag is shared with the handle so a test
/// can flip it to model a child that died on its own.
struct FakeSpawner {
    mode: Mode,
    alive: Arc<AtomicBool>,
}

impl FakeSpawner {
    fn new(mode: Mode) -> (Box<FakeSpawner>, Arc<AtomicBool>) {
        let alive = Arc::new(AtomicBool::new(true));
        (
            Box::new(FakeSpawner {
                mode,
                alive: Arc::clone(&alive),
            }),
            alive,
        )
    }
}

struct FakeHandle {
    listener: Option<TcpListener>,
    alive: Arc<AtomicBool>,
}

impl TunnelHandle for FakeHandle {
    fn is_alive(&mut self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
    fn stop(&mut self) -> Result<(), DriverError> {
        self.listener = None;
        self.alive.store(false, Ordering::SeqCst);
        Ok(())
    }
}

impl TunnelSpawner for FakeSpawner {
    fn spawn(&mut self, spec: &TunnelSpec) -> Result<Box<dyn TunnelHandle>, DriverError> {
        match self.mode {
            Mode::FailSpawn => Err(DriverError("scripted spawn failure".into())),
            Mode::Listen => {
                let listener = TcpListener::bind(("127.0.0.1", spec.local_port))
                    .map_err(|e| DriverError(format!("fake bind: {e}")))?;
                Ok(Box::new(FakeHandle {
                    listener: Some(listener),
                    alive: Arc::clone(&self.alive),
                }))
            }
            Mode::DontListen => Ok(Box::new(FakeHandle {
                listener: None,
                alive: Arc::clone(&self.alive),
            })),
        }
    }
}

fn short(spawner: Box<dyn TunnelSpawner>) -> TunnelSet {
    // A tight probe so the "never comes up" test does not wait the full
    // production budget.
    TunnelSet::with_probe(spawner, 5, Duration::from_millis(50))
}

#[test]
fn up_brings_the_forward_up_and_down_tears_it_down() {
    let port = free_port();
    let (spawner, _alive) = FakeSpawner::new(Mode::Listen);
    let mut ts = short(spawner);
    let host = vnc_host(port);

    ts.up(&host).unwrap();
    assert!(ts.listening(&host).unwrap(), "the forward should be up");
    assert!(port_open(port), "the port should accept");

    ts.down(&host).unwrap();
    assert!(!ts.listening(&host).unwrap(), "the forward should be down");
    assert!(!port_open(port), "the port should be closed");
}

#[test]
fn down_is_idempotent() {
    let port = free_port();
    let (spawner, _alive) = FakeSpawner::new(Mode::Listen);
    let mut ts = short(spawner);
    let host = vnc_host(port);
    ts.up(&host).unwrap();
    ts.down(&host).unwrap();
    // A second down on an already-torn-down host succeeds and stays quiet.
    ts.down(&host).unwrap();
}

#[test]
fn down_of_a_never_opened_host_succeeds() {
    let port = free_port();
    let (spawner, _alive) = FakeSpawner::new(Mode::Listen);
    let mut ts = short(spawner);
    // Never brought up: revert must still be a clean no-op (idempotence).
    ts.down(&vnc_host(port)).unwrap();
}

#[test]
fn up_fails_and_retains_nothing_when_the_forward_never_listens() {
    let port = free_port();
    let (spawner, _alive) = FakeSpawner::new(Mode::DontListen);
    let mut ts = short(spawner);
    let host = vnc_host(port);

    let err = ts.up(&host).unwrap_err();
    assert!(err.to_string().contains("did not come up"), "{err}");
    // Atomic-or-reported: nothing retained, the port is untouched.
    assert!(!ts.listening(&host).unwrap());
    assert!(!port_open(port));
}

#[test]
fn up_propagates_a_spawn_failure() {
    let port = free_port();
    let (spawner, _alive) = FakeSpawner::new(Mode::FailSpawn);
    let mut ts = short(spawner);
    let err = ts.up(&vnc_host(port)).unwrap_err();
    assert!(err.to_string().contains("scripted spawn failure"), "{err}");
}

#[test]
fn a_child_that_died_on_its_own_reads_as_not_listening() {
    let port = free_port();
    let (spawner, alive) = FakeSpawner::new(Mode::Listen);
    let mut ts = short(spawner);
    let host = vnc_host(port);
    ts.up(&host).unwrap();
    assert!(ts.listening(&host).unwrap());

    // The child dies out from under us: listening keys on is_alive, so it goes
    // false even though the (leaked) socket might momentarily linger.
    alive.store(false, Ordering::SeqCst);
    assert!(!ts.listening(&host).unwrap());
}

#[test]
fn down_reports_a_stray_still_holding_the_port_rather_than_killing_it() {
    // Models a boot orphan: a forward on the fixed port that this TunnelSet
    // does not own. down must not silently succeed (fail-open), nor kill an
    // arbitrary process by port — it reports the port stuck.
    let port = free_port();
    let _squatter = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let (spawner, _alive) = FakeSpawner::new(Mode::Listen);
    let mut ts = short(spawner);

    let err = ts.down(&vnc_host(port)).unwrap_err();
    assert!(err.to_string().contains("still bound"), "{err}");
}
