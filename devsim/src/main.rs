//! The e2e device simulator: a pty-backed "cooperative device" running the
//! REAL `lychgate-embed` engine and the real `lychgate-wire` verifier — the
//! same code the reference firmware compiles — so the acceptance battery
//! exercises actual device logic, not a lookalike. Only the HAL is fake:
//! a scaled uptime clock (so TTL-expiry oracles run in seconds), a
//! file-backed seq store (so "reboot" keeps the anti-replay mark, exactly
//! like flash), and a gate that mirrors into a greppable state file.
//!
//! Nemesis moves arrive on a control FIFO:
//!   reboot          — new engine, fresh uptime epoch, same seq store (the
//!                     power-cycle: the grant dies, the mark survives)
//!   replay          — re-present the last accepted TOK line; the verdict
//!                     lands in state.json's last_result
//!   corrupt-replay  — same, with one signature character flipped
//!
//! Layout under --workdir:
//!   announce.json  {"pts": "...", "pid": N}   written LAST, the ready signal
//!   ctl            the nemesis FIFO
//!   state.json     {"state","grant_nonce","remaining_secs","uptime_ms",
//!                   "stored_seq","last_result","closed_reason"}
//!   seq.json       the durable mark (survives reboot on purpose)

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::Instant;

use lychgate_embed::{DeviceEngine, Gate, SeqStore, StoreError, TrustRoot, UptimeClock};
use lychgate_wire::line;
use lychgate_wire::line::FailState;

fn die(msg: &str) -> ! {
    eprintln!("lychgate-devsim: {msg}");
    std::process::exit(2);
}

fn unhex(s: &str, what: &str) -> Vec<u8> {
    if !s.len().is_multiple_of(2) {
        die(&format!("{what}: odd hex length"));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .unwrap_or_else(|_| die(&format!("{what}: not hex")))
        })
        .collect()
}

/// Uptime = real elapsed time × scale, so a 90s TTL expires in 3s of wall
/// time at --time-scale 30. Legitimate by design: a device clock's rate is
/// its own business (the crystal argument, docs/EMBEDDED.md §3).
struct ScaledClock {
    epoch: Instant,
    scale: u64,
}

impl UptimeClock for ScaledClock {
    fn uptime_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64 * self.scale
    }
}

/// The durable mark, in a file — "flash". Written through on every store.
struct FileSeq {
    path: std::path::PathBuf,
}

impl SeqStore for FileSeq {
    fn load(&mut self) -> Result<u64, StoreError> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => text.trim().parse().map_err(|_| StoreError),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(_) => Err(StoreError),
        }
    }

    fn store(&mut self, seq: u64) -> Result<(), StoreError> {
        std::fs::write(&self.path, seq.to_string()).map_err(|_| StoreError)
    }
}

/// The gate: a shared commanded flag, plus (in actuator mode) a modeled
/// LOAD line that follows the command unless the relay is stuck — the two
/// separate oracles the daemon's actuator matrix reads.
#[derive(Clone)]
struct FlagGate {
    commanded: std::rc::Rc<std::cell::Cell<bool>>,
    actuator: Option<ActuatorSim>,
}

#[derive(Clone)]
struct ActuatorSim {
    fail_state: FailState,
    load: std::rc::Rc<std::cell::Cell<bool>>,
    stuck: std::rc::Rc<std::cell::Cell<bool>>,
}

impl Gate for FlagGate {
    fn set_open(&mut self, open: bool) {
        self.commanded.set(open);
        if let Some(a) = &self.actuator {
            // A healthy relay follows the command; a stuck one holds.
            if !a.stuck.get() {
                a.load.set(open);
            }
        }
    }

    fn load(&self) -> Option<bool> {
        self.actuator.as_ref().map(|a| a.load.get())
    }

    fn fail_state(&self) -> Option<FailState> {
        self.actuator.as_ref().map(|a| a.fail_state)
    }
}

type Engine = DeviceEngine<ScaledClock, FileSeq, FlagGate>;

struct Args {
    pubkey: Vec<u8>,
    device_id: [u8; 16],
    workdir: std::path::PathBuf,
    scale: u64,
    actuator: Option<FailState>,
}

fn parse_args() -> Args {
    let mut pubkey = None;
    let mut device_id = None;
    let mut workdir = None;
    let mut scale = 1u64;
    let mut actuator = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut val = |name: &str| {
            it.next()
                .unwrap_or_else(|| die(&format!("--{name} needs a value")))
        };
        match a.as_str() {
            "--pubkey" => pubkey = Some(unhex(&val("pubkey"), "--pubkey")),
            "--device-id" => {
                let bytes = unhex(&val("device-id"), "--device-id");
                device_id = Some(
                    <[u8; 16]>::try_from(bytes.as_slice())
                        .unwrap_or_else(|_| die("--device-id: expected 16 bytes of hex")),
                )
            }
            "--workdir" => workdir = Some(std::path::PathBuf::from(val("workdir"))),
            "--time-scale" => {
                scale = val("time-scale")
                    .parse()
                    .unwrap_or_else(|_| die("--time-scale: not a number"))
            }
            "--actuator" => {
                actuator = Some(match val("actuator").as_str() {
                    "energized" => FailState::Energized,
                    "de-energized" => FailState::DeEnergized,
                    other => die(&format!("--actuator: unknown fail-state {other}")),
                })
            }
            other => die(&format!("unknown argument {other}")),
        }
    }
    Args {
        pubkey: pubkey.unwrap_or_else(|| die("missing --pubkey <hex>")),
        device_id: device_id.unwrap_or_else(|| die("missing --device-id <hex32>")),
        workdir: workdir.unwrap_or_else(|| die("missing --workdir <dir>")),
        scale: scale.max(1),
        actuator,
    }
}

fn trust_root(pubkey: &[u8]) -> TrustRoot {
    match pubkey.len() {
        32 => TrustRoot::Ed25519(pubkey.try_into().expect("length checked")),
        65 => TrustRoot::P256(pubkey.try_into().expect("length checked")),
        n => die(&format!(
            "--pubkey: expected 32 (ed25519) or 65 (uncompressed sec1) bytes, got {n}"
        )),
    }
}

fn open_pty() -> (std::fs::File, String) {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if master < 0 {
            die("posix_openpt failed");
        }
        if libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
            die("grantpt/unlockpt failed");
        }
        let name = libc::ptsname(master);
        if name.is_null() {
            die("ptsname failed");
        }
        let path = std::ffi::CStr::from_ptr(name)
            .to_string_lossy()
            .into_owned();
        // Nonblocking master: the main loop multiplexes pty + fifo by polling.
        let flags = libc::fcntl(master, libc::F_GETFL);
        libc::fcntl(master, libc::F_SETFL, flags | libc::O_NONBLOCK);
        (std::fs::File::from_raw_fd(master), path)
    }
}

fn open_fifo(path: &std::path::Path) -> std::fs::File {
    let cpath = std::ffi::CString::new(path.to_string_lossy().as_bytes()).expect("no NUL");
    unsafe {
        if libc::mkfifo(cpath.as_ptr(), 0o600) != 0 {
            die(&format!("mkfifo {} failed", path.display()));
        }
        // O_RDWR so the fifo never sees EOF between writers.
        let fd = libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK);
        if fd < 0 {
            die(&format!("opening fifo {} failed", path.display()));
        }
        std::fs::File::from_raw_fd(fd)
    }
}

struct Sim {
    engine: Engine,
    gate_flag: std::rc::Rc<std::cell::Cell<bool>>,
    actuator: Option<ActuatorSim>,
    args: Args,
    /// Mirrors the engine clock's epoch for the state file's uptime_ms.
    epoch: Instant,
    /// The last raw TOK line the daemon delivered — the replay ammunition.
    last_token_line: Option<String>,
    last_result: String,
}

impl Sim {
    fn fresh_engine(
        args: &Args,
        gate_flag: &std::rc::Rc<std::cell::Cell<bool>>,
        actuator: &Option<ActuatorSim>,
    ) -> Engine {
        // A power cycle drops the load line to the configured FAIL-STATE
        // before the engine (which then commands closed) exists — the boot
        // reality the daemon's reason=boot exception models.
        if let Some(a) = actuator {
            a.load.set(a.fail_state == FailState::Energized);
            // Hold the load at its fail-state through the constructor's
            // gate-close (a real relay only moves when DRIVEN, and at boot
            // nothing has driven it yet); unstuck right after.
            a.stuck.set(true);
        }
        let engine = DeviceEngine::new(
            args.device_id,
            trust_root(&args.pubkey),
            ScaledClock {
                epoch: Instant::now(),
                scale: args.scale,
            },
            FileSeq {
                path: args.workdir.join("seq.json"),
            },
            FlagGate {
                commanded: std::rc::Rc::clone(gate_flag),
                actuator: actuator.clone(),
            },
        );
        if let Some(a) = actuator {
            a.stuck.set(false);
        }
        engine
    }

    fn handle(&mut self, input: &str) -> String {
        if input.trim().is_empty() {
            return String::new();
        }
        let mut buf = [0u8; line::MAX_LINE_LEN];
        self.engine.handle_line(input, &mut buf).to_string()
    }

    /// A line arriving from the DAEMON (the pty side): genuine deliveries
    /// are the replay ammunition. Control-path re-presentations must NOT be
    /// re-recorded, or a corrupt-replay would poison the stash.
    fn handle_delivery(&mut self, input: &str) -> String {
        if let Some(rest) = input.trim_end().strip_prefix("TOK ") {
            self.last_token_line = Some(format!("TOK {rest}"));
        }
        self.handle(input)
    }

    fn control(&mut self, cmd: &str) {
        match cmd.trim() {
            "" => {}
            "reboot" => {
                // The power cycle: grant state dies with the engine, the seq
                // file survives, the uptime epoch resets, and the new engine
                // boots with the gate driven closed (an actuator's load line
                // boots to its fail-state).
                self.engine = Self::fresh_engine(&self.args, &self.gate_flag, &self.actuator);
                self.epoch = Instant::now();
                self.last_result = "rebooted".into();
            }
            "replay" => match self.last_token_line.clone() {
                Some(line) => {
                    let reply = self.handle(&line);
                    self.last_result = format!("replay -> {reply}");
                }
                None => self.last_result = "replay -> no token seen yet".into(),
            },
            "stick-relay on" => {
                if let Some(a) = &self.actuator {
                    a.stuck.set(true);
                    self.last_result = "relay stuck".into();
                } else {
                    self.last_result = "stick-relay: not an actuator".into();
                }
            }
            "stick-relay off" => {
                if let Some(a) = &self.actuator {
                    a.stuck.set(false);
                    // A freed relay snaps to the commanded state.
                    a.load.set(self.gate_flag.get());
                    self.last_result = "relay freed".into();
                }
            }
            "corrupt-replay" => match self.last_token_line.clone() {
                Some(mut line) => {
                    let last = line.pop().unwrap_or('A');
                    line.push(if last == 'A' { 'B' } else { 'A' });
                    let reply = self.handle(&line);
                    self.last_result = format!("corrupt-replay -> {reply}");
                }
                None => self.last_result = "corrupt-replay -> no token seen yet".into(),
            },
            other => self.last_result = format!("unknown control {other:?}"),
        }
    }

    fn write_state(&mut self) {
        // Rendered via the engine's own STAT so the file can never disagree
        // with what the daemon would be told.
        let mut buf = [0u8; line::MAX_LINE_LEN];
        let stat = self.engine.handle_line("STAT", &mut buf).to_string();
        let report = match line::parse_reply(&stat) {
            Ok(line::Reply::State(r)) => r,
            _ => return,
        };
        let doc = serde_json::json!({
            "state": if report.open.is_some() { "open" } else { "closed" },
            "grant_nonce": report.open.map(|(n, _)| n.iter().map(|b| format!("{b:02x}")).collect::<String>()),
            "remaining_secs": report.open.map(|(_, r)| r),
            "uptime_ms": self.uptime_ms(),
            "stored_seq": report.seq,
            "load": report.load,
            "last_result": self.last_result,
            "closed_reason": report.reason.map(|r| match r {
                line::CloseReason::Revert => "revert",
                line::CloseReason::Expiry => "expiry",
                line::CloseReason::Boot => "boot",
            }),
        });
        let tmp = self.args.workdir.join("state.json.tmp");
        if std::fs::write(&tmp, doc.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, self.args.workdir.join("state.json"));
        }
    }

    fn uptime_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64 * self.args.scale
    }
}

fn main() {
    let args = parse_args();
    std::fs::create_dir_all(&args.workdir).unwrap_or_else(|e| die(&format!("workdir: {e}")));

    let (mut master, pts) = open_pty();
    let mut ctl = open_fifo(&args.workdir.join("ctl"));

    let gate_flag = std::rc::Rc::new(std::cell::Cell::new(false));
    let actuator = args.actuator.map(|fail_state| ActuatorSim {
        fail_state,
        load: std::rc::Rc::new(std::cell::Cell::new(false)),
        stuck: std::rc::Rc::new(std::cell::Cell::new(false)),
    });
    let mut sim = Sim {
        engine: Sim::fresh_engine(&args, &gate_flag, &actuator),
        gate_flag: std::rc::Rc::clone(&gate_flag),
        actuator,
        args,
        epoch: Instant::now(),
        last_token_line: None,
        last_result: "boot".into(),
    };
    sim.write_state();

    // Announce LAST: the pts path appearing means everything is ready.
    let announce = serde_json::json!({ "pts": pts, "pid": std::process::id() });
    std::fs::write(sim.args.workdir.join("announce.json"), announce.to_string())
        .unwrap_or_else(|e| die(&format!("announce: {e}")));

    let mut pty_buf = String::new();
    let mut ctl_buf = String::new();
    let mut read_chunk = [0u8; 512];
    loop {
        sim.engine.tick();

        match master.read(&mut read_chunk) {
            Ok(0) => {}
            Ok(n) => pty_buf.push_str(&String::from_utf8_lossy(&read_chunk[..n])),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) if e.raw_os_error() == Some(libc::EIO) => {} // pts closed; keep serving
            Err(e) => die(&format!("pty read: {e}")),
        }
        while let Some(pos) = pty_buf.find('\n') {
            let input: String = pty_buf.drain(..=pos).collect();
            let reply = sim.handle_delivery(&input);
            if !reply.is_empty() {
                let _ = master.write_all(reply.as_bytes());
                let _ = master.write_all(b"\n");
            }
        }

        match ctl.read(&mut read_chunk) {
            Ok(0) => {}
            Ok(n) => ctl_buf.push_str(&String::from_utf8_lossy(&read_chunk[..n])),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => die(&format!("ctl read: {e}")),
        }
        while let Some(pos) = ctl_buf.find('\n') {
            let cmd: String = ctl_buf.drain(..=pos).collect();
            sim.control(&cmd);
        }

        sim.write_state();
        std::thread::sleep(std::time::Duration::from_millis(50));
        // Keep the raw fd alive for the loop (fcntl'd nonblocking above).
        let _ = master.as_raw_fd();
    }
}
