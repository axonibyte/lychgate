mod drivers;
mod journal;
mod lifecycle;
mod listener;
mod store;
mod transport;

#[cfg(test)]
mod scratch;

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::Context;
use clap::Parser;

use lychgate_core::{DriverSet, GrantRegistry, Inventory};

use crate::journal::{Event, Journal};
use crate::lifecycle::Daemon;
use crate::store::Store;

#[derive(Parser)]
#[command(name = "lychgated", version, about = "lychgate control-plane daemon")]
struct Cli {
    /// Path to the host inventory
    #[arg(long)]
    inventory: PathBuf,

    /// Directory holding grant state and the audit journal
    #[arg(long)]
    state_dir: PathBuf,

    /// Control socket path (default: <state-dir>/lychgated.sock)
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Seconds between passes. Zero is refused: a zero interval is a spin.
    #[arg(long, default_value_t = 10)]
    interval: u64,

    /// One pass, then exit, serving no requests. For cron and for tests
    /// driving the real binary.
    #[arg(long)]
    once: bool,

    /// Register no channel drivers: grants open and close as pure bookkeeping,
    /// touching no host. For validating an inventory, rehearsing the grant
    /// lifecycle, and the hermetic end-to-end tests — nothing is driven, so a
    /// grant's applied-channel set is always empty.
    #[arg(long)]
    dry_run: bool,
}

/// Set by the signal handler, read by the loops. SIGKILL-safety is not this
/// handler — it is the atomic state write plus per-line journal sync, proven
/// by the end-to-end battery.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    // Raw libc, no signal crates: the house pattern (reaper does the same
    // for its outbound signals), and storing one atomic flag is
    // async-signal-safe.
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Handlers go in before anything observable happens — the moment the
    // socket accepts, a SIGTERM must already shut down cleanly.
    install_signal_handlers();

    if cli.interval == 0 {
        anyhow::bail!("--interval 0 is refused: a zero interval is a spin, not a daemon");
    }

    let text = fs::read_to_string(&cli.inventory)
        .with_context(|| format!("reading {}", cli.inventory.display()))?;
    let inventory = Inventory::parse(&text)
        .with_context(|| format!("validating {}", cli.inventory.display()))?;

    let store = Store::at(cli.state_dir.join("grants.json"));
    store.probe_writable()?;
    // Boot refusals happen before the first journal line: a run that is
    // refused journals nothing.
    let doc = store.read()?;
    GrantRegistry::from_parts(&inventory, &doc)
        .with_context(|| format!("validating {}", store.path().display()))?;

    let socket_path = cli
        .socket
        .clone()
        .unwrap_or_else(|| cli.state_dir.join("lychgated.sock"));
    // --once serves no requests, so it must not fight a running daemon for
    // the socket; it is the cron shape, and cron passes coexist with a
    // daemon by design (the store lock serializes them).
    let listener = if cli.once {
        None
    } else {
        Some(listener::bind(&socket_path)?)
    };

    let mut journal = Journal::open(cli.state_dir.join("journal.jsonl"))?;
    journal.record(
        SystemTime::now(),
        &Event::DaemonStart {
            inventory: cli.inventory.display().to_string(),
            hosts: inventory.hosts.len(),
        },
    )?;

    // The ssh-borne and bmc channels are live. --dry-run registers nothing, so
    // every declared channel is bookkeeping-only and no host is touched.
    let mut driver_set = DriverSet::new();
    if !cli.dry_run {
        driver_set
            .register(drivers::ssh::SshPostureDriver::new(Box::new(
                transport::ExecSshTransport,
            )))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        driver_set
            .register(drivers::ssh::AuthorizedKeysDriver::new(Box::new(
                transport::ExecSshTransport,
            )))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        driver_set
            .register(drivers::bmc::BmcDriver::new(
                Box::new(drivers::bmc::CurlBmcTransport),
                Box::new(drivers::bmc::UrandomPasswords),
                Box::new(drivers::bmc::NoEscrow),
            ))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        driver_set
            .register(drivers::vnc::VncDriver::new(
                Box::new(drivers::vnc::ExecSshVncTransport),
                Box::new(drivers::vnc::UrandomVncPasswords),
                Box::new(drivers::tunnel::TunnelSet::new(Box::new(
                    drivers::tunnel::ExecTunnelSpawner,
                ))),
            ))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    let daemon = Arc::new(Daemon {
        inventory,
        store,
        journal: Mutex::new(journal),
        drivers: Mutex::new(driver_set),
        deadman: Mutex::new(drivers::deadman::ExecDeadman::new(Box::new(
            transport::ExecSshTransport,
        ))),
    });

    // Recover from a crash mid-open before serving anything.
    daemon.boot_recover(SystemTime::now())?;

    if cli.dry_run {
        println!(
            "lychgated: watching {} host(s) in --dry-run; no channel is driven, \
             grants open and close as bookkeeping only",
            daemon.inventory.hosts.len()
        );
    } else {
        println!(
            "lychgated: watching {} host(s); ssh, authorized-keys, bmc and vnc \
             channels are live",
            daemon.inventory.hosts.len()
        );
    }

    let listener_thread = listener.map(|listener| {
        let daemon = Arc::clone(&daemon);
        std::thread::spawn(move || listener::serve(&listener, &daemon, &SHUTDOWN))
    });

    let mut fatal: Option<anyhow::Error> = None;
    loop {
        daemon.pass(SystemTime::now())?;

        if cli.once {
            break;
        }
        // Sleep in slices so a shutdown signal is honored promptly rather
        // than after up to a full interval.
        let deadline = std::time::Instant::now() + Duration::from_secs(cli.interval);
        while std::time::Instant::now() < deadline {
            if SHUTDOWN.load(Ordering::SeqCst) {
                break;
            }
            // A listener that stopped without a shutdown request hit the
            // fatal path: stop the daemon with it.
            if listener_thread.as_ref().is_some_and(|h| h.is_finished()) {
                SHUTDOWN.store(true, Ordering::SeqCst);
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        if SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }
    }

    if let Some(handle) = listener_thread {
        SHUTDOWN.store(true, Ordering::SeqCst);
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => fatal = Some(e),
            Err(_) => fatal = Some(anyhow::anyhow!("listener thread panicked")),
        }
        let _ = fs::remove_file(&socket_path);
    }

    // Tear down any daemon-held resource (a vnc tunnel) without reverting: the
    // grant stays open on disk and its reachability is restored on the next
    // boot. Belt-and-suspenders alongside the child's parent-death signal.
    daemon
        .drivers
        .lock()
        .expect("drivers poisoned")
        .suspend_all();

    daemon
        .journal
        .lock()
        .expect("journal mutex poisoned")
        .record(SystemTime::now(), &Event::DaemonStop)?;
    println!("lychgated: stopping");
    match fatal {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
