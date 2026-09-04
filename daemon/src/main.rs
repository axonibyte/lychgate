mod journal;
mod listener;
mod store;

#[cfg(test)]
mod scratch;

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use clap::Parser;

use lychgate_core::{Channel, GrantRegistry, GrantStatus, Inventory, OpenGrant};

use crate::journal::{Event, Journal};
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

pub(crate) fn epoch_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn channels_of(inventory: &Inventory, host: &str) -> Vec<Channel> {
    inventory
        .hosts
        .iter()
        .find(|h| h.name == host)
        .map(|h| h.channels.clone())
        .unwrap_or_default()
}

/// One pass: reap observed expiries under the store lock, then journal them.
/// The journal write comes after the state commit on purpose — see the
/// journal module docs for what that ordering does and does not promise.
fn pass(inventory: &Inventory, store: &Store, journal: &Mutex<Journal>) -> anyhow::Result<()> {
    let now = SystemTime::now();
    let (expired, statuses) = store.mutate(|doc| {
        let before = doc.open_grants.clone();
        let mut registry = GrantRegistry::from_parts(inventory, doc)
            .with_context(|| format!("validating {}", store.path().display()))?;
        let reaped = registry.reap(now);
        let expired: Vec<(String, OpenGrant)> = reaped
            .into_iter()
            .map(|host| {
                let interval = before[&host];
                (host, interval)
            })
            .collect();
        let statuses: Vec<(String, GrantStatus)> = registry
            .statuses(now)
            .into_iter()
            .map(|(h, s)| (h.to_string(), s))
            .collect();
        *doc = registry.snapshot();
        Ok((expired, statuses))
    })?;

    for (host, interval) in &expired {
        // A journal that cannot record is fatal: accruing unrecorded
        // transitions would defeat the audit record.
        journal.lock().expect("journal mutex poisoned").record(
            now,
            &Event::Expire {
                host: host.clone(),
                channels: channels_of(inventory, host),
                opened_at: epoch_secs(interval.opened_at),
                expires_at: epoch_secs(interval.expires_at),
            },
        )?;
        println!(
            "lychgated: grant for {host} expired; bookkeeping closed — \
             no drivers yet, nothing was reverted on the host"
        );
    }

    for (host, status) in &statuses {
        match status {
            GrantStatus::Closed => println!("lychgated: {host} closed"),
            GrantStatus::Open { remaining } => {
                println!("lychgated: {host} open, {}s remaining", remaining.as_secs())
            }
            // reap() ran in the same locked mutation, so nothing can still be
            // observed expired here at the same `now`.
            GrantStatus::Expired => println!("lychgated: {host} expired, reap pending"),
        }
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Handlers go in before anything observable happens — the moment the
    // socket accepts, a SIGTERM must already shut down cleanly. Installing
    // them after the bind left a window (widened by the journal's fsync)
    // where a prompt SIGTERM killed the daemon with default disposition;
    // the FreeBSD guest's e2e run caught it.
    install_signal_handlers();

    if cli.interval == 0 {
        anyhow::bail!("--interval 0 is refused: a zero interval is a spin, not a daemon");
    }

    let text = fs::read_to_string(&cli.inventory)
        .with_context(|| format!("reading {}", cli.inventory.display()))?;
    let inventory = Arc::new(
        Inventory::parse(&text)
            .with_context(|| format!("validating {}", cli.inventory.display()))?,
    );

    let store = Arc::new(Store::at(cli.state_dir.join("grants.json")));
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

    let journal = Arc::new(Mutex::new(Journal::open(
        cli.state_dir.join("journal.jsonl"),
    )?));
    journal.lock().expect("journal mutex poisoned").record(
        SystemTime::now(),
        &Event::DaemonStart {
            inventory: cli.inventory.display().to_string(),
            hosts: inventory.hosts.len(),
        },
    )?;

    println!(
        "lychgated: watching {} host(s); grants can be opened over the \
         control socket, but no drivers exist yet — an open grant changes \
         bookkeeping and journal, not any host",
        inventory.hosts.len()
    );

    let listener_thread = listener.map(|listener| {
        let inventory = Arc::clone(&inventory);
        let store = Arc::clone(&store);
        let journal = Arc::clone(&journal);
        std::thread::spawn(move || {
            listener::serve(&listener, &inventory, &store, &journal, &SHUTDOWN)
        })
    });

    let mut fatal: Option<anyhow::Error> = None;
    loop {
        pass(&inventory, &store, &journal)?;

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
            // fatal path (journal failure): stop the daemon with it.
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

    journal
        .lock()
        .expect("journal mutex poisoned")
        .record(SystemTime::now(), &Event::DaemonStop)?;
    println!("lychgated: stopping");
    match fatal {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
