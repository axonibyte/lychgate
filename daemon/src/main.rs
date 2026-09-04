mod journal;
mod store;

#[cfg(test)]
mod scratch;

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
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

    /// Seconds between passes. Zero is refused: a zero interval is a spin.
    #[arg(long, default_value_t = 10)]
    interval: u64,

    /// One pass, then exit. For cron and for tests driving the real binary.
    #[arg(long)]
    once: bool,
}

/// Set by the signal handler, read by the loop. SIGKILL-safety is not this
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

fn epoch_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn channels_of(inventory: &Inventory, host: &str) -> Vec<Channel> {
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
fn pass(inventory: &Inventory, store: &Store, journal: &mut Journal) -> anyhow::Result<()> {
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
        journal.record(
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

    let mut journal = Journal::open(cli.state_dir.join("journal.jsonl"))?;
    journal.record(
        SystemTime::now(),
        &Event::DaemonStart {
            inventory: cli.inventory.display().to_string(),
            hosts: inventory.hosts.len(),
        },
    )?;
    install_signal_handlers();

    println!(
        "lychgated: watching {} host(s); no transport and no drivers yet — \
         this process journals observed expiries and nothing more",
        inventory.hosts.len()
    );

    loop {
        pass(&inventory, &store, &mut journal)?;

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
            std::thread::sleep(Duration::from_millis(250));
        }
        if SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }
    }

    journal.record(SystemTime::now(), &Event::DaemonStop)?;
    println!("lychgated: stopping");
    Ok(())
}
