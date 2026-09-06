mod drivers;
mod fido2_counters;
mod journal;
mod lifecycle;
mod listener;
mod lockfile;
mod store;
mod totp_ledger;
mod transport;

#[cfg(test)]
mod scratch;
#[cfg(test)]
mod sim;

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::Context;
use clap::Parser;

use lychgate_core::{DriverSet, GrantRegistry, Inventory, MAX_APPROVAL_WINDOW_SECS};

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

    /// The MCP front-door socket. When set, the daemon binds a SECOND socket for
    /// the lychgate-mcp server; ops arriving there are gated per profile (only
    /// `mcp = true` profiles may be opened/approved). Off by default — no MCP
    /// surface exists unless this is given (fail-closed).
    #[arg(long)]
    mcp_socket: Option<PathBuf>,

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
    /// grant's applied-channel set is always empty. Also approves grants
    /// without a real token (there is nothing to protect).
    #[arg(long)]
    dry_run: bool,

    /// Seconds an unapproved request may sit pending before it lapses,
    /// fail-closed. Zero is refused; capped at the approval-window ceiling.
    #[arg(long, default_value_t = 300)]
    approval_window: u64,

    /// Treat every configured secret file (TOTP secrets, password hashes) as a
    /// TPM-sealed blob (made by `lychgate tpm-seal`) and unseal it via this
    /// TCTI at startup, e.g. device:/dev/tpm0. Requires a `tpm-seal` feature
    /// build and a working TPM 2.0 — fail-closed: configured but unusable
    /// refuses the start. Run `lychgate tpm-probe` first.
    #[arg(long, value_name = "TCTI")]
    tpm_unseal: Option<String>,
}

/// How startup secret files are read: plaintext, or unsealed through the TPM.
/// One seam so the TOTP and password loaders cannot diverge.
enum SecretReader {
    Plain,
    #[cfg(feature = "tpm-seal")]
    TpmUnseal(lychgate_tpm::Context),
}

impl SecretReader {
    /// Build from --tpm-unseal. Fail-closed both ways: the flag without the
    /// feature is a refusal (not silently plaintext), and the flag with an
    /// unreachable TPM refuses the start naming the TCTI problem.
    fn new(tpm_unseal: Option<&str>) -> anyhow::Result<SecretReader> {
        match tpm_unseal {
            None => Ok(SecretReader::Plain),
            #[cfg(feature = "tpm-seal")]
            Some(tcti) => Ok(SecretReader::TpmUnseal(lychgate_tpm::context(tcti)?)),
            #[cfg(not(feature = "tpm-seal"))]
            Some(_) => anyhow::bail!(
                "--tpm-unseal requires a build with the tpm-seal feature \
                 (or tpm-seal-bindgen on FreeBSD); this build has no TPM support"
            ),
        }
    }

    fn read(&mut self, path: &str, what: &str) -> anyhow::Result<String> {
        let text = fs::read_to_string(path).with_context(|| format!("reading {what} {path}"))?;
        match self {
            SecretReader::Plain => Ok(text),
            #[cfg(feature = "tpm-seal")]
            SecretReader::TpmUnseal(ctx) => {
                let blob = lychgate_tpm::blob_from_str(&text)
                    .with_context(|| format!("{path} is not a sealed blob ({what})"))?;
                let bytes = lychgate_tpm::unseal(ctx, &blob)
                    .with_context(|| format!("unsealing {what} {path}"))?;
                String::from_utf8(bytes)
                    .map_err(|_| anyhow::anyhow!("{what} {path} unsealed to non-UTF-8 bytes"))
            }
        }
    }
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
    if cli.approval_window == 0 {
        anyhow::bail!("--approval-window 0 is refused: a request could never be approved");
    }
    if cli.approval_window > MAX_APPROVAL_WINDOW_SECS {
        anyhow::bail!(
            "--approval-window {} exceeds the {MAX_APPROVAL_WINDOW_SECS}s ceiling",
            cli.approval_window
        );
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
    // The MCP front-door socket, when configured. --once serves no requests, so
    // it binds neither socket.
    let mcp_listener = match (&cli.mcp_socket, cli.once) {
        (Some(path), false) => Some(listener::bind(path)?),
        _ => None,
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
    // The approval policy. --dry-run evaluates none (nothing is driven, so the
    // first proof opens); otherwise the weighted-threshold model is built from
    // [approval], and a deployment with no policy is refused at boot rather than
    // failing every open — opening a grant is not possible without one.
    let approval = if cli.dry_run {
        None
    } else {
        match inventory
            .approval_model()
            .map_err(|e| anyhow::anyhow!("{e}"))?
        {
            Some(model) => Some(model),
            None => anyhow::bail!(
                "no [approval] policy configured; opening a grant would always be refused. \
                 Configure [approval] with at least one profile, or run with --dry-run"
            ),
        }
    };

    // Read each TOTP authenticator's base32 secret from its mode-600 file at
    // startup — fail-closed, like a bad ed25519 key: a missing/unreadable/
    // malformed secret refuses the daemon rather than surfacing at 03:00. With
    // --tpm-unseal the files are TPM-sealed blobs and are unsealed here; the
    // plaintext exists only in this process's memory.
    let mut secret_reader = SecretReader::new(cli.tpm_unseal.as_deref())?;
    let mut totp_secrets = std::collections::BTreeMap::new();
    if let Some(model) = &approval {
        for (id, secret_file) in model.totp_authenticators() {
            let text = secret_reader
                .read(secret_file, "TOTP secret")
                .with_context(|| format!("TOTP secret for authenticator {id:?}"))?;
            let secret = lychgate_core::TotpSecret::from_base32(&text)
                .map_err(|e| anyhow::anyhow!("TOTP secret for authenticator {id:?}: {e}"))?;
            totp_secrets.insert(id.to_string(), secret);
        }
    }
    let totp_ledger = totp_ledger::TotpLedger::at(cli.state_dir.join("totp-ledger.json"));

    // Read each password authenticator's Argon2id hash from its mode-600 file at
    // startup and validate it — a missing/unreadable/malformed hash refuses the
    // start (fail-closed), like a bad ed25519 key or TOTP secret.
    let mut password_hashes = std::collections::BTreeMap::new();
    if let Some(model) = &approval {
        for (id, hash_file) in model.password_authenticators() {
            let phc = secret_reader
                .read(hash_file, "password hash")
                .with_context(|| format!("password hash for authenticator {id:?}"))?
                .trim()
                .to_string();
            lychgate_core::password::validate_hash(&phc)
                .map_err(|e| anyhow::anyhow!("password hash for authenticator {id:?}: {e}"))?;
            password_hashes.insert(id.to_string(), phc);
        }
    }

    let daemon = Arc::new(Daemon {
        inventory,
        store,
        journal: Mutex::new(journal),
        drivers: Mutex::new(driver_set),
        deadman: Mutex::new(drivers::deadman::ExecDeadman::new(Box::new(
            transport::ExecSshTransport,
        ))),
        approval_window: Duration::from_secs(cli.approval_window),
        approval,
        totp_secrets,
        totp_ledger,
        password_hashes,
        fido2_counters: fido2_counters::Fido2Counters::at(
            cli.state_dir.join("fido2-counters.json"),
        ),
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
             channels are live; opening a grant requires operator approval",
            daemon.inventory.hosts.len()
        );
    }

    let listener_thread = listener.map(|listener| {
        let daemon = Arc::clone(&daemon);
        std::thread::spawn(move || {
            listener::serve(&listener, &daemon, &SHUTDOWN, lifecycle::Origin::Operator)
        })
    });
    let mcp_thread = mcp_listener.map(|listener| {
        let daemon = Arc::clone(&daemon);
        std::thread::spawn(move || {
            listener::serve(&listener, &daemon, &SHUTDOWN, lifecycle::Origin::Mcp)
        })
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
            if listener_thread.as_ref().is_some_and(|h| h.is_finished())
                || mcp_thread.as_ref().is_some_and(|h| h.is_finished())
            {
                SHUTDOWN.store(true, Ordering::SeqCst);
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        if SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }
    }

    if listener_thread.is_some() || mcp_thread.is_some() {
        SHUTDOWN.store(true, Ordering::SeqCst);
    }
    if let Some(handle) = listener_thread {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => fatal = Some(e),
            Err(_) => fatal = Some(anyhow::anyhow!("listener thread panicked")),
        }
        let _ = fs::remove_file(&socket_path);
    }
    if let Some(handle) = mcp_thread {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => fatal = fatal.or(Some(e)),
            Err(_) => fatal = fatal.or(Some(anyhow::anyhow!("mcp listener thread panicked"))),
        }
        if let Some(path) = &cli.mcp_socket {
            let _ = fs::remove_file(path);
        }
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
