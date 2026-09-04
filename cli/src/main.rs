mod transport;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use lychgate_core::proto::{GrantState, Op, Response, ResponseResult};
use lychgate_core::Ttl;

#[derive(Parser)]
#[command(
    name = "lychgate",
    version,
    about = "Break-glass emergency access, opened deliberately and closed on a timer"
)]
struct Cli {
    /// Path to lychgated's control socket
    #[arg(long, default_value_os_t = transport::default_socket())]
    socket: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Open a grant against a host for a limited time
    Open {
        #[arg(long)]
        host: String,
        /// Time to live, e.g. 90s, 15m, 2h; capped at 24h
        #[arg(long)]
        ttl: String,
    },
    /// Renew a host's open grant (accepted only near expiry)
    Renew {
        #[arg(long)]
        host: String,
        /// Fresh time to live from now, e.g. 2h; capped at 24h
        #[arg(long)]
        ttl: String,
    },
    /// Close a host's grant and revert everything it opened
    Close {
        #[arg(long)]
        host: String,
    },
    /// Report the state of every grant
    Status,
}

fn human(secs: u64) -> String {
    match secs {
        s if s >= 3600 => format!("{}h{:02}m", s / 3600, (s % 3600) / 60),
        s if s >= 60 => format!("{}m{:02}s", s / 60, s % 60),
        s => format!("{s}s"),
    }
}

fn run() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();

    let op = match &cli.command {
        Command::Open { host, ttl } => {
            // Policy is enforced client-side first so a bad TTL fails with
            // core's error before a connection is attempted; the daemon
            // enforces it again regardless.
            Ttl::parse(ttl)?;
            Op::Open {
                host: host.clone(),
                ttl: ttl.clone(),
            }
        }
        Command::Renew { host, ttl } => {
            Ttl::parse(ttl)?;
            Op::Renew {
                host: host.clone(),
                ttl: ttl.clone(),
            }
        }
        Command::Close { host } => Op::Close { host: host.clone() },
        Command::Status => Op::Status,
    };

    let response: Response = transport::roundtrip(&cli.socket, &op)?;

    if response.result == ResponseResult::Refused {
        // The daemon's words, verbatim.
        eprintln!(
            "refused: {}",
            response.error.as_deref().unwrap_or("(no reason given)")
        );
        return Ok(ExitCode::FAILURE);
    }

    match (&cli.command, &response) {
        (Command::Open { host, .. }, r) => {
            let expires = r.expires_at.unwrap_or(0);
            println!("grant open on {host} until epoch {expires}");
        }
        (Command::Renew { host, .. }, r) => {
            let expires = r.expires_at.unwrap_or(0);
            println!("grant on {host} renewed until epoch {expires}");
        }
        (Command::Close { host }, r) => match r.outcome.as_deref() {
            Some("closed") => println!("grant on {host} closed"),
            Some("already-closed") => println!("grant on {host} was already closed"),
            other => println!("grant on {host}: {}", other.unwrap_or("(no outcome)")),
        },
        (Command::Status, r) => {
            for g in r.grants.as_deref().unwrap_or(&[]) {
                match (&g.state, g.remaining_secs) {
                    (GrantState::Open, Some(secs)) => {
                        println!("{}\topen\t{} remaining", g.host, human(secs))
                    }
                    (GrantState::Open, None) => println!("{}\topen", g.host),
                    (GrantState::Opening, _) => println!("{}\topening", g.host),
                    (GrantState::Closed, _) => println!("{}\tclosed", g.host),
                    (GrantState::Expired, _) => {
                        println!("{}\texpired\trevert pending", g.host)
                    }
                    (GrantState::NeedsRevert, _) => println!(
                        "{}\tneeds-revert\t{:?}",
                        g.host,
                        g.stuck_channels.as_deref().unwrap_or(&[])
                    ),
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("lychgate: {e:#}");
            ExitCode::FAILURE
        }
    }
}
