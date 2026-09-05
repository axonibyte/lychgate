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
    /// Request a grant against a host (returns a challenge to approve)
    Open {
        #[arg(long)]
        host: String,
        /// Time to live, e.g. 90s, 15m, 2h; capped at 24h
        #[arg(long)]
        ttl: String,
        /// Which approval profile to open under. Omit when the host permits
        /// exactly one.
        #[arg(long = "as")]
        profile: Option<String>,
    },
    /// Approve a pending request with a signed token, opening the grant
    Approve {
        #[arg(long)]
        host: String,
        /// The approval token. Omit to read it from stdin (until EOF), which
        /// keeps a secret-bearing token off the command line.
        #[arg(long)]
        token: Option<String>,
        /// Read the token from a file instead of stdin.
        #[arg(long)]
        token_file: Option<PathBuf>,
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
        Command::Open { host, ttl, profile } => {
            // Policy is enforced client-side first so a bad TTL fails with
            // core's error before a connection is attempted; the daemon
            // enforces it again regardless.
            Ttl::parse(ttl)?;
            Op::Open {
                host: host.clone(),
                ttl: ttl.clone(),
                profile: profile.clone(),
            }
        }
        Command::Approve {
            host,
            token,
            token_file,
        } => {
            use std::io::Read;
            let tok = if let Some(t) = token {
                t.clone()
            } else if let Some(f) = token_file {
                std::fs::read_to_string(f)?.trim().to_string()
            } else {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s.trim().to_string()
            };
            Op::Approve {
                host: host.clone(),
                token: tok,
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

    // The now-open grant plus its one-time secret and endpoint — shared by the
    // approve command, which is where a grant actually opens.
    let print_opened = |host: &str, r: &Response| {
        let expires = r.expires_at.unwrap_or(0);
        println!("grant open on {host} until epoch {expires}");
        if let Some(outcome) = &r.outcome {
            println!("{outcome}");
        }
        if let Some(secret) = &r.secret {
            // Shown exactly once — the daemon does not store or journal it.
            // The label defaults to the BMC wording so an older daemon prints
            // exactly as before.
            let label = r
                .secret_label
                .as_deref()
                .unwrap_or("break-glass BMC password");
            println!("{label} (shown once): {secret}");
        }
    };

    match (&cli.command, &response) {
        (Command::Open { host, .. }, r) => match &r.pending {
            Some(p) => {
                println!(
                    "approval required for {host} under profile {:?} (ttl {}, approve within {}s)",
                    p.profile,
                    human(p.ttl_secs),
                    p.approval_deadline.saturating_sub(p.requested_at)
                );
                println!(
                    "weight {}/{} so far; outstanding: {}",
                    p.weight,
                    p.threshold,
                    if p.missing.is_empty() {
                        "(none)".to_string()
                    } else {
                        p.missing.join(" | ")
                    }
                );
                println!("challenge: {}", p.challenge);
                println!(
                    "sign it on your device, e.g.:\n  \
                     printf %s '{}' | ssh-keygen -Y sign -n lychgate-approval -f ~/.ssh/id_ed25519",
                    p.challenge
                );
                println!("then: lychgate approve --host {host}   (paste the signature, then EOF)");
            }
            // A daemon in --dry-run or an older one may open directly.
            None => print_opened(host, r),
        },
        (Command::Approve { host, .. }, r) => match &r.pending {
            // The proof was accepted but the threshold is not yet met: show
            // progress. More proofs (or an elapsed wait) will open the grant.
            Some(p) => {
                println!(
                    "proof accepted for {host}: weight {}/{}",
                    p.weight, p.threshold
                );
                if !p.missing.is_empty() {
                    println!("still outstanding: {}", p.missing.join(" | "));
                }
                println!("submit more proofs, or wait, to reach the threshold");
            }
            None => print_opened(host, r),
        },
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
                    (GrantState::AwaitingApproval, Some(secs)) => {
                        println!("{}\tawaiting-approval\t{} to approve", g.host, human(secs))
                    }
                    (GrantState::AwaitingApproval, None) => {
                        println!("{}\tawaiting-approval", g.host)
                    }
                    (GrantState::ApprovalExpired, _) => {
                        println!("{}\tapproval-expired", g.host)
                    }
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
