use anyhow::bail;
use clap::{Parser, Subcommand};

use lychgate_core::Ttl;

#[derive(Parser)]
#[command(
    name = "lychgate",
    version,
    about = "Break-glass emergency access, opened deliberately and closed on a timer"
)]
struct Cli {
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
    /// Close a host's grant and revert everything it opened
    Close {
        #[arg(long)]
        host: String,
    },
    /// Report the state of every grant
    Status,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Open { host, ttl } => {
            // Policy is enforced before any transport exists, so a bad TTL
            // fails here with core's error rather than at the daemon.
            let ttl = Ttl::parse(&ttl)?;
            bail!(
                "cannot open {ttl} grant against {host:?}: \
                 no daemon transport implemented yet; lychgated integration is forthcoming"
            );
        }
        Command::Close { host } => {
            bail!(
                "cannot close grant against {host:?}: \
                 no daemon transport implemented yet; lychgated integration is forthcoming"
            );
        }
        Command::Status => {
            bail!("no daemon transport implemented yet; lychgated integration is forthcoming");
        }
    }
}
