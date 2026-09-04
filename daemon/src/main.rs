use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;

use lychgate_core::{Inventory, Os};

#[derive(Parser)]
#[command(name = "lychgated", version, about = "lychgate control-plane daemon")]
struct Cli {
    /// Path to the host inventory
    #[arg(long)]
    inventory: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let text = fs::read_to_string(&cli.inventory)
        .with_context(|| format!("reading {}", cli.inventory.display()))?;
    let inventory = Inventory::parse(&text)
        .with_context(|| format!("validating {}", cli.inventory.display()))?;

    let freebsd = inventory
        .hosts
        .iter()
        .filter(|h| h.os == Os::Freebsd)
        .count();
    let linux = inventory.hosts.iter().filter(|h| h.os == Os::Linux).count();
    let channels: usize = inventory.hosts.iter().map(|h| h.channels.len()).sum();
    println!(
        "lychgated: inventory holds {} host(s) ({freebsd} freebsd, {linux} linux) across {channels} channel(s)",
        inventory.hosts.len()
    );
    println!("lychgated: control plane not yet implemented; inventory validated, exiting");
    Ok(())
}
