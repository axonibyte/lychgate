//! `lychgate-mcp` — the MCP front door. A Claude session speaks MCP (JSON-RPC
//! 2.0 over stdio) to this process; it translates the tool calls to the
//! daemon's ops over the dedicated MCP socket, and signs the AI's approval
//! factor with an Ed25519 principal key. It holds no drivers and no secrets: the
//! daemon remains the privilege boundary, and the per-profile `mcp` gate on the
//! MCP socket bounds what this front door can reach.

mod rpc;
mod signer;
mod tools;
mod transport;

use std::io::{BufRead, Write};
use std::path::PathBuf;

use clap::Parser;

use crate::rpc::Server;
use crate::signer::Signer;
use crate::transport::SocketBackend;

#[derive(Parser)]
#[command(
    name = "lychgate-mcp",
    version,
    about = "MCP front door for lychgate: the AI as a weighted approval factor"
)]
struct Cli {
    /// The daemon's MCP socket (lychgated --mcp-socket <path>).
    #[arg(long)]
    mcp_socket: PathBuf,

    /// The AI principal's OpenSSH Ed25519 private key (unencrypted, mode 600).
    /// Its public half is configured as an `ed25519` authenticator in the policy.
    #[arg(long)]
    principal_key: PathBuf,

    /// Print the principal's public key (the `[[approval.authenticator]]` line
    /// to configure) and exit, instead of serving MCP.
    #[arg(long)]
    show_public_key: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let signer = Signer::from_file(&cli.principal_key)?;

    if cli.show_public_key {
        println!("{}", signer.public_openssh()?);
        return Ok(());
    }

    let backend = SocketBackend {
        socket: cli.mcp_socket,
    };
    let mut server = Server::new(backend, signer);

    // The stdio transport: one JSON-RPC object per line in, one per line out.
    // Diagnostics go to stderr — stdout is the protocol channel and must carry
    // nothing but responses.
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break; // EOF — the client closed the pipe.
        }
        if let Some(response) = server.handle_line(&line) {
            writer.write_all(response.as_bytes())?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
