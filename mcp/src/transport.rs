//! The client side of the daemon's MCP socket: one request line out, one
//! response line in — the same NDJSON wire the CLI speaks, pointed at the
//! daemon's dedicated MCP socket (`lychgated --mcp-socket`).

use std::path::PathBuf;

use lychgate_core::proto::{Op, Response};

/// A source of daemon responses. Abstracted so the tool layer can be tested
/// against a fake without a live daemon.
pub trait Backend {
    fn call(&self, op: &Op) -> anyhow::Result<Response>;
}

pub struct SocketBackend {
    pub socket: PathBuf,
}

impl Backend for SocketBackend {
    fn call(&self, op: &Op) -> anyhow::Result<Response> {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixStream;

        use anyhow::Context;
        use lychgate_core::proto::encode_request;

        let mut stream = UnixStream::connect(&self.socket).with_context(|| {
            format!(
                "connecting to the daemon MCP socket {} (is lychgated running with --mcp-socket?)",
                self.socket.display()
            )
        })?;
        let mut line = encode_request(op);
        line.push('\n');
        stream
            .write_all(line.as_bytes())
            .context("sending the request")?;

        let mut reply = String::new();
        BufReader::new(&stream)
            .read_line(&mut reply)
            .context("reading the response")?;
        Response::decode(reply.trim_end_matches('\n'))
            .map_err(|e| anyhow::anyhow!("malformed response from the daemon: {e}"))
    }
}
