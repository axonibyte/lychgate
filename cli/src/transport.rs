//! The client side of the wire: one request line out, one response line in.

use std::path::PathBuf;

use lychgate_core::proto::{Op, Response};

/// Where the daemon listens by default, matching the service files' state
/// directories. Overridable with --socket.
pub fn default_socket() -> PathBuf {
    if cfg!(target_os = "freebsd") {
        PathBuf::from("/var/db/lychgate/lychgated.sock")
    } else {
        PathBuf::from("/var/lib/lychgate/lychgated.sock")
    }
}

#[cfg(unix)]
pub fn roundtrip(socket: &std::path::Path, op: &Op) -> anyhow::Result<Response> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    use anyhow::Context;
    use lychgate_core::proto::encode_request;

    let mut stream = UnixStream::connect(socket).with_context(|| {
        format!(
            "connecting to {} (is lychgated running, and is this user permitted?)",
            socket.display()
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

/// The daemon manages sshd, authorized_keys and BMCs on unix hosts and does
/// not run here; the client ships so an operator's workstation can be
/// anything, but a *local* socket needs a local daemon. Remote transport is
/// an M8 design question (docs/ROADMAP.md).
#[cfg(not(unix))]
pub fn roundtrip(
    _socket: &std::path::Path,
    _op: &Op,
) -> anyhow::Result<lychgate_core::proto::Response> {
    anyhow::bail!(
        "no local daemon transport on this platform: lychgated runs on \
         FreeBSD and Linux; run lychgate there (e.g. over ssh) instead"
    )
}
