//! The unix-socket listener: one request line in, one response line out.
//!
//! Connections are handled one at a time — every mutation serializes on the
//! store's lock anyway, and a break-glass control socket has no concurrency
//! story worth buying complexity for. Transport failures on a connection are
//! that connection's problem (logged, next accept proceeds); a daemon-fatal
//! failure (store I/O, journal write) stops the daemon.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use anyhow::Context;

use lychgate_core::proto::{self, Response};

use crate::lifecycle::Daemon;

/// Claims the socket path. A live listener there means another daemon is
/// running — a refusal, not a takeover. A dead one (connect refused) is
/// stale and replaced. The socket is chmod 0600 before any request is
/// served: this socket is the entire authorization surface until M8.
pub fn bind(path: &Path) -> anyhow::Result<UnixListener> {
    if path.exists() {
        match UnixStream::connect(path) {
            Ok(_) => anyhow::bail!(
                "{}: another lychgated is already listening; refusing to start twice",
                path.display()
            ),
            Err(_) => {
                // Nothing answers: a leftover from an unclean death. Another
                // starter racing us to the same conclusion may remove it
                // first; a file that is already gone is the outcome we want.
                match std::fs::remove_file(path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(e)
                            .with_context(|| format!("removing stale socket {}", path.display()))
                    }
                }
            }
        }
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, {
        use std::os::unix::fs::PermissionsExt;
        std::fs::Permissions::from_mode(0o600)
    })
    .with_context(|| format!("restricting {}", path.display()))?;
    listener
        .set_nonblocking(true)
        .context("setting the listener non-blocking")?;
    Ok(listener)
}

/// Accept loop. Returns when `shutdown` is set; returns Err only on the
/// daemon-fatal case surfaced by the lifecycle (store I/O, journal write).
pub fn serve(
    listener: &UnixListener,
    daemon: &Daemon,
    shutdown: &AtomicBool,
) -> anyhow::Result<()> {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return Ok(());
        }
        match listener.accept() {
            Ok((stream, _)) => handle(stream, daemon)?,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("lychgated: accept failed: {e}");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn handle(stream: UnixStream, daemon: &Daemon) -> anyhow::Result<()> {
    // Blocking I/O with a deadline on this one connection; the listener's
    // non-blocking flag must not leak onto the stream.
    stream.set_nonblocking(false).ok();
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

    // Read one line. take() bounds what a writer that never sends a newline
    // can make this allocate; the cap refusal itself lives in
    // decode_request, which sees any over-cap read (take stops at cap+1, so
    // an oversized line always arrives over-length). The allocation bound
    // has no cheap behavioral oracle — the observable is memory, not a
    // response — and is stated here rather than pretend-tested.
    let mut reader = BufReader::new(&stream).take(proto::MAX_LINE_BYTES as u64 + 1);
    let mut line = String::new();
    if let Err(e) = reader.read_line(&mut line) {
        eprintln!("lychgated: dropping connection: {e}");
        return Ok(());
    }

    let response = match proto::decode_request(line.trim_end_matches('\n')) {
        Err(e) => Response::refused(e),
        Ok(op) => daemon.dispatch(&op, SystemTime::now())?,
    };

    let mut out = response.encode();
    out.push('\n');
    if let Err(e) = (&stream).write_all(out.as_bytes()) {
        eprintln!("lychgated: response write failed: {e}");
    }
    Ok(())
}
