//! The unix-socket listener: one request line in, one response line out.
//!
//! Connections are handled one at a time — every mutation serializes on the
//! store's lock anyway, and a break-glass control socket has no concurrency
//! story worth buying complexity for. Transport failures on a connection are
//! that connection's problem (logged, next accept proceeds); a journal
//! failure is the daemon's problem and fatal, because accruing unrecorded
//! transitions would defeat the audit record.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use anyhow::Context;

use lychgate_core::proto::{self, Response, Transition};
use lychgate_core::{GrantRegistry, Inventory};

use crate::journal::{Event, Journal};
use crate::store::Store;
use crate::{channels_of, epoch_secs};

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
/// fatal case (journal failure).
pub fn serve(
    listener: &UnixListener,
    inventory: &Inventory,
    store: &Store,
    journal: &Mutex<Journal>,
    shutdown: &AtomicBool,
) -> anyhow::Result<()> {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return Ok(());
        }
        match listener.accept() {
            Ok((stream, _)) => {
                // Journal failures are the only errors handle() returns;
                // everything connection-scoped is dealt with inline.
                handle(stream, inventory, store, journal)?;
            }
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

fn handle(
    stream: UnixStream,
    inventory: &Inventory,
    store: &Store,
    journal: &Mutex<Journal>,
) -> anyhow::Result<()> {
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

    let response = {
        match proto::decode_request(line.trim_end_matches('\n')) {
            Err(e) => Response::refused(e),
            Ok(op) => {
                let now = SystemTime::now();
                let outcome = store.mutate(|doc| {
                    let mut registry = GrantRegistry::from_parts(inventory, doc)
                        .with_context(|| format!("validating {}", store.path().display()))?;
                    let (response, transition) = proto::apply(&mut registry, &op, now);
                    *doc = registry.snapshot();
                    Ok((response, transition))
                });
                match outcome {
                    Ok((response, transition)) => {
                        if let Some(t) = transition {
                            // After the state commit, and fatal on failure —
                            // see the journal module docs.
                            let mut journal = journal.lock().expect("journal mutex poisoned");
                            journal.record(now, &transition_event(inventory, t))?;
                        }
                        response
                    }
                    Err(e) => Response::refused(format!("daemon error: {e:#}")),
                }
            }
        }
    };

    let mut out = response.encode();
    out.push('\n');
    if let Err(e) = (&stream).write_all(out.as_bytes()) {
        eprintln!("lychgated: response write failed: {e}");
    }
    Ok(())
}

fn transition_event(inventory: &Inventory, t: Transition) -> Event {
    match t {
        Transition::Opened {
            host,
            ttl_secs,
            expires_at,
        } => Event::Open {
            channels: channels_of(inventory, &host),
            host,
            ttl_secs,
            expires_at: epoch_secs(expires_at),
        },
        Transition::Renewed {
            host,
            ttl_secs,
            expires_at,
        } => Event::Renew {
            host,
            ttl_secs,
            expires_at: epoch_secs(expires_at),
        },
        Transition::Closed { host } => Event::Close { host },
    }
}
