//! The append-only audit journal: journal.jsonl, one JSON object per line.
//!
//! The journal is a record, never an input — nothing in production reads it
//! back, and no state is reconstructed from it. It is written only after the
//! state change it describes has committed, which fixes what it can and
//! cannot promise:
//!
//! - It never over-records: every line describes an observation the daemon
//!   really made against committed state. Phantom entries are impossible.
//! - It does not promise completeness: a crash between the state rename and
//!   the append loses that line. The loss is detectable — every line carries
//!   the writing pid and a per-process sequence number counting from zero,
//!   so a gap inside a pid's bracket, or a daemon-start with no matching
//!   daemon-stop, marks an unclean window.
//! - After OS-level power loss, a synced line whose state rename did not
//!   reach disk can be duplicated on the next run: the expiry is re-observed
//!   and re-journaled. An honest observation twice, never a lie.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use lychgate_core::Channel;

#[derive(Debug)]
pub enum JournalError {
    Io { path: PathBuf, source: io::Error },
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalError::Io { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for JournalError {}

#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum Event {
    DaemonStart {
        inventory: String,
        hosts: usize,
    },
    DaemonStop,
    Open {
        host: String,
        channels: Vec<Channel>,
        ttl_secs: u64,
        expires_at: u64,
    },
    Renew {
        host: String,
        ttl_secs: u64,
        expires_at: u64,
    },
    Close {
        host: String,
    },
    Expire {
        host: String,
        channels: Vec<Channel>,
        opened_at: u64,
        expires_at: u64,
    },
}

#[derive(Serialize)]
struct Line<'a> {
    ts: u64,
    pid: u32,
    seq: u64,
    #[serde(flatten)]
    event: &'a Event,
}

#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    file: File,
    pid: u32,
    seq: u64,
}

impl Journal {
    /// Opens for append, creating if absent. Never truncates: the journal
    /// accumulates across daemon runs.
    pub fn open(path: impl Into<PathBuf>) -> Result<Journal, JournalError> {
        let path = path.into();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| JournalError::Io {
                path: path.clone(),
                source,
            })?;
        Ok(Journal {
            path,
            file,
            pid: std::process::id(),
            seq: 0,
        })
    }

    /// Appends one line and syncs it. The sync per line is a deliberate
    /// departure from the house no-fsync habit: an audit line that vanishes
    /// on power loss defeats the journal's purpose. The sequence number
    /// advances only after a successful sync, so seq gaps mean lost lines,
    /// never miscounted ones.
    pub fn record(&mut self, now: SystemTime, event: &Event) -> Result<(), JournalError> {
        let ts = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = Line {
            ts,
            pid: self.pid,
            seq: self.seq,
            event,
        };
        // Infallible for these types: no non-string map keys, no floats.
        let mut text = serde_json::to_string(&line).expect("journal lines always serialize");
        text.push('\n');

        let io_err = |source| JournalError::Io {
            path: self.path.clone(),
            source,
        };
        self.file.write_all(text.as_bytes()).map_err(io_err)?;
        self.file.flush().map_err(io_err)?;
        self.file.sync_all().map_err(io_err)?;
        self.seq += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
