//! The TOTP single-use ledger: totp-ledger.json, recording every `(authenticator,
//! counter)` a code has been spent on, so a code cannot be replayed — not even
//! across a daemon restart within its validity window.
//!
//! This mirrors the grant store's discipline (a lockfile, read-modify-write,
//! atomic rename, sync-before-rename) rather than reusing it, because the store
//! is monomorphic over the grant document. The one departure from the store is
//! pruning: an entry older than the retain window can never be replayed anyway
//! (its counter is long outside any live skew window), so it is dropped to keep
//! the file bounded.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::lockfile;

/// Consumed entries older than this are pruned: a TOTP counter this old is far
/// outside any live ±skew window, so it could never be accepted again regardless.
/// Generous against the 30s step and ±1 skew.
const RETAIN_SECS: u64 = 600;

const LEDGER_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LedgerDoc {
    version: u32,
    #[serde(default)]
    consumed: Vec<Entry>,
}

impl Default for LedgerDoc {
    fn default() -> LedgerDoc {
        LedgerDoc {
            version: LEDGER_VERSION,
            consumed: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    authenticator: String,
    counter: u64,
    /// Unix seconds the code was consumed, for pruning.
    at: u64,
}

pub struct TotpLedger {
    path: PathBuf,
    lock_timeout: Duration,
    stale_lock_after: Duration,
}

impl TotpLedger {
    pub fn at(path: impl Into<PathBuf>) -> TotpLedger {
        TotpLedger {
            path: path.into(),
            lock_timeout: Duration::from_secs(10),
            stale_lock_after: Duration::from_secs(120),
        }
    }

    /// Record `(authenticator, counter)` as consumed. Returns `true` if it was
    /// newly recorded (the code is fresh and may be honoured), `false` if it was
    /// already present (a replay — refuse it). Prunes stale entries on the way.
    /// Locked and atomic, so two concurrent approves cannot both spend one code.
    pub fn consume(&self, authenticator: &str, counter: u64, now: SystemTime) -> io::Result<bool> {
        let _guard = self.lock()?;
        let mut doc = self.read()?;
        let now_secs = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Prune entries whose window has long passed.
        doc.consumed
            .retain(|e| now_secs.saturating_sub(e.at) <= RETAIN_SECS);

        let already = doc
            .consumed
            .iter()
            .any(|e| e.authenticator == authenticator && e.counter == counter);
        if already {
            // A replay: nothing to write beyond the prune, but persist the prune
            // so the file stays bounded.
            self.write(&doc)?;
            return Ok(false);
        }
        doc.consumed.push(Entry {
            authenticator: authenticator.to_string(),
            counter,
            at: now_secs,
        });
        self.write(&doc)?;
        Ok(true)
    }

    fn read(&self) -> io::Result<LedgerDoc> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(LedgerDoc::default()),
            Err(e) => return Err(e),
        };
        // A corrupt ledger is not fail-open: refuse rather than silently forget
        // which codes were spent. A refusal here blocks approvals until a human
        // looks — which is the safe direction for an anti-replay record.
        let doc: LedgerDoc = serde_json::from_str(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if doc.version != LEDGER_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "totp ledger version {} (this daemon writes {LEDGER_VERSION})",
                    doc.version
                ),
            ));
        }
        Ok(doc)
    }

    fn write(&self, doc: &LedgerDoc) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let text = serde_json::to_string_pretty(doc)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let tmp = self
            .path
            .with_extension(format!("tmp.{}", std::process::id()));
        {
            let mut file = fs::File::create(&tmp)?;
            io::Write::write_all(&mut file, text.as_bytes())?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &self.path)
    }

    /// Acquire the ledger lock. Shares the grant store's discipline, including
    /// the dead-holder steal that keeps a SIGKILLed daemon from wedging the next
    /// start; see [`crate::lockfile`].
    fn lock(&self) -> io::Result<lockfile::LockGuard> {
        let path = self.path.with_extension("lock");
        lockfile::acquire(&path, self.lock_timeout, self.stale_lock_after).map_err(|e| match e {
            lockfile::LockError::Held { .. } => io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("{}: totp ledger lock held too long", path.display()),
            ),
            lockfile::LockError::Io(e) => e,
        })
    }

    /// Test-only: the ids currently recorded as consumed (for assertions).
    #[cfg(test)]
    pub(crate) fn consumed_ids(&self) -> std::collections::BTreeSet<String> {
        self.read()
            .unwrap_or_default()
            .consumed
            .into_iter()
            .map(|e| e.authenticator)
            .collect()
    }
}

#[cfg(test)]
mod tests;
