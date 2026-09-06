//! The FIDO2 signature-counter ledger: fido2-counters.json, recording the
//! highest counter each credential has ever presented, so a counter that goes
//! BACKWARDS is caught — two devices signing with one credential (a clone) is
//! exactly what the counter exists to reveal (WebAuthn §6.1.1).
//!
//! Semantics: a counter of zero means the authenticator does not implement
//! counters (the software authenticator always sends 0), so nothing is checked
//! or recorded. Once a credential has presented a nonzero counter, every later
//! assertion must present a strictly greater one; equal-or-less — including a
//! sudden zero — is a regression and the approval is refused. Mirrors the TOTP
//! ledger's discipline (the shared lockfile, read-modify-write, atomic rename,
//! corrupt-refuses) — an anti-replay record must not fail open.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::lockfile;

const LEDGER_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LedgerDoc {
    version: u32,
    /// Highest counter seen, keyed by the credential id (base64url).
    #[serde(default)]
    counters: BTreeMap<String, u32>,
}

impl Default for LedgerDoc {
    fn default() -> LedgerDoc {
        LedgerDoc {
            version: LEDGER_VERSION,
            counters: BTreeMap::new(),
        }
    }
}

/// The verdict on one presented counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterVerdict {
    /// Fresh or advancing (or counters unimplemented): the assertion may count.
    Ok,
    /// The counter did not advance past the recorded high-water mark: refuse.
    Regressed,
}

pub struct Fido2Counters {
    path: PathBuf,
    lock_timeout: Duration,
    stale_lock_after: Duration,
}

impl Fido2Counters {
    pub fn at(path: impl Into<PathBuf>) -> Fido2Counters {
        Fido2Counters {
            path: path.into(),
            lock_timeout: Duration::from_secs(10),
            stale_lock_after: Duration::from_secs(120),
        }
    }

    /// Judge `counter` for `credential_id` and, when it advances, persist it as
    /// the new high-water mark. Locked and atomic: two concurrent approves
    /// cannot both pass the same counter.
    pub fn observe(&self, credential_id: &[u8], counter: u32) -> io::Result<CounterVerdict> {
        // Zero: the authenticator has no counter. Nothing to judge — but if a
        // nonzero mark EXISTS, a zero is itself a regression (a device that
        // used to count suddenly does not: the clone shape).
        let key = data_encoding::BASE64URL_NOPAD.encode(credential_id);
        let _guard = self.lock()?;
        let mut doc = self.read()?;
        let stored = doc.counters.get(&key).copied().unwrap_or(0);
        if stored > 0 && counter <= stored {
            return Ok(CounterVerdict::Regressed);
        }
        if counter > 0 {
            doc.counters.insert(key, counter);
            self.write(&doc)?;
        }
        Ok(CounterVerdict::Ok)
    }

    fn read(&self) -> io::Result<LedgerDoc> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(LedgerDoc::default()),
            Err(e) => return Err(e),
        };
        // Corrupt is a refusal, not a fresh start: forgetting the high-water
        // marks would let a cloned credential replay freely.
        let doc: LedgerDoc = serde_json::from_str(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if doc.version != LEDGER_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "fido2 counter ledger version {} (this daemon writes {LEDGER_VERSION})",
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

    fn lock(&self) -> io::Result<lockfile::LockGuard> {
        let path = self.path.with_extension("lock");
        lockfile::acquire(&path, self.lock_timeout, self.stale_lock_after).map_err(|e| match e {
            lockfile::LockError::Held { .. } => io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "{}: fido2 counter ledger lock held too long",
                    path.display()
                ),
            ),
            lockfile::LockError::Io(e) => e,
        })
    }
}

#[cfg(test)]
mod tests;
