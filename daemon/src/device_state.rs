//! The device-channel state ledger: device-state.json, recording per device
//! the next capability-token sequence number and the nonce of the currently
//! open grant.
//!
//! `next_seq` is the anti-replay ground truth the daemon side must never
//! rewind: the sequence is bumped AND PERSISTED before a token is emitted, so
//! a crash between the two wastes a number and never reuses one (a reused
//! seq would let a captured token replay). `open_nonce` is not a secret (it
//! travels in the clear inside the token); persisting it is what lets a
//! restarted daemon verify the device still holds ITS grant rather than
//! somebody's. Mirrors the fido2-counter ledger's discipline: shared
//! lockfile, read-modify-write, atomic rename, corrupt-refuses.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::lockfile;

const LEDGER_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
struct DeviceRecord {
    /// The next seq to issue (strictly monotonic, never rewound).
    #[serde(default)]
    next_seq: u64,
    /// The hex nonce of the grant this daemon believes is open, if any.
    #[serde(default)]
    open_nonce: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LedgerDoc {
    version: u32,
    /// Keyed by the device id (hex).
    #[serde(default)]
    devices: BTreeMap<String, DeviceRecord>,
}

impl Default for LedgerDoc {
    fn default() -> LedgerDoc {
        LedgerDoc {
            version: LEDGER_VERSION,
            devices: BTreeMap::new(),
        }
    }
}

fn hex16(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct DeviceState {
    path: PathBuf,
    lock_timeout: Duration,
    stale_lock_after: Duration,
}

impl DeviceState {
    pub fn at(path: impl Into<PathBuf>) -> DeviceState {
        DeviceState {
            path: path.into(),
            lock_timeout: Duration::from_secs(10),
            stale_lock_after: Duration::from_secs(120),
        }
    }

    /// Reserve the next sequence number for `device_id`: bump AND persist
    /// (fsynced) before returning it, so the number handed back can be signed
    /// into a token knowing a crash cannot reissue it.
    pub fn reserve_seq(&self, device_id: &[u8; 16]) -> io::Result<u64> {
        let _guard = self.lock()?;
        let mut doc = self.read()?;
        let record = doc.devices.entry(hex16(device_id)).or_default();
        record.next_seq += 1;
        let seq = record.next_seq;
        self.write(&doc)?;
        Ok(seq)
    }

    /// Record the nonce of the grant now open on `device_id`.
    pub fn set_open_nonce(&self, device_id: &[u8; 16], nonce: &[u8; 16]) -> io::Result<()> {
        let _guard = self.lock()?;
        let mut doc = self.read()?;
        doc.devices.entry(hex16(device_id)).or_default().open_nonce = Some(hex16(nonce));
        self.write(&doc)
    }

    /// Forget the open nonce (the grant closed).
    pub fn clear_open_nonce(&self, device_id: &[u8; 16]) -> io::Result<()> {
        let _guard = self.lock()?;
        let mut doc = self.read()?;
        if let Some(record) = doc.devices.get_mut(&hex16(device_id)) {
            record.open_nonce = None;
            self.write(&doc)?;
        }
        Ok(())
    }

    /// The nonce this daemon believes is open on `device_id`, if any.
    pub fn open_nonce(&self, device_id: &[u8; 16]) -> io::Result<Option<[u8; 16]>> {
        let _guard = self.lock()?;
        let doc = self.read()?;
        let Some(hex) = doc
            .devices
            .get(&hex16(device_id))
            .and_then(|r| r.open_nonce.clone())
        else {
            return Ok(None);
        };
        let mut out = [0u8; 16];
        if hex.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stored open_nonce is not 32 hex chars",
            ));
        }
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "open_nonce not hex"))?;
        }
        Ok(Some(out))
    }

    fn read(&self) -> io::Result<LedgerDoc> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(LedgerDoc::default()),
            Err(e) => return Err(e),
        };
        // Corrupt is a refusal, not a fresh start: forgetting next_seq would
        // reissue sequence numbers and open the replay window.
        let doc: LedgerDoc = serde_json::from_str(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if doc.version != LEDGER_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "device state ledger version {} (this daemon writes {LEDGER_VERSION})",
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
                format!("{}: device state ledger lock held too long", path.display()),
            ),
            lockfile::LockError::Io(e) => e,
        })
    }
}

#[cfg(test)]
mod tests;
