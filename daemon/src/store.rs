//! The grant store: grants.json, read-modify-written atomically under a
//! lockfile. The shape is reaper's session store; the one deliberate
//! departure is durability (see write()), because this file is the truth
//! about what break-glass access is open, not a cache of it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use lychgate_core::{StateDoc, STATE_VERSION};

#[derive(Debug)]
pub enum StoreError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Corrupt {
        path: PathBuf,
        message: String,
    },
    /// Another process holds the lock and did not let go in time.
    Locked {
        path: PathBuf,
        held_for: Duration,
    },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            StoreError::Corrupt { path, message } => {
                write!(f, "{}: unreadable grant store: {message}", path.display())
            }
            StoreError::Locked { path, held_for } => write!(
                f,
                "{}: another lychgated has held the grant lock for {}s; \
                 if nothing else is running, remove it",
                path.display(),
                held_for.as_secs()
            ),
        }
    }
}

impl std::error::Error for StoreError {}

type Result<T> = std::result::Result<T, StoreError>;

pub struct Store {
    path: PathBuf,
    lock_timeout: Duration,
    stale_lock_after: Duration,
}

impl Store {
    pub fn at(path: impl Into<PathBuf>) -> Store {
        Store {
            path: path.into(),
            lock_timeout: Duration::from_secs(10),
            stale_lock_after: Duration::from_secs(120),
        }
    }

    /// Test-only: the production timeouts make a wedged-lock test take ten
    /// seconds, and a slow test is a test that stops being run.
    #[cfg(test)]
    pub(crate) fn with_timeouts(
        path: impl Into<PathBuf>,
        lock_timeout: Duration,
        stale_lock_after: Duration,
    ) -> Store {
        Store {
            path: path.into(),
            lock_timeout,
            stale_lock_after,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Refuse early if this store could not be written to. The probe never
    /// creates the store file itself: an empty grants.json would read as
    /// corrupt, so an absent file is probed through its parent directory.
    pub fn probe_writable(&self) -> Result<()> {
        let io_err = |path: &Path, e: io::Error| StoreError::Io {
            path: path.to_path_buf(),
            source: e,
        };
        if self.path.exists() {
            fs::OpenOptions::new()
                .write(true)
                .open(&self.path)
                .map_err(|e| io_err(&self.path, e))?;
            return Ok(());
        }
        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(dir).map_err(|e| io_err(dir, e))?;
        let probe = dir.join(format!(".lychgate-probe.{}", std::process::id()));
        fs::write(&probe, b"").map_err(|e| io_err(&self.path, e))?;
        let _ = fs::remove_file(&probe);
        Ok(())
    }

    pub fn read(&self) -> Result<StateDoc> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            // A store that has never been written is an empty store, not an
            // error. Every other I/O failure is real and is reported.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(StateDoc::default()),
            Err(e) => {
                return Err(StoreError::Io {
                    path: self.path.clone(),
                    source: e,
                })
            }
        };

        let doc: StateDoc = serde_json::from_str(&text).map_err(|e| StoreError::Corrupt {
            path: self.path.clone(),
            message: e.to_string(),
        })?;

        // Read the versions this build understands; refuse the rest naming
        // both. Older files still load — a v2 (pre-approval) or v3 (pre-profile)
        // record is a subset v4 validates unchanged — and the next write
        // upgrades the file to the current version.
        const READABLE: &[u32] = &[2, 3, STATE_VERSION];
        if !READABLE.contains(&doc.version) {
            return Err(StoreError::Corrupt {
                path: self.path.clone(),
                message: format!(
                    "written by a different version of lychgate (file says {}, this reads {READABLE:?})",
                    doc.version
                ),
            });
        }

        Ok(doc)
    }

    /// Read-modify-write under the lock. A failing closure skips the write
    /// and releases the lock. anyhow because this is a bin crate and the
    /// closure composes snapshot validation with store I/O.
    pub fn mutate<T, F>(&self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(&mut StateDoc) -> anyhow::Result<T>,
    {
        let _guard = self.lock()?;
        let mut doc = self.read()?;
        let out = f(&mut doc)?;
        self.write(&doc)?;
        Ok(out)
    }

    /// Write by replacement, never in place: a crash midway through an
    /// in-place rewrite would leave truncated JSON, and the next run would
    /// refuse to read it. The sync_all before the rename is a deliberate
    /// departure from reaper's store, which is a cache; this file is the
    /// truth about open break-glass access, so it must survive a power cut
    /// as either the old truth or the new one. The directory entry is not
    /// synced — that residual window is documented, not ignored.
    fn write(&self, doc: &StateDoc) -> Result<()> {
        let io_err = |path: &Path, source| StoreError::Io {
            path: path.to_path_buf(),
            source,
        };

        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir).map_err(|e| io_err(dir, e))?;
        }

        let text = serde_json::to_string_pretty(doc).map_err(|e| StoreError::Corrupt {
            path: self.path.clone(),
            message: e.to_string(),
        })?;

        let tmp = self
            .path
            .with_extension(format!("tmp.{}", std::process::id()));
        let write_synced = || -> io::Result<()> {
            let mut file = fs::File::create(&tmp)?;
            io::Write::write_all(&mut file, text.as_bytes())?;
            file.sync_all()
        };
        write_synced().map_err(|e| io_err(&tmp, e))?;
        fs::rename(&tmp, &self.path).map_err(|e| io_err(&self.path, e))
    }

    fn lock_path(&self) -> PathBuf {
        self.path.with_extension("lock")
    }

    fn lock(&self) -> Result<LockGuard> {
        let path = self.lock_path();
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| StoreError::Io {
                path: dir.to_path_buf(),
                source: e,
            })?;
        }

        let deadline = SystemTime::now() + self.lock_timeout;
        loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Ok(LockGuard { path }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(StoreError::Io {
                        path: path.clone(),
                        source: e,
                    })
                }
            }

            // A lock nobody released is worse than no lock: it wedges every
            // future run. Age it out rather than requiring a person to know
            // this file exists.
            let held_for = fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| SystemTime::now().duration_since(m).ok())
                .unwrap_or_default();
            if held_for > self.stale_lock_after {
                // Steal by rename, then retry the create. rename is atomic,
                // so when two waiters age the same lock out only one wins
                // the steal — remove-then-create would let both "acquire" it
                // and reintroduce the lost update the lock exists to
                // prevent. The deadline check below still runs: a steal that
                // keeps failing (an unwritable directory) must end in
                // Locked, not a spin.
                let stale = path.with_extension(format!("lock.stale.{}", std::process::id()));
                if fs::rename(&path, &stale).is_ok() {
                    let _ = fs::remove_file(&stale);
                }
            }

            if SystemTime::now() >= deadline {
                return Err(StoreError::Locked { path, held_for });
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests;
