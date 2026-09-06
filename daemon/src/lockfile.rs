//! A cooperative lock file, shared by the grant store and the TOTP ledger.
//!
//! Acquired by exclusive create (`create_new`); the holder records its PID in
//! the file so a later waiter can tell a **crashed** holder (whose PID is gone)
//! from a **live** one, and steal a dead holder's lock at once rather than
//! waiting out the stale-age window or failing its acquire. A daemon SIGKILLed
//! mid-mutation leaves its lock behind; without this a restart within the stale
//! window would wedge on the acquire timeout. Aging by mtime remains the
//! backstop — for a holder on another host, or a lock whose PID is unreadable.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub enum LockError {
    /// The lock stayed held past the acquire deadline.
    Held { held_for: Duration },
    /// An I/O error other than the lock being held.
    Io(io::Error),
}

/// Holds a lock file for its lifetime; removes it on drop.
pub struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Acquire `path` as a lock, waiting up to `lock_timeout`. A held lock is stolen
/// immediately when its recorded holder PID is dead, or once the file is older
/// than `stale_lock_after` (the backstop for an unreadable PID or a cross-host
/// holder). Returns `LockError::Held` if it never comes free within the timeout.
pub fn acquire(
    path: &Path,
    lock_timeout: Duration,
    stale_lock_after: Duration,
) -> Result<LockGuard, LockError> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(LockError::Io)?;
    }
    let deadline = SystemTime::now() + lock_timeout;
    loop {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(mut file) => {
                // Record the holder so a later waiter can detect a crash. Best
                // effort: if the write fails the lock still holds, and a waiter
                // that cannot read a PID falls back to the age-based steal.
                let _ = write!(file, "{}", std::process::id());
                return Ok(LockGuard {
                    path: path.to_path_buf(),
                });
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(LockError::Io(e)),
        }

        let held_for = fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| SystemTime::now().duration_since(m).ok())
            .unwrap_or_default();
        // A crashed holder's PID no longer exists: steal at once rather than
        // making the next daemon wait out the stale window (or fail) after a
        // SIGKILL. Aging is the backstop for an unreadable/cross-host holder.
        let holder_dead = holder_pid(path).is_some_and(|pid| !pid_alive(pid));
        if holder_dead || held_for > stale_lock_after {
            // Steal by atomic rename so only one waiter wins; remove-then-create
            // would let two "acquire" it and reintroduce the lost update the lock
            // exists to prevent. A steal that keeps failing (an unwritable
            // directory) still ends at the deadline below, not in a spin.
            let stale = path.with_extension(format!("lock.stale.{}", std::process::id()));
            if fs::rename(path, &stale).is_ok() {
                let _ = fs::remove_file(&stale);
            }
        }

        if SystemTime::now() >= deadline {
            return Err(LockError::Held { held_for });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The PID recorded in a lock file, if it holds a parseable one. `None` for an
/// empty file — a holder that created the lock but had not yet written its PID,
/// or a lock from before PIDs were recorded — so the caller falls back to
/// age-based staleness rather than treating an unknown holder as dead.
fn holder_pid(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Whether a process with `pid` exists on this host. `kill(pid, 0)` sends no
/// signal: it returns 0 when the process exists, sets `EPERM` when it exists but
/// we may not signal it, and `ESRCH` when it does not. On PID reuse an unrelated
/// live process reads as alive — the safe direction, since we then wait rather
/// than steal a lock that might be genuinely held.
fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: `kill` is async-signal-safe and, with signal 0, only error-checks
    // the target; it mutates nothing in this process.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(test)]
mod tests;
