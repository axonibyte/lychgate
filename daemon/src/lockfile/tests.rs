use super::*;

use std::time::Instant;

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lychgate-lockfile-{}-{}-{name}",
        std::process::id(),
        // A per-call salt so parallel tests never share a path; the counter is
        // process-local and monotonic.
        {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            N.fetch_add(1, Ordering::Relaxed)
        }
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("thing.lock")
}

// A PID that cannot name a live process on any supported host (well past the
// pid_max of Linux/FreeBSD), so kill(pid, 0) is ESRCH — deterministically dead,
// with no reuse race.
const DEAD_PID: &str = "999999999";

#[test]
fn a_dead_holders_lock_is_stolen_immediately() {
    // A crashed daemon left a *fresh* lock naming a dead PID. Acquire must steal
    // it at once, not wait out the long stale window — so a short timeout still
    // succeeds. (If the steal did not fire, this would return Held after 300ms.)
    let path = tmp("deadholder");
    std::fs::write(&path, DEAD_PID).unwrap();

    let started = Instant::now();
    let guard = acquire(
        &path,
        Duration::from_millis(300),
        Duration::from_secs(3_600),
    );
    assert!(
        guard.is_ok(),
        "a dead holder's lock must be stolen immediately"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the steal should be immediate, not a wait: took {:?}",
        started.elapsed()
    );
    // The guard now owns the lock and records *our* live PID.
    assert_eq!(
        holder_pid(&path),
        Some(std::process::id()),
        "the new holder records its own PID"
    );
    drop(guard);
    assert!(!path.exists(), "dropping the guard removes the lock");
}

#[test]
fn a_live_holders_lock_is_respected() {
    // The second oracle: a lock naming a LIVE process (ourselves) that is not yet
    // stale must NOT be stolen — acquire waits and then reports Held. This is
    // what stops the dead-PID steal from also cannibalising a genuine holder.
    let path = tmp("liveholder");
    std::fs::write(&path, std::process::id().to_string()).unwrap();

    let started = Instant::now();
    let result = acquire(
        &path,
        Duration::from_millis(200),
        Duration::from_secs(3_600),
    );
    assert!(
        matches!(result, Err(LockError::Held { .. })),
        "a live holder's lock must be respected, not stolen"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "acquire should have waited out the timeout, not stolen early"
    );
    // The live holder's lock is untouched.
    assert_eq!(holder_pid(&path), Some(std::process::id()));
}

#[test]
fn an_unreadable_pid_falls_back_to_age_based_staleness() {
    // A lock with no PID (a holder that created it but crashed before writing,
    // or a pre-PID lock) is not treated as dead: acquire respects it until it
    // ages out. A fresh empty lock under a long stale window is held.
    let path = tmp("nopid");
    std::fs::write(&path, "").unwrap();

    let result = acquire(
        &path,
        Duration::from_millis(150),
        Duration::from_secs(3_600),
    );
    assert!(
        matches!(result, Err(LockError::Held { .. })),
        "an empty (unreadable-PID) fresh lock is respected, not stolen as dead"
    );
}

#[test]
fn a_free_path_is_acquired_and_released() {
    let path = tmp("free");
    let guard = acquire(
        &path,
        Duration::from_millis(200),
        Duration::from_secs(3_600),
    )
    .ok()
    .expect("a free path acquires");
    assert!(path.exists());
    drop(guard);
    assert!(!path.exists());
}
