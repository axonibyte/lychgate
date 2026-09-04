use super::*;
use crate::scratch::scratch_dir;

use std::collections::BTreeMap;
use std::time::UNIX_EPOCH;

use lychgate_core::{Channel, GrantRecord};

fn doc_with(host: &str) -> StateDoc {
    StateDoc {
        version: STATE_VERSION,
        grants: BTreeMap::from([(
            host.to_string(),
            GrantRecord {
                state: "open".to_string(),
                opened_at: Some(UNIX_EPOCH + Duration::from_secs(1_000)),
                expires_at: Some(UNIX_EPOCH + Duration::from_secs(1_600)),
                since: None,
                channels: vec![Channel::Ssh],
            },
        )]),
    }
}

#[test]
fn a_store_that_has_never_been_written_is_empty_rather_than_broken() {
    // Bind the guard: chaining scratch_dir(..).join(..) drops the directory
    // at the end of the statement and leaves the path dangling.
    let dir = scratch_dir("absent");
    let store = Store::at(dir.join("grants.json"));
    assert_eq!(store.read().unwrap(), StateDoc::default());
}

#[test]
fn a_state_doc_round_trips_through_the_store() {
    let dir = scratch_dir("roundtrip");
    let store = Store::at(dir.join("grants.json"));
    store
        .mutate(|doc| {
            *doc = doc_with("db-01");
            Ok(())
        })
        .unwrap();
    assert_eq!(store.read().unwrap(), doc_with("db-01"));
}

#[test]
fn writes_replace_the_file_rather_than_editing_it_in_place() {
    // The temp file must be gone and the real file whole. A half-written
    // store is worse than an absent one.
    let dir = scratch_dir("atomic");
    let path = dir.join("grants.json");
    let store = Store::at(&path);
    store
        .mutate(|doc| {
            *doc = doc_with("db-01");
            Ok(())
        })
        .unwrap();

    let leftovers: Vec<_> = std::fs::read_dir(&*dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.contains("tmp") || n.contains("lock"))
        .collect();
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
    assert!(
        serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(&path).unwrap()).is_ok()
    );
}

#[test]
fn a_corrupt_store_is_reported_not_silently_emptied() {
    // Silently treating unreadable state as "no grants" would forget that
    // break-glass access is open, which is the one outcome this design must
    // never produce quietly.
    let dir = scratch_dir("corrupt");
    let path = dir.join("grants.json");
    std::fs::write(&path, "{ this is not json").unwrap();
    let e = Store::at(&path).read().expect_err("should refuse");
    assert!(e.to_string().contains("unreadable"), "{e}");
    assert!(e.to_string().contains("grants.json"), "{e}");
}

#[test]
fn a_store_from_another_version_is_refused_rather_than_misread() {
    let dir = scratch_dir("version");
    let path = dir.join("grants.json");
    std::fs::write(&path, r#"{"version":99,"grants":{}}"#).unwrap();
    let e = Store::at(&path).read().expect_err("should refuse");
    let msg = e.to_string();
    // Both versions named: the file's (99) and the one this binary speaks.
    assert!(
        msg.contains("99") && msg.contains(&STATE_VERSION.to_string()),
        "{msg}"
    );
    assert!(msg.contains("different version"), "{msg}");
}

#[test]
fn a_stale_lock_is_aged_out_rather_than_wedging_every_future_run() {
    let dir = scratch_dir("stalelock");
    let path = dir.join("grants.json");
    let lock = dir.join("grants.lock");
    std::fs::write(&lock, "").unwrap();

    // Backdate it well past the staleness threshold.
    let old = SystemTime::now() - Duration::from_secs(3_600);
    let f = std::fs::File::open(&lock).unwrap();
    f.set_modified(old).unwrap();
    drop(f);

    Store::at(&path)
        .mutate(|doc| {
            *doc = doc_with("db-01");
            Ok(())
        })
        .expect("a stale lock should not block forever");
}

#[test]
fn an_unstealable_stale_lock_ends_in_locked_not_a_spin() {
    // With the directory unwritable the steal cannot succeed; the old shape
    // of this loop (in reaper, where this store comes from) skipped both the
    // deadline and the sleep and span forever at 100% CPU. The wedge binds
    // only where DAC binds: as root the "unstealable" lock is simply stolen,
    // and that branch is asserted instead. What neither world may do is spin.
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch_dir("wedgedlock");
    let path = dir.join("grants.json");
    let lock = dir.join("grants.lock");
    let probe = dir.join("probe");
    std::fs::write(&lock, "").unwrap();
    std::fs::write(&probe, "").unwrap();
    let f = std::fs::File::open(&lock).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(3_600))
        .unwrap();
    drop(f);
    std::fs::set_permissions(&*dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let wedge_holds = std::fs::remove_file(&probe).is_err();

    let store = Store::with_timeouts(&path, Duration::from_millis(300), Duration::from_secs(120));
    let started = std::time::Instant::now();
    let result = store.mutate(|_| Ok(()));
    // Permissions come back BEFORE any assertion: a test that can only be
    // cleaned up when it passes leaks an unremovable directory when it fails.
    std::fs::set_permissions(&*dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    if wedge_holds {
        let e = result.expect_err("should refuse");
        assert!(
            e.downcast_ref::<StoreError>()
                .is_some_and(|e| matches!(e, StoreError::Locked { .. })),
            "wanted Locked, got {e}"
        );
    } else {
        result.expect("a stealable stale lock is stolen, not fatal");
    }
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "took {:?}: the loop must end at the deadline, not spin",
        started.elapsed()
    );
}

#[test]
fn a_contended_fresh_lock_times_out_as_locked_rather_than_waiting_forever() {
    let dir = scratch_dir("contended");
    let path = dir.join("grants.json");
    // A fresh lock held by "someone else": mtime is now, so it is not stale.
    std::fs::write(dir.join("grants.lock"), "").unwrap();

    let store = Store::with_timeouts(&path, Duration::from_millis(300), Duration::from_secs(120));
    let e = store.mutate(|_| Ok(())).expect_err("should time out");
    assert!(
        e.downcast_ref::<StoreError>()
            .is_some_and(|e| matches!(e, StoreError::Locked { .. })),
        "wanted Locked, got {e}"
    );
}

#[test]
fn probing_a_missing_store_does_not_create_it() {
    let dir = scratch_dir("probe");
    let path = dir.join("grants.json");
    Store::at(&path).probe_writable().unwrap();
    // An empty state file left behind by the probe would read as corrupt.
    assert!(!path.exists());
    // And nothing else may be left behind either.
    assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 0);
}

#[test]
fn an_unwritable_state_dir_fails_the_probe_before_any_work() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch_dir("unwritable");
    let path = dir.join("grants.json");
    std::fs::set_permissions(&*dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    // Root ignores DAC; probe the wedge like the lock test does.
    let wedge_holds = std::fs::write(dir.join("probe"), b"").is_err();
    let result = Store::at(&path).probe_writable();
    std::fs::set_permissions(&*dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let _ = std::fs::remove_file(dir.join("probe"));
    if wedge_holds {
        result.expect_err("an unwritable dir must fail the probe");
    } else {
        result.expect("root writes anywhere; the probe rightly passes");
    }
}

#[test]
fn a_mutation_that_fails_leaves_the_store_unchanged_and_the_lock_released() {
    let dir = scratch_dir("failedmutation");
    let path = dir.join("grants.json");
    let store = Store::at(&path);
    store
        .mutate(|doc| {
            *doc = doc_with("db-01");
            Ok(())
        })
        .unwrap();

    let e = store
        .mutate(|doc| -> anyhow::Result<()> {
            *doc = StateDoc::default();
            anyhow::bail!("validation refused this state")
        })
        .expect_err("the closure's error must surface");
    assert!(e.to_string().contains("refused"), "{e}");

    // Unchanged: the failed closure's edit never reached disk...
    assert_eq!(store.read().unwrap(), doc_with("db-01"));
    // ...and the lock is released, so the next mutation proceeds at once.
    store.mutate(|_| Ok(())).unwrap();
    assert!(!dir.join("grants.lock").exists());
}
