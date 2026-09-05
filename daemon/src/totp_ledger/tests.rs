use super::*;

use crate::scratch::scratch_dir;

fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

#[test]
fn a_fresh_code_is_consumed_once_and_then_replays_are_refused() {
    let dir = scratch_dir("totp-ledger");
    let ledger = TotpLedger::at(dir.join("totp-ledger.json"));
    // First use: newly consumed.
    assert!(ledger.consume("phone", 42, t(1_000)).unwrap());
    // Replay of the same (authenticator, counter): refused.
    assert!(!ledger.consume("phone", 42, t(1_000)).unwrap());
    assert!(!ledger.consume("phone", 42, t(1_010)).unwrap());
}

#[test]
fn a_different_counter_or_authenticator_is_independent() {
    let dir = scratch_dir("totp-ledger-indep");
    let ledger = TotpLedger::at(dir.join("totp-ledger.json"));
    assert!(ledger.consume("phone", 42, t(1_000)).unwrap());
    // A later step is a different counter — fresh.
    assert!(ledger.consume("phone", 43, t(1_030)).unwrap());
    // A different authenticator at the same counter is fresh.
    assert!(ledger.consume("yubi", 42, t(1_000)).unwrap());
}

#[test]
fn a_consumed_code_stays_consumed_across_a_reload() {
    // The anti-replay guarantee must survive a daemon restart within the window:
    // a fresh TotpLedger over the same file still refuses the replay.
    let dir = scratch_dir("totp-ledger-reload");
    let path = dir.join("totp-ledger.json");
    assert!(TotpLedger::at(&path).consume("phone", 7, t(1_000)).unwrap());
    // A brand-new ledger handle, as a restarted daemon would open.
    assert!(!TotpLedger::at(&path).consume("phone", 7, t(1_005)).unwrap());
}

#[test]
fn stale_entries_are_pruned_so_the_file_stays_bounded() {
    let dir = scratch_dir("totp-ledger-prune");
    let path = dir.join("totp-ledger.json");
    let ledger = TotpLedger::at(&path);
    ledger.consume("phone", 1, t(1_000)).unwrap();
    // Far in the future, past the retain window: the old entry is pruned...
    ledger
        .consume("phone", 999, t(1_000 + RETAIN_SECS + 60))
        .unwrap();
    let ids: Vec<_> = ledger.consumed_ids().into_iter().collect();
    // Only the recent entry remains (both share the id "phone", so assert on the
    // document directly): the pruned counter 1 could be replayed with no harm
    // now (its window is long gone), which is the whole point of pruning.
    let doc = ledger.read().unwrap();
    assert_eq!(doc.consumed.len(), 1, "the stale counter should be pruned");
    assert_eq!(doc.consumed[0].counter, 999);
    assert_eq!(ids, ["phone"]);
}

#[test]
fn a_corrupt_ledger_is_refused_not_silently_emptied() {
    // Fail-closed: forgetting which codes were spent would reopen the replay
    // window, so a corrupt ledger errors rather than reading as empty.
    let dir = scratch_dir("totp-ledger-corrupt");
    let path = dir.join("totp-ledger.json");
    std::fs::write(&path, "{ not json").unwrap();
    assert!(TotpLedger::at(&path).consume("phone", 1, t(1_000)).is_err());
}
