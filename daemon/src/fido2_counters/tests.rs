use super::*;

use crate::scratch::scratch_dir;

const CRED: &[u8] = &[0xabu8; 16];

fn ledger(dir: &crate::scratch::Scratch) -> Fido2Counters {
    Fido2Counters::at(dir.join("fido2-counters.json"))
}

#[test]
fn a_fresh_credential_and_an_advancing_counter_pass() {
    let dir = scratch_dir("f2c-advance");
    let l = ledger(&dir);
    assert_eq!(l.observe(CRED, 5).unwrap(), CounterVerdict::Ok);
    assert_eq!(l.observe(CRED, 6).unwrap(), CounterVerdict::Ok);
    assert_eq!(l.observe(CRED, 100).unwrap(), CounterVerdict::Ok);
}

#[test]
fn a_counter_that_does_not_advance_is_a_regression() {
    // The clone signal: equal or lower than the high-water mark.
    let dir = scratch_dir("f2c-regress");
    let l = ledger(&dir);
    assert_eq!(l.observe(CRED, 5).unwrap(), CounterVerdict::Ok);
    assert_eq!(l.observe(CRED, 5).unwrap(), CounterVerdict::Regressed);
    assert_eq!(l.observe(CRED, 4).unwrap(), CounterVerdict::Regressed);
    // A regression must not lower the mark: 6 still advances.
    assert_eq!(l.observe(CRED, 6).unwrap(), CounterVerdict::Ok);
}

#[test]
fn zero_means_no_counter_support_until_a_mark_exists() {
    let dir = scratch_dir("f2c-zero");
    let l = ledger(&dir);
    // Counterless authenticators (the software one) always pass with 0...
    assert_eq!(l.observe(CRED, 0).unwrap(), CounterVerdict::Ok);
    assert_eq!(l.observe(CRED, 0).unwrap(), CounterVerdict::Ok);
    // ...but once a device has counted, a sudden zero is the clone shape.
    assert_eq!(l.observe(CRED, 3).unwrap(), CounterVerdict::Ok);
    assert_eq!(l.observe(CRED, 0).unwrap(), CounterVerdict::Regressed);
}

#[test]
fn credentials_are_independent() {
    let dir = scratch_dir("f2c-indep");
    let l = ledger(&dir);
    assert_eq!(l.observe(CRED, 9).unwrap(), CounterVerdict::Ok);
    // A different credential starts fresh; CRED's mark is untouched by it.
    assert_eq!(l.observe(&[0x01u8; 16], 2).unwrap(), CounterVerdict::Ok);
    assert_eq!(l.observe(CRED, 9).unwrap(), CounterVerdict::Regressed);
}

#[test]
fn the_marks_survive_a_reopen() {
    // Durability: a restart must not forget the high-water marks, or a clone
    // could replay freely after every daemon restart.
    let dir = scratch_dir("f2c-durable");
    {
        let l = ledger(&dir);
        assert_eq!(l.observe(CRED, 7).unwrap(), CounterVerdict::Ok);
    }
    let l2 = ledger(&dir);
    assert_eq!(l2.observe(CRED, 7).unwrap(), CounterVerdict::Regressed);
    assert_eq!(l2.observe(CRED, 8).unwrap(), CounterVerdict::Ok);
}

#[test]
fn a_corrupt_ledger_refuses_rather_than_forgetting() {
    let dir = scratch_dir("f2c-corrupt");
    std::fs::write(dir.join("fido2-counters.json"), "{ not json").unwrap();
    let l = ledger(&dir);
    assert!(
        l.observe(CRED, 5).is_err(),
        "corrupt must refuse, not reset"
    );
}
