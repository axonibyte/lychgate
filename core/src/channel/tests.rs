use super::fakes::{CallLog, FakeDriver, Script};
use super::*;
use crate::inventory::Inventory;

use std::sync::{Arc, Mutex};

fn host() -> Host {
    Inventory::parse(
        r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "freebsd"
        channels = ["ssh", "authorized-keys", "bmc"]

[hosts.ssh]
agent_user = "lychgate"
root_posture_default = "no"
root_posture_emergency = "prohibit-password"
emergency_keys = ["ssh-ed25519 EMERG breakglass"]

[hosts.bmc]
endpoint = "https://10.0.9.5"
method = "redfish"
account_user = "breakglass"
account_id = "4"
auth_user = "admin"
auth_password_file = "/etc/lychgate/bmc.pw"
tls = { mode = "insecure" }
        "#,
    )
    .unwrap()
    .hosts
    .remove(0)
}

fn set_with(scripts: &[(Channel, Script)]) -> (DriverSet, CallLog) {
    let log: CallLog = Arc::new(Mutex::new(Vec::new()));
    let mut set = DriverSet::new();
    for &(channel, script) in scripts {
        set.register(FakeDriver::new(channel, script, Arc::clone(&log)))
            .unwrap();
    }
    (set, log)
}

const ALL: [Channel; 3] = [Channel::Ssh, Channel::AuthorizedKeys, Channel::Bmc];

#[test]
fn a_clean_apply_opens_every_channel_in_declaration_order() {
    let (mut set, log) = set_with(&[
        (Channel::Ssh, Script::Succeed),
        (Channel::AuthorizedKeys, Script::Succeed),
        (Channel::Bmc, Script::Succeed),
    ]);
    let outcome = apply_channels(&mut set, &host(), &ALL);
    assert_eq!(
        outcome,
        ApplyOutcome::Applied {
            applied: ALL.to_vec()
        }
    );
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            (Channel::Ssh, "apply"),
            (Channel::AuthorizedKeys, "apply"),
            (Channel::Bmc, "apply"),
        ]
    );
}

#[test]
fn a_mid_sequence_failure_reverts_the_applied_prefix_in_reverse() {
    let (mut set, log) = set_with(&[
        (Channel::Ssh, Script::Succeed),
        (Channel::AuthorizedKeys, Script::Succeed),
        (Channel::Bmc, Script::FailApply),
    ]);
    let outcome = apply_channels(&mut set, &host(), &ALL);
    match outcome {
        ApplyOutcome::Failed {
            failed,
            reverted,
            stuck,
            ..
        } => {
            assert_eq!(failed, Channel::Bmc);
            // The failed channel first (it may be half applied), then the
            // prefix in reverse.
            assert_eq!(
                reverted,
                vec![Channel::Bmc, Channel::AuthorizedKeys, Channel::Ssh]
            );
            assert_eq!(stuck, Vec::new());
        }
        other => panic!("wanted Failed, got {other:?}"),
    }
    // Second oracle: the calls themselves, in order — the unwind really
    // happened, and nothing was applied after the failure.
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            (Channel::Ssh, "apply"),
            (Channel::AuthorizedKeys, "apply"),
            (Channel::Bmc, "apply"),
            (Channel::Bmc, "revert"),
            (Channel::AuthorizedKeys, "revert"),
            (Channel::Ssh, "revert"),
        ]
    );
}

#[test]
fn a_first_channel_failure_applies_nothing_else() {
    let (mut set, log) = set_with(&[
        (Channel::Ssh, Script::FailApply),
        (Channel::AuthorizedKeys, Script::Succeed),
        (Channel::Bmc, Script::Succeed),
    ]);
    let outcome = apply_channels(&mut set, &host(), &ALL);
    match outcome {
        ApplyOutcome::Failed {
            failed,
            reverted,
            stuck,
            ..
        } => {
            assert_eq!(failed, Channel::Ssh);
            assert_eq!(reverted, vec![Channel::Ssh]);
            assert_eq!(stuck, Vec::new());
        }
        other => panic!("wanted Failed, got {other:?}"),
    }
    // Absence asserted, not just presence: the later channels were never
    // touched.
    let touched: Vec<Channel> = log.lock().unwrap().iter().map(|(c, _)| *c).collect();
    assert!(!touched.contains(&Channel::AuthorizedKeys), "{touched:?}");
    assert!(!touched.contains(&Channel::Bmc), "{touched:?}");
}

#[test]
fn an_unwind_that_cannot_revert_reports_the_stuck_channels() {
    let (mut set, _log) = set_with(&[
        (Channel::Ssh, Script::FailRevert), // applies fine, will not revert
        (Channel::AuthorizedKeys, Script::Succeed),
        (Channel::Bmc, Script::FailApply),
    ]);
    let outcome = apply_channels(&mut set, &host(), &ALL);
    match outcome {
        ApplyOutcome::Failed {
            failed,
            reverted,
            stuck,
            ..
        } => {
            assert_eq!(failed, Channel::Bmc);
            assert_eq!(reverted, vec![Channel::Bmc, Channel::AuthorizedKeys]);
            // ssh applied but its revert is scripted to fail: stuck, loudly.
            assert_eq!(stuck, vec![Channel::Ssh]);
        }
        other => panic!("wanted Failed, got {other:?}"),
    }
}

#[test]
fn revert_attempts_every_channel_even_after_a_failure() {
    let (mut set, log) = set_with(&[
        (Channel::Ssh, Script::Succeed),
        (Channel::AuthorizedKeys, Script::FailRevert),
        (Channel::Bmc, Script::Succeed),
    ]);
    let outcome = revert_channels(&mut set, &host(), &ALL);
    match outcome {
        RevertOutcome::Stuck { stuck } => {
            assert_eq!(stuck.len(), 1);
            assert_eq!(stuck[0].0, Channel::AuthorizedKeys);
            assert!(!stuck[0].1.to_string().is_empty());
        }
        other => panic!("wanted Stuck, got {other:?}"),
    }
    // All three were attempted, in reverse of application order.
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            (Channel::Bmc, "revert"),
            (Channel::AuthorizedKeys, "revert"),
            (Channel::Ssh, "revert"),
        ]
    );
}

#[test]
fn a_clean_revert_reports_reverted() {
    let (mut set, _log) = set_with(&[(Channel::Ssh, Script::Succeed)]);
    assert_eq!(
        revert_channels(&mut set, &host(), &[Channel::Ssh]),
        RevertOutcome::Reverted
    );
}

#[test]
fn reverting_a_channel_with_no_driver_is_stuck_not_skipped() {
    // A channel recorded as applied whose driver has since vanished cannot
    // be silently dropped: nobody else will ever revert it.
    let (mut set, _log) = set_with(&[(Channel::Ssh, Script::Succeed)]);
    let outcome = revert_channels(&mut set, &host(), &[Channel::Ssh, Channel::Bmc]);
    match outcome {
        RevertOutcome::Stuck { stuck } => {
            assert_eq!(stuck.len(), 1);
            assert_eq!(stuck[0].0, Channel::Bmc);
            assert!(
                stuck[0].1.to_string().contains("no driver"),
                "{}",
                stuck[0].1
            );
        }
        other => panic!("wanted Stuck, got {other:?}"),
    }
}

#[test]
fn a_second_driver_for_the_same_channel_is_refused() {
    let log: CallLog = Arc::new(Mutex::new(Vec::new()));
    let mut set = DriverSet::new();
    set.register(FakeDriver::new(
        Channel::Ssh,
        Script::Succeed,
        Arc::clone(&log),
    ))
    .unwrap();
    let err = set
        .register(FakeDriver::new(Channel::Ssh, Script::Succeed, log))
        .unwrap_err();
    assert!(err.to_string().contains("already registered"));
}

#[test]
fn drivable_filters_to_registered_channels_preserving_order() {
    let (set, _log) = set_with(&[
        (Channel::Bmc, Script::Succeed),
        (Channel::Ssh, Script::Succeed),
    ]);
    assert_eq!(
        set.drivable(&[Channel::Ssh, Channel::AuthorizedKeys, Channel::Bmc]),
        vec![Channel::Ssh, Channel::Bmc]
    );
    assert_eq!(DriverSet::new().drivable(&ALL), Vec::<Channel>::new());
}

#[test]
fn fake_verify_reads_the_state_the_fake_host_is_actually_in() {
    // Self-test of the fakes: verify must reflect apply/revert, or the
    // higher tiers' second oracle is reading a constant.
    let (mut set, log) = set_with(&[(Channel::Ssh, Script::Succeed)]);
    let h = host();
    fn driver(set: &mut DriverSet) -> &mut Box<dyn ChannelDriver + Send> {
        set.drivers.get_mut(&Channel::Ssh).unwrap()
    }
    assert_eq!(driver(&mut set).verify(&h).unwrap(), ChannelState::Closed);
    driver(&mut set).apply(&h).unwrap();
    assert_eq!(driver(&mut set).verify(&h).unwrap(), ChannelState::Open);
    driver(&mut set).revert(&h).unwrap();
    assert_eq!(driver(&mut set).verify(&h).unwrap(), ChannelState::Closed);
    assert_eq!(log.lock().unwrap().len(), 5);
}

#[test]
fn a_failed_apply_still_shows_open_on_the_fake_host() {
    // The atomic-or-reported worst case: apply errored but the access is
    // half open. The fakes must model it or the error-injection tier tests
    // a kinder world than the real one.
    let (mut set, _log) = set_with(&[(Channel::Ssh, Script::FailApply)]);
    let h = host();
    let d = set.drivers.get_mut(&Channel::Ssh).unwrap();
    assert!(d.apply(&h).is_err());
    assert_eq!(d.verify(&h).unwrap(), ChannelState::Open);
}

#[test]
fn a_channel_that_fails_apply_and_wont_revert_is_stuck_itself() {
    let (mut set, _log) = set_with(&[
        (Channel::Ssh, Script::Succeed),
        (Channel::AuthorizedKeys, Script::FailBoth),
    ]);
    let outcome = apply_channels(&mut set, &host(), &[Channel::Ssh, Channel::AuthorizedKeys]);
    match outcome {
        ApplyOutcome::Failed {
            failed,
            reverted,
            stuck,
            ..
        } => {
            assert_eq!(failed, Channel::AuthorizedKeys);
            // The prefix unwound fine; the half-applied failer itself is
            // what remains stuck.
            assert_eq!(reverted, vec![Channel::Ssh]);
            assert_eq!(stuck, vec![Channel::AuthorizedKeys]);
        }
        other => panic!("wanted Failed, got {other:?}"),
    }
}
