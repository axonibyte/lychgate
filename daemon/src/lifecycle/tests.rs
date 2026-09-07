//! The error-injection tier: the grant lifecycle driven against scripted
//! fakes, with two oracles per claim — what the registry reports (read back
//! from committed state) AND what the fakes' call log shows really happened.

use super::*;
use crate::scratch::scratch_dir;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use lychgate_core::channel::fakes::{CallLog, FakeDriver, Script};
use lychgate_core::proto::{GrantState, Op, ResponseResult};
use lychgate_core::{Channel, GrantRegistry};

const INVENTORY: &str = r#"
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

[[hosts]]
name = "gadget-01"
address = "10.0.9.31"
os = "embedded"
channels = ["http"]

# verify = "none" on purpose: the narrowings test proves the reduced claim is
# SURFACED in the open response, not only configured in the inventory.
[hosts.http]
endpoint = "https://10.0.9.31:8443"
tls = { mode = "insecure" }
verify = "none"

[hosts.http.open]
method = "POST"
path = "/api/maint"
expect_status = 200

[hosts.http.revert]
method = "POST"
path = "/api/maint"
expect_status = 200
"#;

/// A scripted dead-man: logs every call, fails on demand, reports firing.
struct FakeDeadman {
    log: Arc<Mutex<Vec<String>>>,
    fail_install: bool,
    fail_remove: bool,
    fired: Arc<Mutex<bool>>,
}

impl crate::drivers::deadman::DeadmanControl for FakeDeadman {
    fn install(
        &mut self,
        host: &Host,
        expires_at: SystemTime,
    ) -> Result<(), lychgate_core::DriverError> {
        self.log
            .lock()
            .unwrap()
            .push(format!("install {} {}", host.name, epoch_secs(expires_at)));
        if self.fail_install {
            return Err(lychgate_core::DriverError(
                "scripted install failure".into(),
            ));
        }
        Ok(())
    }

    fn remove(&mut self, host: &Host) -> Result<bool, lychgate_core::DriverError> {
        self.log
            .lock()
            .unwrap()
            .push(format!("remove {}", host.name));
        if self.fail_remove {
            return Err(lychgate_core::DriverError("scripted remove failure".into()));
        }
        Ok(*self.fired.lock().unwrap())
    }
}

struct Harness {
    daemon: Daemon,
    log: CallLog,
    deadman_log: Arc<Mutex<Vec<String>>>,
    deadman_fired: Arc<Mutex<bool>>,
    _dir: crate::scratch::Scratch,
}

impl Harness {
    fn new(scripts: &[(Channel, Script)]) -> Harness {
        Harness::with_deadman(scripts, false, false)
    }

    fn with_deadman(
        scripts: &[(Channel, Script)],
        fail_install: bool,
        fail_remove: bool,
    ) -> Harness {
        let dir = scratch_dir("lifecycle");
        let log: CallLog = Arc::new(Mutex::new(Vec::new()));
        let mut drivers = DriverSet::new();
        for &(channel, script) in scripts {
            drivers
                .register(FakeDriver::new(channel, script, Arc::clone(&log)))
                .unwrap();
        }
        let deadman_log = Arc::new(Mutex::new(Vec::new()));
        let deadman_fired = Arc::new(Mutex::new(false));
        let daemon = Daemon {
            inventory: Inventory::parse(INVENTORY).unwrap(),
            store: Store::at(dir.join("grants.json")),
            journal: Mutex::new(Journal::open(dir.join("journal.jsonl")).unwrap()),
            drivers: Mutex::new(drivers),
            deadman: Mutex::new(Box::new(FakeDeadman {
                log: Arc::clone(&deadman_log),
                fail_install,
                fail_remove,
                fired: Arc::clone(&deadman_fired),
            })),
            approval_window: std::time::Duration::from_secs(300),
            approval: None,
            totp_secrets: std::collections::BTreeMap::new(),
            totp_ledger: crate::totp_ledger::TotpLedger::at(dir.join("totp-ledger.json")),
            password_hashes: std::collections::BTreeMap::new(),
            fido2_counters: crate::fido2_counters::Fido2Counters::at(
                dir.join("fido2-counters.json"),
            ),
        };
        Harness {
            daemon,
            log,
            deadman_log,
            deadman_fired,
            _dir: dir,
        }
    }

    fn journal_events(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self._dir.join("journal.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn status(&self, now: SystemTime) -> Vec<(String, GrantState, Vec<Channel>)> {
        self.daemon
            .status(now)
            .unwrap()
            .into_iter()
            .map(|l| (l.host, l.state, l.stuck_channels.unwrap_or_default()))
            .collect()
    }

    fn state(&self, host: &str, now: SystemTime) -> GrantState {
        self.status(now)
            .into_iter()
            .find(|(h, _, _)| h == host)
            .map(|(_, s, _)| s)
            .unwrap()
    }

    fn calls(&self) -> Vec<(Channel, &'static str)> {
        self.log.lock().unwrap().clone()
    }

    /// The store on disk, read fresh — the second oracle's ground truth.
    fn committed(&self) -> lychgate_core::StateDoc {
        self.daemon.store.read().unwrap()
    }
}

fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Open then approve, so the grant actually opens (the Harness runs with
/// `approval: None` — dry-run-style — so the first proof opens). Returns the
/// final result — Ok once open,
/// or the refusal if the open itself was refused (e.g. AlreadyOpen/Already
/// Pending). The two steps run at the same `now`, well inside the approval
/// window.
fn open(h: &Harness, now: SystemTime, ttl: &str) -> ResponseResult {
    let requested = h
        .daemon
        .dispatch(
            &Op::Open {
                host: "db-01".into(),
                ttl: ttl.into(),
                profile: None,
            },
            now,
        )
        .unwrap();
    if requested.result != ResponseResult::Ok {
        return requested.result;
    }
    h.daemon
        .dispatch(
            &Op::Approve {
                host: "db-01".into(),
                token: "any-token".into(),
            },
            now,
        )
        .unwrap()
        .result
}

#[test]
fn a_clean_open_applies_every_drivable_channel_and_commits_open() {
    let h = Harness::new(&[
        (Channel::Ssh, Script::Succeed),
        (Channel::AuthorizedKeys, Script::Succeed),
        (Channel::Bmc, Script::Succeed),
    ]);
    assert_eq!(open(&h, t(0), "4h"), ResponseResult::Ok);
    // Oracle 1: committed state says open.
    assert_eq!(h.state("db-01", t(1)), GrantState::Open);
    assert_eq!(h.committed().grants["db-01"].state, "open");
    // Oracle 2: the drivers were actually applied, in order.
    assert_eq!(
        h.calls(),
        vec![
            (Channel::Ssh, "apply"),
            (Channel::AuthorizedKeys, "apply"),
            (Channel::Bmc, "apply"),
        ]
    );
}

#[test]
fn a_failed_open_that_unwinds_cleanly_leaves_the_grant_closed() {
    let h = Harness::new(&[
        (Channel::Ssh, Script::Succeed),
        (Channel::AuthorizedKeys, Script::Succeed),
        (Channel::Bmc, Script::FailApply), // fails; ssh+auth revert cleanly
    ]);
    assert_eq!(open(&h, t(0), "4h"), ResponseResult::Refused);
    // Oracle 1: nothing is open, and the store holds no grant for the host.
    assert_eq!(h.state("db-01", t(1)), GrantState::Closed);
    assert!(!h.committed().grants.contains_key("db-01"));
    // Oracle 2: the applied prefix (and the failer) were reverted.
    let calls = h.calls();
    assert!(calls.contains(&(Channel::Ssh, "revert")));
    assert!(calls.contains(&(Channel::AuthorizedKeys, "revert")));
}

#[test]
fn a_failed_open_whose_unwind_sticks_lands_in_needs_revert_not_open() {
    // ssh applies but will not revert; bmc's apply fails and triggers the
    // unwind. The half-applied ssh is stuck.
    let h = Harness::new(&[
        (Channel::Ssh, Script::FailRevert),
        (Channel::Bmc, Script::FailApply),
    ]);
    // Inventory order is ssh, authorized-keys, bmc; only ssh and bmc have
    // drivers, so the drivable sequence is [ssh, bmc].
    assert_eq!(open(&h, t(0), "4h"), ResponseResult::Refused);
    // Oracle 1: the grant is needs-revert, NOT open, and names ssh.
    assert_eq!(h.state("db-01", t(1)), GrantState::NeedsRevert);
    let record = &h.committed().grants["db-01"];
    assert_eq!(record.state, "needs-revert");
    assert_eq!(record.channels, vec![Channel::Ssh]);
    // Oracle 2: ssh's revert really was attempted (and failed).
    assert!(h.calls().contains(&(Channel::Ssh, "revert")));
}

#[test]
fn no_sequence_of_apply_failures_ever_reports_a_cleanly_open_grant() {
    // The headline M3 property, swept across which channel fails.
    for fail_at in [Channel::Ssh, Channel::AuthorizedKeys, Channel::Bmc] {
        let scripts: Vec<(Channel, Script)> = [Channel::Ssh, Channel::AuthorizedKeys, Channel::Bmc]
            .into_iter()
            .map(|c| {
                (
                    c,
                    if c == fail_at {
                        Script::FailApply
                    } else {
                        Script::Succeed
                    },
                )
            })
            .collect();
        let h = Harness::new(&scripts);
        assert_eq!(
            open(&h, t(0), "4h"),
            ResponseResult::Refused,
            "failing {fail_at:?}"
        );
        assert_ne!(
            h.state("db-01", t(1)),
            GrantState::Open,
            "a failure at {fail_at:?} left the grant open"
        );
    }
}

#[test]
fn a_stuck_revert_is_retried_by_the_pass_until_it_clears() {
    // A driver whose revert we can flip from failing to succeeding, so the
    // retry has something to succeed at.
    let dir = scratch_dir("retry");
    let log: CallLog = Arc::new(Mutex::new(Vec::new()));
    let mut drivers = DriverSet::new();
    // ssh: fails revert (stuck); bmc: applies and reverts fine.
    drivers
        .register(FakeDriver::new(
            Channel::Ssh,
            Script::FailBoth,
            Arc::clone(&log),
        ))
        .unwrap();
    let daemon = Daemon {
        inventory: Inventory::parse(INVENTORY).unwrap(),
        store: Store::at(dir.join("grants.json")),
        journal: Mutex::new(Journal::open(dir.join("journal.jsonl")).unwrap()),
        drivers: Mutex::new(drivers),
        deadman: Mutex::new(Box::new(FakeDeadman {
            log: Arc::new(Mutex::new(Vec::new())),
            fail_install: false,
            fail_remove: false,
            fired: Arc::new(Mutex::new(false)),
        })),
        approval_window: std::time::Duration::from_secs(300),
        approval: None,
        totp_secrets: std::collections::BTreeMap::new(),
        totp_ledger: crate::totp_ledger::TotpLedger::at(dir.join("totp-ledger.json")),
        password_hashes: std::collections::BTreeMap::new(),
        fido2_counters: crate::fido2_counters::Fido2Counters::at(dir.join("fido2-counters.json")),
    };

    // Open is requested, then approved — and the apply fails (ssh apply fails,
    // revert fails): needs-revert, stuck on ssh.
    daemon
        .dispatch(
            &Op::Open {
                host: "db-01".into(),
                ttl: "4h".into(),
                profile: None,
            },
            t(0),
        )
        .unwrap();
    daemon
        .dispatch(
            &Op::Approve {
                host: "db-01".into(),
                token: "any".into(),
            },
            t(0),
        )
        .unwrap();
    let reg = GrantRegistry::from_parts(
        &Inventory::parse(INVENTORY).unwrap(),
        &daemon.store.read().unwrap(),
    )
    .unwrap();
    assert!(!reg.needing_revert(t(1)).is_empty());

    // A pass retries and stays stuck (revert still fails).
    daemon.pass(t(2)).unwrap();
    assert_eq!(
        daemon.store.read().unwrap().grants["db-01"].state,
        "needs-revert"
    );

    // Flip ssh's driver to succeed on revert, then a pass clears it.
    {
        let mut drivers = daemon.drivers.lock().unwrap();
        *drivers = DriverSet::new();
        drivers
            .register(FakeDriver::new(
                Channel::Ssh,
                Script::Succeed,
                Arc::clone(&log),
            ))
            .unwrap();
    }
    daemon.pass(t(3)).unwrap();
    // Cleared: no grant for the host, nothing needing revert.
    assert!(!daemon.store.read().unwrap().grants.contains_key("db-01"));
}

#[test]
fn an_operator_close_reverts_the_channels_applied_at_open_time() {
    let h = Harness::new(&[
        (Channel::Ssh, Script::Succeed),
        (Channel::Bmc, Script::Succeed),
    ]);
    open(&h, t(0), "4h");
    let resp = h
        .daemon
        .dispatch(
            &Op::Close {
                host: "db-01".into(),
            },
            t(100),
        )
        .unwrap();
    assert_eq!(resp.result, ResponseResult::Ok);
    assert!(!h.committed().grants.contains_key("db-01"));
    // Both channels reverted (reverse order); asserted from the call log.
    let reverts: Vec<Channel> = h
        .calls()
        .into_iter()
        .filter(|(_, m)| *m == "revert")
        .map(|(c, _)| c)
        .collect();
    assert_eq!(reverts, vec![Channel::Bmc, Channel::Ssh]);
}

#[test]
fn an_expiry_reverts_through_needs_revert_and_the_drivers_run() {
    let h = Harness::new(&[(Channel::Ssh, Script::Succeed)]);
    open(&h, t(0), "600s"); // note: 600s, expires at t(600)
                            // A pass past expiry reaps to needs-revert and reverts in the same pass.
    h.daemon.pass(t(9_999)).unwrap();
    assert!(!h.committed().grants.contains_key("db-01"));
    assert!(h.calls().contains(&(Channel::Ssh, "revert")));
}

#[test]
fn an_expiry_whose_revert_sticks_stays_expired_looking_until_it_clears() {
    let h = Harness::new(&[(Channel::Ssh, Script::FailRevert)]);
    open(&h, t(0), "600s");
    h.daemon.pass(t(9_999)).unwrap();
    // The grant did not close: it is needs-revert, retried, never a silent
    // Closed.
    assert_eq!(h.state("db-01", t(9_999)), GrantState::NeedsRevert);
    assert_eq!(h.committed().grants["db-01"].state, "needs-revert");
}

#[test]
fn boot_recovery_demotes_a_stored_opening_to_needs_revert() {
    // Simulate a crash mid-open: write a store with an Opening grant, then
    // boot a fresh daemon over it.
    let dir = scratch_dir("bootrecover");
    let inv = Inventory::parse(INVENTORY).unwrap();
    let mut reg = GrantRegistry::new(&inv);
    reg.begin_open(
        "db-01",
        t(0),
        &lychgate_core::Ttl::from_secs(600).unwrap(),
        vec![Channel::Ssh, Channel::Bmc],
    )
    .unwrap();
    let store = Store::at(dir.join("grants.json"));
    store
        .mutate(|doc| {
            *doc = reg.snapshot();
            Ok(())
        })
        .unwrap();
    assert_eq!(store.read().unwrap().grants["db-01"].state, "opening");

    let daemon = Daemon {
        inventory: inv,
        store,
        journal: Mutex::new(Journal::open(dir.join("journal.jsonl")).unwrap()),
        drivers: Mutex::new(DriverSet::new()),
        deadman: Mutex::new(Box::new(FakeDeadman {
            log: Arc::new(Mutex::new(Vec::new())),
            fail_install: false,
            fail_remove: false,
            fired: Arc::new(Mutex::new(false)),
        })),
        approval_window: std::time::Duration::from_secs(300),
        approval: None,
        totp_secrets: std::collections::BTreeMap::new(),
        totp_ledger: crate::totp_ledger::TotpLedger::at(dir.join("totp-ledger.json")),
        password_hashes: std::collections::BTreeMap::new(),
        fido2_counters: crate::fido2_counters::Fido2Counters::at(dir.join("fido2-counters.json")),
    };
    daemon.boot_recover(t(10)).unwrap();
    // Demoted: every intended channel is now awaiting revert.
    let record = &daemon.store.read().unwrap().grants["db-01"];
    assert_eq!(record.state, "needs-revert");
    assert_eq!(record.channels, vec![Channel::Ssh, Channel::Bmc]);

    // And the demotion is on the audit record, not silent: a crash that
    // stranded access must leave a trace naming the host.
    let lines: Vec<serde_json::Value> = std::fs::read_to_string(dir.join("journal.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let demotion = lines
        .iter()
        .find(|l| l["event"] == "open-failed")
        .expect("boot recovery must journal the demotion");
    assert_eq!(demotion["host"], "db-01");
    assert!(
        demotion["error"].as_str().unwrap().contains("mid-open"),
        "{demotion}"
    );
}

#[test]
fn refusals_and_status_reads_change_no_state() {
    let h = Harness::new(&[(Channel::Ssh, Script::Succeed)]);
    // A bad TTL is refused and touches nothing.
    assert_eq!(open(&h, t(0), "25h"), ResponseResult::Refused);
    assert!(h.committed().grants.is_empty());
    assert!(h.calls().is_empty());
    // Status likewise.
    h.daemon.dispatch(&Op::Status, t(0)).unwrap();
    assert!(h.calls().is_empty());
}

#[test]
fn the_empty_production_driver_set_opens_and_closes_with_no_channels() {
    // The real M4-less daemon: nothing drivable, so open records Open with
    // an empty applied set and close reverts nothing — the lifecycle still
    // runs end to end.
    let h = Harness::new(&[]);
    assert_eq!(open(&h, t(0), "4h"), ResponseResult::Ok);
    assert_eq!(
        h.committed().grants["db-01"].channels,
        Vec::<Channel>::new()
    );
    assert!(h.calls().is_empty());
    let resp = h
        .daemon
        .dispatch(
            &Op::Close {
                host: "db-01".into(),
            },
            t(1),
        )
        .unwrap();
    assert_eq!(resp.result, ResponseResult::Ok);
    assert!(!h.committed().grants.contains_key("db-01"));
}

// --- M5: the dead-man backstop ---------------------------------------------

#[test]
fn opening_installs_the_deadman_after_the_channels_apply() {
    let h = Harness::new(&[(Channel::Ssh, Script::Succeed)]);
    assert_eq!(open(&h, t(0), "4h"), ResponseResult::Ok);
    // Installed with the grant's expiry baked in.
    assert_eq!(
        *h.deadman_log.lock().unwrap(),
        vec![format!("install db-01 {}", 4 * 3600)]
    );
    // Order: the channel applied before the backstop went in.
    assert_eq!(h.calls(), vec![(Channel::Ssh, "apply")]);
}

#[test]
fn a_deadman_install_failure_fails_the_open_and_unwinds_the_channels() {
    let h = Harness::with_deadman(&[(Channel::Ssh, Script::Succeed)], true, false);
    h.daemon
        .dispatch(
            &Op::Open {
                host: "db-01".into(),
                ttl: "4h".into(),
                profile: None,
            },
            t(0),
        )
        .unwrap();
    // The drivers run — and the dead-man install fails — on approve.
    let resp = h
        .daemon
        .dispatch(
            &Op::Approve {
                host: "db-01".into(),
                token: "any".into(),
            },
            t(0),
        )
        .unwrap();
    assert_eq!(resp.result, ResponseResult::Refused);
    assert!(
        resp.error.unwrap().contains("backstop"),
        "the refusal names the cause"
    );
    // Oracle 1: the grant is not open.
    assert_eq!(h.state("db-01", t(1)), GrantState::Closed);
    // Oracle 2: the freshly applied channel really was reverted.
    assert_eq!(
        h.calls(),
        vec![(Channel::Ssh, "apply"), (Channel::Ssh, "revert")]
    );
}

#[test]
fn closing_removes_the_deadman_only_after_the_channels_revert() {
    let h = Harness::new(&[(Channel::Ssh, Script::Succeed)]);
    open(&h, t(0), "4h");
    h.daemon
        .dispatch(
            &Op::Close {
                host: "db-01".into(),
            },
            t(100),
        )
        .unwrap();
    // The driver revert happened, then the removal.
    assert_eq!(
        h.calls(),
        vec![(Channel::Ssh, "apply"), (Channel::Ssh, "revert")]
    );
    let dlog = h.deadman_log.lock().unwrap().clone();
    assert_eq!(dlog.last().unwrap(), "remove db-01");
    // Journaled as not-fired: the daemon got there first.
    let close = h
        .journal_events()
        .into_iter()
        .find(|e| e["event"] == "close")
        .unwrap();
    assert_eq!(close["deadman_fired"], false);
}

#[test]
fn a_fired_deadman_is_journaled_on_the_eventual_close() {
    let h = Harness::new(&[(Channel::Ssh, Script::Succeed)]);
    open(&h, t(0), "600s");
    *h.deadman_fired.lock().unwrap() = true;
    // Expiry pass: reap, revert, remove — and the firing is on the record.
    h.daemon.pass(t(9_999)).unwrap();
    let close = h
        .journal_events()
        .into_iter()
        .find(|e| e["event"] == "close")
        .unwrap();
    assert_eq!(close["deadman_fired"], true);
}

#[test]
fn a_deadman_removal_failure_keeps_the_grant_needs_revert_and_the_backstop() {
    let h = Harness::with_deadman(&[(Channel::Ssh, Script::Succeed)], false, true);
    open(&h, t(0), "4h");
    let resp = h
        .daemon
        .dispatch(
            &Op::Close {
                host: "db-01".into(),
            },
            t(100),
        )
        .unwrap();
    assert_eq!(resp.result, ResponseResult::Refused);
    // Still needs-revert: retried, never silently closed while the removal
    // is unconfirmed — and the backstop stays in place while stuck.
    assert_eq!(h.state("db-01", t(101)), GrantState::NeedsRevert);
    assert!(h.journal_events().iter().all(|e| e["event"] != "close"));
    // Order oracle: the channels were reverted BEFORE the removal was even
    // attempted — the backstop is the last thing to go.
    assert!(
        h.calls().contains(&(Channel::Ssh, "revert")),
        "{:?}",
        h.calls()
    );
    assert_eq!(
        h.deadman_log.lock().unwrap().last().unwrap(),
        "remove db-01"
    );
}

#[test]
fn renew_reschedules_the_deadman_before_committing_the_new_expiry() {
    let h = Harness::new(&[(Channel::Ssh, Script::Succeed)]);
    open(&h, t(0), "600s");
    let resp = h
        .daemon
        .dispatch(
            &Op::Renew {
                host: "db-01".into(),
                ttl: "2h".into(),
            },
            t(550),
        )
        .unwrap();
    assert_eq!(resp.result, ResponseResult::Ok);
    // The reschedule carried the new expiry (550 + 7200).
    let dlog = h.deadman_log.lock().unwrap().clone();
    assert!(
        dlog.contains(&format!("install db-01 {}", 550 + 7200)),
        "{dlog:?}"
    );
    // And the store agrees.
    assert_eq!(
        h.committed().grants["db-01"].expires_at,
        Some(t(550 + 7200))
    );
}

#[test]
fn a_reschedule_failure_refuses_the_renewal_and_keeps_the_old_expiry() {
    let h = Harness::with_deadman(&[(Channel::Ssh, Script::Succeed)], true, false);
    // Install failure also fails the open, so open driverlessly: use a
    // grant whose channels skip the deadman (no ssh-borne channels applied
    // means no install at open)... instead, flip the fake after opening is
    // not possible; so open with install succeeding is required. Build a
    // second harness: open cleanly, then swap in a failing deadman.
    drop(h);
    let h = Harness::new(&[(Channel::Ssh, Script::Succeed)]);
    open(&h, t(0), "600s");
    *h.daemon.deadman.lock().unwrap() = Box::new(FakeDeadman {
        log: Arc::clone(&h.deadman_log),
        fail_install: true,
        fail_remove: false,
        fired: Arc::clone(&h.deadman_fired),
    });
    let resp = h
        .daemon
        .dispatch(
            &Op::Renew {
                host: "db-01".into(),
                ttl: "2h".into(),
            },
            t(550),
        )
        .unwrap();
    assert_eq!(resp.result, ResponseResult::Refused);
    assert!(resp.error.unwrap().contains("rescheduled"));
    // The expiry is unchanged: refusal means refusal.
    assert_eq!(h.committed().grants["db-01"].expires_at, Some(t(600)));
    // And no renew event reached the journal.
    assert!(h.journal_events().iter().all(|e| e["event"] != "renew"));
}

#[test]
fn hosts_whose_applied_channels_are_not_ssh_borne_get_no_deadman() {
    // No drivers registered: the open applies nothing, so there is nothing
    // for a backstop to revert and none is installed.
    let h = Harness::new(&[]);
    assert_eq!(open(&h, t(0), "4h"), ResponseResult::Ok);
    assert!(
        h.deadman_log.lock().unwrap().is_empty(),
        "a driverless grant grew a backstop"
    );
}

#[test]
fn a_bmc_style_secret_reaches_the_open_response_but_never_the_journal() {
    // A fake bmc driver yields a one-time password at apply. The operator
    // must get it in the open response; the journal must never contain it.
    use lychgate_core::channel::fakes::FakeDriver;
    let dir = scratch_dir("bmcsecret");
    let log: CallLog = Arc::new(Mutex::new(Vec::new()));
    let mut drivers = DriverSet::new();
    drivers
        .register(FakeDriver::with_secret(
            Channel::Bmc,
            Arc::clone(&log),
            "top-secret-bmc-pw",
        ))
        .unwrap();
    let daemon = Daemon {
        inventory: Inventory::parse(INVENTORY).unwrap(),
        store: Store::at(dir.join("grants.json")),
        journal: Mutex::new(Journal::open(dir.join("journal.jsonl")).unwrap()),
        drivers: Mutex::new(drivers),
        deadman: Mutex::new(Box::new(FakeDeadman {
            log: Arc::new(Mutex::new(Vec::new())),
            fail_install: false,
            fail_remove: false,
            fired: Arc::new(Mutex::new(false)),
        })),
        approval_window: std::time::Duration::from_secs(300),
        approval: None,
        totp_secrets: std::collections::BTreeMap::new(),
        totp_ledger: crate::totp_ledger::TotpLedger::at(dir.join("totp-ledger.json")),
        password_hashes: std::collections::BTreeMap::new(),
        fido2_counters: crate::fido2_counters::Fido2Counters::at(dir.join("fido2-counters.json")),
    };
    daemon
        .dispatch(
            &Op::Open {
                host: "db-01".into(),
                ttl: "4h".into(),
                profile: None,
            },
            t(0),
        )
        .unwrap();
    // The secret is produced on approve (where the grant actually opens), not
    // on the pending open.
    let resp = daemon
        .dispatch(
            &Op::Approve {
                host: "db-01".into(),
                token: "any".into(),
            },
            t(0),
        )
        .unwrap();
    // Oracle 1: the operator got the password in the (approve) response.
    assert_eq!(resp.secret.as_deref(), Some("top-secret-bmc-pw"));

    // Oracle 2: the journal file, read raw, contains no trace of it — not in
    // the open event, not anywhere.
    let raw = std::fs::read_to_string(dir.join("journal.jsonl")).unwrap();
    assert!(raw.contains("\"event\":\"open\""), "the open was journaled");
    assert!(
        !raw.contains("top-secret-bmc-pw"),
        "the secret leaked into the journal"
    );
}

// --- M7: vnc re-establishment and console serialization --------------------

const VNC_INVENTORY: &str = r#"
[[hosts]]
name = "hv"
address = "10.0.5.20"
os = "freebsd"
channels = ["vnc"]

[hosts.vnc]
agent_user = "lychgate"
rfb_port = 5900
local_port = 5959
target = "vm"
set_password_cmd = "set {target} {password_file}"
clear_password_cmd = "clear {target}"
"#;

fn dummy_deadman() -> Box<FakeDeadman> {
    Box::new(FakeDeadman {
        log: Arc::new(Mutex::new(Vec::new())),
        fail_install: false,
        fail_remove: false,
        fired: Arc::new(Mutex::new(false)),
    })
}

fn inject_open(dir: &std::path::Path, host: &str, opened: u64, expires: u64, channels: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("grants.json"),
        format!(
            r#"{{"version":2,"grants":{{"{host}":{{"state":"open","opened_at":{opened},"expires_at":{expires},"channels":{channels}}}}}}}"#
        ),
    )
    .unwrap();
}

#[test]
fn boot_reestablishes_an_open_vnc_grant_that_outlived_a_restart() {
    // A durably-open vnc grant plus a resource that survived (already_open →
    // reestablish reads Open): boot restores it and journals a reestablish,
    // and the grant stays open.
    let dir = scratch_dir("vnc-reest");
    let log: CallLog = Arc::new(Mutex::new(Vec::new()));
    let mut drivers = DriverSet::new();
    drivers
        .register(FakeDriver::already_open(
            Channel::Vnc,
            Script::Succeed,
            Arc::clone(&log),
        ))
        .unwrap();
    inject_open(&dir, "hv", 1000, 80_000, r#"["vnc"]"#);
    let daemon = Daemon {
        inventory: Inventory::parse(VNC_INVENTORY).unwrap(),
        store: Store::at(dir.join("grants.json")),
        journal: Mutex::new(Journal::open(dir.join("journal.jsonl")).unwrap()),
        drivers: Mutex::new(drivers),
        deadman: Mutex::new(dummy_deadman()),
        approval_window: std::time::Duration::from_secs(300),
        approval: None,
        totp_secrets: std::collections::BTreeMap::new(),
        totp_ledger: crate::totp_ledger::TotpLedger::at(dir.join("totp-ledger.json")),
        password_hashes: std::collections::BTreeMap::new(),
        fido2_counters: crate::fido2_counters::Fido2Counters::at(dir.join("fido2-counters.json")),
    };

    daemon.boot_recover(t(2000)).unwrap();

    // Still open, and re-establishment was recorded.
    assert_eq!(daemon.status(t(2000)).unwrap()[0].state, GrantState::Open);
    let events: Vec<String> = std::fs::read_to_string(dir.join("journal.jsonl"))
        .unwrap()
        .lines()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["event"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert!(events.contains(&"reestablish".to_string()), "{events:?}");
    // The default reestablish delegated to verify — a driver call, not a re-apply.
    let calls = log.lock().unwrap();
    assert!(calls.contains(&(Channel::Vnc, "verify")), "{calls:?}");
    assert!(
        !calls.contains(&(Channel::Vnc, "apply")),
        "reestablish must not re-apply: {calls:?}"
    );
}

#[test]
fn a_vnc_grant_whose_tunnel_cannot_be_reestablished_is_reverted() {
    // The resource did not survive (open=false → reestablish reads Closed):
    // boot demotes the grant to needs-revert rather than leave it half-open.
    let dir = scratch_dir("vnc-reest-lost");
    let log: CallLog = Arc::new(Mutex::new(Vec::new()));
    let mut drivers = DriverSet::new();
    drivers
        .register(FakeDriver::new(
            Channel::Vnc,
            Script::Succeed,
            Arc::clone(&log),
        ))
        .unwrap();
    inject_open(&dir, "hv", 1000, 80_000, r#"["vnc"]"#);
    let daemon = Daemon {
        inventory: Inventory::parse(VNC_INVENTORY).unwrap(),
        store: Store::at(dir.join("grants.json")),
        journal: Mutex::new(Journal::open(dir.join("journal.jsonl")).unwrap()),
        drivers: Mutex::new(drivers),
        deadman: Mutex::new(dummy_deadman()),
        approval_window: std::time::Duration::from_secs(300),
        approval: None,
        totp_secrets: std::collections::BTreeMap::new(),
        totp_ledger: crate::totp_ledger::TotpLedger::at(dir.join("totp-ledger.json")),
        password_hashes: std::collections::BTreeMap::new(),
        fido2_counters: crate::fido2_counters::Fido2Counters::at(dir.join("fido2-counters.json")),
    };

    daemon.boot_recover(t(2000)).unwrap();

    let line = &daemon.status(t(2000)).unwrap()[0];
    assert_eq!(line.state, GrantState::NeedsRevert);
    assert_eq!(line.stuck_channels.as_deref(), Some(&[Channel::Vnc][..]));
}

#[test]
fn simultaneous_opens_of_one_console_produce_one_grant_and_one_apply() {
    // Tier 6, the milestone's headline: N threads race to open the same host.
    // The store's file lock plus begin_pending (which refuses any non-Closed
    // grant) serialize them, so exactly one request goes pending and the losers
    // are refused — no driver runs yet. A single approve then opens it, and
    // exactly one apply runs: one tunnel, one password. The oracles are the
    // committed state (one pending, then one open) and the resource state (one
    // apply); response counts are only corroboration.
    let dir = scratch_dir("vnc-race");
    let log: CallLog = Arc::new(Mutex::new(Vec::new()));
    let mut drivers = DriverSet::new();
    drivers
        .register(FakeDriver::new(
            Channel::Vnc,
            Script::Succeed,
            Arc::clone(&log),
        ))
        .unwrap();
    let daemon = Arc::new(Daemon {
        inventory: Inventory::parse(VNC_INVENTORY).unwrap(),
        // A short lock timeout so a genuine deadlock fails fast rather than
        // hanging the suite; the fake apply is instant, so 16-way contention
        // resolves well within it.
        store: Store::with_timeouts(
            dir.join("grants.json"),
            Duration::from_secs(5),
            Duration::from_secs(120),
        ),
        journal: Mutex::new(Journal::open(dir.join("journal.jsonl")).unwrap()),
        drivers: Mutex::new(drivers),
        deadman: Mutex::new(dummy_deadman()),
        approval_window: std::time::Duration::from_secs(300),
        approval: None,
        totp_secrets: std::collections::BTreeMap::new(),
        totp_ledger: crate::totp_ledger::TotpLedger::at(dir.join("totp-ledger.json")),
        password_hashes: std::collections::BTreeMap::new(),
        fido2_counters: crate::fido2_counters::Fido2Counters::at(dir.join("fido2-counters.json")),
    });

    const N: usize = 16;
    let barrier = Arc::new(std::sync::Barrier::new(N));
    let handles: Vec<_> = (0..N)
        .map(|_| {
            let d = Arc::clone(&daemon);
            let b = Arc::clone(&barrier);
            std::thread::spawn(move || {
                b.wait();
                d.dispatch(
                    &Op::Open {
                        host: "hv".into(),
                        ttl: "1h".into(),
                        profile: None,
                    },
                    t(1000),
                )
                .unwrap()
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // No driver ran during the race: opening only records a pending request.
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .filter(|(_, op)| *op == "apply")
            .count(),
        0,
        "opening must not drive a channel before approval"
    );

    // Oracle 1 — committed state: exactly one grant, awaiting approval.
    let doc = daemon.store.read().unwrap();
    assert_eq!(doc.grants.len(), 1);
    assert_eq!(
        daemon.status(t(1000)).unwrap()[0].state,
        GrantState::AwaitingApproval
    );
    // Corroboration: exactly one open won the pending slot; the rest were
    // refused as already-pending, never as a driver failure.
    let oks = results
        .iter()
        .filter(|r| r.result == ResponseResult::Ok)
        .count();
    assert_eq!(oks, 1);
    for r in results
        .iter()
        .filter(|r| r.result == ResponseResult::Refused)
    {
        let e = r.error.as_deref().unwrap_or("");
        assert!(
            e.contains("awaiting approval") || e.contains("mid-open"),
            "loser refused for the wrong reason: {e}"
        );
    }

    // A single approval opens it, and exactly one apply runs — one tunnel, one
    // password.
    let approved = daemon
        .dispatch(
            &Op::Approve {
                host: "hv".into(),
                token: "any".into(),
            },
            t(1000),
        )
        .unwrap();
    assert_eq!(approved.result, ResponseResult::Ok);
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .filter(|(c, op)| *c == Channel::Vnc && *op == "apply")
            .count(),
        1,
        "exactly one apply may run"
    );
    assert_eq!(daemon.status(t(1000)).unwrap()[0].state, GrantState::Open);
}

#[test]
fn a_vnc_open_returns_the_one_time_password_labelled_and_the_console_endpoint() {
    let dir = scratch_dir("vnc-open-resp");
    let log: CallLog = Arc::new(Mutex::new(Vec::new()));
    let mut drivers = DriverSet::new();
    drivers
        .register(FakeDriver::with_secret(
            Channel::Vnc,
            Arc::clone(&log),
            "vnc-one-time-pw",
        ))
        .unwrap();
    let daemon = Daemon {
        inventory: Inventory::parse(VNC_INVENTORY).unwrap(),
        store: Store::at(dir.join("grants.json")),
        journal: Mutex::new(Journal::open(dir.join("journal.jsonl")).unwrap()),
        drivers: Mutex::new(drivers),
        deadman: Mutex::new(dummy_deadman()),
        approval_window: std::time::Duration::from_secs(300),
        approval: None,
        totp_secrets: std::collections::BTreeMap::new(),
        totp_ledger: crate::totp_ledger::TotpLedger::at(dir.join("totp-ledger.json")),
        password_hashes: std::collections::BTreeMap::new(),
        fido2_counters: crate::fido2_counters::Fido2Counters::at(dir.join("fido2-counters.json")),
    };
    daemon
        .dispatch(
            &Op::Open {
                host: "hv".into(),
                ttl: "1h".into(),
                profile: None,
            },
            t(1000),
        )
        .unwrap();
    // The grant opens — and the secret is produced — on approve.
    let r = daemon
        .dispatch(
            &Op::Approve {
                host: "hv".into(),
                token: "any".into(),
            },
            t(1000),
        )
        .unwrap();
    assert_eq!(r.result, ResponseResult::Ok);
    // The one-time password, labelled for the CLI, with the console endpoint.
    assert_eq!(r.secret.as_deref(), Some("vnc-one-time-pw"));
    assert_eq!(r.secret_label.as_deref(), Some("one-time VNC password"));
    assert_eq!(r.outcome.as_deref(), Some("vnc console at 127.0.0.1:5959"));
    // And the password never reaches the journal.
    let raw = std::fs::read_to_string(dir.join("journal.jsonl")).unwrap();
    assert!(!raw.contains("vnc-one-time-pw"), "the secret leaked: {raw}");
}

// --- open-on-wait: a `wait` factor opens a grant with no proof --------------

const WAIT_ONLY_INVENTORY: &str = r#"
[[hosts]]
name = "db-01"
address = "10.0.4.11"
os = "linux"
channels = ["ssh"]

[hosts.ssh]
agent_user = "root"
root_posture_default = "no"
root_posture_emergency = "yes"

[[approval.profile]]
id = "timed"
threshold = 1
factor = [ { wait = "5s", weight = 1 } ]
"#;

/// A daemon with a real authority model, no drivers registered (so an approved
/// open applies nothing but still commits Open), and a fake dead-man. Proves the
/// pass-loop opens a pending grant once its `wait` matures — no proof involved.
#[test]
fn a_wait_only_profile_opens_on_the_pass_once_the_wait_matures() {
    let dir = scratch_dir("wait-open");
    let inventory = Inventory::parse(WAIT_ONLY_INVENTORY).unwrap();
    let model = inventory
        .approval_model()
        .unwrap()
        .expect("a policy is configured");
    let daemon = Daemon {
        inventory,
        store: Store::at(dir.join("grants.json")),
        journal: Mutex::new(Journal::open(dir.join("journal.jsonl")).unwrap()),
        drivers: Mutex::new(DriverSet::new()),
        deadman: Mutex::new(Box::new(FakeDeadman {
            log: Arc::new(Mutex::new(Vec::new())),
            fail_install: false,
            fail_remove: false,
            fired: Arc::new(Mutex::new(false)),
        })),
        approval_window: Duration::from_secs(300),
        approval: Some(model),
        totp_secrets: std::collections::BTreeMap::new(),
        totp_ledger: crate::totp_ledger::TotpLedger::at(dir.join("totp-ledger.json")),
        password_hashes: std::collections::BTreeMap::new(),
        fido2_counters: crate::fido2_counters::Fido2Counters::at(dir.join("fido2-counters.json")),
    };

    // Open under the wait-only profile: pending, nothing applied.
    let r = daemon
        .dispatch(
            &Op::Open {
                host: "db-01".into(),
                ttl: "1h".into(),
                profile: Some("timed".into()),
            },
            t(1_000),
        )
        .unwrap();
    assert_eq!(r.result, ResponseResult::Ok);
    assert!(
        r.pending.is_some(),
        "open should return a pending challenge"
    );

    // A pass before the wait elapses leaves it pending — the oracle self-test:
    // if the grant opened here, the wait boundary would mean nothing.
    daemon.pass(t(1_002)).unwrap();
    let before = daemon.status(t(1_002)).unwrap();
    let db01 = before.iter().find(|l| l.host == "db-01").unwrap();
    assert_eq!(db01.state, GrantState::AwaitingApproval);

    // A pass at/after the 5s wait opens it, with no proof ever submitted.
    daemon.pass(t(1_006)).unwrap();
    let after = daemon.status(t(1_006)).unwrap();
    let db01 = after.iter().find(|l| l.host == "db-01").unwrap();
    assert_eq!(
        db01.state,
        GrantState::Open,
        "the matured wait should open it"
    );

    // The committed store agrees, and the open was journaled.
    let doc = daemon.store.read().unwrap();
    assert_eq!(doc.grants["db-01"].state, "open");
    let raw = std::fs::read_to_string(dir.join("journal.jsonl")).unwrap();
    assert!(
        raw.contains("\"event\":\"approved\""),
        "no approved event: {raw}"
    );
    assert!(raw.contains("\"event\":\"open\""), "no open event: {raw}");
}

// --- TOTP proofs: verify path, single-use, dispatch -------------------------

const TOTP_SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// A daemon whose only host opens driverlessly (empty DriverSet, ssh channel →
/// nothing applied, no dead-man) under a profile that requires one TOTP factor
/// "phone". The secret is injected directly (main.rs reads it from a file; the
/// unit test bypasses that), matching the RFC seed so a code can be computed.
fn totp_harness(dir: &crate::scratch::Scratch) -> Daemon {
    let inv_text = r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "linux"
        channels = ["ssh"]
        [hosts.ssh]
        agent_user = "root"
        root_posture_default = "no"
        root_posture_emergency = "yes"

        [[approval.authenticator]]
        id = "phone"
        kind = "totp"
        secret-file = "/unused-in-unit-test"
        [[approval.profile]]
        id = "totp"
        threshold = 1
        factor = [ { authenticator = "phone", weight = 1 } ]
    "#;
    let inventory = Inventory::parse(inv_text).unwrap();
    let model = inventory.approval_model().unwrap().unwrap();
    let mut totp_secrets = std::collections::BTreeMap::new();
    totp_secrets.insert(
        "phone".to_string(),
        lychgate_core::TotpSecret::from_base32(TOTP_SEED_B32).unwrap(),
    );
    Daemon {
        inventory,
        store: Store::at(dir.join("grants.json")),
        journal: Mutex::new(Journal::open(dir.join("journal.jsonl")).unwrap()),
        drivers: Mutex::new(DriverSet::new()),
        deadman: Mutex::new(Box::new(FakeDeadman {
            log: Arc::new(Mutex::new(Vec::new())),
            fail_install: false,
            fail_remove: false,
            fired: Arc::new(Mutex::new(false)),
        })),
        approval_window: Duration::from_secs(300),
        approval: Some(model),
        totp_secrets,
        totp_ledger: crate::totp_ledger::TotpLedger::at(dir.join("totp-ledger.json")),
        password_hashes: std::collections::BTreeMap::new(),
        fido2_counters: crate::fido2_counters::Fido2Counters::at(dir.join("fido2-counters.json")),
    }
}

fn totp_code_at(now: SystemTime) -> String {
    let secret = lychgate_core::TotpSecret::from_base32(TOTP_SEED_B32).unwrap();
    let counter = now.duration_since(UNIX_EPOCH).unwrap().as_secs() / 30;
    lychgate_core::totp::code_at(&secret, counter)
}

fn open_totp(d: &Daemon, now: SystemTime) {
    let r = d
        .dispatch(
            &Op::Open {
                host: "db-01".into(),
                ttl: "1h".into(),
                profile: Some("totp".into()),
            },
            now,
        )
        .unwrap();
    assert_eq!(r.result, ResponseResult::Ok);
}

fn approve_totp(d: &Daemon, code: &str, now: SystemTime) -> ResponseResult {
    d.dispatch(
        &Op::Approve {
            host: "db-01".into(),
            token: code.to_string(),
        },
        now,
    )
    .unwrap()
    .result
}

fn is_open(d: &Daemon, now: SystemTime) -> bool {
    d.status(now)
        .unwrap()
        .iter()
        .any(|l| l.host == "db-01" && l.state == GrantState::Open)
}

#[test]
fn a_valid_totp_code_opens_a_single_factor_profile() {
    let dir = scratch_dir("totp-open");
    let d = totp_harness(&dir);
    let now = t(1_000_000_020);
    open_totp(&d, now);
    assert_eq!(
        approve_totp(&d, &totp_code_at(now), now),
        ResponseResult::Ok
    );
    assert!(is_open(&d, now), "a valid TOTP code should open the grant");
}

#[test]
fn a_wrong_totp_code_is_refused() {
    let dir = scratch_dir("totp-wrong");
    let d = totp_harness(&dir);
    let now = t(1_000_000_020);
    open_totp(&d, now);
    assert_eq!(approve_totp(&d, "000000", now), ResponseResult::Refused);
    assert!(!is_open(&d, now));
}

#[test]
fn a_totp_code_cannot_be_replayed_across_grants() {
    // Single-use is enforced by the ledger, not the pending state: a code that
    // opened one grant is refused on a later grant even though the code is still
    // within its time window.
    let dir = scratch_dir("totp-replay");
    let d = totp_harness(&dir);
    let now = t(1_000_000_020);
    let code = totp_code_at(now);
    open_totp(&d, now);
    assert_eq!(approve_totp(&d, &code, now), ResponseResult::Ok);
    assert!(is_open(&d, now));
    // Close and open a fresh grant; the same still-valid code must not reopen it.
    d.dispatch(
        &Op::Close {
            host: "db-01".into(),
        },
        now,
    )
    .unwrap();
    open_totp(&d, now);
    assert_eq!(
        approve_totp(&d, &code, now),
        ResponseResult::Refused,
        "a spent code must be refused even within its window"
    );
    assert!(!is_open(&d, now));
}

#[test]
fn a_digit_code_against_a_profile_with_no_totp_factor_is_refused_cleanly() {
    // Dispatch: a numeric token routes to the TOTP path; with no configured
    // secret matching it, it is refused, not misread as an SSHSIG.
    let dir = scratch_dir("totp-dispatch");
    let mut d = totp_harness(&dir);
    d.totp_secrets.clear(); // no TOTP secrets loaded
    let now = t(1_000_000_020);
    open_totp(&d, now);
    assert_eq!(approve_totp(&d, "123456", now), ResponseResult::Refused);
    assert!(!is_open(&d, now));
}

// --- password proofs: verify path, reusable, dispatch ----------------------

/// A daemon whose only host opens driverlessly under a threshold-1 profile
/// requiring one password factor "pw". The Argon2id hash is injected directly
/// (main.rs reads it from a file; the unit test bypasses that).
fn password_harness(dir: &crate::scratch::Scratch, password: &str) -> Daemon {
    let inv_text = r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "linux"
        channels = ["ssh"]
        [hosts.ssh]
        agent_user = "root"
        root_posture_default = "no"
        root_posture_emergency = "yes"

        [[approval.authenticator]]
        id = "pw"
        kind = "password"
        hash-file = "/unused-in-unit-test"
        [[approval.profile]]
        id = "pw"
        threshold = 1
        factor = [ { authenticator = "pw", weight = 1 } ]
    "#;
    let inventory = Inventory::parse(inv_text).unwrap();
    let model = inventory.approval_model().unwrap().unwrap();
    let mut password_hashes = std::collections::BTreeMap::new();
    password_hashes.insert(
        "pw".to_string(),
        lychgate_core::password::hash(password, &[0x2bu8; 16]).unwrap(),
    );
    Daemon {
        inventory,
        store: Store::at(dir.join("grants.json")),
        journal: Mutex::new(Journal::open(dir.join("journal.jsonl")).unwrap()),
        drivers: Mutex::new(DriverSet::new()),
        deadman: Mutex::new(Box::new(FakeDeadman {
            log: Arc::new(Mutex::new(Vec::new())),
            fail_install: false,
            fail_remove: false,
            fired: Arc::new(Mutex::new(false)),
        })),
        approval_window: Duration::from_secs(300),
        approval: Some(model),
        totp_secrets: std::collections::BTreeMap::new(),
        totp_ledger: crate::totp_ledger::TotpLedger::at(dir.join("totp-ledger.json")),
        password_hashes,
        fido2_counters: crate::fido2_counters::Fido2Counters::at(dir.join("fido2-counters.json")),
    }
}

fn open_pw(d: &Daemon, now: SystemTime) {
    let r = d
        .dispatch(
            &Op::Open {
                host: "db-01".into(),
                ttl: "1h".into(),
                profile: Some("pw".into()),
            },
            now,
        )
        .unwrap();
    assert_eq!(r.result, ResponseResult::Ok);
}

fn approve_pw(d: &Daemon, token: &str, now: SystemTime) -> ResponseResult {
    d.dispatch(
        &Op::Approve {
            host: "db-01".into(),
            token: token.to_string(),
        },
        now,
    )
    .unwrap()
    .result
}

#[test]
fn a_correct_password_opens_a_password_profile() {
    let dir = scratch_dir("pw-open");
    let d = password_harness(&dir, "hunter2");
    let now = t(1_000);
    open_pw(&d, now);
    assert_eq!(approve_pw(&d, "hunter2", now), ResponseResult::Ok);
    assert!(is_open(&d, now), "a correct password should open the grant");
}

#[test]
fn a_wrong_password_is_refused() {
    let dir = scratch_dir("pw-wrong");
    let d = password_harness(&dir, "hunter2");
    let now = t(1_000);
    open_pw(&d, now);
    assert_eq!(approve_pw(&d, "hunter3", now), ResponseResult::Refused);
    assert!(!is_open(&d, now));
}

#[test]
fn a_password_is_reusable_with_no_ledger() {
    // Deliberate: unlike a TOTP code, a password has no single-use ledger — the
    // same secret opens a second grant. This asserts the "reusable, weakest
    // factor" property is intended, not an accident.
    let dir = scratch_dir("pw-reuse");
    let d = password_harness(&dir, "hunter2");
    let now = t(1_000);
    open_pw(&d, now);
    assert_eq!(approve_pw(&d, "hunter2", now), ResponseResult::Ok);
    assert!(is_open(&d, now));
    d.dispatch(
        &Op::Close {
            host: "db-01".into(),
        },
        now,
    )
    .unwrap();
    open_pw(&d, now);
    assert_eq!(
        approve_pw(&d, "hunter2", now),
        ResponseResult::Ok,
        "a password is reusable — the same secret opens again"
    );
    assert!(is_open(&d, now));
}

// --- FIDO2 assertions: verify path, challenge binding, dispatch -------------

// A software authenticator: fixed ES256 private key + credential id, whose
// derived public key goes in the inventory. build_assertion signs the daemon's
// actual (per-open) challenge, so these exercise the real challenge binding.
const FIDO2_PRIV: [u8; 32] = [0x11u8; 32];
const FIDO2_CRED_ID: [u8; 16] = [0xabu8; 16];

fn fido2_harness(dir: &crate::scratch::Scratch) -> Daemon {
    let pub_b64 = data_encoding::BASE64URL_NOPAD
        .encode(&lychgate_core::fido2::public_key(lychgate_core::Alg::Es256, &FIDO2_PRIV).unwrap());
    let cred_b64 = data_encoding::BASE64URL_NOPAD.encode(&FIDO2_CRED_ID);
    let inv_text = format!(
        r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "linux"
        channels = ["ssh"]
        [hosts.ssh]
        agent_user = "root"
        root_posture_default = "no"
        root_posture_emergency = "yes"

        [[approval.authenticator]]
        id = "key"
        kind = "fido2"
        alg = "es256"
        credential-id = "{cred_b64}"
        public-key = "{pub_b64}"
        [[approval.profile]]
        id = "fido2"
        threshold = 1
        factor = [ {{ authenticator = "key", weight = 1 }} ]
        "#
    );
    let inventory = Inventory::parse(&inv_text).unwrap();
    let model = inventory.approval_model().unwrap().unwrap();
    Daemon {
        inventory,
        store: Store::at(dir.join("grants.json")),
        journal: Mutex::new(Journal::open(dir.join("journal.jsonl")).unwrap()),
        drivers: Mutex::new(DriverSet::new()),
        deadman: Mutex::new(Box::new(FakeDeadman {
            log: Arc::new(Mutex::new(Vec::new())),
            fail_install: false,
            fail_remove: false,
            fired: Arc::new(Mutex::new(false)),
        })),
        approval_window: Duration::from_secs(300),
        approval: Some(model),
        totp_secrets: std::collections::BTreeMap::new(),
        totp_ledger: crate::totp_ledger::TotpLedger::at(dir.join("totp-ledger.json")),
        password_hashes: std::collections::BTreeMap::new(),
        fido2_counters: crate::fido2_counters::Fido2Counters::at(dir.join("fido2-counters.json")),
    }
}

/// Open under the fido2 profile and return the daemon's challenge string.
fn open_fido2(d: &Daemon, now: SystemTime) -> String {
    let r = d
        .dispatch(
            &Op::Open {
                host: "db-01".into(),
                ttl: "1h".into(),
                profile: Some("fido2".into()),
            },
            now,
        )
        .unwrap();
    assert_eq!(r.result, ResponseResult::Ok);
    r.pending.expect("a pending challenge").challenge
}

fn approve_fido2(d: &Daemon, token: &str, now: SystemTime) -> ResponseResult {
    d.dispatch(
        &Op::Approve {
            host: "db-01".into(),
            token: token.to_string(),
        },
        now,
    )
    .unwrap()
    .result
}

#[test]
fn a_valid_fido2_assertion_opens_a_profile() {
    let dir = scratch_dir("fido2-open");
    let d = fido2_harness(&dir);
    let now = t(1_000);
    let challenge = open_fido2(&d, now);
    let token = lychgate_core::fido2::build_assertion(
        lychgate_core::Alg::Es256,
        &FIDO2_PRIV,
        &FIDO2_CRED_ID,
        &challenge,
    )
    .unwrap();
    assert_eq!(approve_fido2(&d, &token, now), ResponseResult::Ok);
    assert!(is_open(&d, now), "a valid assertion should open the grant");
}

#[test]
fn an_assertion_for_a_different_challenge_is_refused() {
    // The challenge binding: an assertion signed over some other challenge does
    // not open a grant whose pending request has a different nonce.
    let dir = scratch_dir("fido2-challenge");
    let d = fido2_harness(&dir);
    let now = t(1_000);
    let _real = open_fido2(&d, now);
    let token = lychgate_core::fido2::build_assertion(
        lychgate_core::Alg::Es256,
        &FIDO2_PRIV,
        &FIDO2_CRED_ID,
        "lg1.req.SOMETHING-ELSE",
    )
    .unwrap();
    assert_eq!(approve_fido2(&d, &token, now), ResponseResult::Refused);
    assert!(!is_open(&d, now));
}

#[test]
fn a_non_fido2_token_does_not_route_to_the_fido2_branch() {
    // Dispatch: an all-digits token is a TOTP code, not misread as a FIDO2
    // assertion; with no TOTP authenticator configured it is refused, and the
    // fido2 profile stays pending.
    let dir = scratch_dir("fido2-dispatch");
    let d = fido2_harness(&dir);
    let now = t(1_000);
    open_fido2(&d, now);
    assert_eq!(approve_fido2(&d, "123456", now), ResponseResult::Refused);
    assert!(!is_open(&d, now));
}

// --- the MCP front-door gate (Origin::Mcp + the per-profile `mcp` flag) -----

// A host permitting two profiles: `ai-open` opts into MCP, `humans` does not.
// Both are threshold-1 over one authenticator; the gate refuses before any
// verification, so the authenticator never has to produce a real proof here.
fn mcp_harness(dir: &crate::scratch::Scratch) -> Daemon {
    let inv_text = r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "linux"
        channels = ["ssh"]
        [hosts.ssh]
        agent_user = "root"
        root_posture_default = "no"
        root_posture_emergency = "yes"

        [[approval.authenticator]]
        id = "phone"
        kind = "totp"
        secret-file = "/unused-in-unit-test"
        [[approval.profile]]
        id = "ai-open"
        threshold = 1
        mcp = true
        factor = [ { authenticator = "phone", weight = 1 } ]
        [[approval.profile]]
        id = "humans"
        threshold = 1
        factor = [ { authenticator = "phone", weight = 1 } ]
    "#;
    let inventory = Inventory::parse(inv_text).unwrap();
    let model = inventory.approval_model().unwrap().unwrap();
    Daemon {
        inventory,
        store: Store::at(dir.join("grants.json")),
        journal: Mutex::new(Journal::open(dir.join("journal.jsonl")).unwrap()),
        drivers: Mutex::new(DriverSet::new()),
        deadman: Mutex::new(Box::new(FakeDeadman {
            log: Arc::new(Mutex::new(Vec::new())),
            fail_install: false,
            fail_remove: false,
            fired: Arc::new(Mutex::new(false)),
        })),
        approval_window: Duration::from_secs(300),
        approval: Some(model),
        totp_secrets: std::collections::BTreeMap::new(),
        totp_ledger: crate::totp_ledger::TotpLedger::at(dir.join("totp-ledger.json")),
        password_hashes: std::collections::BTreeMap::new(),
        fido2_counters: crate::fido2_counters::Fido2Counters::at(dir.join("fido2-counters.json")),
    }
}

fn open_op(profile: &str) -> Op {
    Op::Open {
        host: "db-01".into(),
        ttl: "1h".into(),
        profile: Some(profile.into()),
    }
}

fn is_pending(d: &Daemon, now: SystemTime) -> bool {
    matches!(
        d.dispatch(&Op::Status, now)
            .unwrap()
            .grants
            .unwrap()
            .iter()
            .find(|g| g.host == "db-01")
            .map(|g| &g.state),
        Some(lychgate_core::proto::GrantState::AwaitingApproval)
    )
}

#[test]
fn an_mcp_open_on_a_non_mcp_profile_is_refused() {
    let dir = scratch_dir("mcp-open-refused");
    let d = mcp_harness(&dir);
    let now = t(1_000);
    let r = d
        .dispatch_from(&open_op("humans"), now, Origin::Mcp)
        .unwrap();
    assert_eq!(
        r.result,
        ResponseResult::Refused,
        "a non-mcp profile must be refused over MCP"
    );
    assert!(
        !is_pending(&d, now),
        "nothing should be pending after a gated refusal"
    );
}

#[test]
fn an_mcp_open_on_an_mcp_profile_is_allowed() {
    let dir = scratch_dir("mcp-open-allowed");
    let d = mcp_harness(&dir);
    let now = t(1_000);
    let r = d
        .dispatch_from(&open_op("ai-open"), now, Origin::Mcp)
        .unwrap();
    assert_eq!(
        r.result,
        ResponseResult::Ok,
        "an mcp=true profile must be openable over MCP"
    );
    assert!(
        r.pending.is_some(),
        "the open should return a pending challenge"
    );
}

#[test]
fn the_operator_socket_is_not_gated_by_the_mcp_flag() {
    // The second oracle: the gate is origin-scoped. The same non-mcp profile that
    // MCP is refused opens fine for a human on the operator socket.
    let dir = scratch_dir("mcp-operator-ungated");
    let d = mcp_harness(&dir);
    let now = t(1_000);
    let r = d.dispatch(&open_op("humans"), now).unwrap();
    assert_eq!(
        r.result,
        ResponseResult::Ok,
        "the operator socket must open a non-mcp profile"
    );
    assert!(r.pending.is_some());
}

#[test]
fn an_mcp_approve_on_a_non_mcp_profile_is_refused() {
    // A human opens a non-mcp grant on the operator socket; MCP must not be able
    // to inject its factor into it. The gate refuses before any verification.
    let dir = scratch_dir("mcp-approve-refused");
    let d = mcp_harness(&dir);
    let now = t(1_000);
    assert_eq!(
        d.dispatch(&open_op("humans"), now).unwrap().result,
        ResponseResult::Ok
    );
    let r = d
        .dispatch_from(
            &Op::Approve {
                host: "db-01".into(),
                token: "irrelevant".into(),
            },
            now,
            Origin::Mcp,
        )
        .unwrap();
    assert_eq!(
        r.result,
        ResponseResult::Refused,
        "MCP approve of a non-mcp grant must be refused"
    );
    assert!(!is_open(&d, now));
}

#[test]
fn an_mcp_gate_refusal_is_journaled() {
    // The audit oracle: a refused MCP op leaves an `mcp-refused` record.
    let dir = scratch_dir("mcp-journaled");
    let d = mcp_harness(&dir);
    let now = t(1_000);
    let _ = d
        .dispatch_from(&open_op("humans"), now, Origin::Mcp)
        .unwrap();
    let raw = std::fs::read_to_string(dir.join("journal.jsonl")).unwrap();
    assert!(
        raw.contains("\"event\":\"mcp-refused\"") && raw.contains("db-01"),
        "the gate refusal should be journaled as mcp-refused; got:\n{raw}"
    );
}

// --- drill mode: the standing revert oracle (Op::Drill on a canary) ---------

// A canary daemon: one host, optionally drill = true, with a FakeDriver on its
// ssh channel scripted to succeed or to fail its revert (the sabotage oracle).
fn drill_daemon(dir: &crate::scratch::Scratch, canary: bool, script: Script) -> Daemon {
    let inv_text = format!(
        r#"
        [[hosts]]
        name = "canary"
        address = "127.0.0.1"
        os = "linux"
        channels = ["ssh"]
        drill = {canary}
        [hosts.ssh]
        agent_user = "root"
        root_posture_default = "no"
        root_posture_emergency = "yes"
        "#
    );
    let log: CallLog = Arc::new(Mutex::new(Vec::new()));
    let mut drivers = DriverSet::new();
    drivers
        .register(FakeDriver::new(Channel::Ssh, script, Arc::clone(&log)))
        .unwrap();
    Daemon {
        inventory: Inventory::parse(&inv_text).unwrap(),
        store: Store::at(dir.join("grants.json")),
        journal: Mutex::new(Journal::open(dir.join("journal.jsonl")).unwrap()),
        drivers: Mutex::new(drivers),
        deadman: Mutex::new(Box::new(FakeDeadman {
            log: Arc::new(Mutex::new(Vec::new())),
            fail_install: false,
            fail_remove: false,
            fired: Arc::new(Mutex::new(false)),
        })),
        approval_window: Duration::from_secs(300),
        approval: None,
        totp_secrets: std::collections::BTreeMap::new(),
        totp_ledger: crate::totp_ledger::TotpLedger::at(dir.join("totp-ledger.json")),
        password_hashes: std::collections::BTreeMap::new(),
        fido2_counters: crate::fido2_counters::Fido2Counters::at(dir.join("fido2-counters.json")),
    }
}

fn drill(d: &Daemon, now: SystemTime) -> Response {
    d.dispatch(
        &Op::Drill {
            host: "canary".into(),
        },
        now,
    )
    .unwrap()
}

fn journal_has(dir: &crate::scratch::Scratch, needle: &str) -> bool {
    std::fs::read_to_string(dir.join("journal.jsonl"))
        .unwrap_or_default()
        .contains(needle)
}

#[test]
fn a_drill_on_a_canary_passes_and_leaves_it_closed() {
    let dir = scratch_dir("drill-pass");
    let d = drill_daemon(&dir, true, Script::Succeed);
    let now = t(1_000);
    let r = drill(&d, now);
    assert_eq!(r.result, ResponseResult::Ok, "a canary drill should pass");
    assert!(r.outcome.unwrap_or_default().contains("drill passed"));
    assert!(journal_has(&dir, "\"event\":\"drill-passed\""));
    // The canary is idle again — a drill leaves nothing behind.
    assert!(matches!(
        d.dispatch(&Op::Status, now)
            .unwrap()
            .grants
            .unwrap()
            .iter()
            .find(|g| g.host == "canary")
            .map(|g| &g.state),
        Some(lychgate_core::proto::GrantState::Closed)
    ));
}

#[test]
fn a_drill_on_a_non_canary_host_is_refused() {
    let dir = scratch_dir("drill-noncanary");
    let d = drill_daemon(&dir, false, Script::Succeed);
    let now = t(1_000);
    let r = drill(&d, now);
    assert_eq!(
        r.result,
        ResponseResult::Refused,
        "only a drill = true host is drillable"
    );
    assert!(r.error.unwrap_or_default().contains("not a drill canary"));
    // Nothing was opened.
    assert!(matches!(
        d.dispatch(&Op::Status, now)
            .unwrap()
            .grants
            .unwrap()
            .iter()
            .find(|g| g.host == "canary")
            .map(|g| &g.state),
        Some(lychgate_core::proto::GrantState::Closed) | None
    ));
}

#[test]
fn a_drill_whose_revert_fails_is_reported_as_failed() {
    // The sabotage oracle: a driver that applies but cannot revert must make the
    // drill FAIL — if it passed here, the drill would be measuring nothing.
    let dir = scratch_dir("drill-sabotage");
    let d = drill_daemon(&dir, true, Script::FailRevert);
    let now = t(1_000);
    let r = drill(&d, now);
    assert_eq!(
        r.result,
        ResponseResult::Refused,
        "a stuck revert must fail the drill"
    );
    assert!(r.error.unwrap_or_default().contains("drill FAILED"));
    assert!(journal_has(&dir, "\"event\":\"drill-failed\""));
    // The canary is now needs-revert; a follow-up drill refuses (not idle).
    let again = drill(&d, now);
    assert_eq!(again.result, ResponseResult::Refused);
    assert!(again.error.unwrap_or_default().contains("not idle"));
}

// --- concurrency hardening: approve/pass racing to open a pending grant -----

// Two actors can both find a pending grant at threshold — the operator's approve
// and a reap-loop pass. The atomic Pending->Opening claim lets exactly one win;
// the loser must treat "already opening/open" as success, never a spurious
// refusal. This races two opens on the same pending grant many times and asserts
// the invariant holds every interleaving.
#[test]
fn racing_opens_claim_once_and_neither_is_spuriously_refused() {
    use std::sync::Arc;
    for _ in 0..50 {
        let dir = scratch_dir("race-open");
        let d = Arc::new(mcp_harness(&dir));
        let now = t(1_000);
        // A pending grant to race the open on.
        assert_eq!(
            d.dispatch(&open_op("ai-open"), now).unwrap().result,
            ResponseResult::Ok
        );
        let cfg = d.host("db-01").unwrap();

        let (d1, c1) = (Arc::clone(&d), cfg.clone());
        let (d2, c2) = (Arc::clone(&d), cfg.clone());
        let h1 = std::thread::spawn(move || d1.open_pending_now("db-01", &c1, now, now).unwrap());
        let h2 = std::thread::spawn(move || d2.open_pending_now("db-01", &c2, now, now).unwrap());
        let r1 = h1.join().unwrap();
        let r2 = h2.join().unwrap();

        assert_eq!(r1.result, ResponseResult::Ok, "opener 1 spuriously refused");
        assert_eq!(r2.result, ResponseResult::Ok, "opener 2 spuriously refused");
        assert!(is_open(&d, now), "the grant must be open after the race");
    }
}

// pass leaves a proof-met grant for the operator's approve: it opens only grants
// where the wait is load-bearing. Otherwise a pass could win a secret-bearing
// open and the operator would never receive the one-time secret.
#[test]
fn a_pass_leaves_a_proof_met_grant_for_approve() {
    let dir = scratch_dir("pass-defers");
    let d = mcp_harness(&dir);
    let now = t(1_000);
    assert_eq!(
        d.dispatch(&open_op("ai-open"), now).unwrap().result,
        ResponseResult::Ok
    );
    // Record the sole factor as satisfied — the grant is now met by proof alone
    // (no wait involved), exactly the case pass must defer.
    d.with_registry(|reg| reg.add_satisfied("db-01", now, "phone".to_string()))
        .unwrap()
        .unwrap();

    d.pass(now).unwrap();

    let status = d.dispatch(&Op::Status, now).unwrap().grants.unwrap();
    let db01 = status.iter().find(|g| g.host == "db-01").unwrap();
    assert_eq!(
        db01.state,
        lychgate_core::proto::GrantState::AwaitingApproval,
        "pass must leave a proof-met grant pending for approve, not open it"
    );
}

// --- tpm factor + fido2 counter ledger (M9) ---------------------------------

fn tpm_harness(dir: &crate::scratch::Scratch) -> Daemon {
    let pub_b64 = data_encoding::BASE64URL_NOPAD
        .encode(&lychgate_core::tpm::public_key(&[0x44u8; 32]).unwrap());
    let inv_text = format!(
        r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "linux"
        channels = ["ssh"]
        [hosts.ssh]
        agent_user = "root"
        root_posture_default = "no"
        root_posture_emergency = "yes"

        [[approval.authenticator]]
        id = "host-tpm"
        kind = "tpm"
        public-key = "{pub_b64}"
        [[approval.profile]]
        id = "tpm"
        threshold = 1
        factor = [ {{ authenticator = "host-tpm", weight = 1 }} ]
        "#
    );
    let inventory = Inventory::parse(&inv_text).unwrap();
    let model = inventory.approval_model().unwrap().unwrap();
    Daemon {
        inventory,
        store: Store::at(dir.join("grants.json")),
        journal: Mutex::new(Journal::open(dir.join("journal.jsonl")).unwrap()),
        drivers: Mutex::new(DriverSet::new()),
        deadman: Mutex::new(Box::new(FakeDeadman {
            log: Arc::new(Mutex::new(Vec::new())),
            fail_install: false,
            fail_remove: false,
            fired: Arc::new(Mutex::new(false)),
        })),
        approval_window: Duration::from_secs(300),
        approval: Some(model),
        totp_secrets: std::collections::BTreeMap::new(),
        totp_ledger: crate::totp_ledger::TotpLedger::at(dir.join("totp-ledger.json")),
        password_hashes: std::collections::BTreeMap::new(),
        fido2_counters: crate::fido2_counters::Fido2Counters::at(dir.join("fido2-counters.json")),
    }
}

fn open_profile(d: &Daemon, profile: &str, now: SystemTime) -> String {
    let r = d
        .dispatch(
            &Op::Open {
                host: "db-01".into(),
                ttl: "1h".into(),
                profile: Some(profile.into()),
            },
            now,
        )
        .unwrap();
    assert_eq!(r.result, ResponseResult::Ok);
    r.pending.expect("a pending challenge").challenge
}

fn approve_token_result(d: &Daemon, token: &str, now: SystemTime) -> Response {
    d.dispatch(
        &Op::Approve {
            host: "db-01".into(),
            token: token.to_string(),
        },
        now,
    )
    .unwrap()
}

#[test]
fn a_valid_tpm_signature_opens_a_profile() {
    let dir = scratch_dir("tpm-open");
    let d = tpm_harness(&dir);
    let now = t(1_000);
    let challenge = open_profile(&d, "tpm", now);
    let token = lychgate_core::tpm::sign(&[0x44u8; 32], &challenge).unwrap();
    let r = approve_token_result(&d, &token, now);
    assert_eq!(r.result, ResponseResult::Ok, "{:?}", r.error);
    assert!(is_open(&d, now));
}

#[test]
fn a_tpm_signature_for_another_challenge_is_refused() {
    let dir = scratch_dir("tpm-stale");
    let d = tpm_harness(&dir);
    let now = t(1_000);
    let _live = open_profile(&d, "tpm", now);
    let stale = lychgate_core::tpm::sign(&[0x44u8; 32], "lg1.req.SOMETHING-ELSE").unwrap();
    let r = approve_token_result(&d, &stale, now);
    assert_eq!(r.result, ResponseResult::Refused);
    assert!(!is_open(&d, now));
}

#[test]
fn a_tpm_signature_by_an_unconfigured_key_is_refused() {
    let dir = scratch_dir("tpm-stranger");
    let d = tpm_harness(&dir);
    let now = t(1_000);
    let challenge = open_profile(&d, "tpm", now);
    let stranger = lychgate_core::tpm::sign(&[0x55u8; 32], &challenge).unwrap();
    let r = approve_token_result(&d, &stranger, now);
    assert_eq!(r.result, ResponseResult::Refused);
    assert!(!is_open(&d, now));
}

fn close_db01(d: &Daemon, now: SystemTime) {
    // Empty driver set: the revert commits synchronously to Closed.
    let r = d
        .dispatch(
            &Op::Close {
                host: "db-01".into(),
            },
            now,
        )
        .unwrap();
    assert_eq!(r.result, ResponseResult::Ok, "{:?}", r.error);
}

#[test]
fn a_fido2_counter_regression_is_refused_across_grants() {
    // A hardware credential counts 5 on its first grant. A second assertion
    // claiming 5 again (or less, or a sudden 0) is the clone shape — refused
    // and journaled — while a proper advance to 6 is accepted.
    let dir = scratch_dir("f2c-daemon");
    let d = fido2_harness(&dir);
    let now = t(1_000);

    let c1 = open_fido2(&d, now);
    let t5 = lychgate_core::fido2::build_assertion_with_counter(
        lychgate_core::Alg::Es256,
        &FIDO2_PRIV,
        &FIDO2_CRED_ID,
        &c1,
        5,
    )
    .unwrap();
    assert_eq!(approve_fido2(&d, &t5, now), ResponseResult::Ok);
    assert!(is_open(&d, now));
    close_db01(&d, now);

    // Same counter again on a fresh grant: regression.
    let c2 = open_fido2(&d, now);
    let t5_again = lychgate_core::fido2::build_assertion_with_counter(
        lychgate_core::Alg::Es256,
        &FIDO2_PRIV,
        &FIDO2_CRED_ID,
        &c2,
        5,
    )
    .unwrap();
    assert_eq!(approve_fido2(&d, &t5_again, now), ResponseResult::Refused);
    assert!(!is_open(&d, now), "a regressed counter must not open");
    let raw = std::fs::read_to_string(dir.join("journal.jsonl")).unwrap();
    assert!(
        raw.contains("cloned"),
        "the refusal should be journaled with the clone diagnosis"
    );

    // An advancing counter on the SAME pending grant is accepted.
    let t6 = lychgate_core::fido2::build_assertion_with_counter(
        lychgate_core::Alg::Es256,
        &FIDO2_PRIV,
        &FIDO2_CRED_ID,
        &c2,
        6,
    )
    .unwrap();
    assert_eq!(approve_fido2(&d, &t6, now), ResponseResult::Ok);
    assert!(is_open(&d, now));
    close_db01(&d, now);

    // A sudden zero from a credential that used to count: also the clone shape.
    let c3 = open_fido2(&d, now);
    let t0 = lychgate_core::fido2::build_assertion_with_counter(
        lychgate_core::Alg::Es256,
        &FIDO2_PRIV,
        &FIDO2_CRED_ID,
        &c3,
        0,
    )
    .unwrap();
    assert_eq!(approve_fido2(&d, &t0, now), ResponseResult::Refused);
}

#[test]
fn counterless_software_assertions_stay_usable() {
    // The software authenticator always sends 0; with no recorded mark, zeros
    // pass forever — the ledger must not break the CI/software path.
    let dir = scratch_dir("f2c-zero-daemon");
    let d = fido2_harness(&dir);
    let now = t(1_000);
    for _ in 0..2 {
        let c = open_fido2(&d, now);
        let tok = lychgate_core::fido2::build_assertion(
            lychgate_core::Alg::Es256,
            &FIDO2_PRIV,
            &FIDO2_CRED_ID,
            &c,
        )
        .unwrap();
        assert_eq!(approve_fido2(&d, &tok, now), ResponseResult::Ok);
        assert!(is_open(&d, now));
        close_db01(&d, now);
    }
}

// --- narrowings (E2): verify = "none" is surfaced at open time -------------

/// Open a named host through request + approve (the Harness runs approval:
/// None, so the first proof opens).
fn open_host(h: &Harness, host: &str, now: SystemTime) -> Response {
    let requested = h
        .daemon
        .dispatch(
            &Op::Open {
                host: host.into(),
                ttl: "4h".into(),
                profile: None,
            },
            now,
        )
        .unwrap();
    assert_eq!(
        requested.result,
        ResponseResult::Ok,
        "{:?}",
        requested.error
    );
    h.daemon
        .dispatch(
            &Op::Approve {
                host: host.into(),
                token: "any-token".into(),
            },
            now,
        )
        .unwrap()
}

#[test]
fn opening_a_verify_none_channel_surfaces_the_narrowing_in_the_response() {
    // Mutation: drop the `narrowings: narrowings_for(...)` population in
    // drive_open (or make narrowings_for return None) and this fails.
    let h = Harness::new(&[(Channel::Http, Script::Succeed)]);
    let response = open_host(&h, "gadget-01", t(0));
    assert_eq!(response.result, ResponseResult::Ok, "{:?}", response.error);
    let narrowings = response
        .narrowings
        .expect("a verify = \"none\" open must carry its narrowing");
    assert_eq!(narrowings.len(), 1);
    assert!(
        narrowings[0].contains("verify = \"none\"") && narrowings[0].contains("gadget-01"),
        "the narrowing must name the rule and the host: {}",
        narrowings[0]
    );
}

#[test]
fn opening_fully_verified_channels_carries_no_narrowing() {
    let h = Harness::new(&[
        (Channel::Ssh, Script::Succeed),
        (Channel::AuthorizedKeys, Script::Succeed),
        (Channel::Bmc, Script::Succeed),
    ]);
    assert_eq!(open(&h, t(0), "4h"), ResponseResult::Ok);
    let response = h.daemon.dispatch(&Op::Status, t(1)).unwrap();
    assert_eq!(response.narrowings, None);
    // And a fresh open response on the verified host carries none either.
    let h2 = Harness::new(&[
        (Channel::Ssh, Script::Succeed),
        (Channel::AuthorizedKeys, Script::Succeed),
        (Channel::Bmc, Script::Succeed),
    ]);
    let response = open_host(&h2, "db-01", t(0));
    assert_eq!(response.result, ResponseResult::Ok);
    assert_eq!(
        response.narrowings, None,
        "a fully-verified open must not invent narrowings"
    );
}
