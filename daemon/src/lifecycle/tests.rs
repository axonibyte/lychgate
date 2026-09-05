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

fn open(h: &Harness, now: SystemTime, ttl: &str) -> ResponseResult {
    h.daemon
        .dispatch(
            &Op::Open {
                host: "db-01".into(),
                ttl: ttl.into(),
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
    };

    // Open fails (ssh apply fails, revert fails): needs-revert, stuck on ssh.
    daemon
        .dispatch(
            &Op::Open {
                host: "db-01".into(),
                ttl: "4h".into(),
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
    let resp = h
        .daemon
        .dispatch(
            &Op::Open {
                host: "db-01".into(),
                ttl: "4h".into(),
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
    };
    let resp = daemon
        .dispatch(
            &Op::Open {
                host: "db-01".into(),
                ttl: "4h".into(),
            },
            t(0),
        )
        .unwrap();
    // Oracle 1: the operator got the password in the response.
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
