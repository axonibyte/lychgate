use super::*;
use crate::grant::GrantStatus;
use crate::ttl::Ttl;

fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn ttl(secs: u64) -> Ttl {
    Ttl::from_secs(secs).expect("test ttls are legal")
}

fn inventory() -> Inventory {
    Inventory::parse(
        r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "freebsd"
        channels = ["vnc"]

        [[hosts]]
        name = "web-02"
        address = "10.0.4.12"
        os = "linux"
        channels = ["vnc"]
        "#,
    )
    .expect("test inventory is legal")
}

fn chans() -> Vec<Channel> {
    vec![Channel::Ssh, Channel::Bmc]
}

fn record(
    state: &str,
    opened: Option<u64>,
    expires: Option<u64>,
    since: Option<u64>,
) -> GrantRecord {
    GrantRecord {
        state: state.to_string(),
        opened_at: opened.map(t),
        expires_at: expires.map(t),
        since: since.map(t),
        channels: chans(),
    }
}

fn doc_with(host: &str, record: GrantRecord) -> StateDoc {
    StateDoc {
        version: STATE_VERSION,
        grants: BTreeMap::from([(host.to_string(), record)]),
    }
}

#[test]
fn a_snapshot_records_every_lifecycle_state_and_omits_closed() {
    let inv = inventory();
    let mut reg = GrantRegistry::new(&inv);
    reg.begin_open("db-01", t(1_000), &ttl(600), chans())
        .unwrap();
    // web-02 stays closed: absent from the snapshot.
    let doc = reg.snapshot();
    assert_eq!(doc.version, STATE_VERSION);
    assert_eq!(
        doc.grants,
        BTreeMap::from([(
            "db-01".to_string(),
            record("opening", Some(1_000), Some(1_600), None)
        )])
    );

    reg.finish_open("db-01").unwrap();
    assert_eq!(reg.snapshot().grants["db-01"].state, "open");

    reg.begin_revert("db-01", t(1_200)).unwrap();
    let doc = reg.snapshot();
    assert_eq!(
        doc.grants["db-01"],
        GrantRecord {
            state: "needs-revert".to_string(),
            opened_at: None,
            expires_at: None,
            since: Some(t(1_200)),
            channels: chans(),
        }
    );

    reg.finish_revert("db-01").unwrap();
    assert_eq!(reg.snapshot().grants.len(), 0);
}

#[test]
fn every_lifecycle_state_round_trips_through_its_snapshot() {
    let inv = inventory();
    for setup in ["opening", "open", "needs-revert"] {
        let mut reg = GrantRegistry::new(&inv);
        reg.begin_open("db-01", t(1_000), &ttl(600), chans())
            .unwrap();
        if setup != "opening" {
            reg.finish_open("db-01").unwrap();
        }
        if setup == "needs-revert" {
            reg.begin_revert("db-01", t(1_100)).unwrap();
        }
        let rebuilt = GrantRegistry::from_parts(&inv, &reg.snapshot()).unwrap();
        assert_eq!(
            rebuilt.statuses(t(1_150)),
            reg.statuses(t(1_150)),
            "state {setup} did not survive the round trip"
        );
    }
}

#[test]
fn a_grant_opened_before_a_restart_refuses_a_second_open_after_it() {
    let inv = inventory();
    let mut reg = GrantRegistry::new(&inv);
    reg.begin_open("db-01", t(1_000), &ttl(600), chans())
        .unwrap();
    reg.finish_open("db-01").unwrap();
    let mut rebuilt = GrantRegistry::from_parts(&inv, &reg.snapshot()).unwrap();
    assert!(rebuilt
        .begin_open("db-01", t(1_100), &ttl(600), chans())
        .is_err());
}

#[test]
fn an_unreaped_expiry_survives_the_round_trip_and_is_observed_on_reload() {
    let inv = inventory();
    let mut reg = GrantRegistry::new(&inv);
    reg.begin_open("db-01", t(1_000), &ttl(600), chans())
        .unwrap();
    reg.finish_open("db-01").unwrap();
    // Snapshot long after expiry, without any reap: observation-free, so
    // the open record persists...
    let doc = reg.snapshot();
    assert_eq!(doc.grants["db-01"].state, "open");
    // ...and the reload observes the expiry with the channels intact.
    let mut rebuilt = GrantRegistry::from_parts(&inv, &doc).unwrap();
    assert_eq!(
        rebuilt.status("db-01", t(9_999)).unwrap(),
        GrantStatus::Expired
    );
    let expired = rebuilt.reap_to_revert(t(9_999));
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].channels, chans());
}

#[test]
fn a_snapshot_naming_hosts_missing_from_the_inventory_is_refused_naming_all_of_them() {
    let doc = StateDoc {
        version: STATE_VERSION,
        grants: BTreeMap::from([
            (
                "ghost-a".to_string(),
                record("open", Some(0), Some(600), None),
            ),
            (
                "db-01".to_string(),
                record("open", Some(0), Some(600), None),
            ),
            (
                "ghost-b".to_string(),
                record("open", Some(0), Some(600), None),
            ),
        ]),
    };
    let err = GrantRegistry::from_parts(&inventory(), &doc).unwrap_err();
    assert_eq!(
        err,
        SnapshotError::UnknownHosts(vec!["ghost-a".to_string(), "ghost-b".to_string()])
    );
}

#[test]
fn a_snapshot_whose_expiry_is_not_after_its_opening_is_refused() {
    for (opened, expires) in [(600, 600), (600, 100)] {
        let doc = doc_with("db-01", record("open", Some(opened), Some(expires), None));
        assert_eq!(
            GrantRegistry::from_parts(&inventory(), &doc),
            Err(SnapshotError::ExpiryNotAfterOpening {
                host: "db-01".to_string()
            })
        );
    }
}

#[test]
fn a_snapshot_whose_span_exceeds_the_ttl_cap_is_refused() {
    let at_cap = doc_with("db-01", record("open", Some(0), Some(MAX_TTL_SECS), None));
    assert!(GrantRegistry::from_parts(&inventory(), &at_cap).is_ok());
    let over = doc_with(
        "db-01",
        record("open", Some(0), Some(MAX_TTL_SECS + 1), None),
    );
    assert_eq!(
        GrantRegistry::from_parts(&inventory(), &over),
        Err(SnapshotError::ExceedsCap {
            host: "db-01".to_string(),
            secs: MAX_TTL_SECS + 1
        })
    );
}

#[test]
fn field_combinations_the_daemon_never_writes_are_refused_naming_the_host() {
    let cases: Vec<(GrantRecord, &str)> = vec![
        (record("open", None, Some(600), None), "opened_at"),
        (record("open", Some(0), None, None), "expires_at"),
        (record("open", Some(0), Some(600), Some(5)), "since"),
        (record("opening", Some(0), None, None), "expires_at"),
        (record("needs-revert", Some(0), None, Some(5)), "since"),
        (record("needs-revert", None, None, None), "since"),
        (record("banished", Some(0), Some(600), None), "banished"),
    ];
    for (rec, needle) in cases {
        let err = GrantRegistry::from_parts(&inventory(), &doc_with("db-01", rec.clone()))
            .expect_err(&format!("{rec:?} must be refused"));
        let msg = err.to_string();
        assert!(msg.contains("db-01"), "{msg}");
        assert!(msg.contains(needle), "{rec:?}: {msg}");
    }
}

#[test]
fn a_needs_revert_record_with_no_channels_round_trips_as_a_closing_transient() {
    // A driverless close writes exactly this: needs-revert, nothing left to
    // revert, about to close on the next pass. It must survive a reload.
    let doc = doc_with(
        "db-01",
        GrantRecord {
            state: "needs-revert".to_string(),
            opened_at: None,
            expires_at: None,
            since: Some(t(5)),
            channels: Vec::new(),
        },
    );
    let reg = GrantRegistry::from_parts(&inventory(), &doc).unwrap();
    assert_eq!(
        reg.status("db-01", t(6)).unwrap(),
        GrantStatus::NeedsRevert {
            channels: Vec::new()
        }
    );
}

#[test]
fn epoch_seconds_that_overflow_the_clock_are_refused_not_a_panic() {
    let text = format!(
        r#"{{"version":2,"grants":{{"db-01":{{"state":"open","opened_at":0,"expires_at":{},"channels":[]}}}}}}"#,
        u64::MAX
    );
    let err = serde_json::from_str::<StateDoc>(&text).unwrap_err();
    assert!(err.to_string().contains("overflow"), "{err}");
}

#[test]
fn state_times_serialize_as_whole_epoch_seconds() {
    let inv = inventory();
    let mut reg = GrantRegistry::new(&inv);
    reg.begin_open("db-01", t(1_700_000_000), &ttl(14_400), vec![Channel::Ssh])
        .unwrap();
    reg.finish_open("db-01").unwrap();
    let json = serde_json::to_string(&reg.snapshot()).unwrap();
    assert_eq!(
        json,
        r#"{"version":2,"grants":{"db-01":{"state":"open","opened_at":1700000000,"expires_at":1700014400,"channels":["ssh"]}}}"#
    );
    let doc: StateDoc = serde_json::from_str(&json).unwrap();
    assert_eq!(doc, reg.snapshot());
}
