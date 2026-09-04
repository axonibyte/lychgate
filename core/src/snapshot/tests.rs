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
        channels = ["ssh"]

        [[hosts]]
        name = "web-02"
        address = "10.0.4.12"
        os = "linux"
        channels = ["vnc"]
        "#,
    )
    .expect("test inventory is legal")
}

fn open_grant(opened: u64, expires: u64) -> OpenGrant {
    OpenGrant {
        opened_at: t(opened),
        expires_at: t(expires),
    }
}

#[test]
fn a_snapshot_records_only_open_grants() {
    let inv = inventory();
    let mut reg = GrantRegistry::new(&inv);
    reg.open("db-01", t(1_000), &ttl(600)).unwrap();
    let doc = reg.snapshot();
    assert_eq!(doc.version, STATE_VERSION);
    assert_eq!(
        doc.open_grants,
        BTreeMap::from([("db-01".to_string(), open_grant(1_000, 1_600))])
    );
}

#[test]
fn a_registry_round_trips_through_its_snapshot() {
    let inv = inventory();
    let mut reg = GrantRegistry::new(&inv);
    reg.open("db-01", t(1_000), &ttl(600)).unwrap();
    let rebuilt = GrantRegistry::from_parts(&inv, &reg.snapshot()).unwrap();
    assert_eq!(rebuilt.statuses(t(1_100)), reg.statuses(t(1_100)));
    assert_eq!(
        rebuilt.status("db-01", t(1_100)).unwrap(),
        GrantStatus::Open {
            remaining: Duration::from_secs(500)
        }
    );
}

#[test]
fn a_grant_opened_before_a_restart_refuses_a_second_open_after_it() {
    let inv = inventory();
    let mut reg = GrantRegistry::new(&inv);
    reg.open("db-01", t(1_000), &ttl(600)).unwrap();
    let mut rebuilt = GrantRegistry::from_parts(&inv, &reg.snapshot()).unwrap();
    assert!(rebuilt.open("db-01", t(1_100), &ttl(600)).is_err());
}

#[test]
fn an_unreaped_expiry_survives_the_round_trip_and_is_observed_on_reload() {
    let inv = inventory();
    let mut reg = GrantRegistry::new(&inv);
    reg.open("db-01", t(1_000), &ttl(600)).unwrap();
    // Snapshot taken long after expiry, without any reap: the snapshot is
    // observation-free, so the open interval must persist...
    let doc = reg.snapshot();
    assert!(doc.open_grants.contains_key("db-01"));
    // ...and the reload observes the expiry, so the restarted daemon can
    // journal it.
    let mut rebuilt = GrantRegistry::from_parts(&inv, &doc).unwrap();
    assert_eq!(
        rebuilt.status("db-01", t(9_999)).unwrap(),
        GrantStatus::Expired
    );
    assert_eq!(rebuilt.reap(t(9_999)), vec!["db-01".to_string()]);
}

#[test]
fn a_snapshot_naming_hosts_missing_from_the_inventory_is_refused_naming_all_of_them() {
    let doc = StateDoc {
        version: STATE_VERSION,
        open_grants: BTreeMap::from([
            ("ghost-a".to_string(), open_grant(0, 600)),
            ("db-01".to_string(), open_grant(0, 600)),
            ("ghost-b".to_string(), open_grant(0, 600)),
        ]),
    };
    let err = GrantRegistry::from_parts(&inventory(), &doc).unwrap_err();
    assert_eq!(
        err,
        SnapshotError::UnknownHosts(vec!["ghost-a".to_string(), "ghost-b".to_string()])
    );
    let msg = err.to_string();
    assert!(msg.contains("ghost-a") && msg.contains("ghost-b"), "{msg}");
}

#[test]
fn a_snapshot_whose_expiry_is_not_after_its_opening_is_refused() {
    for (opened, expires) in [(600, 600), (600, 100)] {
        let doc = StateDoc {
            version: STATE_VERSION,
            open_grants: BTreeMap::from([("db-01".to_string(), open_grant(opened, expires))]),
        };
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
    let at_cap = StateDoc {
        version: STATE_VERSION,
        open_grants: BTreeMap::from([("db-01".to_string(), open_grant(0, MAX_TTL_SECS))]),
    };
    assert!(GrantRegistry::from_parts(&inventory(), &at_cap).is_ok());

    let over = StateDoc {
        version: STATE_VERSION,
        open_grants: BTreeMap::from([("db-01".to_string(), open_grant(0, MAX_TTL_SECS + 1))]),
    };
    assert_eq!(
        GrantRegistry::from_parts(&inventory(), &over),
        Err(SnapshotError::ExceedsCap {
            host: "db-01".to_string(),
            secs: MAX_TTL_SECS + 1
        })
    );
}

#[test]
fn epoch_seconds_that_overflow_the_clock_are_refused_not_a_panic() {
    let text = format!(
        r#"{{"version":1,"open_grants":{{"db-01":{{"opened_at":0,"expires_at":{}}}}}}}"#,
        u64::MAX
    );
    let err = serde_json::from_str::<StateDoc>(&text).unwrap_err();
    assert!(err.to_string().contains("overflow"), "{err}");
}

#[test]
fn state_times_serialize_as_whole_epoch_seconds() {
    let doc = StateDoc {
        version: STATE_VERSION,
        open_grants: BTreeMap::from([(
            "db-01".to_string(),
            open_grant(1_700_000_000, 1_700_014_400),
        )]),
    };
    let json = serde_json::to_string(&doc).unwrap();
    assert_eq!(
        json,
        r#"{"version":1,"open_grants":{"db-01":{"opened_at":1700000000,"expires_at":1700014400}}}"#
    );
    assert_eq!(serde_json::from_str::<StateDoc>(&json).unwrap(), doc);
}
