use super::*;
use crate::inventory::Inventory;

use std::time::{Duration, UNIX_EPOCH};

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
        channels = ["ssh", "bmc"]

        [[hosts]]
        name = "web-02"
        address = "10.0.4.12"
        os = "linux"
        channels = ["vnc"]
        "#,
    )
    .expect("test inventory is legal")
}

#[test]
fn every_inventory_host_starts_closed() {
    let reg = GrantRegistry::new(&inventory());
    let statuses = reg.statuses(t(0));
    assert_eq!(
        statuses,
        vec![
            ("db-01", GrantStatus::Closed),
            ("web-02", GrantStatus::Closed)
        ]
    );
}

#[test]
fn operations_on_unknown_hosts_are_refused_by_name() {
    let mut reg = GrantRegistry::new(&inventory());
    let refused = RegistryError::UnknownHost("ghost".into());
    assert_eq!(reg.open("ghost", t(0), &ttl(600)), Err(refused.clone()));
    assert_eq!(reg.close("ghost"), Err(refused.clone()));
    assert_eq!(reg.renew("ghost", t(0), &ttl(600)), Err(refused.clone()));
    assert_eq!(reg.status("ghost", t(0)), Err(refused.clone()));
    // The refusal names the host so the operator can spot the typo.
    assert!(refused.to_string().contains("ghost"));
}

#[test]
fn opening_through_the_registry_delegates_to_the_grant() {
    let mut reg = GrantRegistry::new(&inventory());
    let expires = reg.open("db-01", t(1_000), &ttl(600)).unwrap();
    assert_eq!(expires, t(1_600));
    assert_eq!(
        reg.status("db-01", t(1_100)),
        Ok(GrantStatus::Open {
            remaining: Duration::from_secs(500)
        })
    );
    // The other host's grant is untouched.
    assert_eq!(reg.status("web-02", t(1_100)), Ok(GrantStatus::Closed));
}

#[test]
fn grant_refusals_surface_through_the_registry_unaltered() {
    let mut reg = GrantRegistry::new(&inventory());
    reg.open("db-01", t(1_000), &ttl(600)).unwrap();
    assert_eq!(
        reg.open("db-01", t(1_100), &ttl(600)),
        Err(RegistryError::Grant(GrantError::AlreadyOpen))
    );
}

#[test]
fn renewing_through_the_registry_delegates_and_reports_the_new_expiry() {
    let mut reg = GrantRegistry::new(&inventory());
    reg.open("db-01", t(0), &ttl(600)).unwrap();
    // 600s ttl, observed at 500s: 100s remain, inside the renewal window.
    let expires = reg.renew("db-01", t(500), &ttl(600)).unwrap();
    assert_eq!(expires, t(1_100));
}

#[test]
fn closing_through_the_registry_reports_the_outcome() {
    let mut reg = GrantRegistry::new(&inventory());
    reg.open("db-01", t(0), &ttl(600)).unwrap();
    assert_eq!(reg.close("db-01"), Ok(CloseOutcome::WasOpen));
    assert_eq!(reg.close("db-01"), Ok(CloseOutcome::AlreadyClosed));
}

#[test]
fn reap_closes_every_observed_expired_grant_and_returns_its_name() {
    let mut reg = GrantRegistry::new(&inventory());
    reg.open("db-01", t(0), &ttl(600)).unwrap();
    reg.open("web-02", t(0), &ttl(600)).unwrap();
    let reaped = reg.reap(t(1_000));
    assert_eq!(reaped, vec!["db-01".to_string(), "web-02".to_string()]);
    assert_eq!(reg.status("db-01", t(1_000)), Ok(GrantStatus::Closed));
    assert_eq!(reg.status("web-02", t(1_000)), Ok(GrantStatus::Closed));
}

#[test]
fn reap_reports_an_expiry_exactly_once() {
    let mut reg = GrantRegistry::new(&inventory());
    reg.open("db-01", t(0), &ttl(600)).unwrap();
    assert_eq!(reg.reap(t(1_000)).len(), 1);
    assert_eq!(reg.reap(t(1_000)), Vec::<String>::new());
}

#[test]
fn reap_leaves_open_and_closed_grants_untouched() {
    let mut reg = GrantRegistry::new(&inventory());
    // db-01 stays closed; web-02 is open and not yet expired.
    reg.open("web-02", t(0), &ttl(600)).unwrap();
    assert_eq!(reg.reap(t(100)), Vec::<String>::new());
    assert_eq!(reg.status("db-01", t(100)), Ok(GrantStatus::Closed));
    assert_eq!(
        reg.status("web-02", t(100)),
        Ok(GrantStatus::Open {
            remaining: Duration::from_secs(500)
        })
    );
}

#[test]
fn statuses_reports_every_host_in_name_order() {
    let mut reg = GrantRegistry::new(&inventory());
    reg.open("web-02", t(0), &ttl(600)).unwrap();
    let statuses = reg.statuses(t(100));
    assert_eq!(
        statuses,
        vec![
            ("db-01", GrantStatus::Closed),
            (
                "web-02",
                GrantStatus::Open {
                    remaining: Duration::from_secs(500)
                }
            ),
        ]
    );
}
