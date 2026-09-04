use super::*;
use crate::grant::GrantStatus;

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

fn chans() -> Vec<Channel> {
    vec![Channel::Ssh, Channel::Bmc]
}

fn open(reg: &mut GrantRegistry, host: &str, now: SystemTime, secs: u64) {
    reg.begin_open(host, now, &ttl(secs), chans()).unwrap();
    reg.finish_open(host).unwrap();
}

#[test]
fn every_inventory_host_starts_closed() {
    let reg = GrantRegistry::new(&inventory());
    assert_eq!(
        reg.statuses(t(0)),
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
    assert_eq!(
        reg.begin_open("ghost", t(0), &ttl(600), chans()),
        Err(refused.clone())
    );
    assert_eq!(reg.finish_open("ghost"), Err(refused.clone()));
    assert_eq!(reg.begin_revert("ghost", t(0)), Err(refused.clone()));
    assert_eq!(reg.renew("ghost", t(0), &ttl(600)), Err(refused.clone()));
    assert_eq!(reg.status("ghost", t(0)), Err(refused.clone()));
    assert!(refused.to_string().contains("ghost"));
}

#[test]
fn the_full_open_lifecycle_delegates_to_the_grant() {
    let mut reg = GrantRegistry::new(&inventory());
    let expires = reg
        .begin_open("db-01", t(1_000), &ttl(600), chans())
        .unwrap();
    assert_eq!(expires, t(1_600));
    assert_eq!(reg.status("db-01", t(1_100)), Ok(GrantStatus::Opening));
    reg.finish_open("db-01").unwrap();
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
    open(&mut reg, "db-01", t(1_000), 600);
    assert_eq!(
        reg.begin_open("db-01", t(1_100), &ttl(600), chans()),
        Err(RegistryError::Grant(GrantError::AlreadyOpen))
    );
}

#[test]
fn reap_transitions_every_expired_grant_to_needs_revert_with_its_interval() {
    let mut reg = GrantRegistry::new(&inventory());
    open(&mut reg, "db-01", t(0), 600);
    open(&mut reg, "web-02", t(100), 600);
    let expired = reg.reap_to_revert(t(1_000));
    assert_eq!(
        expired,
        vec![
            ExpiredGrant {
                host: "db-01".into(),
                opened_at: t(0),
                expires_at: t(600),
                channels: chans(),
            },
            ExpiredGrant {
                host: "web-02".into(),
                opened_at: t(100),
                expires_at: t(700),
                channels: chans(),
            },
        ]
    );
    assert_eq!(
        reg.status("db-01", t(1_000)),
        Ok(GrantStatus::NeedsRevert { channels: chans() })
    );
}

#[test]
fn reap_reports_an_expiry_exactly_once() {
    let mut reg = GrantRegistry::new(&inventory());
    open(&mut reg, "db-01", t(0), 600);
    assert_eq!(reg.reap_to_revert(t(1_000)).len(), 1);
    assert_eq!(reg.reap_to_revert(t(1_000)), Vec::new());
}

#[test]
fn reap_leaves_open_closed_and_mid_open_grants_untouched() {
    let mut reg = GrantRegistry::new(&inventory());
    open(&mut reg, "db-01", t(0), 600);
    reg.begin_open("web-02", t(0), &ttl(600), vec![Channel::Vnc])
        .unwrap();
    assert_eq!(reg.reap_to_revert(t(100)), Vec::new());
    assert_eq!(
        reg.status("db-01", t(100)),
        Ok(GrantStatus::Open {
            remaining: Duration::from_secs(500)
        })
    );
    assert_eq!(reg.status("web-02", t(100)), Ok(GrantStatus::Opening));
}

#[test]
fn needing_revert_lists_the_retry_set_in_name_order() {
    let mut reg = GrantRegistry::new(&inventory());
    open(&mut reg, "db-01", t(0), 600);
    reg.begin_revert("db-01", t(50)).unwrap();
    reg.retain_stuck("db-01", vec![Channel::Bmc]).unwrap();
    assert_eq!(
        reg.needing_revert(t(60)),
        vec![("db-01".to_string(), vec![Channel::Bmc])]
    );
    reg.finish_revert("db-01").unwrap();
    assert_eq!(reg.needing_revert(t(61)), Vec::new());
}

#[test]
fn boot_demotion_turns_stored_opening_into_needs_revert_for_every_intended_channel() {
    let mut reg = GrantRegistry::new(&inventory());
    reg.begin_open("db-01", t(0), &ttl(600), chans()).unwrap();
    let demoted = reg.demote_opening(t(10));
    assert_eq!(demoted, vec![("db-01".to_string(), chans())]);
    assert_eq!(
        reg.status("db-01", t(10)),
        Ok(GrantStatus::NeedsRevert { channels: chans() })
    );
    // Nothing else demoted, and a second demotion finds nothing.
    assert_eq!(reg.demote_opening(t(11)), Vec::new());
}
