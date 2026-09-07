use super::*;
use std::sync::{Arc, Mutex};

// Mutation notes (each observed failing): drop the ACK nonce-echo check →
// an_ack_for_someone_elses_nonce_is_refused; drop the implausible-remaining
// check → an_implausible_remaining_time_is_refused; make verify map a
// foreign nonce to Closed → verify_never_reports_a_state_for_a_foreign_grant;
// drop apply's STAT read-back → apply_requires_the_device_to_read_back_open.

const NONCE: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];
const NONCE_HEX: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
const FOREIGN_HEX: &str = "ffffffffffffffffffffffffffffffff";

struct FakeTransport {
    replies: Vec<String>,
    log: Arc<Mutex<Vec<String>>>,
}

impl DeviceTransport for FakeTransport {
    fn transact(
        &mut self,
        _host: &Host,
        _device: &DeviceConfig,
        command: &str,
    ) -> Result<String, DriverError> {
        self.log.lock().unwrap().push(command.to_string());
        if self.replies.is_empty() {
            return Err(DriverError("unexpected extra transaction".into()));
        }
        Ok(self.replies.remove(0))
    }
}

/// Signs nothing real; records what it was asked for.
struct FakeSigner {
    log: Arc<Mutex<Vec<String>>>,
    n: u64,
}

impl TokenSigner for FakeSigner {
    fn next_cap(
        &mut self,
        _device: &DeviceConfig,
        nonce: [u8; 16],
        ttl_secs: u32,
    ) -> Result<String, DriverError> {
        self.n += 1;
        self.log
            .lock()
            .unwrap()
            .push(format!("cap nonce={} ttl={ttl_secs}", hex(&nonce)));
        Ok(format!("lgcap.fake.{}", self.n))
    }

    fn next_rvk(&mut self, _device: &DeviceConfig, nonce: [u8; 16]) -> Result<String, DriverError> {
        self.n += 1;
        self.log
            .lock()
            .unwrap()
            .push(format!("rvk nonce={}", hex(&nonce)));
        Ok(format!("lgrvk.fake.{}", self.n))
    }
}

struct FixedNonces;

impl NonceSource for FixedNonces {
    fn nonce(&mut self) -> [u8; 16] {
        NONCE
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn host() -> Host {
    lychgate_core::Inventory::parse(
        r#"
        [signing]
        key_file = "/nonexistent"

        [[hosts]]
        name = "esp-1"
        address = "local-serial"
        os = "embedded"
        channels = ["device"]
        [hosts.device]
        device_id = "000102030405060708090a0b0c0d0e0f"
        transport = "serial"
        [hosts.device.serial]
        device = "/dev/nonexistent"
    "#,
    )
    .unwrap()
    .hosts
    .remove(0)
}

struct Rig {
    driver: Box<DeviceDriver>,
    transport_log: Arc<Mutex<Vec<String>>>,
    signer_log: Arc<Mutex<Vec<String>>>,
    state_path: std::path::PathBuf,
}

fn rig(name: &str, replies: &[&str]) -> Rig {
    let dir = std::env::temp_dir().join(format!("lychgate-devdrv-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let state_path = dir.join("device-state.json");
    let transport_log = Arc::new(Mutex::new(Vec::new()));
    let signer_log = Arc::new(Mutex::new(Vec::new()));
    let driver = DeviceDriver::new(
        Box::new(FakeTransport {
            replies: replies.iter().map(|s| s.to_string()).collect(),
            log: Arc::clone(&transport_log),
        }),
        Box::new(FakeSigner {
            log: Arc::clone(&signer_log),
            n: 0,
        }),
        Box::new(FixedNonces),
        DeviceState::at(&state_path),
    );
    Rig {
        driver,
        transport_log,
        signer_log,
        state_path,
    }
}

fn ctx(ttl: u64) -> ApplyCtx {
    ApplyCtx {
        ttl_secs: ttl,
        expires_at: std::time::UNIX_EPOCH + std::time::Duration::from_secs(ttl),
    }
}

#[test]
fn apply_delivers_the_token_and_reads_actual_state_back() {
    let ack = format!("ACK {NONCE_HEX} 900");
    let stat = format!("STATE open {NONCE_HEX} 890 seq=1");
    let mut r = rig("happy", &[&ack, &stat]);
    r.driver.apply(&host(), &ctx(900)).unwrap();
    assert_eq!(
        *r.transport_log.lock().unwrap(),
        vec!["TOK lgcap.fake.1", "STAT"]
    );
    assert_eq!(
        *r.signer_log.lock().unwrap(),
        vec![format!("cap nonce={NONCE_HEX} ttl=900")]
    );
    // The nonce was persisted for restart-time recognition.
    assert_eq!(
        DeviceState::at(&r.state_path)
            .open_nonce(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
            .unwrap(),
        Some(NONCE)
    );
}

#[test]
fn an_ack_for_someone_elses_nonce_is_refused() {
    let ack = format!("ACK {FOREIGN_HEX} 900");
    let mut r = rig("foreign-ack", &[&ack]);
    let err = r.driver.apply(&host(), &ctx(900)).unwrap_err();
    assert!(err.0.contains("DIFFERENT grant nonce"), "{err:?}");
}

#[test]
fn an_implausible_remaining_time_is_refused() {
    // A device claiming more time than the ttl grants is mis-anchored (or
    // lying); zero means it never armed.
    for remaining in ["901", "0"] {
        let ack = format!("ACK {NONCE_HEX} {remaining}");
        let mut r = rig("bad-remaining", &[&ack]);
        let err = r.driver.apply(&host(), &ctx(900)).unwrap_err();
        assert!(err.0.contains("implausible remaining"), "{err:?}");
    }
}

#[test]
fn a_device_nak_surfaces_its_reason() {
    let mut r = rig("nak", &["NAK replay"]);
    let err = r.driver.apply(&host(), &ctx(900)).unwrap_err();
    assert!(err.0.contains("refused the capability: replay"), "{err:?}");
}

#[test]
fn apply_requires_the_device_to_read_back_open() {
    let ack = format!("ACK {NONCE_HEX} 900");
    let mut r = rig("no-readback", &[&ack, "STATE closed seq=1"]);
    let err = r.driver.apply(&host(), &ctx(900)).unwrap_err();
    assert!(err.0.contains("did not read back open"), "{err:?}");
}

#[test]
fn verify_never_reports_a_state_for_a_foreign_grant() {
    // Open under our nonce -> Open; closed -> Closed; open under a FOREIGN
    // nonce -> an error, never Closed (a revert path shrugging at a live
    // foreign grant) and never Open (adopting it).
    let ack = format!("ACK {NONCE_HEX} 900");
    let stat = format!("STATE open {NONCE_HEX} 890 seq=1");
    let mut r = rig(
        "verify",
        &[
            &ack,
            &stat,
            &format!("STATE open {NONCE_HEX} 880 seq=1"),
            "STATE closed seq=1",
            &format!("STATE open {FOREIGN_HEX} 880 seq=9"),
        ],
    );
    let h = host();
    r.driver.apply(&h, &ctx(900)).unwrap();
    assert_eq!(r.driver.verify(&h).unwrap(), ChannelState::Open);
    assert_eq!(r.driver.verify(&h).unwrap(), ChannelState::Closed);
    let err = r.driver.verify(&h).unwrap_err();
    assert!(err.0.contains("did not record"), "{err:?}");
}

#[test]
fn revert_revokes_verifies_and_clears_the_nonce() {
    let ack = format!("ACK {NONCE_HEX} 900");
    let stat = format!("STATE open {NONCE_HEX} 890 seq=1");
    let mut r = rig(
        "revert",
        &[
            &ack,
            &stat,
            "ACK closed",
            "STATE closed seq=2",
            "STATE closed seq=2",
        ],
    );
    let h = host();
    r.driver.apply(&h, &ctx(900)).unwrap();
    r.driver.revert(&h).unwrap();
    assert!(r.signer_log.lock().unwrap()[1].starts_with("rvk nonce="));
    // Idempotent: a second revert finds no recorded nonce and a closed
    // device — it must succeed WITHOUT sending another revocation (the
    // absence is asserted via the transport log).
    let before = r.transport_log.lock().unwrap().len();
    r.driver.revert(&h).unwrap();
    let after = r.transport_log.lock().unwrap().len();
    assert_eq!(after, before + 1, "only a STAT, no second RVK");
}

#[test]
fn revert_names_the_device_reported_nonce_when_ours_is_lost() {
    // No recorded nonce (fresh state dir), device open under some grant: the
    // revocation must name the grant the DEVICE reports rather than give up.
    let mut r = rig(
        "lost-nonce",
        &[
            &format!("STATE open {FOREIGN_HEX} 500 seq=9"),
            "ACK closed",
            "STATE closed seq=10",
        ],
    );
    r.driver.revert(&host()).unwrap();
    assert!(
        r.signer_log.lock().unwrap()[0].contains(FOREIGN_HEX),
        "the rvk must name the device-reported nonce"
    );
}

#[test]
fn renew_reuses_the_recorded_nonce_with_the_new_ttl() {
    let ack = format!("ACK {NONCE_HEX} 900");
    let stat = format!("STATE open {NONCE_HEX} 890 seq=1");
    let renew_ack = format!("ACK {NONCE_HEX} 1800");
    let mut r = rig("renew", &[&ack, &stat, &renew_ack]);
    let h = host();
    r.driver.apply(&h, &ctx(900)).unwrap();
    r.driver.renew(&h, &ctx(1800)).unwrap();
    assert_eq!(
        r.signer_log.lock().unwrap()[1],
        format!("cap nonce={NONCE_HEX} ttl=1800")
    );
}

#[test]
fn renew_without_a_recorded_grant_refuses() {
    let mut r = rig("renew-none", &[]);
    let err = r.driver.renew(&host(), &ctx(1800)).unwrap_err();
    assert!(err.0.contains("cannot renew"), "{err:?}");
}

#[test]
fn reestablish_reads_ours_as_open_and_anything_else_as_closed() {
    let ack = format!("ACK {NONCE_HEX} 900");
    let stat = format!("STATE open {NONCE_HEX} 890 seq=1");
    let mut r = rig(
        "reestablish",
        &[
            &ack,
            &stat,
            &format!("STATE open {NONCE_HEX} 880 seq=1"),
            &format!("STATE open {FOREIGN_HEX} 880 seq=9"),
            "STATE closed seq=1",
        ],
    );
    let h = host();
    r.driver.apply(&h, &ctx(900)).unwrap();
    assert_eq!(r.driver.reestablish(&h).unwrap(), ChannelState::Open);
    // A foreign grant reads Closed here on purpose: that routes into the
    // Lost/retract path, whose revert then names the device-reported nonce.
    assert_eq!(r.driver.reestablish(&h).unwrap(), ChannelState::Closed);
    assert_eq!(r.driver.reestablish(&h).unwrap(), ChannelState::Closed);
}

// --- the actuator second oracle (E8) ---------------------------------------
//
// Mutation notes: invert the load-vs-grant comparison → the stuck-relay and
// dead-load cases fail; drop the reason=boot exception → the fail-energized
// boot case fails; drop the fail= equality check → the drift case fails.

fn actuator_host(fail_state: &str, current_sense: bool) -> Host {
    lychgate_core::Inventory::parse(&format!(
        r#"
        [signing]
        key_file = "/nonexistent"

        [[hosts]]
        name = "pdu-1"
        address = "local-serial"
        os = "embedded"
        channels = ["device"]
        drill = true
        [hosts.device]
        device_id = "000102030405060708090a0b0c0d0e0f"
        transport = "serial"
        [hosts.device.serial]
        device = "/dev/nonexistent"
        [hosts.device.actuator]
        fail_state = "{fail_state}"
        current_sense = {current_sense}
    "#
    ))
    .unwrap()
    .hosts
    .remove(0)
}

#[test]
fn a_stuck_relay_fails_the_revert_loudly() {
    // Commanded closed, load still ON: the exact silent failure drills exist
    // to catch — a revert that did not actually revert.
    let ack = format!("ACK {NONCE_HEX} 900");
    let open_stat = format!("STATE open {NONCE_HEX} 890 seq=1 load=on fail=de-energized");
    let stuck = "STATE closed seq=2 load=on fail=de-energized reason=revert";
    let mut r = rig("stuck", &[&ack, &open_stat, "ACK closed", stuck]);
    let h = actuator_host("de-energized", true);
    r.driver.apply(&h, &ctx(900)).unwrap();
    let err = r.driver.revert(&h).unwrap_err();
    assert!(err.0.contains("load reads ON"), "{err:?}");
}

#[test]
fn a_dead_load_fails_the_open() {
    // Commanded open, load never came up: the actuator did not actuate.
    let ack = format!("ACK {NONCE_HEX} 900");
    let dead = format!("STATE open {NONCE_HEX} 890 seq=1 load=off fail=de-energized");
    let mut r = rig("dead-load", &[&ack, &dead]);
    let err = r
        .driver
        .apply(&actuator_host("de-energized", true), &ctx(900))
        .unwrap_err();
    assert!(err.0.contains("load reads OFF"), "{err:?}");
}

#[test]
fn a_fail_energized_boot_reads_load_on_while_closed_by_name() {
    // The don't-hard-down case: after a power cycle a fail-energized outlet
    // legitimately carries load with no grant — allowed EXACTLY when the
    // device says reason=boot and the policy says energized.
    let boot = "STATE closed seq=1 load=on fail=energized reason=boot";
    let mut r = rig("boot-energized", &[boot]);
    assert_eq!(
        r.driver.verify(&actuator_host("energized", true)).unwrap(),
        ChannelState::Closed
    );
    // The same reading WITHOUT the boot reason is a stuck relay.
    let stuck = "STATE closed seq=1 load=on fail=energized reason=revert";
    let mut r = rig("not-boot", &[stuck]);
    let err = r
        .driver
        .verify(&actuator_host("energized", true))
        .unwrap_err();
    assert!(err.0.contains("load reads ON"), "{err:?}");
}

#[test]
fn fail_state_drift_and_a_missing_promised_sensor_are_errors() {
    // The device's configured fail-state disagreeing with the inventory is
    // policy drift, surfaced before it matters in an outage.
    let drift = "STATE closed seq=1 load=off fail=de-energized reason=revert";
    let mut r = rig("drift", &[drift]);
    let err = r
        .driver
        .verify(&actuator_host("energized", true))
        .unwrap_err();
    assert!(err.0.contains("DIFFERENT fail-state"), "{err:?}");

    // current_sense promised, no load= in STATE: refused by name.
    let sensorless = "STATE closed seq=1 fail=energized reason=revert";
    let mut r = rig("no-sense", &[sensorless]);
    let err = r
        .driver
        .verify(&actuator_host("energized", true))
        .unwrap_err();
    assert!(err.0.contains("no load reading"), "{err:?}");
}
