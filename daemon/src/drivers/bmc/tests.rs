//! The BMC driver against a scripted Redfish transport: what requests go
//! out, and what happens when the iDRAC lies or fails mid-operation.

use super::*;
use lychgate_core::bmc::Secret;
use lychgate_core::Inventory;

use std::sync::{Arc, Mutex};

const INVENTORY: &str = r#"
[[hosts]]
name = "idrac-01"
address = "10.0.9.5"
os = "linux"
channels = ["bmc"]

[hosts.bmc]
endpoint = "https://10.0.9.5"
method = "redfish"
account_user = "breakglass"
account_id = "4"
auth_user = "admin"
auth_password_file = "/etc/lychgate/bmc.pw"
tls = { mode = "insecure" }
"#;

fn host() -> Host {
    Inventory::parse(INVENTORY).unwrap().hosts.remove(0)
}

type Req = (String, String, Option<String>); // method, path, body

/// A fake iDRAC: holds an account state, logs requests, answers GETs from
/// its state and applies PATCHes to it. Optional scripted failures.
struct FakeIdrac {
    log: Arc<Mutex<Vec<Req>>>,
    enabled: Arc<Mutex<bool>>,
    user: Arc<Mutex<String>>,
    fail_patch: bool,
    wrong_user_after_patch: bool,
    ignore_disable: bool,
    get_status: u16,
}

impl BmcTransport for FakeIdrac {
    fn request(
        &mut self,
        _bmc: &BmcConfig,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, String), DriverError> {
        self.log
            .lock()
            .unwrap()
            .push((method.into(), path.into(), body.map(String::from)));
        match method {
            "GET" => {
                let user = self.user.lock().unwrap().clone();
                let enabled = *self.enabled.lock().unwrap();
                Ok((
                    self.get_status,
                    format!(r#"{{"UserName":"{user}","Enabled":{enabled}}}"#),
                ))
            }
            "PATCH" => {
                if self.fail_patch {
                    return Ok((500, r#"{"error":"boom"}"#.to_string()));
                }
                let body = body.unwrap_or("{}");
                let v: serde_json::Value = serde_json::from_str(body).unwrap();
                if let Some(e) = v.get("Enabled").and_then(|e| e.as_bool()) {
                    if !(self.ignore_disable && !e) {
                        *self.enabled.lock().unwrap() = e;
                    }
                }
                if let Some(u) = v.get("UserName").and_then(|u| u.as_str()) {
                    *self.user.lock().unwrap() = if self.wrong_user_after_patch {
                        "someone-else".to_string()
                    } else {
                        u.to_string()
                    };
                }
                Ok((204, String::new()))
            }
            other => Err(DriverError(format!("unexpected method {other}"))),
        }
    }
}

/// A deterministic password generator for request assertions.
struct FixedPassword(&'static str);
impl PasswordGen for FixedPassword {
    fn generate(&mut self) -> Secret {
        Secret::new(self.0.to_string())
    }
}

struct RecordingEscrow {
    deposited: Arc<Mutex<Vec<String>>>,
    fail: bool,
}
impl Escrow for RecordingEscrow {
    fn deposit(&mut self, host: &str, user: &str, pw: &Secret) -> Result<(), DriverError> {
        if self.fail {
            return Err(DriverError("scripted escrow failure".into()));
        }
        // Store the revealed length only — never the plaintext, even in a test.
        self.deposited
            .lock()
            .unwrap()
            .push(format!("{host}/{user}/{}", pw.reveal().len()));
        Ok(())
    }
}

struct Rig {
    driver: Box<BmcDriver>,
    log: Arc<Mutex<Vec<Req>>>,
    enabled: Arc<Mutex<bool>>,
    escrowed: Arc<Mutex<Vec<String>>>,
}

fn rig(start_enabled: bool, start_user: &str, fail_patch: bool, fail_escrow: bool) -> Rig {
    let log = Arc::new(Mutex::new(Vec::new()));
    let enabled = Arc::new(Mutex::new(start_enabled));
    let user = Arc::new(Mutex::new(start_user.to_string()));
    let escrowed = Arc::new(Mutex::new(Vec::new()));
    let driver = BmcDriver::new(
        Box::new(FakeIdrac {
            log: Arc::clone(&log),
            enabled: Arc::clone(&enabled),
            user,
            fail_patch,
            wrong_user_after_patch: false,
            ignore_disable: false,
            get_status: 200,
        }),
        Box::new(FixedPassword("fixed-test-password")),
        Box::new(RecordingEscrow {
            deposited: Arc::clone(&escrowed),
            fail: fail_escrow,
        }),
    );
    Rig {
        driver,
        log,
        enabled,
        escrowed,
    }
}

#[test]
fn apply_enables_the_account_with_a_rotated_password_and_verifies() {
    let mut r = rig(false, "breakglass", false, false);
    r.driver.apply(&host()).unwrap();
    assert!(*r.enabled.lock().unwrap(), "account not enabled");

    // The enable PATCH carried the username, the fresh password, and Enabled.
    let log = r.log.lock().unwrap();
    let patch = log.iter().find(|(m, _, _)| m == "PATCH").unwrap();
    let body: serde_json::Value = serde_json::from_str(patch.2.as_deref().unwrap()).unwrap();
    assert_eq!(body["UserName"], "breakglass");
    assert_eq!(body["Password"], "fixed-test-password");
    assert_eq!(body["Enabled"], true);
    // A GET happened before the PATCH (slot check) and after (verify).
    let methods: Vec<&str> = log.iter().map(|(m, _, _)| m.as_str()).collect();
    assert_eq!(methods, ["GET", "PATCH", "GET"]);
}

#[test]
fn the_generated_password_is_handed_off_once_and_then_gone() {
    let mut r = rig(false, "breakglass", false, false);
    r.driver.apply(&host()).unwrap();
    assert_eq!(
        r.driver.take_secret().map(|s| s.reveal().to_string()),
        Some("fixed-test-password".to_string())
    );
    // Taken once: a second take is empty.
    assert!(r.driver.take_secret().is_none());
}

#[test]
fn the_password_is_escrowed_before_the_account_is_enabled() {
    let mut r = rig(false, "breakglass", false, false);
    r.driver.apply(&host()).unwrap();
    assert_eq!(
        *r.escrowed.lock().unwrap(),
        vec![format!(
            "idrac-01/breakglass/{}",
            "fixed-test-password".len()
        )]
    );
}

#[test]
fn an_escrow_failure_fails_the_apply_before_the_account_is_enabled() {
    let mut r = rig(false, "breakglass", false, true);
    let err = r.driver.apply(&host()).unwrap_err();
    assert!(err.to_string().contains("escrow"), "{err}");
    // The account was never enabled — no unrecoverable credential.
    assert!(!*r.enabled.lock().unwrap());
    // And no PATCH was sent (escrow gates the enable).
    assert!(!r.log.lock().unwrap().iter().any(|(m, _, _)| m == "PATCH"));
}

#[test]
fn a_slot_held_by_a_stranger_is_refused_before_any_write() {
    let mut r = rig(true, "root", false, false);
    let err = r.driver.apply(&host()).unwrap_err();
    assert!(err.to_string().contains("root"), "{err}");
    // Only the GET happened; no PATCH, no escrow.
    assert!(!r.log.lock().unwrap().iter().any(|(m, _, _)| m == "PATCH"));
    assert!(r.escrowed.lock().unwrap().is_empty());
}

#[test]
fn a_failing_patch_fails_the_apply_with_the_http_status() {
    let mut r = rig(false, "breakglass", true, false);
    let err = r.driver.apply(&host()).unwrap_err();
    assert!(err.to_string().contains("500"), "{err}");
    assert!(!*r.enabled.lock().unwrap());
}

#[test]
fn apply_fails_if_the_account_does_not_read_back_enabled() {
    // A PATCH that "succeeds" but the account reads back as a different user
    // (so the verify GET refuses): apply must fail, not claim success.
    let log = Arc::new(Mutex::new(Vec::new()));
    let enabled = Arc::new(Mutex::new(false));
    let user = Arc::new(Mutex::new("breakglass".to_string()));
    let mut driver = BmcDriver::new(
        Box::new(FakeIdrac {
            log: Arc::clone(&log),
            enabled: Arc::clone(&enabled),
            user,
            fail_patch: false,
            wrong_user_after_patch: true,
            ignore_disable: false,
            get_status: 200,
        }),
        Box::new(FixedPassword("pw")),
        Box::new(NoEscrow),
    );
    let err = driver.apply(&host()).unwrap_err();
    assert!(
        err.to_string().contains("someone-else") || err.to_string().contains("verify"),
        "{err}"
    );
    // No password handed off from a failed apply.
    assert!(driver.take_secret().is_none());
}

#[test]
fn revert_disables_the_account_and_verifies_disabled() {
    let mut r = rig(true, "breakglass", false, false);
    r.driver.revert(&host()).unwrap();
    assert!(!*r.enabled.lock().unwrap());
    let log = r.log.lock().unwrap();
    let patch = log.iter().find(|(m, _, _)| m == "PATCH").unwrap();
    let body: serde_json::Value = serde_json::from_str(patch.2.as_deref().unwrap()).unwrap();
    assert_eq!(body["Enabled"], false);
    // Revert never sends a password.
    assert!(body.get("Password").is_none());
}

#[test]
fn verify_reads_the_actual_account_state() {
    let mut r = rig(true, "breakglass", false, false);
    assert_eq!(r.driver.verify(&host()).unwrap(), ChannelState::Open);
    *r.enabled.lock().unwrap() = false;
    assert_eq!(r.driver.verify(&host()).unwrap(), ChannelState::Closed);
}

#[test]
fn revert_fails_if_the_account_does_not_read_back_disabled() {
    // The disable PATCH "succeeds" but the BMC ignores it (account stays
    // enabled): revert must fail on the verify, not claim a clean close.
    let log = Arc::new(Mutex::new(Vec::new()));
    let enabled = Arc::new(Mutex::new(true));
    let mut driver = BmcDriver::new(
        Box::new(FakeIdrac {
            log,
            enabled: Arc::clone(&enabled),
            user: Arc::new(Mutex::new("breakglass".to_string())),
            fail_patch: false,
            wrong_user_after_patch: false,
            ignore_disable: true,
            get_status: 200,
        }),
        Box::new(FixedPassword("pw")),
        Box::new(NoEscrow),
    );
    let err = driver.revert(&host()).unwrap_err();
    assert!(err.to_string().contains("disabled"), "{err}");
    // Still enabled: the failed revert is honest about it (the lifecycle
    // keeps the grant needs-revert and retries).
    assert!(*enabled.lock().unwrap());
}

#[test]
fn a_non_200_account_read_fails_the_operation() {
    // The iDRAC returns 401 on the account GET (auth expired, say): every
    // operation that reads the account must fail rather than parse an error
    // page as state.
    let mut driver = BmcDriver::new(
        Box::new(FakeIdrac {
            log: Arc::new(Mutex::new(Vec::new())),
            enabled: Arc::new(Mutex::new(false)),
            user: Arc::new(Mutex::new("breakglass".to_string())),
            fail_patch: false,
            wrong_user_after_patch: false,
            ignore_disable: false,
            get_status: 401,
        }),
        Box::new(FixedPassword("pw")),
        Box::new(NoEscrow),
    );
    let err = driver.apply(&host()).unwrap_err();
    assert!(err.to_string().contains("401"), "{err}");
    assert!(driver.verify(&host()).is_err());
}
