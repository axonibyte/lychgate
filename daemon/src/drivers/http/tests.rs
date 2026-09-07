use super::*;
use std::sync::{Arc, Mutex};

// Mutation notes (each observed failing): drop apply's probe-must-read-Open
// requirement → apply_refuses_when_the_probe_does_not_read_open fails; make
// probe() with verify="none" return Ok(Closed) →
// verify_none_refuses_to_guess fails; drop run()'s status check →
// a_wrong_status_fails_the_request fails.

/// Scripted transport: pops (status, body) replies in order, logs requests.
struct FakeTransport {
    replies: Vec<(u16, String)>,
    log: Arc<Mutex<Vec<String>>>,
}

impl HttpTransport for FakeTransport {
    fn request(
        &mut self,
        _http: &HttpConfig,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, String), DriverError> {
        self.log
            .lock()
            .unwrap()
            .push(format!("{method} {path} {}", body.unwrap_or("-")));
        if self.replies.is_empty() {
            return Err(DriverError("unexpected extra request".into()));
        }
        Ok(self.replies.remove(0))
    }
}

fn host(verify: &str) -> Host {
    let toml = format!(
        r#"
        [[hosts]]
        name = "cam-1"
        address = "10.0.9.31"
        os = "embedded"
        channels = ["http"]
        [hosts.http]
        endpoint = "https://10.0.9.31"
        tls = {{ mode = "insecure" }}
        {inline}
        [hosts.http.open]
        method = "POST"
        path = "/maint"
        body = 'on'
        expect_status = 200
        [hosts.http.revert]
        method = "POST"
        path = "/maint"
        body = 'off'
        expect_status = 200
        {table}
    "#,
        inline = if verify == "none" {
            r#"verify = "none""#
        } else {
            ""
        },
        table = if verify == "probe" {
            r#"
            [hosts.http.verify]
            method = "GET"
            path = "/state"
            expect_status = 200
            open_marker = "MAINT ON"
            closed_marker = "MAINT OFF"
        "#
        } else {
            ""
        },
    );
    lychgate_core::Inventory::parse(&toml)
        .unwrap()
        .hosts
        .remove(0)
}

fn driver(replies: &[(u16, &str)]) -> (Box<HttpDriver>, Arc<Mutex<Vec<String>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let transport = FakeTransport {
        replies: replies.iter().map(|(s, b)| (*s, b.to_string())).collect(),
        log: Arc::clone(&log),
    };
    (HttpDriver::new(Box::new(transport)), log)
}

#[test]
fn apply_runs_open_then_requires_the_probe_to_read_open() {
    let (mut d, log) = driver(&[(200, "ok"), (200, "MAINT ON")]);
    d.apply(&host("probe")).unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        vec!["POST /maint on", "GET /state -"],
        "apply must run the open request and then the probe"
    );
}

#[test]
fn apply_refuses_when_the_probe_does_not_read_open() {
    let (mut d, _) = driver(&[(200, "ok"), (200, "MAINT OFF")]);
    let err = d.apply(&host("probe")).unwrap_err();
    assert!(err.0.contains("did not read back open"), "{err:?}");
}

#[test]
fn a_wrong_status_fails_the_request() {
    let (mut d, _) = driver(&[(500, "boom")]);
    let err = d.apply(&host("probe")).unwrap_err();
    assert!(err.0.contains("HTTP 500"), "{err:?}");
}

#[test]
fn apply_with_verify_none_runs_exactly_one_request() {
    // The narrowing in action: no probe exists, so exactly one transaction —
    // asserted as an absence, not assumed.
    let (mut d, log) = driver(&[(200, "ok")]);
    d.apply(&host("none")).unwrap();
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[test]
fn revert_is_idempotent_and_requires_closed_back() {
    let (mut d, _) = driver(&[
        (200, "ok"),
        (200, "MAINT OFF"),
        (200, "ok"),
        (200, "MAINT OFF"),
    ]);
    let h = host("probe");
    d.revert(&h).unwrap();
    d.revert(&h).unwrap();
}

#[test]
fn revert_refuses_when_the_probe_still_reads_open() {
    let (mut d, _) = driver(&[(200, "ok"), (200, "MAINT ON")]);
    let err = d.revert(&host("probe")).unwrap_err();
    assert!(err.0.contains("did not read back closed"), "{err:?}");
}

#[test]
fn verify_maps_markers_and_refuses_ambiguity() {
    let (mut d, _) = driver(&[(200, "MAINT ON")]);
    assert_eq!(d.verify(&host("probe")).unwrap(), ChannelState::Open);
    let (mut d, _) = driver(&[(200, "MAINT OFF")]);
    assert_eq!(d.verify(&host("probe")).unwrap(), ChannelState::Closed);
    let (mut d, _) = driver(&[(200, "whatever")]);
    assert!(d.verify(&host("probe")).unwrap_err().0.contains("neither"));
    let (mut d, _) = driver(&[(200, "MAINT ON MAINT OFF")]);
    assert!(d.verify(&host("probe")).unwrap_err().0.contains("both"));
}

#[test]
fn verify_none_refuses_to_guess() {
    // Standalone verify under verify="none" must be an error — state that
    // cannot be read is never reported as a state (returning Closed here
    // would silently fail-close reestablishment; returning Open would be a
    // fail-open lie).
    let (mut d, log) = driver(&[]);
    let err = d.verify(&host("none")).unwrap_err();
    assert!(err.0.contains("unverifiable"), "{err:?}");
    assert!(log.lock().unwrap().is_empty(), "no request should be made");
}
