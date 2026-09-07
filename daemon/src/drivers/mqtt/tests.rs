use super::*;
use std::sync::{Arc, Mutex};

// Mutation notes (each observed failing): map the probe's no-message None to
// Ok(Closed) → silence_within_the_budget_is_an_error_not_a_state fails (the
// dead-broker-reads-as-reverted catch); drop apply's probe requirement →
// apply_refuses_when_the_probe_does_not_read_open; drop revert's Closed
// requirement → revert_refuses_when_the_device_still_reads_open.

enum Reply {
    Message(&'static str),
    Silence,
}

struct FakeTransport {
    replies: Vec<Reply>,
    log: Arc<Mutex<Vec<String>>>,
}

impl MqttTransport for FakeTransport {
    fn publish(
        &mut self,
        _mqtt: &MqttConfig,
        topic: &str,
        payload: &str,
    ) -> Result<(), DriverError> {
        self.log
            .lock()
            .unwrap()
            .push(format!("pub {topic} {payload}"));
        Ok(())
    }

    fn await_message(
        &mut self,
        _mqtt: &MqttConfig,
        topic: &str,
        timeout_secs: u64,
    ) -> Result<Option<String>, DriverError> {
        self.log
            .lock()
            .unwrap()
            .push(format!("sub {topic} {timeout_secs}s"));
        if self.replies.is_empty() {
            return Err(DriverError("unexpected extra subscribe".into()));
        }
        Ok(match self.replies.remove(0) {
            Reply::Message(m) => Some(m.to_string()),
            Reply::Silence => None,
        })
    }
}

fn host(verify: &str) -> Host {
    let toml = format!(
        r#"
        [[hosts]]
        name = "iot-7"
        address = "10.0.9.20"
        os = "embedded"
        channels = ["mqtt"]
        [hosts.mqtt]
        broker = "10.0.9.20:1883"
        {inline}
        [hosts.mqtt.open]
        topic = "dev/7/cmd"
        payload = "maint-on"
        [hosts.mqtt.revert]
        topic = "dev/7/cmd"
        payload = "maint-off"
        {table}
    "#,
        inline = if verify == "none" {
            r#"verify = "none""#
        } else {
            ""
        },
        table = if verify == "probe" {
            r#"
            [hosts.mqtt.verify]
            topic = "dev/7/state"
            open_marker = "maint-on"
            closed_marker = "maint-off"
            timeout_secs = 3
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

fn driver(replies: Vec<Reply>) -> (Box<MqttDriver>, Arc<Mutex<Vec<String>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let transport = FakeTransport {
        replies,
        log: Arc::clone(&log),
    };
    (MqttDriver::new(Box::new(transport)), log)
}

#[test]
fn apply_publishes_open_then_requires_the_state_topic_to_read_open() {
    let (mut d, log) = driver(vec![Reply::Message("maint-on")]);
    d.apply(&host("probe")).unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        vec!["pub dev/7/cmd maint-on", "sub dev/7/state 3s"]
    );
}

#[test]
fn apply_refuses_when_the_probe_does_not_read_open() {
    let (mut d, _) = driver(vec![Reply::Message("maint-off")]);
    let err = d.apply(&host("probe")).unwrap_err();
    assert!(err.0.contains("did not read back open"), "{err:?}");
}

#[test]
fn silence_within_the_budget_is_an_error_not_a_state() {
    // The dead-broker catch: a revert whose verify hears NOTHING must not
    // read as Closed (that would report a fail-open as reverted) and must not
    // read as Open either — it is "unverified", an error naming the budget.
    let (mut d, _) = driver(vec![Reply::Silence]);
    let err = d.revert(&host("probe")).unwrap_err();
    assert!(
        err.0.contains("no message") && err.0.contains("unverified"),
        "{err:?}"
    );
    let (mut d, _) = driver(vec![Reply::Silence]);
    let err = d.verify(&host("probe")).unwrap_err();
    assert!(err.0.contains("unverified"), "{err:?}");
}

#[test]
fn revert_refuses_when_the_device_still_reads_open() {
    let (mut d, _) = driver(vec![Reply::Message("maint-on")]);
    let err = d.revert(&host("probe")).unwrap_err();
    assert!(err.0.contains("did not read back closed"), "{err:?}");
}

#[test]
fn apply_with_verify_none_publishes_exactly_once_and_subscribes_never() {
    let (mut d, log) = driver(vec![]);
    d.apply(&host("none")).unwrap();
    assert_eq!(*log.lock().unwrap(), vec!["pub dev/7/cmd maint-on"]);
}

#[test]
fn verify_none_refuses_to_guess() {
    let (mut d, log) = driver(vec![]);
    let err = d.verify(&host("none")).unwrap_err();
    assert!(err.0.contains("unverifiable"), "{err:?}");
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn verify_maps_markers_and_refuses_ambiguity() {
    let (mut d, _) = driver(vec![Reply::Message("maint-on")]);
    assert_eq!(d.verify(&host("probe")).unwrap(), ChannelState::Open);
    let (mut d, _) = driver(vec![Reply::Message("maint-off")]);
    assert_eq!(d.verify(&host("probe")).unwrap(), ChannelState::Closed);
    let (mut d, _) = driver(vec![Reply::Message("maint-on maint-off")]);
    assert!(d.verify(&host("probe")).unwrap_err().0.contains("both"));
}

#[test]
fn broker_args_reject_a_portless_broker_and_carry_tls_certs() {
    let mut h = host("probe");
    let mqtt = h.mqtt.as_mut().unwrap();
    mqtt.broker = "no-port-here".into();
    assert!(broker_args(mqtt).unwrap_err().0.contains("host:port"));

    let toml = r#"
        [[hosts]]
        name = "iot-7"
        address = "b"
        os = "embedded"
        channels = ["mqtt"]
        [hosts.mqtt]
        broker = "10.0.9.20:8883"
        auth = { mode = "tls-client-cert", certfile = "c.pem", keyfile = "k.pem", cafile = "ca.pem" }
        verify = "none"
        [hosts.mqtt.open]
        topic = "t"
        payload = "p"
        [hosts.mqtt.revert]
        topic = "t"
        payload = "q"
    "#;
    let inv = lychgate_core::Inventory::parse(toml).unwrap();
    let args = broker_args(inv.hosts[0].mqtt.as_ref().unwrap()).unwrap();
    for expected in ["--cert", "c.pem", "--key", "k.pem", "--cafile", "ca.pem"] {
        assert!(args.iter().any(|a| a == expected), "missing {expected}");
    }
}
