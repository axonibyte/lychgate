//! The generic mqtt channel driver: open/revert/verify a device through an
//! MQTT broker from inventory-supplied publish/subscribe specs.
//!
//! The transport execs the mosquitto clients (mosquitto_pub, and
//! mosquitto_sub -C 1 -W <secs> for the bounded verify read) — the curl
//! precedent: no MQTT client library dragged across the build for one
//! caller, and TLS comes from the tools. Broker auth is anonymous or TLS
//! client-cert only; password auth was already refused at inventory load
//! because the mosquitto clients take it on argv.
//!
//! Verify discipline: the probe subscribes to the state topic for one
//! message (a retained state topic answers immediately). **No message within
//! the budget is an error — "unverified", never a state.** Reporting silence
//! as Closed would let a dead broker read as a completed revert; reporting
//! it as Open would fail open. `verify = "none"` degrades exactly like the
//! other generic channels. No dead-man; the daemon's reap loop is the only
//! expiry enforcement (documented residual).

use lychgate_core::generic::match_state;
use lychgate_core::{
    Channel, ChannelDriver, ChannelState, DriverError, Host, MqttAuth, MqttConfig, VerifyMode,
};

pub trait MqttTransport: Send {
    fn publish(&mut self, mqtt: &MqttConfig, topic: &str, payload: &str)
        -> Result<(), DriverError>;

    /// Await one message on `topic` for up to `timeout_secs`. `Ok(None)` is
    /// "the budget elapsed with no message" — the DRIVER decides what that
    /// means (always an error), the transport just reports it.
    fn await_message(
        &mut self,
        mqtt: &MqttConfig,
        topic: &str,
        timeout_secs: u64,
    ) -> Result<Option<String>, DriverError>;
}

pub struct MqttDriver {
    transport: Box<dyn MqttTransport>,
}

impl MqttDriver {
    pub fn new(transport: Box<dyn MqttTransport>) -> Box<MqttDriver> {
        Box::new(MqttDriver { transport })
    }

    fn config(host: &Host) -> Result<&MqttConfig, DriverError> {
        host.mqtt
            .as_ref()
            .ok_or_else(|| DriverError(format!("host {:?} has no [hosts.mqtt] config", host.name)))
    }

    fn probe(&mut self, host: &Host, mqtt: &MqttConfig) -> Result<ChannelState, DriverError> {
        let v = match &mqtt.verify {
            VerifyMode::Probe(v) => v,
            VerifyMode::None(_) => {
                return Err(DriverError(format!(
                    "mqtt state on {:?} is unverifiable: the inventory says verify = \"none\"",
                    host.name
                )))
            }
        };
        let message = self
            .transport
            .await_message(mqtt, &v.topic, v.timeout_secs)?
            .ok_or_else(|| {
                DriverError(format!(
                    "mqtt verify on {:?}: no message on {:?} within {}s — state unverified",
                    host.name, v.topic, v.timeout_secs
                ))
            })?;
        match_state(&message, &v.open_marker, &v.closed_marker)
            .map_err(|e| DriverError(format!("mqtt verify on {:?}: {e}", host.name)))
    }
}

impl ChannelDriver for MqttDriver {
    fn channel(&self) -> Channel {
        Channel::Mqtt
    }

    fn apply(&mut self, host: &Host) -> Result<(), DriverError> {
        let mqtt = Self::config(host)?.clone();
        self.transport
            .publish(&mqtt, &mqtt.open.topic, &mqtt.open.payload)?;
        if matches!(mqtt.verify, VerifyMode::Probe(_))
            && self.probe(host, &mqtt)? != ChannelState::Open
        {
            return Err(DriverError(format!(
                "mqtt verify failed on {:?}: the device did not read back open",
                host.name
            )));
        }
        Ok(())
    }

    fn revert(&mut self, host: &Host) -> Result<(), DriverError> {
        let mqtt = Self::config(host)?.clone();
        self.transport
            .publish(&mqtt, &mqtt.revert.topic, &mqtt.revert.payload)?;
        if matches!(mqtt.verify, VerifyMode::Probe(_))
            && self.probe(host, &mqtt)? != ChannelState::Closed
        {
            return Err(DriverError(format!(
                "mqtt verify failed on {:?}: the device did not read back closed",
                host.name
            )));
        }
        Ok(())
    }

    fn verify(&mut self, host: &Host) -> Result<ChannelState, DriverError> {
        let mqtt = Self::config(host)?.clone();
        self.probe(host, &mqtt)
    }
}

/// The production transport: exec the mosquitto clients. Anonymous or TLS
/// client-cert only (password auth never reaches here — refused at load).
pub struct ExecMosquittoTransport;

fn broker_args(mqtt: &MqttConfig) -> Result<Vec<String>, DriverError> {
    let (bhost, bport) = mqtt
        .broker
        .rsplit_once(':')
        .ok_or_else(|| DriverError(format!("mqtt broker {:?} is not host:port", mqtt.broker)))?;
    let mut args = vec![
        "-h".to_string(),
        bhost.to_string(),
        "-p".to_string(),
        bport.to_string(),
    ];
    if let Some(id) = &mqtt.client_id {
        args.push("-i".to_string());
        args.push(id.clone());
    }
    match &mqtt.auth {
        None => {}
        Some(MqttAuth::TlsClientCert {
            certfile,
            keyfile,
            cafile,
        }) => {
            args.push("--cert".to_string());
            args.push(certfile.clone());
            args.push("--key".to_string());
            args.push(keyfile.clone());
            args.push("--cafile".to_string());
            args.push(cafile.clone());
        }
        Some(MqttAuth::Password { .. }) => {
            // Unreachable through a loaded inventory; refuse anyway rather
            // than silently connecting unauthenticated.
            return Err(DriverError(
                "mqtt password auth is refused (argv leak); the inventory validator should have \
                 caught this"
                    .to_string(),
            ));
        }
    }
    Ok(args)
}

fn run(mut cmd: std::process::Command) -> Result<std::process::Output, DriverError> {
    cmd.stdin(std::process::Stdio::null());
    cmd.output()
        .map_err(|e| DriverError(format!("spawning {:?}: {e}", cmd.get_program())))
}

impl MqttTransport for ExecMosquittoTransport {
    fn publish(
        &mut self,
        mqtt: &MqttConfig,
        topic: &str,
        payload: &str,
    ) -> Result<(), DriverError> {
        let mut cmd = std::process::Command::new("mosquitto_pub");
        cmd.args(broker_args(mqtt)?);
        cmd.arg("-t").arg(topic).arg("-m").arg(payload);
        let out = run(cmd)?;
        if !out.status.success() {
            return Err(DriverError(format!(
                "mosquitto_pub to {:?} failed: {}",
                topic,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    fn await_message(
        &mut self,
        mqtt: &MqttConfig,
        topic: &str,
        timeout_secs: u64,
    ) -> Result<Option<String>, DriverError> {
        let mut cmd = std::process::Command::new("mosquitto_sub");
        cmd.args(broker_args(mqtt)?);
        cmd.arg("-t")
            .arg(topic)
            .arg("-C")
            .arg("1")
            .arg("-W")
            .arg(timeout_secs.to_string());
        let out = run(cmd)?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let message = stdout.trim_end_matches('\n');
        if !message.is_empty() {
            return Ok(Some(message.to_string()));
        }
        // Empty stdout: either the -W budget elapsed quietly (mosquitto_sub
        // exits 27) or something actually failed. Only the quiet timeout maps
        // to None; anything with a complaint is a transport error.
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.trim().is_empty() {
            Ok(None)
        } else {
            Err(DriverError(format!(
                "mosquitto_sub on {:?} failed: {}",
                topic,
                stderr.trim()
            )))
        }
    }
}

#[cfg(test)]
mod tests;
