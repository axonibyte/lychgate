//! The generic http channel driver: open/revert/verify a device's HTTP
//! management surface from inventory-supplied request specs.
//!
//! Same shape as the bmc driver (whose curl transport this reuses in
//! spirit): requests go through an `HttpTransport` seam, apply runs the open
//! request and then requires the verify probe to read Open, revert is
//! idempotent and requires Closed back. A host configured `verify = "none"`
//! gets the honest degraded behavior: apply/revert trust their own request's
//! expectation (that narrowing is surfaced in the open response), and
//! standalone `verify` REFUSES rather than guesses — state that cannot be
//! read is an error, not a coin flip; on a daemon restart that fail-closes
//! the grant rather than assuming it survived.
//!
//! No dead-man for this channel (nothing to install a crontab on): expiry
//! enforcement lives solely in lychgated's reap loop — the bmc residual,
//! documented in README/TESTING and docs/EMBEDDED.md.

use lychgate_core::generic::match_state;
use lychgate_core::{
    Channel, ChannelDriver, ChannelState, DriverError, Host, HttpConfig, HttpRequestSpec,
    VerifyMode,
};

/// One HTTP transaction. Returns (http_status, response_body).
pub trait HttpTransport: Send {
    fn request(
        &mut self,
        http: &HttpConfig,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, String), DriverError>;
}

pub struct HttpDriver {
    transport: Box<dyn HttpTransport>,
}

impl HttpDriver {
    pub fn new(transport: Box<dyn HttpTransport>) -> Box<HttpDriver> {
        Box::new(HttpDriver { transport })
    }

    fn config(host: &Host) -> Result<&HttpConfig, DriverError> {
        host.http
            .as_ref()
            .ok_or_else(|| DriverError(format!("host {:?} has no [hosts.http] config", host.name)))
    }

    /// Run one configured request and hold it to its own expectation.
    fn run(
        &mut self,
        host: &Host,
        http: &HttpConfig,
        which: &str,
        spec: &HttpRequestSpec,
    ) -> Result<(), DriverError> {
        let (status, body) =
            self.transport
                .request(http, &spec.method, &spec.path, spec.body.as_deref())?;
        if status != spec.expect_status {
            return Err(DriverError(format!(
                "http {which} on {:?} returned HTTP {status} (expected {}): {}",
                host.name,
                spec.expect_status,
                body.trim()
            )));
        }
        Ok(())
    }

    /// The verify probe, when one is configured.
    fn probe(&mut self, host: &Host, http: &HttpConfig) -> Result<ChannelState, DriverError> {
        let v = match &http.verify {
            VerifyMode::Probe(v) => v,
            VerifyMode::None(_) => {
                return Err(DriverError(format!(
                    "http state on {:?} is unverifiable: the inventory says verify = \"none\"",
                    host.name
                )))
            }
        };
        let (status, body) = self.transport.request(http, &v.method, &v.path, None)?;
        if status != v.expect_status {
            return Err(DriverError(format!(
                "http verify on {:?} returned HTTP {status} (expected {})",
                host.name, v.expect_status
            )));
        }
        match_state(&body, &v.open_marker, &v.closed_marker)
            .map_err(|e| DriverError(format!("http verify on {:?}: {e}", host.name)))
    }
}

impl ChannelDriver for HttpDriver {
    fn channel(&self) -> Channel {
        Channel::Http
    }

    fn apply(&mut self, host: &Host) -> Result<(), DriverError> {
        let http = Self::config(host)?.clone();
        self.run(host, &http, "open", &http.open)?;
        // Read the actual state back wherever a probe exists; with
        // verify = "none" the open request's expectation was the only oracle
        // (the surfaced narrowing).
        if matches!(http.verify, VerifyMode::Probe(_))
            && self.probe(host, &http)? != ChannelState::Open
        {
            return Err(DriverError(format!(
                "http verify failed on {:?}: the device did not read back open",
                host.name
            )));
        }
        Ok(())
    }

    fn revert(&mut self, host: &Host) -> Result<(), DriverError> {
        let http = Self::config(host)?.clone();
        // Idempotent by the template contract: the revert request must be
        // acceptable against an already-reverted device.
        self.run(host, &http, "revert", &http.revert)?;
        if matches!(http.verify, VerifyMode::Probe(_))
            && self.probe(host, &http)? != ChannelState::Closed
        {
            return Err(DriverError(format!(
                "http verify failed on {:?}: the device did not read back closed",
                host.name
            )));
        }
        Ok(())
    }

    fn verify(&mut self, host: &Host) -> Result<ChannelState, DriverError> {
        let http = Self::config(host)?.clone();
        self.probe(host, &http)
    }
}

/// The production transport: curl, exactly the bmc discipline — status
/// captured separately from the body, TLS trust from the inventory, and any
/// basic-auth credential fed through a curl config on stdin, never argv.
pub struct CurlHttpTransport;

impl HttpTransport for CurlHttpTransport {
    fn request(
        &mut self,
        http: &HttpConfig,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, String), DriverError> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let url = format!("{}{}", http.endpoint.trim_end_matches('/'), path);
        let mut cmd = Command::new("curl");
        cmd.arg("-sS")
            .arg("-o")
            .arg("/dev/stdout")
            .arg("-w")
            .arg("\n%{http_code}")
            .arg("-X")
            .arg(method);
        if let Some(body) = body {
            cmd.arg("-H").arg("Content-Type: application/json");
            cmd.arg("--data-binary").arg(body);
        }
        match &http.tls {
            lychgate_core::BmcTls::CaFile { path } => {
                cmd.arg("--cacert").arg(path);
            }
            lychgate_core::BmcTls::Insecure => {
                cmd.arg("--insecure");
            }
        }
        let config = match (&http.auth_user, &http.auth_password_file) {
            (Some(user), Some(file)) => {
                let password = std::fs::read_to_string(file)
                    .map_err(|e| DriverError(format!("reading {file}: {e}")))?;
                cmd.arg("--config").arg("-");
                Some(format!("user = \"{}:{}\"\n", user, password.trim_end()))
            }
            (None, None) => None,
            _ => {
                return Err(DriverError(format!(
                    "http auth on {url}: auth_user and auth_password_file must be set together"
                )))
            }
        };
        cmd.arg(&url);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| DriverError(format!("spawning curl: {e}")))?;
        if let Some(config) = config {
            child
                .stdin
                .take()
                .expect("stdin piped")
                .write_all(config.as_bytes())
                .map_err(|e| DriverError(format!("feeding curl config: {e}")))?;
        } else {
            drop(child.stdin.take());
        }
        let out = child
            .wait_with_output()
            .map_err(|e| DriverError(format!("waiting on curl: {e}")))?;
        if !out.status.success() {
            return Err(DriverError(format!(
                "curl to {url} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let combined = String::from_utf8_lossy(&out.stdout);
        let (body, code) = combined
            .rsplit_once('\n')
            .ok_or_else(|| DriverError("curl produced no status code".to_string()))?;
        let status: u16 = code
            .trim()
            .parse()
            .map_err(|_| DriverError(format!("curl status code unparseable: {code:?}")))?;
        Ok((status, body.to_string()))
    }
}

#[cfg(test)]
mod tests;
