//! The BMC driver: enable/disable a break-glass iDRAC account over Redfish.
//!
//! Redfish is driven by shelling out (curl) through a `BmcTransport` seam,
//! the same shape as the ssh driver — no HTTP-client dependency dragged
//! across the build for one caller. apply rotates the account's password and
//! enables it; revert disables it; verify reads Enabled back. The generated
//! password reaches the operator through the open response and an optional
//! escrow, and is never journaled or logged.
//!
//! There is no dead-man for this channel: the crontab backstop needs a shell
//! on the target, and an iDRAC has none. Expiry enforcement for bmc lives
//! solely in lychgated's reap loop — a documented residual (README, TESTING).

use lychgate_core::bmc::{
    account_path, disable_body, enable_body, parse_account, password_from_bytes, AccountState,
    PasswordGen, Secret,
};
use lychgate_core::{BmcConfig, BmcTls, Channel, ChannelDriver, ChannelState, DriverError, Host};

/// One Redfish request over whatever transport. GET has no body; PATCH sends
/// `body`. Returns (http_status, response_body).
pub trait BmcTransport: Send {
    fn request(
        &mut self,
        bmc: &BmcConfig,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, String), DriverError>;
}

/// Takes the freshly generated break-glass password at open. The default is
/// a no-op; a ddwill-backed implementation slots in here later without the
/// driver hard-depending on escrow.
pub trait Escrow: Send {
    fn deposit(
        &mut self,
        host: &str,
        account_user: &str,
        password: &Secret,
    ) -> Result<(), DriverError>;
}

pub struct NoEscrow;

impl Escrow for NoEscrow {
    fn deposit(&mut self, _host: &str, _user: &str, _pw: &Secret) -> Result<(), DriverError> {
        Ok(())
    }
}

/// Production password generator: 20 characters from the OS CSPRNG mapped
/// onto the safe alphabet.
pub struct UrandomPasswords;

impl PasswordGen for UrandomPasswords {
    fn generate(&mut self) -> Secret {
        use std::io::Read;
        let mut bytes = [0u8; lychgate_core::bmc::PASSWORD_LEN];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .expect("/dev/urandom is readable on every supported platform");
        password_from_bytes(&bytes)
    }
}

pub struct BmcDriver {
    transport: Box<dyn BmcTransport>,
    passwords: Box<dyn PasswordGen>,
    escrow: Box<dyn Escrow>,
    /// The password from the most recent successful apply, taken by the
    /// lifecycle to hand to the operator. Redacted in Debug; cleared once
    /// taken.
    last_password: Option<Secret>,
}

impl BmcDriver {
    pub fn new(
        transport: Box<dyn BmcTransport>,
        passwords: Box<dyn PasswordGen>,
        escrow: Box<dyn Escrow>,
    ) -> Box<BmcDriver> {
        Box::new(BmcDriver {
            transport,
            passwords,
            escrow,
            last_password: None,
        })
    }

    fn bmc(host: &Host) -> Result<&BmcConfig, DriverError> {
        host.bmc
            .as_ref()
            .ok_or_else(|| DriverError(format!("host {:?} has no [hosts.bmc] config", host.name)))
    }

    fn get_account(&mut self, host: &Host, bmc: &BmcConfig) -> Result<AccountState, DriverError> {
        let (status, body) =
            self.transport
                .request(bmc, "GET", &account_path(&bmc.account_id), None)?;
        if status != 200 {
            return Err(DriverError(format!(
                "reading account on {:?} returned HTTP {status}",
                host.name
            )));
        }
        parse_account(&body, &bmc.account_user).map_err(|e| DriverError(e.to_string()))
    }

    fn patch(&mut self, host: &Host, bmc: &BmcConfig, body: &str) -> Result<(), DriverError> {
        let (status, resp) =
            self.transport
                .request(bmc, "PATCH", &account_path(&bmc.account_id), Some(body))?;
        // Redfish PATCH success is 200 or 204.
        if status != 200 && status != 204 {
            return Err(DriverError(format!(
                "account PATCH on {:?} returned HTTP {status}: {}",
                host.name,
                resp.trim()
            )));
        }
        Ok(())
    }
}

impl ChannelDriver for BmcDriver {
    fn channel(&self) -> Channel {
        Channel::Bmc
    }

    fn apply(&mut self, host: &Host) -> Result<(), DriverError> {
        let bmc = Self::bmc(host)?.clone();
        // Refuse a slot held by a stranger before touching anything.
        self.get_account(host, &bmc)?;

        let password = self.passwords.generate();
        // Escrow before enabling: if the operator's copy is lost, the escrow
        // still holds it. An escrow failure fails the apply (the lifecycle
        // unwinds) — a break-glass credential nobody can recover is worse
        // than a refused open.
        self.escrow
            .deposit(&host.name, &bmc.account_user, &password)?;

        self.patch(host, &bmc, &enable_body(&bmc.account_user, &password))?;

        // Verify against the host's actual state.
        if self.get_account(host, &bmc)? != AccountState::Enabled {
            return Err(DriverError(format!(
                "bmc verify failed on {:?}: the account did not read back enabled",
                host.name
            )));
        }
        self.last_password = Some(password);
        Ok(())
    }

    fn revert(&mut self, host: &Host) -> Result<(), DriverError> {
        let bmc = Self::bmc(host)?.clone();
        self.patch(host, &bmc, &disable_body())?;
        if self.get_account(host, &bmc)? != AccountState::Disabled {
            return Err(DriverError(format!(
                "bmc verify failed on {:?}: the account did not read back disabled",
                host.name
            )));
        }
        Ok(())
    }

    fn verify(&mut self, host: &Host) -> Result<ChannelState, DriverError> {
        let bmc = Self::bmc(host)?.clone();
        Ok(match self.get_account(host, &bmc)? {
            AccountState::Enabled => ChannelState::Open,
            AccountState::Disabled => ChannelState::Closed,
        })
    }

    /// The break-glass password from the last apply, handed off once.
    fn take_secret(&mut self) -> Option<Secret> {
        self.last_password.take()
    }
}

/// The production transport: curl to the Redfish endpoint. Auth via the
/// password file (never on argv); TLS trust from the inventory. Response
/// body and HTTP status are captured separately so a non-200 is a clean
/// error, not a parse of an error page.
pub struct CurlBmcTransport;

impl BmcTransport for CurlBmcTransport {
    fn request(
        &mut self,
        bmc: &BmcConfig,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, String), DriverError> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let url = format!("{}{}", bmc.endpoint.trim_end_matches('/'), path);
        let mut cmd = Command::new("curl");
        cmd.arg("-sS")
            .arg("-o")
            .arg("/dev/stdout")
            .arg("-w")
            .arg("\n%{http_code}")
            .arg("-X")
            .arg(method)
            // Credentials from a file, never on the command line where ps(1)
            // would show them: --user reads "user:" and curl prompts for the
            // password on stdin via -K would be cleaner, but iDRAC needs
            // Basic; feed "user:password" through a config file on stdin.
            .arg("--config")
            .arg("-");
        if let Some(body) = body {
            cmd.arg("-H").arg("Content-Type: application/json");
            cmd.arg("--data-binary").arg(body);
        }
        match &bmc.tls {
            BmcTls::CaFile { path } => {
                cmd.arg("--cacert").arg(path);
            }
            BmcTls::Insecure => {
                cmd.arg("--insecure");
            }
        }
        cmd.arg(&url);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let password = std::fs::read_to_string(&bmc.auth_password_file)
            .map_err(|e| DriverError(format!("reading {}: {e}", bmc.auth_password_file)))?;
        // curl --config stdin: keep the secret off argv and out of the
        // process table.
        let config = format!("user = \"{}:{}\"\n", bmc.auth_user, password.trim_end());

        let mut child = cmd
            .spawn()
            .map_err(|e| DriverError(format!("spawning curl: {e}")))?;
        child
            .stdin
            .take()
            .expect("stdin piped")
            .write_all(config.as_bytes())
            .map_err(|e| DriverError(format!("feeding curl config: {e}")))?;
        let out = child
            .wait_with_output()
            .map_err(|e| DriverError(format!("waiting on curl: {e}")))?;
        if !out.status.success() {
            return Err(DriverError(format!(
                "curl to {url} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        // stdout is the body followed by "\n<http_code>".
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
