mod transport;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use lychgate_core::proto::{GrantState, Op, Response, ResponseResult};
use lychgate_core::Ttl;

#[derive(Parser)]
#[command(
    name = "lychgate",
    version,
    about = "Break-glass emergency access, opened deliberately and closed on a timer"
)]
struct Cli {
    /// Path to lychgated's control socket
    #[arg(long, default_value_os_t = transport::default_socket())]
    socket: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Request a grant against a host (returns a challenge to approve)
    Open {
        #[arg(long)]
        host: String,
        /// Time to live, e.g. 90s, 15m, 2h; capped at 24h
        #[arg(long)]
        ttl: String,
        /// Which approval profile to open under. Omit when the host permits
        /// exactly one.
        #[arg(long = "as")]
        profile: Option<String>,
    },
    /// Approve a pending request with a signed token, opening the grant
    Approve {
        #[arg(long)]
        host: String,
        /// The approval token. Omit to read it from stdin (until EOF), which
        /// keeps a secret-bearing token off the command line.
        #[arg(long)]
        token: Option<String>,
        /// Read the token from a file instead of stdin.
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// Renew a host's open grant (accepted only near expiry)
    Renew {
        #[arg(long)]
        host: String,
        /// Fresh time to live from now, e.g. 2h; capped at 24h
        #[arg(long)]
        ttl: String,
    },
    /// Close a host's grant and revert everything it opened
    Close {
        #[arg(long)]
        host: String,
    },
    /// Report the state of every grant
    Status,
    /// Drill a canary host: open-and-revert it as a standing self-test of the
    /// revert path. Refused unless the host is a `drill = true` canary. Exits
    /// non-zero on a failed drill — schedule it in cron and alert on failure.
    Drill {
        #[arg(long)]
        host: String,
    },
    /// Hash a password (read from stdin) into an Argon2id PHC string for a
    /// `[[approval.authenticator]] kind="password"` hash-file. Local — talks to
    /// no daemon. Redirect the output into a mode-600 file.
    HashPassword,
    /// Register a FIDO2 credential and print its `[[approval.authenticator]]`
    /// block. Local — talks to no daemon. `--software-key <file>` creates (or
    /// reuses) a software authenticator in that mode-600 file; the hardware
    /// ceremony is the `fido2-client`-feature build.
    Fido2Register {
        /// Signature algorithm: es256 or eddsa.
        #[arg(long, default_value = "es256")]
        alg: String,
        /// The software authenticator file to create/reuse (mode 600). Omit to
        /// use a hardware key (requires the `fido2-client`-feature build).
        #[arg(long)]
        software_key: Option<PathBuf>,
        /// PIN for a hardware authenticator that requires one (ignored in
        /// software mode).
        #[arg(long)]
        pin: Option<String>,
    },
    /// Produce a FIDO2 assertion over a challenge, printing the token to pipe
    /// into `approve`. Local. `--software-key <file>` uses a software
    /// authenticator; hardware is the `fido2-client`-feature build.
    Fido2Assert {
        /// The challenge string from `open`.
        #[arg(long)]
        challenge: String,
        /// The software authenticator file (from fido2-register). Omit to use a
        /// hardware key (requires the `fido2-client`-feature build).
        #[arg(long)]
        software_key: Option<PathBuf>,
        /// The registered credential-id (base64url), as printed by
        /// fido2-register. Required in hardware mode (the key is non-resident, so
        /// the id must be presented); ignored in software mode.
        #[arg(long)]
        credential_id: Option<String>,
        /// PIN for a hardware authenticator that requires one (ignored in
        /// software mode).
        #[arg(long)]
        pin: Option<String>,
    },
}

fn human(secs: u64) -> String {
    match secs {
        s if s >= 3600 => format!("{}h{:02}m", s / 3600, (s % 3600) / 60),
        s if s >= 60 => format!("{}m{:02}s", s / 60, s % 60),
        s => format!("{s}s"),
    }
}

/// Hash a password read from stdin into an Argon2id PHC string. Local: no daemon.
/// The password is trimmed to match how `approve` and the daemon trim a submitted
/// token, so the hash verifies the same bytes the operator will later type.
fn hash_password() -> anyhow::Result<ExitCode> {
    use std::io::Read;
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let password = input.trim();
    if password.is_empty() {
        anyhow::bail!("no password on stdin");
    }
    // Salt from the OS CSPRNG (the daemon reads /dev/urandom the same way for its
    // challenge nonce); core hashing takes the salt injected.
    let mut salt = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut salt))
        .map_err(|e| anyhow::anyhow!("reading /dev/urandom for a salt: {e}"))?;
    let phc = lychgate_core::password::hash(password, &salt).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{phc}");
    Ok(ExitCode::SUCCESS)
}

fn read_urandom(n: usize) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let mut b = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| anyhow::anyhow!("reading /dev/urandom: {e}"))?;
    Ok(b)
}

fn parse_alg(s: &str) -> anyhow::Result<lychgate_core::Alg> {
    match s {
        "es256" => Ok(lychgate_core::Alg::Es256),
        "eddsa" => Ok(lychgate_core::Alg::EdDsa),
        other => anyhow::bail!("unknown fido2 alg {other:?}; expected es256 or eddsa"),
    }
}

/// A software authenticator file, mode 600: three base-content lines —
/// `<alg>`, `<credential-id base64url>`, `<private-key base64url>`.
fn read_softkey(path: &std::path::Path) -> anyhow::Result<(lychgate_core::Alg, Vec<u8>, Vec<u8>)> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    let mut lines = text.lines();
    let alg = parse_alg(lines.next().unwrap_or("").trim())?;
    let dec = |s: Option<&str>, what: &str| -> anyhow::Result<Vec<u8>> {
        data_encoding::BASE64URL_NOPAD
            .decode(s.unwrap_or("").trim().as_bytes())
            .map_err(|_| anyhow::anyhow!("{what} in the key file is not base64url"))
    };
    let cred_id = dec(lines.next(), "credential-id")?;
    let priv_key = dec(lines.next(), "private key")?;
    Ok((alg, cred_id, priv_key))
}

/// The software authenticator's registration: create or reuse the key file and
/// return `(credential_id, public_key)` in the storage form the inventory wants.
fn software_register(
    alg: lychgate_core::Alg,
    alg_str: &str,
    path: &std::path::Path,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let (cred_id, priv_key) = if path.exists() {
        let (existing_alg, cred_id, priv_key) = read_softkey(path)?;
        if existing_alg != alg {
            anyhow::bail!(
                "{} is a {existing_alg:?} key, not {alg_str}",
                path.display()
            );
        }
        (cred_id, priv_key)
    } else {
        // A valid ES256 scalar is almost any 32 bytes; retry the rare reject.
        // Ed25519 accepts any 32 bytes.
        let priv_key = loop {
            let candidate = read_urandom(32)?;
            if lychgate_core::fido2::public_key(alg, &candidate).is_ok() {
                break candidate;
            }
        };
        let cred_id = read_urandom(16)?;
        let b64 = data_encoding::BASE64URL_NOPAD;
        let body = format!(
            "{alg_str}\n{}\n{}\n",
            b64.encode(&cred_id),
            b64.encode(&priv_key)
        );
        std::fs::write(path, &body)
            .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
        // The software key is a secret: owner-only where the platform has unix
        // modes. The Windows client build has no mode_t (this was its one
        // compile error); NTFS ACL tightening is out of scope for the client.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| anyhow::anyhow!("chmod {}: {e}", path.display()))?;
        }
        (cred_id, priv_key)
    };
    let public =
        lychgate_core::fido2::public_key(alg, &priv_key).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok((cred_id, public))
}

fn fido2_register(
    alg_str: &str,
    software_key: Option<&std::path::Path>,
    pin: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let alg = parse_alg(alg_str)?;
    let (cred_id, public) = match software_key {
        Some(path) => software_register(alg, alg_str, path)?,
        None => hardware_register(alg, pin)?,
    };
    let b64 = data_encoding::BASE64URL_NOPAD;
    println!("[[approval.authenticator]]");
    println!("id = \"fido2\"                       # rename as you like");
    println!("kind = \"fido2\"");
    println!("alg = \"{alg_str}\"");
    println!("credential-id = \"{}\"", b64.encode(&cred_id));
    println!("public-key = \"{}\"", b64.encode(&public));
    Ok(ExitCode::SUCCESS)
}

fn fido2_assert(
    challenge: &str,
    software_key: Option<&std::path::Path>,
    credential_id: Option<&str>,
    pin: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let token = match software_key {
        Some(path) => {
            let (alg, cred_id, priv_key) = read_softkey(path)?;
            lychgate_core::fido2::build_assertion(alg, &priv_key, &cred_id, challenge)
                .map_err(|e| anyhow::anyhow!("{e}"))?
        }
        None => {
            let cred_id_b64 = credential_id.ok_or_else(|| {
                anyhow::anyhow!(
                    "a hardware assertion needs --credential-id <base64url> \
                     (the id fido2-register printed)"
                )
            })?;
            let cred_id = data_encoding::BASE64URL_NOPAD
                .decode(cred_id_b64.trim().as_bytes())
                .map_err(|_| anyhow::anyhow!("--credential-id is not base64url"))?;
            hardware_assert(challenge, &cred_id, pin)?
        }
    };
    println!("{token}");
    Ok(ExitCode::SUCCESS)
}

// --- hardware backend: the CTAP2/USB-HID client behind the fido2-client feature.
// The seam is identical in both builds; only the body differs, so the caller
// (fido2_register/fido2_assert) never needs a #[cfg]. Without the feature the
// hardware path is a clear, actionable refusal — never a silent fallback.

#[cfg(not(feature = "fido2-client"))]
fn hardware_register(
    _alg: lychgate_core::Alg,
    _pin: Option<&str>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    anyhow::bail!(
        "this build has no hardware FIDO2 support; rebuild with \
         `--features fido2-client` (unix, needs the system hidapi library), \
         or pass --software-key <file> for a software authenticator"
    )
}

#[cfg(not(feature = "fido2-client"))]
fn hardware_assert(
    _challenge: &str,
    _credential_id: &[u8],
    _pin: Option<&str>,
) -> anyhow::Result<String> {
    anyhow::bail!(
        "this build has no hardware FIDO2 support; rebuild with \
         `--features fido2-client` (unix, needs the system hidapi library), \
         or pass --software-key <file> for a software authenticator"
    )
}

#[cfg(feature = "fido2-client")]
fn hardware_register(
    alg: lychgate_core::Alg,
    pin: Option<&str>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    hw::register(alg, pin)
}

#[cfg(feature = "fido2-client")]
fn hardware_assert(
    challenge: &str,
    credential_id: &[u8],
    pin: Option<&str>,
) -> anyhow::Result<String> {
    hw::assert(challenge, credential_id, pin)
}

/// The CTAP2 hardware client: drives a real (or virtual) authenticator over
/// USB-HID via `ctap-hid-fido2`. It produces exactly the bytes the software
/// path and the KAT-pinned verifier accept — the clientDataJSON and the token
/// are assembled by `lychgate_core::fido2`, so there is one wire format.
///
/// This path has no CI oracle (no hardware on the build hosts). It is exercised
/// against a *virtual* authenticator over USB/IP in TESTING's simulated tier,
/// and the ceremony on a specific real key is a one-time manual check.
#[cfg(feature = "fido2-client")]
mod hw {
    use anyhow::{anyhow, Result};
    use ctap_hid_fido2::fidokey::CredentialSupportedKeyType;
    use ctap_hid_fido2::{Cfg, FidoKeyHid, FidoKeyHidFactory};
    use lychgate_core::fido2::RP_ID;
    use lychgate_core::Alg;

    fn open_device() -> Result<FidoKeyHid> {
        // Keep-alive prompts ("touch the key") must go to stderr — stdout carries
        // only the token, so `fido2-assert | approve` pipes cleanly.
        let cfg = Cfg::init().with_keep_alive_msg_to_stderr(true);
        FidoKeyHidFactory::create(&cfg)
            .map_err(|e| anyhow!("no FIDO2 authenticator found over USB-HID: {e}"))
    }

    /// Register: CTAP2 authenticatorMakeCredential with rpId = lychgate, keeping
    /// the credential id and public key. We do not verify the attestation — we
    /// trust the key material the user is registering, exactly as the inventory
    /// does (see DESIGN); a self-check confirms the extracted key parses.
    pub fn register(alg: Alg, pin: Option<&str>) -> Result<(Vec<u8>, Vec<u8>)> {
        let dev = open_device()?;
        let key_type = match alg {
            Alg::Es256 => CredentialSupportedKeyType::Ecdsa256,
            Alg::EdDsa => CredentialSupportedKeyType::Ed25519,
        };
        // The makeCredential clientDataHash is irrelevant to us (we do not check
        // the attestation), but the call needs one — a fixed, distinctive tag.
        let att = dev
            .make_credential_with_key_type(RP_ID, b"lychgate-fido2-register", pin, Some(key_type))
            .map_err(|e| anyhow!("makeCredential failed (touch the key? PIN?): {e}"))?;
        let public = extract_public_key(alg, &att.credential_publickey.der)?;
        // Self-check: the bytes we are about to print MUST parse as this alg's
        // public key, or registration would silently record an unusable key.
        lychgate_core::fido2::check_public_key(alg, &public)
            .map_err(|e| anyhow!("the authenticator's public key did not parse: {e}"))?;
        Ok((att.credential_descriptor.id, public))
    }

    /// Assert: CTAP2 authenticatorGetAssertion. We hand the authenticator the
    /// raw clientDataJSON as its `challenge`; the crate SHA-256's it into the
    /// clientDataHash the key signs (with authenticatorData) — which is what our
    /// verifier recomputes. The same clientDataJSON goes into the token.
    pub fn assert(challenge: &str, credential_id: &[u8], pin: Option<&str>) -> Result<String> {
        let dev = open_device()?;
        let cdj = lychgate_core::fido2::client_data_json(challenge);
        // The credential is non-resident: its id must be in the allow-list so
        // the authenticator can unwrap the private key.
        let assertion = dev
            .get_assertion(RP_ID, &cdj, &[credential_id.to_vec()], pin)
            .map_err(|e| anyhow!("getAssertion failed (touch the key? PIN?): {e}"))?;
        Ok(lychgate_core::fido2::assemble_token(
            &assertion.credential_id,
            &assertion.auth_data,
            &cdj,
            &assertion.signature,
        ))
    }

    /// A SubjectPublicKeyInfo DER → the storage form `verify` expects. For P-256
    /// the SPKI ends in the 65-byte uncompressed SEC1 point (0x04‖X‖Y); for
    /// Ed25519 it ends in the raw 32-byte key. `check_public_key` in the caller
    /// is the oracle that this slice is right.
    fn extract_public_key(alg: Alg, der: &[u8]) -> Result<Vec<u8>> {
        let n = match alg {
            Alg::Es256 => 65,
            Alg::EdDsa => 32,
        };
        if der.len() < n {
            return Err(anyhow!(
                "authenticator public-key DER is {} bytes, too short for {alg:?}",
                der.len()
            ));
        }
        Ok(der[der.len() - n..].to_vec())
    }
}

fn run() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();

    // Local utilities — no daemon connection. Handled before an Op is built.
    match &cli.command {
        Command::HashPassword => return hash_password(),
        Command::Fido2Register {
            alg,
            software_key,
            pin,
        } => return fido2_register(alg, software_key.as_deref(), pin.as_deref()),
        Command::Fido2Assert {
            challenge,
            software_key,
            credential_id,
            pin,
        } => {
            return fido2_assert(
                challenge,
                software_key.as_deref(),
                credential_id.as_deref(),
                pin.as_deref(),
            )
        }
        _ => {}
    }

    let op = match &cli.command {
        Command::Open { host, ttl, profile } => {
            // Policy is enforced client-side first so a bad TTL fails with
            // core's error before a connection is attempted; the daemon
            // enforces it again regardless.
            Ttl::parse(ttl)?;
            Op::Open {
                host: host.clone(),
                ttl: ttl.clone(),
                profile: profile.clone(),
            }
        }
        Command::Approve {
            host,
            token,
            token_file,
        } => {
            use std::io::Read;
            let tok = if let Some(t) = token {
                t.clone()
            } else if let Some(f) = token_file {
                std::fs::read_to_string(f)?.trim().to_string()
            } else {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s.trim().to_string()
            };
            Op::Approve {
                host: host.clone(),
                token: tok,
            }
        }
        Command::Renew { host, ttl } => {
            Ttl::parse(ttl)?;
            Op::Renew {
                host: host.clone(),
                ttl: ttl.clone(),
            }
        }
        Command::Close { host } => Op::Close { host: host.clone() },
        Command::Status => Op::Status,
        Command::Drill { host } => Op::Drill { host: host.clone() },
        // Handled before this match (local, no daemon).
        Command::HashPassword | Command::Fido2Register { .. } | Command::Fido2Assert { .. } => {
            unreachable!("local commands are handled before this match")
        }
    };

    let response: Response = transport::roundtrip(&cli.socket, &op)?;

    if response.result == ResponseResult::Refused {
        // The daemon's words, verbatim.
        eprintln!(
            "refused: {}",
            response.error.as_deref().unwrap_or("(no reason given)")
        );
        return Ok(ExitCode::FAILURE);
    }

    // The now-open grant plus its one-time secret and endpoint — shared by the
    // approve command, which is where a grant actually opens.
    let print_opened = |host: &str, r: &Response| {
        let expires = r.expires_at.unwrap_or(0);
        println!("grant open on {host} until epoch {expires}");
        if let Some(outcome) = &r.outcome {
            println!("{outcome}");
        }
        if let Some(secret) = &r.secret {
            // Shown exactly once — the daemon does not store or journal it.
            // The label defaults to the BMC wording so an older daemon prints
            // exactly as before.
            let label = r
                .secret_label
                .as_deref()
                .unwrap_or("break-glass BMC password");
            println!("{label} (shown once): {secret}");
        }
    };

    match (&cli.command, &response) {
        (Command::Open { host, .. }, r) => match &r.pending {
            Some(p) => {
                println!(
                    "approval required for {host} under profile {:?} (ttl {}, approve within {}s)",
                    p.profile,
                    human(p.ttl_secs),
                    p.approval_deadline.saturating_sub(p.requested_at)
                );
                println!(
                    "weight {}/{} so far; outstanding: {}",
                    p.weight,
                    p.threshold,
                    if p.missing.is_empty() {
                        "(none)".to_string()
                    } else {
                        p.missing.join(" | ")
                    }
                );
                println!("challenge: {}", p.challenge);
                println!(
                    "sign it on your device, e.g.:\n  \
                     printf %s '{}' | ssh-keygen -Y sign -n lychgate-approval -f ~/.ssh/id_ed25519",
                    p.challenge
                );
                println!("then: lychgate approve --host {host}   (paste the signature, then EOF)");
            }
            // A daemon in --dry-run or an older one may open directly.
            None => print_opened(host, r),
        },
        (Command::Approve { host, .. }, r) => match &r.pending {
            // The proof was accepted but the threshold is not yet met: show
            // progress. More proofs (or an elapsed wait) will open the grant.
            Some(p) => {
                println!(
                    "proof accepted for {host}: weight {}/{}",
                    p.weight, p.threshold
                );
                if !p.missing.is_empty() {
                    println!("still outstanding: {}", p.missing.join(" | "));
                }
                println!("submit more proofs, or wait, to reach the threshold");
            }
            None => print_opened(host, r),
        },
        (Command::Renew { host, .. }, r) => {
            let expires = r.expires_at.unwrap_or(0);
            println!("grant on {host} renewed until epoch {expires}");
        }
        (Command::Close { host }, r) => match r.outcome.as_deref() {
            Some("closed") => println!("grant on {host} closed"),
            Some("already-closed") => println!("grant on {host} was already closed"),
            other => println!("grant on {host}: {}", other.unwrap_or("(no outcome)")),
        },
        (Command::Status, r) => {
            for g in r.grants.as_deref().unwrap_or(&[]) {
                match (&g.state, g.remaining_secs) {
                    (GrantState::Open, Some(secs)) => {
                        println!("{}\topen\t{} remaining", g.host, human(secs))
                    }
                    (GrantState::Open, None) => println!("{}\topen", g.host),
                    (GrantState::AwaitingApproval, Some(secs)) => {
                        println!("{}\tawaiting-approval\t{} to approve", g.host, human(secs))
                    }
                    (GrantState::AwaitingApproval, None) => {
                        println!("{}\tawaiting-approval", g.host)
                    }
                    (GrantState::ApprovalExpired, _) => {
                        println!("{}\tapproval-expired", g.host)
                    }
                    (GrantState::Opening, _) => println!("{}\topening", g.host),
                    (GrantState::Closed, _) => println!("{}\tclosed", g.host),
                    (GrantState::Expired, _) => {
                        println!("{}\texpired\trevert pending", g.host)
                    }
                    (GrantState::NeedsRevert, _) => println!(
                        "{}\tneeds-revert\t{:?}",
                        g.host,
                        g.stuck_channels.as_deref().unwrap_or(&[])
                    ),
                }
            }
        }
        (Command::Drill { .. }, r) => {
            println!("{}", r.outcome.as_deref().unwrap_or("drill passed"));
        }
        // Returned early before any daemon round trip.
        (Command::HashPassword, _)
        | (Command::Fido2Register { .. }, _)
        | (Command::Fido2Assert { .. }, _) => {
            unreachable!("local commands are handled before this match")
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("lychgate: {e:#}");
            ExitCode::FAILURE
        }
    }
}
