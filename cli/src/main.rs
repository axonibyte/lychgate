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
        /// The software authenticator file to create/reuse (mode 600).
        #[arg(long)]
        software_key: Option<PathBuf>,
    },
    /// Produce a FIDO2 assertion over a challenge, printing the token to pipe
    /// into `approve`. Local. `--software-key <file>` uses a software
    /// authenticator; hardware is the `fido2-client`-feature build.
    Fido2Assert {
        /// The challenge string from `open`.
        #[arg(long)]
        challenge: String,
        /// The software authenticator file (from fido2-register).
        #[arg(long)]
        software_key: Option<PathBuf>,
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

fn fido2_register(
    alg_str: &str,
    software_key: Option<&std::path::Path>,
) -> anyhow::Result<ExitCode> {
    let alg = parse_alg(alg_str)?;
    let path = software_key.ok_or_else(|| {
        anyhow::anyhow!(
            "hardware registration needs the fido2-client feature; \
             pass --software-key <file> for a software authenticator"
        )
    })?;
    let b64 = data_encoding::BASE64URL_NOPAD;
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
        let body = format!(
            "{alg_str}\n{}\n{}\n",
            b64.encode(&cred_id),
            b64.encode(&priv_key)
        );
        std::fs::write(path, &body)
            .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| anyhow::anyhow!("chmod {}: {e}", path.display()))?;
        (cred_id, priv_key)
    };
    let public =
        lychgate_core::fido2::public_key(alg, &priv_key).map_err(|e| anyhow::anyhow!("{e}"))?;
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
) -> anyhow::Result<ExitCode> {
    let path = software_key.ok_or_else(|| {
        anyhow::anyhow!(
            "hardware assertions need the fido2-client feature; \
             pass --software-key <file> for a software authenticator"
        )
    })?;
    let (alg, cred_id, priv_key) = read_softkey(path)?;
    let token = lychgate_core::fido2::build_assertion(alg, &priv_key, &cred_id, challenge)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{token}");
    Ok(ExitCode::SUCCESS)
}

fn run() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();

    // Local utilities — no daemon connection. Handled before an Op is built.
    match &cli.command {
        Command::HashPassword => return hash_password(),
        Command::Fido2Register { alg, software_key } => {
            return fido2_register(alg, software_key.as_deref())
        }
        Command::Fido2Assert {
            challenge,
            software_key,
        } => return fido2_assert(challenge, software_key.as_deref()),
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
