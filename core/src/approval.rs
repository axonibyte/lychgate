//! Operator approval: the human authorizes, the agent works inside the grant.
//!
//! Opening a grant is gated on a token the operator produces on their own
//! device, out of band, over a challenge the daemon issues. This module is the
//! pure verification seam and its first backend; the daemon supplies the
//! configured key material and calls `verify`. No I/O, no clock, no
//! randomness lives here — the challenge's nonce and timestamp arrive already
//! chosen by the daemon.
//!
//! The first backend is **SSHSIG Ed25519**: the operator signs the challenge
//! with `ssh-keygen -Y sign -n lychgate-approval -f <key>`, reusing an existing
//! SSH key (agent keys and hardware `ed25519-sk` keys included), and the daemon
//! verifies that SSHSIG against a configured allowed-signers set. TOTP and
//! FIDO2 backends slot behind the same `ApprovalVerifier` trait in later
//! sub-milestones.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use ssh_key::{PublicKey, SshSig};

/// The SSHSIG namespace the operator must sign under (`ssh-keygen -Y sign -n`).
/// Binds an approval to lychgate, so a signature made for another purpose
/// cannot be replayed here.
pub const APPROVAL_NAMESPACE: &str = "lychgate-approval";

/// The one thing the operator authorizes: this host, for this TTL, once. The
/// nonce (daemon CSPRNG) and requested-at instant (daemon clock) bind the
/// approval to exactly this request so a token cannot be reused for another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    nonce: [u8; 32],
    host: String,
    ttl_secs: u64,
    requested_at: SystemTime,
}

impl ApprovalRequest {
    pub fn new(
        nonce: [u8; 32],
        host: String,
        ttl_secs: u64,
        requested_at: SystemTime,
    ) -> ApprovalRequest {
        ApprovalRequest {
            nonce,
            host,
            ttl_secs,
            requested_at,
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    pub fn requested_at(&self) -> SystemTime {
        self.requested_at
    }

    /// The exact bytes a signature covers. Domain-separated and length-prefixed
    /// (not TOML/JSON): every field is bounded by an explicit big-endian length
    /// rather than a delimiter, so no host name or nonce can be framed to
    /// collide with a different request. The daemon and `ssh-keygen` must agree
    /// on these bytes to the byte — the length prefixes are what make that
    /// unambiguous.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let secs = self
            .requested_at
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut out = Vec::new();
        out.extend_from_slice(b"lychgate-approval\x00v1\x00");
        out.extend_from_slice(&(self.host.len() as u32).to_be_bytes());
        out.extend_from_slice(self.host.as_bytes());
        out.extend_from_slice(&self.ttl_secs.to_be_bytes());
        out.extend_from_slice(&secs.to_be_bytes());
        out.extend_from_slice(&(self.nonce.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }

    /// The challenge the daemon displays and the operator signs: a copy-pasteable
    /// `lg1.req.<base64url(canonical)>`. Signing this exact string binds the
    /// approval to the request it encodes.
    pub fn challenge_string(&self) -> String {
        format!(
            "lg1.req.{}",
            data_encoding::BASE64URL_NOPAD.encode(&self.canonical_bytes())
        )
    }
}

#[derive(Debug)]
pub enum ApprovalError {
    /// The token could not be decoded (not a well-formed SSHSIG, bad armor).
    Malformed(String),
    /// The signature was made under a different namespace than lychgate's.
    WrongNamespace(String),
    /// A well-formed signature from a key that is not in the allowed set.
    UnknownApprover(String),
    /// The signature did not verify over this request's challenge.
    BadSignature,
    /// No approver is configured — fail-closed: nothing can ever be approved.
    NoApproverConfigured,
    /// Every configured approver rejected the token.
    AllRejected(Vec<ApprovalError>),
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApprovalError::Malformed(m) => write!(f, "malformed approval token: {m}"),
            ApprovalError::WrongNamespace(ns) => write!(
                f,
                "approval signed under namespace {ns:?}, not {APPROVAL_NAMESPACE:?}"
            ),
            ApprovalError::UnknownApprover(m) => {
                write!(f, "approval from an unrecognized signer: {m}")
            }
            ApprovalError::BadSignature => {
                write!(f, "approval signature did not verify over the challenge")
            }
            ApprovalError::NoApproverConfigured => write!(
                f,
                "no approver is configured; opening a grant is refused (fail-closed)"
            ),
            ApprovalError::AllRejected(errs) => {
                write!(f, "every configured approver rejected the token: ")?;
                for (i, e) in errs.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{e}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ApprovalError {}

/// A backend that decides whether a token approves a request. Pure for the
/// SSHSIG backend; a stateful backend (TOTP's single-use ledger) uses interior
/// mutability so the seam stays `&self`. `verify` does NOT check the approval
/// window — that is the lifecycle's job via the grant's observed status.
pub trait ApprovalVerifier: Send + Sync {
    fn verify(&self, request: &ApprovalRequest, token: &str) -> Result<(), ApprovalError>;
}

/// Accepts a token if any configured approver accepts it. Fail-closed: an empty
/// set approves nothing.
pub struct AnyOf(pub Vec<Box<dyn ApprovalVerifier>>);

impl ApprovalVerifier for AnyOf {
    fn verify(&self, request: &ApprovalRequest, token: &str) -> Result<(), ApprovalError> {
        if self.0.is_empty() {
            return Err(ApprovalError::NoApproverConfigured);
        }
        let mut errs = Vec::new();
        for verifier in &self.0 {
            match verifier.verify(request, token) {
                Ok(()) => return Ok(()),
                Err(e) => errs.push(e),
            }
        }
        Err(ApprovalError::AllRejected(errs))
    }
}

/// Approves any token. Wired only under `--dry-run`, where no driver runs and
/// no access is granted, and in tests; never in a serving daemon.
pub struct AcceptAny;

impl ApprovalVerifier for AcceptAny {
    fn verify(&self, _request: &ApprovalRequest, _token: &str) -> Result<(), ApprovalError> {
        Ok(())
    }
}

/// Rejects every token — for exercising the deny path in tests.
pub struct RefuseAll;

impl ApprovalVerifier for RefuseAll {
    fn verify(&self, _request: &ApprovalRequest, _token: &str) -> Result<(), ApprovalError> {
        Err(ApprovalError::BadSignature)
    }
}

/// Parses an OpenSSH public key line (`ssh-ed25519 AAAA… comment`). The one
/// place a configured key is turned into a verifiable key, shared by the
/// inventory's load-time validation and the daemon's verifier construction.
pub fn parse_ssh_public_key(line: &str) -> Result<PublicKey, ApprovalError> {
    PublicKey::from_openssh(line.trim())
        .map_err(|e| ApprovalError::Malformed(format!("not an openssh public key: {e}")))
}

/// The SSHSIG Ed25519 backend: verify a `ssh-keygen -Y sign` token over the
/// request's challenge, against an allowed-signers set.
pub struct SshSigVerifier {
    allowed: Vec<(String, PublicKey)>,
}

impl SshSigVerifier {
    pub fn new(allowed: Vec<(String, PublicKey)>) -> SshSigVerifier {
        SshSigVerifier { allowed }
    }
}

impl ApprovalVerifier for SshSigVerifier {
    fn verify(&self, request: &ApprovalRequest, token: &str) -> Result<(), ApprovalError> {
        let sig: SshSig = token
            .trim()
            .parse()
            .map_err(|e| ApprovalError::Malformed(format!("not a valid SSHSIG: {e}")))?;
        if sig.namespace() != APPROVAL_NAMESPACE {
            return Err(ApprovalError::WrongNamespace(sig.namespace().to_string()));
        }
        // The signer must be in the allowed set — matched by key material, so a
        // valid signature from an unlisted key is refused, not verified.
        let matched = self
            .allowed
            .iter()
            .find(|(_, pk)| pk.key_data() == sig.public_key());
        let (_id, pk) = matched.ok_or_else(|| {
            ApprovalError::UnknownApprover("signer is not in the allowed-signers set".to_string())
        })?;
        pk.verify(
            APPROVAL_NAMESPACE,
            request.challenge_string().as_bytes(),
            &sig,
        )
        .map_err(|_| ApprovalError::BadSignature)
    }
}

#[cfg(test)]
mod tests;
