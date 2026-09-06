//! The AI principal's signing key. The MCP server holds an Ed25519 key and,
//! when it opens a grant, signs the challenge into exactly the SSHSIG a human's
//! `ssh-keygen -Y sign -n lychgate-approval` would produce — so the daemon
//! verifies the AI's factor with the same ed25519 path as any operator's.

use std::path::Path;

use anyhow::Context;
use ssh_key::{HashAlg, LineEnding, PrivateKey};

use lychgate_core::APPROVAL_NAMESPACE;

pub struct Signer {
    key: PrivateKey,
}

impl Signer {
    /// Load an unencrypted OpenSSH Ed25519 private key from a file. It is a
    /// service credential, so a passphrase-encrypted key is refused rather than
    /// prompted for.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the AI principal key {}", path.display()))?;
        Self::from_openssh(&text)
            .with_context(|| format!("loading the AI principal key {}", path.display()))
    }

    /// Parse an unencrypted OpenSSH private key from its text.
    pub fn from_openssh(text: &str) -> anyhow::Result<Self> {
        let key =
            PrivateKey::from_openssh(text.trim()).context("parsing the OpenSSH private key")?;
        if key.is_encrypted() {
            anyhow::bail!(
                "the AI principal key is passphrase-encrypted; supply an unencrypted key \
                 (it is an unattended service credential)"
            );
        }
        Ok(Self { key })
    }

    /// Sign a lychgate challenge under the approval namespace, emitting the
    /// `-----BEGIN SSH SIGNATURE-----` PEM token the daemon accepts.
    pub fn sign_challenge(&self, challenge: &str) -> anyhow::Result<String> {
        let sig = self
            .key
            .sign(APPROVAL_NAMESPACE, HashAlg::Sha512, challenge.as_bytes())
            .context("signing the challenge with the AI principal key")?;
        sig.to_pem(LineEnding::LF)
            .context("PEM-encoding the AI signature")
    }

    /// The principal's public key in OpenSSH line form — what an operator pastes
    /// into `[[approval.authenticator]] kind = "ed25519"` for the AI factor.
    pub fn public_openssh(&self) -> anyhow::Result<String> {
        self.key
            .public_key()
            .to_openssh()
            .context("encoding the AI public key")
    }
}
