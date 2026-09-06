//! Shared TPM 2.0 plumbing for lychgate's `tpm-client` (cli) and `tpm-seal`
//! (daemon) features. One crate on purpose: the **seal and unseal sides must
//! agree on the storage-key template byte for byte** (a drift would orphan every
//! sealed blob), and the signing template must be identical between register and
//! sign (a primary key with a fixed template is re-derived, not stored — the
//! same template on the same TPM always yields the same key).
//!
//! Everything real is behind the `tss` feature; without it this crate is an
//! empty stub, so default `--workspace` builds never touch the C TSS stack.
//!
//! v1 policy decisions, documented rather than implied:
//!   - The signing key and the storage parent are **owner-hierarchy primaries
//!     with fixed templates** — nothing is persisted in the TPM, so there is no
//!     handle management and a factory-reset TPM simply yields a new key.
//!   - Sealed blobs bind to **the TPM itself** (fixedtpm/fixedparent), with no
//!     PCR policy and an empty auth value: the threat model is "the file leaked
//!     off the host", not "an attacker runs code on the host as the daemon".
//!     PCR binding is future hardening (see ROADMAP).

#[cfg(feature = "tss")]
mod real;
#[cfg(feature = "tss")]
pub use real::*;
