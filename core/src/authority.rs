//! Weighted-threshold approval authorities, modelled on EOS/Antelope
//! permissions.
//!
//! A *gate* is an [`Authority`]: a `threshold` and a set of weighted factors. A
//! factor is one of
//!   - an **authenticator** — a leaf proof (an Ed25519 SSHSIG today; TOTP,
//!     password and FIDO2 in later sub-milestones), identified by id;
//!   - a **group** — itself an [`Authority`], satisfied when *its* threshold is
//!     met, so gates nest into a DAG;
//!   - a **wait** — satisfied once a duration has elapsed since the request.
//!
//! When the satisfied factors' weights sum to at least the threshold, the gate
//! opens. This subsumes MFA (a group whose threshold equals its factor count)
//! and the single approver (a threshold-1 authority with one weight-1 factor).
//!
//! This module is pure: no clock, no I/O, no randomness. The daemon supplies the
//! set of already-verified authenticator ids and the elapsed time; [`evaluate`]
//! decides. Building a model from config ([`AuthorityModel::from_spec`]) does all
//! the structural validation — dangling references, cycles, unsatisfiable
//! thresholds — so a broken policy fails at load, not at 03:00.
//!
//! [`evaluate`]: AuthorityModel::evaluate

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::Deserialize;
use ssh_key::{PublicKey, SshSig};

use crate::approval::{parse_ssh_public_key, ApprovalError, ApprovalRequest, APPROVAL_NAMESPACE};
use crate::ttl::Ttl;

// ---------------------------------------------------------------------------
// Config spec (deserialized straight from the inventory's [approval] table)
// ---------------------------------------------------------------------------

/// The deployment-wide `[approval]` policy as written in the inventory: a set of
/// named authenticators, a set of named groups, and a set of named profiles.
/// Structural meaning is checked by [`AuthorityModel::from_spec`], not by serde.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSpec {
    #[serde(default)]
    pub authenticator: Vec<AuthenticatorSpec>,
    #[serde(default)]
    pub group: Vec<AuthoritySpec>,
    #[serde(default)]
    pub profile: Vec<AuthoritySpec>,
}

/// One configured authenticator: an id, a kind, and the material that kind
/// needs. Ed25519 carries a public key inline (it is public); secret-bearing
/// kinds will carry a file path, never an inline secret.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AuthenticatorSpec {
    pub id: String,
    pub kind: AuthKind,
    /// Required for `ed25519`; an OpenSSH public-key line.
    #[serde(default)]
    pub public_key: Option<String>,
}

/// The authenticator vocabulary. Only `ed25519` is implemented; the rest parse
/// (so a full policy can be written and referenced now) but are refused at load
/// naming the sub-milestone that will build them — the racadm/ipmitool
/// precedent in `bmc.rs`.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthKind {
    Ed25519,
    Totp,
    Password,
    Fido2,
}

/// A named authority (a group or a profile share the same shape): a threshold
/// over weighted factors.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySpec {
    pub id: String,
    pub threshold: u32,
    pub factor: Vec<FactorSpec>,
}

/// One weighted factor. Exactly one of `authenticator` / `group` / `wait` must
/// be set (checked at build); `wait` is a TTL-style duration string.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FactorSpec {
    pub weight: u32,
    #[serde(default)]
    pub authenticator: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub wait: Option<String>,
}

// ---------------------------------------------------------------------------
// Runtime model (built + validated from the spec)
// ---------------------------------------------------------------------------

/// An authenticator's verifiable material, resolved from its spec.
#[derive(Debug, Clone)]
pub enum Authenticator {
    Ed25519(PublicKey),
}

/// A weighted-threshold authority: `weight-sum(satisfied) >= threshold` opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    pub threshold: u32,
    pub factors: Vec<WeightedFactor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightedFactor {
    pub weight: u32,
    pub factor: Factor,
}

/// A single factor: a leaf authenticator, a nested group, or an elapsed wait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Factor {
    Authenticator(String),
    Group(String),
    Wait(Duration),
}

/// The validated policy: authenticators, groups, and profiles, all references
/// resolved and the group graph proven acyclic.
#[derive(Debug, Clone)]
pub struct AuthorityModel {
    authenticators: BTreeMap<String, Authenticator>,
    groups: BTreeMap<String, Authority>,
    profiles: BTreeMap<String, Authority>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthorityError {
    /// No profile is defined — fail-closed: nothing could ever be opened.
    NoProfiles,
    EmptyId {
        kind: &'static str,
    },
    DuplicateAuthenticator(String),
    DuplicateGroup(String),
    DuplicateProfile(String),
    /// A configured authenticator kind that is not implemented yet.
    UnimplementedKind {
        id: String,
        kind: &'static str,
        milestone: &'static str,
    },
    /// The material a kind needs is missing or malformed.
    MissingMaterial {
        id: String,
        kind: &'static str,
        field: &'static str,
    },
    BadPublicKey {
        id: String,
        message: String,
    },
    /// A threshold of zero would open with no proof at all.
    ZeroThreshold {
        kind: &'static str,
        id: String,
    },
    /// A weight of zero is a factor that can never contribute — dead config.
    ZeroWeight {
        kind: &'static str,
        id: String,
    },
    NoFactors {
        kind: &'static str,
        id: String,
    },
    /// A factor names none, or more than one, of authenticator/group/wait.
    BadFactor {
        kind: &'static str,
        id: String,
        message: &'static str,
    },
    BadWait {
        kind: &'static str,
        id: String,
        message: String,
    },
    /// The threshold exceeds the sum of all factor weights: unopenable.
    Unsatisfiable {
        kind: &'static str,
        id: String,
        threshold: u32,
        available: u64,
    },
    /// A factor references an authenticator/group that is not defined.
    DanglingAuthenticator {
        referrer: String,
        id: String,
    },
    DanglingGroup {
        referrer: String,
        id: String,
    },
    /// Group references form a cycle: evaluation would never terminate.
    GroupCycle {
        id: String,
    },
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorityError::NoProfiles => write!(
                f,
                "[approval] defines no profile; opening a grant could never be authorized (fail-closed)"
            ),
            AuthorityError::EmptyId { kind } => write!(f, "an [approval] {kind} has an empty id"),
            AuthorityError::DuplicateAuthenticator(id) => {
                write!(f, "authenticator id {id:?} appears more than once")
            }
            AuthorityError::DuplicateGroup(id) => write!(f, "group id {id:?} appears more than once"),
            AuthorityError::DuplicateProfile(id) => {
                write!(f, "profile id {id:?} appears more than once")
            }
            AuthorityError::UnimplementedKind { id, kind, milestone } => write!(
                f,
                "authenticator {id:?} is kind {kind:?}, which is not implemented yet (arrives in {milestone}); only ed25519 is live"
            ),
            AuthorityError::MissingMaterial { id, kind, field } => write!(
                f,
                "authenticator {id:?} (kind {kind:?}) is missing its required {field}"
            ),
            AuthorityError::BadPublicKey { id, message } => {
                write!(f, "authenticator {id:?}: public-key does not parse: {message}")
            }
            AuthorityError::ZeroThreshold { kind, id } => write!(
                f,
                "{kind} {id:?} has a threshold of 0, which would open with no proof at all"
            ),
            AuthorityError::ZeroWeight { kind, id } => write!(
                f,
                "{kind} {id:?} has a factor of weight 0, which could never contribute; dead config is a typo"
            ),
            AuthorityError::NoFactors { kind, id } => {
                write!(f, "{kind} {id:?} lists no factors, so it could never be satisfied")
            }
            AuthorityError::BadFactor { kind, id, message } => {
                write!(f, "{kind} {id:?} has a factor that {message}")
            }
            AuthorityError::BadWait { kind, id, message } => {
                write!(f, "{kind} {id:?} has a wait that does not parse: {message}")
            }
            AuthorityError::Unsatisfiable { kind, id, threshold, available } => write!(
                f,
                "{kind} {id:?} has threshold {threshold} but its factors sum to only {available}; it could never be opened"
            ),
            AuthorityError::DanglingAuthenticator { referrer, id } => write!(
                f,
                "{referrer} references authenticator {id:?}, which is not defined"
            ),
            AuthorityError::DanglingGroup { referrer, id } => {
                write!(f, "{referrer} references group {id:?}, which is not defined")
            }
            AuthorityError::GroupCycle { id } => write!(
                f,
                "group {id:?} is part of a reference cycle; a gate that references itself could never be evaluated"
            ),
        }
    }
}

impl std::error::Error for AuthorityError {}

/// What a factor still needs, for the human "what's outstanding" summary. Never
/// carries a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Missing {
    Authenticator(String),
    Group(String),
    Wait { remaining: Duration },
}

/// The result of evaluating an authority against a satisfied set and elapsed
/// time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub weight: u64,
    pub threshold: u32,
    pub met: bool,
    pub missing: Vec<Missing>,
}

impl AuthorityModel {
    /// Build and fully validate a model from the config spec. Every reference is
    /// resolved, every authority is satisfiable, and the group graph is acyclic;
    /// otherwise a named error, so the policy fails at load.
    pub fn from_spec(spec: &ApprovalSpec) -> Result<AuthorityModel, AuthorityError> {
        // 1. Authenticators.
        let mut authenticators = BTreeMap::new();
        for a in &spec.authenticator {
            if a.id.is_empty() {
                return Err(AuthorityError::EmptyId {
                    kind: "authenticator",
                });
            }
            let auth = match a.kind {
                AuthKind::Ed25519 => {
                    let line = a
                        .public_key
                        .as_deref()
                        .ok_or(AuthorityError::MissingMaterial {
                            id: a.id.clone(),
                            kind: "ed25519",
                            field: "public-key",
                        })?;
                    let pk =
                        parse_ssh_public_key(line).map_err(|e| AuthorityError::BadPublicKey {
                            id: a.id.clone(),
                            message: e.to_string(),
                        })?;
                    Authenticator::Ed25519(pk)
                }
                // Reserve the vocabulary without pretending it works.
                AuthKind::Totp => {
                    return Err(AuthorityError::UnimplementedKind {
                        id: a.id.clone(),
                        kind: "totp",
                        milestone: "M8a.3",
                    })
                }
                AuthKind::Password => {
                    return Err(AuthorityError::UnimplementedKind {
                        id: a.id.clone(),
                        kind: "password",
                        milestone: "M8a.4",
                    })
                }
                AuthKind::Fido2 => {
                    return Err(AuthorityError::UnimplementedKind {
                        id: a.id.clone(),
                        kind: "fido2",
                        milestone: "M8a.5",
                    })
                }
            };
            if authenticators.insert(a.id.clone(), auth).is_some() {
                return Err(AuthorityError::DuplicateAuthenticator(a.id.clone()));
            }
        }

        // 2. Groups and profiles (same shape; separate namespaces).
        let mut groups = BTreeMap::new();
        for g in &spec.group {
            let (id, authority) = build_authority("group", g)?;
            if groups.insert(id.clone(), authority).is_some() {
                return Err(AuthorityError::DuplicateGroup(id));
            }
        }
        let mut profiles = BTreeMap::new();
        for p in &spec.profile {
            let (id, authority) = build_authority("profile", p)?;
            if profiles.insert(id.clone(), authority).is_some() {
                return Err(AuthorityError::DuplicateProfile(id));
            }
        }
        if profiles.is_empty() {
            return Err(AuthorityError::NoProfiles);
        }

        // 3. Resolve references: every authenticator/group a factor names exists.
        let check_refs = |referrer: &str, authority: &Authority| -> Result<(), AuthorityError> {
            for wf in &authority.factors {
                match &wf.factor {
                    Factor::Authenticator(id) if !authenticators.contains_key(id) => {
                        return Err(AuthorityError::DanglingAuthenticator {
                            referrer: referrer.to_string(),
                            id: id.clone(),
                        })
                    }
                    Factor::Group(id) if !groups.contains_key(id) => {
                        return Err(AuthorityError::DanglingGroup {
                            referrer: referrer.to_string(),
                            id: id.clone(),
                        })
                    }
                    _ => {}
                }
            }
            Ok(())
        };
        for (id, authority) in &groups {
            check_refs(&format!("group {id:?}"), authority)?;
        }
        for (id, authority) in &profiles {
            check_refs(&format!("profile {id:?}"), authority)?;
        }

        // 4. The group graph must be acyclic (profiles are only ever referrers,
        //    so a cycle can only live among groups).
        let model = AuthorityModel {
            authenticators,
            groups,
            profiles,
        };
        model.check_group_acyclic()?;
        Ok(model)
    }

    fn check_group_acyclic(&self) -> Result<(), AuthorityError> {
        // Three-colour DFS: a back-edge to a node on the current stack is a
        // cycle. References were already proven to resolve.
        #[derive(Clone, Copy, PartialEq)]
        enum Colour {
            White,
            Grey,
            Black,
        }
        let mut colour: BTreeMap<&str, Colour> = self
            .groups
            .keys()
            .map(|k| (k.as_str(), Colour::White))
            .collect();

        // Iterative DFS so a deep chain cannot blow the stack.
        for start in self.groups.keys() {
            if colour[start.as_str()] != Colour::White {
                continue;
            }
            // Stack of (node, entering?) — entering marks grey, leaving marks black.
            let mut stack: Vec<(&str, bool)> = vec![(start.as_str(), true)];
            while let Some((node, entering)) = stack.pop() {
                if entering {
                    colour.insert(node, Colour::Grey);
                    stack.push((node, false));
                    for wf in &self.groups[node].factors {
                        if let Factor::Group(child) = &wf.factor {
                            match colour[child.as_str()] {
                                Colour::Grey => {
                                    return Err(AuthorityError::GroupCycle { id: child.clone() })
                                }
                                Colour::White => stack.push((child.as_str(), true)),
                                Colour::Black => {}
                            }
                        }
                    }
                } else {
                    colour.insert(node, Colour::Black);
                }
            }
        }
        Ok(())
    }

    pub fn profile(&self, id: &str) -> Option<&Authority> {
        self.profiles.get(id)
    }

    pub fn profile_ids(&self) -> impl Iterator<Item = &str> {
        self.profiles.keys().map(|s| s.as_str())
    }

    /// Evaluate an authority against the set of satisfied authenticator ids and
    /// the time elapsed since the request. Recurses into groups; terminates
    /// because the model is validated acyclic.
    pub fn evaluate(
        &self,
        authority: &Authority,
        satisfied: &BTreeSet<String>,
        elapsed: Duration,
    ) -> Outcome {
        let mut weight: u64 = 0;
        let mut missing = Vec::new();
        for wf in &authority.factors {
            let ok = match &wf.factor {
                Factor::Authenticator(id) => satisfied.contains(id),
                Factor::Group(id) => match self.groups.get(id) {
                    // A resolved model always finds the group; be defensive.
                    Some(g) => self.evaluate(g, satisfied, elapsed).met,
                    None => false,
                },
                Factor::Wait(dur) => elapsed >= *dur,
            };
            if ok {
                weight += wf.weight as u64;
            } else {
                missing.push(match &wf.factor {
                    Factor::Authenticator(id) => Missing::Authenticator(id.clone()),
                    Factor::Group(id) => Missing::Group(id.clone()),
                    Factor::Wait(dur) => Missing::Wait {
                        remaining: dur.saturating_sub(elapsed),
                    },
                });
            }
        }
        Outcome {
            weight,
            threshold: authority.threshold,
            met: weight >= authority.threshold as u64,
            missing,
        }
    }

    /// The longest `wait` anywhere in a profile's reachable authority graph.
    /// The daemon uses this to refuse an open whose approval window is too short
    /// for the waits it would need.
    pub fn max_wait(&self, authority: &Authority) -> Duration {
        let mut seen = BTreeSet::new();
        self.max_wait_inner(authority, &mut seen)
    }

    fn max_wait_inner(&self, authority: &Authority, seen: &mut BTreeSet<String>) -> Duration {
        let mut max = Duration::ZERO;
        for wf in &authority.factors {
            let w = match &wf.factor {
                Factor::Wait(dur) => *dur,
                Factor::Group(id) if seen.insert(id.clone()) => match self.groups.get(id) {
                    Some(g) => self.max_wait_inner(g, seen),
                    None => Duration::ZERO,
                },
                _ => Duration::ZERO,
            };
            if w > max {
                max = w;
            }
        }
        max
    }

    /// Verify an Ed25519 SSHSIG token over the request's challenge and return the
    /// id of the authenticator it satisfies. The signer must be a configured
    /// ed25519 authenticator; a valid signature from an unlisted key is refused.
    pub fn verify_ed25519(
        &self,
        request: &ApprovalRequest,
        token: &str,
    ) -> Result<String, ApprovalError> {
        let sig: SshSig = token
            .trim()
            .parse()
            .map_err(|e| ApprovalError::Malformed(format!("not a valid SSHSIG: {e}")))?;
        if sig.namespace() != APPROVAL_NAMESPACE {
            return Err(ApprovalError::WrongNamespace(sig.namespace().to_string()));
        }
        let matched = self.authenticators.iter().find_map(|(id, a)| match a {
            Authenticator::Ed25519(pk) if pk.key_data() == sig.public_key() => Some((id, pk)),
            _ => None,
        });
        let (id, pk) = matched.ok_or_else(|| {
            ApprovalError::UnknownApprover(
                "signer is not a configured ed25519 authenticator".to_string(),
            )
        })?;
        pk.verify(
            APPROVAL_NAMESPACE,
            request.challenge_string().as_bytes(),
            &sig,
        )
        .map(|()| id.clone())
        .map_err(|_| ApprovalError::BadSignature)
    }
}

/// Build one authority (a group or a profile) from its spec, validating the
/// threshold, factors and satisfiability. Reference resolution and cycle
/// detection happen once all authorities exist.
fn build_authority(
    kind: &'static str,
    spec: &AuthoritySpec,
) -> Result<(String, Authority), AuthorityError> {
    if spec.id.is_empty() {
        return Err(AuthorityError::EmptyId { kind });
    }
    if spec.threshold == 0 {
        return Err(AuthorityError::ZeroThreshold {
            kind,
            id: spec.id.clone(),
        });
    }
    if spec.factor.is_empty() {
        return Err(AuthorityError::NoFactors {
            kind,
            id: spec.id.clone(),
        });
    }
    let mut factors = Vec::with_capacity(spec.factor.len());
    let mut available: u64 = 0;
    for fs in &spec.factor {
        if fs.weight == 0 {
            return Err(AuthorityError::ZeroWeight {
                kind,
                id: spec.id.clone(),
            });
        }
        // Exactly one of the three factor kinds must be named.
        let set = [
            fs.authenticator.is_some(),
            fs.group.is_some(),
            fs.wait.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if set != 1 {
            return Err(AuthorityError::BadFactor {
                kind,
                id: spec.id.clone(),
                message: if set == 0 {
                    "names none of authenticator/group/wait"
                } else {
                    "names more than one of authenticator/group/wait"
                },
            });
        }
        let factor = if let Some(a) = &fs.authenticator {
            Factor::Authenticator(a.clone())
        } else if let Some(g) = &fs.group {
            Factor::Group(g.clone())
        } else {
            let w = fs.wait.as_deref().unwrap();
            let dur = Ttl::parse(w)
                .map(|t| t.duration())
                .map_err(|e| AuthorityError::BadWait {
                    kind,
                    id: spec.id.clone(),
                    message: e.to_string(),
                })?;
            Factor::Wait(dur)
        };
        available += fs.weight as u64;
        factors.push(WeightedFactor {
            weight: fs.weight,
            factor,
        });
    }
    if (spec.threshold as u64) > available {
        return Err(AuthorityError::Unsatisfiable {
            kind,
            id: spec.id.clone(),
            threshold: spec.threshold,
            available,
        });
    }
    Ok((
        spec.id.clone(),
        Authority {
            threshold: spec.threshold,
            factors,
        },
    ))
}

#[cfg(test)]
mod tests;
