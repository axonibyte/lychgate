//! The grant lifecycle: write-ahead intent, driver I/O outside the store
//! lock, journal after commit.
//!
//! Every side effect is bracketed by persisted state. Open persists
//! `Opening` (naming the channels it will drive) before a driver runs, then
//! commits `Open` on success or `NeedsRevert` on failure. Close and expiry
//! persist `NeedsRevert` before reverting, then commit `Closed` only once
//! every channel is undone. A crash between any two steps restarts into a
//! state that retries the revert or is demoted to needing one — never into a
//! grant that claims access it does not have, or hides access it does.
//!
//! Driver calls happen with the store lock released: a slow sshd reload must
//! not block status reads. The grant is `Opening` or `NeedsRevert` on disk
//! throughout, so a concurrent pass skips it (reap touches only observed-Open
//! grants; revert retries touch only NeedsRevert, which a fresh open is not).

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;

use lychgate_core::proto::{status_lines, Op, PendingChallenge, Response};
use lychgate_core::{
    apply_channels, reestablish_channels, revert_channels, ApplyOutcome, ApprovalRequest,
    Authority, AuthorityModel, Channel, DriverSet, GrantRegistry, GrantStatus, Host, Inventory,
    Missing, ReestablishOutcome, RegistryError, RevertOutcome, Ttl,
};

use crate::drivers::deadman::DeadmanControl;
use crate::journal::{Event, Journal};
use crate::store::Store;

pub(crate) fn epoch_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A fresh challenge nonce from the OS CSPRNG. Core stays free of randomness;
/// the daemon chooses the nonce and hands it to the pure request type.
fn generate_nonce() -> [u8; 32] {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .expect("/dev/urandom is readable on every supported platform");
    bytes
}

pub struct Daemon {
    pub inventory: Inventory,
    pub store: Store,
    pub journal: Mutex<Journal>,
    pub drivers: Mutex<DriverSet>,
    pub deadman: Mutex<Box<dyn DeadmanControl>>,
    /// How long an unapproved request may sit pending before it lapses.
    pub approval_window: Duration,
    /// The weighted-threshold approval policy. `None` means `--dry-run`: no
    /// authority is evaluated and the first `approve` opens the grant (nothing
    /// is driven). A serving daemon always has `Some` — main refuses to start
    /// without one.
    pub approval: Option<AuthorityModel>,
}

/// The profile name a `--dry-run` daemon records on a pending grant. Dry-run
/// evaluates no authority, so the value only has to be stable and recognisable.
const DRY_RUN_PROFILE: &str = "dry-run";

/// The backstop rides the SSH transport, so only ssh-configured hosts get
/// one; it exists to revert what the ssh-borne channels applied.
fn wants_deadman(host: &Host, applied: &[Channel]) -> bool {
    host.ssh.is_some()
        && applied
            .iter()
            .any(|c| matches!(c, Channel::Ssh | Channel::AuthorizedKeys))
}

impl Daemon {
    fn host(&self, name: &str) -> Option<Host> {
        self.inventory
            .hosts
            .iter()
            .find(|h| h.name == name)
            .cloned()
    }

    fn declared(&self, host: &str) -> Vec<Channel> {
        self.host(host).map(|h| h.channels).unwrap_or_default()
    }

    fn journal(&self, now: SystemTime, event: &Event) -> anyhow::Result<()> {
        // Fatal on failure: accruing unrecorded transitions would defeat the
        // audit record.
        self.journal
            .lock()
            .expect("journal mutex poisoned")
            .record(now, event)
            .context("journaling a transition")
    }

    /// A store mutation that reconstructs the registry, runs one registry
    /// operation, and — only if it returns Ok — commits the snapshot. A
    /// registry refusal leaves the store untouched and surfaces as
    /// `Ok(Err(..))`; store I/O surfaces as the outer `Err`.
    fn with_registry<T>(
        &self,
        op: impl FnOnce(&mut GrantRegistry) -> Result<T, RegistryError>,
    ) -> anyhow::Result<Result<T, RegistryError>> {
        self.store.mutate(|doc| {
            let mut registry = GrantRegistry::from_parts(&self.inventory, doc)
                .with_context(|| format!("validating {}", self.store.path().display()))?;
            match op(&mut registry) {
                Ok(value) => {
                    *doc = registry.snapshot();
                    Ok(Ok(value))
                }
                Err(refusal) => Ok(Err(refusal)),
            }
        })
    }

    /// Dispatches one wire op. Returns the response; the outer Err is a
    /// daemon-fatal failure (store I/O, journal write).
    pub fn dispatch(&self, op: &Op, now: SystemTime) -> anyhow::Result<Response> {
        match op {
            Op::Open { host, ttl, profile } => self.open(host, ttl, profile.as_deref(), now),
            Op::Approve { host, token } => self.approve(host, token, now),
            Op::Renew { host, ttl } => self.renew(host, ttl, now),
            Op::Close { host } => self.close(host, now),
            Op::Status => Ok(Response {
                grants: Some(self.status(now)?),
                ..Response::ok()
            }),
        }
    }

    fn status(&self, now: SystemTime) -> anyhow::Result<Vec<lychgate_core::proto::GrantLine>> {
        let doc = self.store.read()?;
        let registry = GrantRegistry::from_parts(&self.inventory, &doc)
            .with_context(|| format!("validating {}", self.store.path().display()))?;
        Ok(status_lines(&registry, now))
    }

    /// The profiles a host permits: its `[hosts.access].profiles` if it narrows,
    /// else every global profile.
    fn permitted_profiles(&self, model: &AuthorityModel, host_cfg: &Host) -> Vec<String> {
        match &host_cfg.access {
            Some(access) => access.profiles.clone(),
            None => model.profile_ids().map(|s| s.to_string()).collect(),
        }
    }

    /// The effective authority for `(host, profile)`: the host's override if it
    /// has one, else the global profile. Errs (human refusal text) if the host
    /// does not permit the profile.
    fn resolve_authority(
        &self,
        model: &AuthorityModel,
        host_cfg: &Host,
        profile: &str,
    ) -> Result<Authority, String> {
        if !self
            .permitted_profiles(model, host_cfg)
            .iter()
            .any(|p| p == profile)
        {
            return Err(format!(
                "host {:?} does not permit approval profile {profile:?}",
                host_cfg.name
            ));
        }
        if let Some(access) = &host_cfg.access {
            if let Some(body) = access.overrides.get(profile) {
                // Validated at load; rebuild defensively.
                return model
                    .resolve_override(profile, body)
                    .map_err(|e| e.to_string());
            }
        }
        model
            .profile(profile)
            .cloned()
            .ok_or_else(|| format!("approval profile {profile:?} is not defined"))
    }

    /// Satisfied weight, threshold, and human labels for what is outstanding.
    /// A dry-run daemon (no model) reports a trivial single-factor gate.
    fn progress(
        &self,
        authority: Option<&Authority>,
        satisfied: &std::collections::BTreeSet<String>,
        elapsed: Duration,
    ) -> (u64, u32, Vec<String>) {
        match (self.approval.as_ref(), authority) {
            (Some(model), Some(a)) => {
                let out = model.evaluate(a, satisfied, elapsed);
                (out.weight, out.threshold, describe_missing(&out.missing))
            }
            _ => (0, 1, vec!["any approval token (dry-run)".to_string()]),
        }
    }

    /// Open no longer opens: it records a request awaiting operator approval
    /// under a chosen profile and returns the challenge to sign. No driver runs,
    /// no access is granted.
    fn open(
        &self,
        host: &str,
        ttl_str: &str,
        profile: Option<&str>,
        now: SystemTime,
    ) -> anyhow::Result<Response> {
        let ttl = match Ttl::parse(ttl_str) {
            Ok(t) => t,
            Err(e) => return Ok(Response::refused(e)),
        };
        if self.host(host).is_none() {
            return Ok(Response::refused(RegistryError::UnknownHost(
                host.to_string(),
            )));
        }
        let host_cfg = self.host(host).expect("checked present");

        // Resolve the profile and its authority (dry-run has neither).
        let (chosen_profile, authority) = match &self.approval {
            None => (DRY_RUN_PROFILE.to_string(), None),
            Some(model) => {
                let permitted = self.permitted_profiles(model, &host_cfg);
                let chosen = match profile {
                    Some(p) => p.to_string(),
                    None => match permitted.as_slice() {
                        [only] => only.clone(),
                        [] => {
                            return Ok(Response::refused(format!(
                                "host {host:?} permits no approval profiles"
                            )))
                        }
                        _ => {
                            return Ok(Response::refused(format!(
                                "host {host:?} permits {} profiles ({}); specify --as <profile>",
                                permitted.len(),
                                permitted.join(", ")
                            )))
                        }
                    },
                };
                let authority = match self.resolve_authority(model, &host_cfg, &chosen) {
                    Ok(a) => a,
                    Err(reason) => return Ok(Response::refused(reason)),
                };
                // A wait must fit inside the window, or that path could never
                // accrue its weight before the request lapses.
                let max_wait = model.max_wait(&authority);
                if max_wait >= self.approval_window {
                    return Ok(Response::refused(format!(
                        "profile {chosen:?} needs a wait of {}s, but the approval window is only {}s; \
                         raise --approval-window",
                        max_wait.as_secs(),
                        self.approval_window.as_secs()
                    )));
                }
                (chosen, Some(authority))
            }
        };

        let approval_deadline = match now.checked_add(self.approval_window) {
            Some(d) => d,
            None => return Ok(Response::refused("the approval window overflows the clock")),
        };
        let nonce = generate_nonce();
        let declared = self.declared(host);
        // Persist the pending intent, or refuse without writing.
        match self.with_registry(|reg| {
            reg.begin_pending(
                host,
                now,
                approval_deadline,
                ttl,
                nonce,
                chosen_profile.clone(),
            )
        })? {
            Ok(()) => {}
            Err(refusal) => return Ok(Response::refused(refusal)),
        }
        self.journal(
            now,
            &Event::Requested {
                host: host.to_string(),
                declared,
                ttl_secs: ttl.duration().as_secs(),
                requested_at: epoch_secs(now),
                approval_deadline: epoch_secs(approval_deadline),
            },
        )?;
        let challenge =
            ApprovalRequest::new(nonce, host.to_string(), ttl.duration().as_secs(), now)
                .challenge_string();
        let empty = std::collections::BTreeSet::new();
        let (weight, threshold, missing) =
            self.progress(authority.as_ref(), &empty, Duration::ZERO);
        Ok(Response {
            pending: Some(PendingChallenge {
                host: host.to_string(),
                challenge,
                ttl_secs: ttl.duration().as_secs(),
                requested_at: epoch_secs(now),
                approval_deadline: epoch_secs(approval_deadline),
                profile: chosen_profile,
                weight,
                threshold,
                missing,
            }),
            ..Response::ok()
        })
    }

    /// Submit one operator proof toward a host's pending request. In `--dry-run`
    /// the first proof opens the grant. Otherwise the proof is verified against
    /// the request's challenge, its authenticator recorded, and the profile's
    /// authority re-evaluated; the grant opens the moment the weighted threshold
    /// is met, and otherwise stays pending with updated progress.
    fn approve(&self, host: &str, token: &str, now: SystemTime) -> anyhow::Result<Response> {
        // The pending request the token must match, read before verifying.
        let request = {
            let doc = self.store.read()?;
            let registry = GrantRegistry::from_parts(&self.inventory, &doc)
                .with_context(|| format!("validating {}", self.store.path().display()))?;
            match registry.pending(host, now) {
                Ok(r) => r,
                Err(refusal) => return Ok(Response::refused(refusal)),
            }
        };
        let host_cfg = self.host(host).expect("pending implies a known host");

        // Dry-run: no authority, no verification — the first proof opens.
        let Some(model) = &self.approval else {
            return self.open_pending_now(host, &host_cfg, request.requested_at(), now);
        };

        // Verify outside the store lock. A denied proof is journaled — an audit
        // record exists for exactly this.
        let authenticator = match model.verify_ed25519(&request, token) {
            Ok(id) => id,
            Err(e) => {
                self.journal(
                    now,
                    &Event::ApprovalDenied {
                        host: host.to_string(),
                        reason: e.to_string(),
                    },
                )?;
                return Ok(Response::refused(format!("approval refused: {e}")));
            }
        };

        // Record the satisfied authenticator (persisted), journal a newly-added
        // one, then re-evaluate the authority.
        let newly =
            match self.with_registry(|reg| reg.add_satisfied(host, now, authenticator.clone()))? {
                Ok(added) => added,
                Err(refusal) => return Ok(Response::refused(refusal)),
            };
        if newly {
            self.journal(
                now,
                &Event::ProofAccepted {
                    host: host.to_string(),
                    authenticator: authenticator.clone(),
                },
            )?;
        }

        let view = match self.with_read_registry(|reg| reg.pending_view(host, now))? {
            Ok(v) => v,
            Err(refusal) => return Ok(Response::refused(refusal)),
        };
        let authority = match self.resolve_authority(model, &host_cfg, &view.profile) {
            Ok(a) => a,
            Err(reason) => return Ok(Response::refused(reason)),
        };
        let outcome = model.evaluate(&authority, &view.satisfied, view.elapsed);
        if outcome.met {
            return self.open_pending_now(host, &host_cfg, view.requested_at, now);
        }
        // Not yet: acknowledge the proof and report progress. Still pending.
        Ok(Response {
            pending: Some(self.pending_challenge(host, &view, &authority, now)),
            ..Response::ok()
        })
    }

    /// A read-only registry operation (no snapshot write).
    fn with_read_registry<T>(
        &self,
        op: impl FnOnce(&GrantRegistry) -> Result<T, RegistryError>,
    ) -> anyhow::Result<Result<T, RegistryError>> {
        let doc = self.store.read()?;
        let registry = GrantRegistry::from_parts(&self.inventory, &doc)
            .with_context(|| format!("validating {}", self.store.path().display()))?;
        Ok(op(&registry))
    }

    /// Build the pending-progress challenge block for a still-pending grant.
    /// Reconstructs the challenge string from the stored request so the operator
    /// can keep signing toward the threshold.
    fn pending_challenge(
        &self,
        host: &str,
        view: &lychgate_core::PendingView,
        authority: &Authority,
        now: SystemTime,
    ) -> PendingChallenge {
        let _ = now;
        let (weight, threshold, missing) =
            self.progress(Some(authority), &view.satisfied, view.elapsed);
        // The daemon does not keep the nonce here; re-derive nothing secret —
        // report progress without re-issuing the challenge (the operator already
        // has it from open). challenge left empty signals "already issued".
        PendingChallenge {
            host: host.to_string(),
            challenge: String::new(),
            ttl_secs: 0,
            requested_at: epoch_secs(view.requested_at),
            approval_deadline: 0,
            profile: view.profile.clone(),
            weight,
            threshold,
            missing,
        }
    }

    /// The pending->open tail, shared by an approval that meets the threshold, a
    /// dry-run approval, and a wait that matures on a pass: drivable channels,
    /// Pending->Opening under the lock, journal Approved, then drive the open.
    fn open_pending_now(
        &self,
        host: &str,
        host_cfg: &Host,
        requested_at: SystemTime,
        now: SystemTime,
    ) -> anyhow::Result<Response> {
        let declared = self.declared(host);
        let to_apply = self
            .drivers
            .lock()
            .expect("drivers poisoned")
            .drivable(&declared);
        // Pending -> Opening under the lock: re-checks the state, closing the
        // gap with the reads above (a concurrent close or a lapse refuses).
        let expires =
            match self.with_registry(|reg| reg.approve_to_opening(host, now, to_apply.clone()))? {
                Ok(e) => e,
                Err(refusal) => return Ok(Response::refused(refusal)),
            };
        self.journal(
            now,
            &Event::Approved {
                host: host.to_string(),
                requested_at: epoch_secs(requested_at),
            },
        )?;
        let ttl_secs = expires
            .duration_since(now)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.drive_open(host, host_cfg, to_apply, declared, ttl_secs, expires, now)
    }

    /// Runs the drivers for a grant already committed to Opening: installs the
    /// dead-man, commits Open or NeedsRevert, journals it, and hands back any
    /// one-time secret. Reached only after an approval.
    #[allow(clippy::too_many_arguments)]
    fn drive_open(
        &self,
        host: &str,
        host_cfg: &Host,
        to_apply: Vec<Channel>,
        declared: Vec<Channel>,
        ttl_secs: u64,
        expires: SystemTime,
        now: SystemTime,
    ) -> anyhow::Result<Response> {
        let outcome = {
            let mut drivers = self.drivers.lock().expect("drivers poisoned");
            apply_channels(&mut drivers, host_cfg, &to_apply)
        };

        // Commit the terminal state and journal it.
        match outcome {
            ApplyOutcome::Applied { applied } => {
                // The backstop goes in before the grant may exist: a grant
                // without its dead-man must not open. An install failure
                // unwinds the freshly applied channels.
                if wants_deadman(host_cfg, &applied) {
                    let installed = self
                        .deadman
                        .lock()
                        .expect("deadman poisoned")
                        .install(host_cfg, expires);
                    if let Err(error) = installed {
                        let outcome = {
                            let mut drivers = self.drivers.lock().expect("drivers poisoned");
                            revert_channels(&mut drivers, host_cfg, &applied)
                        };
                        let stuck: Vec<Channel> = match outcome {
                            RevertOutcome::Reverted => Vec::new(),
                            RevertOutcome::Stuck { stuck } => {
                                stuck.into_iter().map(|(c, _)| c).collect()
                            }
                        };
                        if stuck.is_empty() {
                            self.with_registry(|reg| reg.abort_open(host))?
                                .expect("an opening grant can always abort");
                        } else {
                            self.with_registry(|reg| reg.fail_open(host, stuck.clone(), now))?
                                .expect("an opening grant can always fail");
                        }
                        self.journal(
                            now,
                            &Event::OpenFailed {
                                host: host.to_string(),
                                failed: Channel::Ssh,
                                stuck,
                                error: format!("dead-man install failed: {error}"),
                            },
                        )?;
                        return Ok(Response::refused(format!(
                            "open refused: the dead-man backstop could not be installed \
                             ({error}); a grant without its backstop must not exist"
                        )));
                    }
                }
                self.with_registry(|reg| reg.finish_open(host))?
                    .expect("an opening grant can always finish");
                self.journal(
                    now,
                    &Event::Open {
                        host: host.to_string(),
                        applied: applied.clone(),
                        declared,
                        ttl_secs,
                        expires_at: epoch_secs(expires),
                    },
                )?;
                // Collect any one-time credential an applied channel produced
                // (a BMC break-glass password, a one-time VNC password) to hand
                // back in the response. It is never journaled — the Open event
                // above records the channels, never the secret.
                let produced = {
                    let mut drivers = self.drivers.lock().expect("drivers poisoned");
                    applied.iter().find_map(|c| {
                        drivers
                            .take_secret(*c)
                            .map(|s| (*c, s.reveal().to_string()))
                    })
                };
                let (secret, secret_label, outcome) = match produced {
                    Some((Channel::Vnc, s)) => {
                        // The non-secret endpoint the operator connects to.
                        let endpoint = host_cfg
                            .vnc
                            .as_ref()
                            .map(|v| format!("vnc console at 127.0.0.1:{}", v.local_port));
                        (Some(s), Some("one-time VNC password".to_string()), endpoint)
                    }
                    Some((_, s)) => (Some(s), Some("break-glass BMC password".to_string()), None),
                    None => (None, None, None),
                };
                Ok(Response {
                    expires_at: Some(epoch_secs(expires)),
                    secret,
                    secret_label,
                    outcome,
                    ..Response::ok()
                })
            }
            ApplyOutcome::Failed {
                failed,
                error,
                stuck,
                ..
            } => {
                if stuck.is_empty() {
                    self.with_registry(|reg| reg.abort_open(host))?
                        .expect("an opening grant can always abort");
                } else {
                    self.with_registry(|reg| reg.fail_open(host, stuck.clone(), now))?
                        .expect("an opening grant can always fail");
                }
                self.journal(
                    now,
                    &Event::OpenFailed {
                        host: host.to_string(),
                        failed,
                        stuck: stuck.clone(),
                        error: error.to_string(),
                    },
                )?;
                let tail = if stuck.is_empty() {
                    "all channels reverted".to_string()
                } else {
                    format!("channels awaiting revert: {stuck:?}")
                };
                Ok(Response::refused(format!(
                    "open failed on {failed:?}: {error}; {tail}"
                )))
            }
        }
    }

    fn renew(&self, host: &str, ttl_str: &str, now: SystemTime) -> anyhow::Result<Response> {
        let ttl = match Ttl::parse(ttl_str) {
            Ok(t) => t,
            Err(e) => return Ok(Response::refused(e)),
        };
        // Dry-run first, then reschedule the backstop, then commit. Both
        // failure orders are fail-closed: a rescheduled backstop with an
        // uncommitted renewal fires late but the daemon still reverts at
        // the old expiry; a refused reschedule refuses the renewal outright
        // — extending the grant past its backstop would be fail-open.
        let dry = {
            let doc = self.store.read()?;
            let mut probe = GrantRegistry::from_parts(&self.inventory, &doc)
                .with_context(|| format!("validating {}", self.store.path().display()))?;
            probe.renew(host, now, &ttl)
        };
        let expires = match dry {
            Ok(expires) => expires,
            Err(refusal) => return Ok(Response::refused(refusal)),
        };
        if let Some(host_cfg) = self.host(host) {
            if host_cfg.ssh.is_some() {
                if let Err(e) = self
                    .deadman
                    .lock()
                    .expect("deadman poisoned")
                    .reschedule(&host_cfg, expires)
                {
                    return Ok(Response::refused(format!(
                        "renewal refused: the dead-man backstop could not be rescheduled ({e})"
                    )));
                }
            }
        }
        match self.with_registry(|reg| reg.renew(host, now, &ttl))? {
            Ok(expires) => {
                self.journal(
                    now,
                    &Event::Renew {
                        host: host.to_string(),
                        ttl_secs: ttl.duration().as_secs(),
                        expires_at: epoch_secs(expires),
                    },
                )?;
                Ok(Response {
                    expires_at: Some(epoch_secs(expires)),
                    ..Response::ok()
                })
            }
            Err(refusal) => Ok(Response::refused(refusal)),
        }
    }

    fn close(&self, host: &str, now: SystemTime) -> anyhow::Result<Response> {
        // A pending request is cancelled, not reverted — it applied nothing.
        let status = {
            let doc = self.store.read()?;
            let registry = GrantRegistry::from_parts(&self.inventory, &doc)
                .with_context(|| format!("validating {}", self.store.path().display()))?;
            registry.status(host, now)
        };
        if matches!(
            status,
            Ok(GrantStatus::AwaitingApproval { .. } | GrantStatus::ApprovalExpired)
        ) {
            self.with_registry(|reg| reg.cancel_pending(host))?
                .expect("a pending grant can always cancel");
            self.journal(
                now,
                &Event::RequestCancelled {
                    host: host.to_string(),
                },
            )?;
            return Ok(Response {
                outcome: Some("cancelled".to_string()),
                ..Response::ok()
            });
        }

        // Close is idempotent: begin_revert refuses an already-closed grant
        // with NotOpen, which we report as a benign "already-closed" outcome
        // rather than an error. Mid-open (MidOpen) and unknown hosts remain
        // refusals — an operator closing those is asking for something the
        // daemon cannot yet safely do.
        let channels = match self.with_registry(|reg| reg.begin_revert(host, now))? {
            Ok(channels) => channels,
            Err(RegistryError::Grant(lychgate_core::GrantError::NotOpen)) => {
                return Ok(Response {
                    outcome: Some("already-closed".to_string()),
                    ..Response::ok()
                })
            }
            Err(refusal) => return Ok(Response::refused(refusal)),
        };
        let outcome = self.drive_one_revert(host, &channels, now)?;
        match outcome {
            RevertProgress::Closed => {
                Ok(Response { outcome: Some("closed".to_string()), ..Response::ok() })
            }
            RevertProgress::Stuck { stuck } => Ok(Response::refused(format!(
                "close of {host:?} incomplete; channels awaiting revert: {stuck:?} (retried on every pass)"
            ))),
        }
    }

    /// One revert attempt for a host already in NeedsRevert: run the drivers
    /// (lock released), then commit finish_revert or retain the stuck set.
    /// The Close event is journaled only when the grant truly closes.
    fn drive_one_revert(
        &self,
        host: &str,
        channels: &[Channel],
        now: SystemTime,
    ) -> anyhow::Result<RevertProgress> {
        let host_cfg = self.host(host).expect("needs-revert implies a known host");
        let outcome = {
            let mut drivers = self.drivers.lock().expect("drivers poisoned");
            revert_channels(&mut drivers, &host_cfg, channels)
        };
        match outcome {
            RevertOutcome::Reverted => {
                // The backstop comes out only after everything it guards is
                // reverted — a stuck revert keeps its dead-man. A removal
                // failure keeps the grant needs-revert and is retried.
                let mut deadman_fired = false;
                if host_cfg.ssh.is_some() {
                    match self
                        .deadman
                        .lock()
                        .expect("deadman poisoned")
                        .remove(&host_cfg)
                    {
                        Ok(fired) => deadman_fired = fired,
                        Err(e) => {
                            println!(
                                "lychgated: {host} channels reverted but the dead-man \
                                 removal failed ({e}); retrying next pass"
                            );
                            let _ = self
                                .with_registry(|reg| reg.retain_stuck(host, channels.to_vec()))?;
                            return Ok(RevertProgress::Stuck {
                                stuck: channels.to_vec(),
                            });
                        }
                    }
                }
                // Driver I/O runs with the store lock released, so a concurrent
                // pass and an operator close can both revert the same host. The
                // store lock serializes the commit: whoever finishes first
                // transitions Closed and journals; a loser finds the grant
                // already Closed (NotOpen) — not an error, and it must not
                // re-journal the Close. Anything else is impossible for a known
                // needs-revert host.
                match self.with_registry(|reg| reg.finish_revert(host))? {
                    Ok(()) => {
                        self.journal(
                            now,
                            &Event::Close {
                                host: host.to_string(),
                                deadman_fired,
                            },
                        )?;
                    }
                    Err(RegistryError::Grant(lychgate_core::GrantError::NotOpen)) => {}
                    Err(other) => {
                        return Err(anyhow::anyhow!("finishing revert of {host:?}: {other}"))
                    }
                }
                Ok(RevertProgress::Closed)
            }
            RevertOutcome::Stuck { stuck } => {
                let stuck_channels: Vec<Channel> = stuck.iter().map(|(c, _)| *c).collect();
                // Same race: a concurrent actor may have finished the revert
                // between our driver call and this commit, closing the grant.
                match self.with_registry(|reg| reg.retain_stuck(host, stuck_channels.clone()))? {
                    Ok(changed) => {
                        if changed {
                            // Progress worth recording; per-retry churn is stdout only.
                            println!(
                                "lychgated: {host} revert incomplete, still stuck: {stuck_channels:?}"
                            );
                        }
                        Ok(RevertProgress::Stuck {
                            stuck: stuck_channels,
                        })
                    }
                    // Already closed out from under us — the grant is closed.
                    Err(RegistryError::Grant(lychgate_core::GrantError::NotOpen)) => {
                        Ok(RevertProgress::Closed)
                    }
                    Err(other) => Err(anyhow::anyhow!("retaining stuck for {host:?}: {other}")),
                }
            }
        }
    }

    /// One daemon pass: reap observed expiries into needs-revert (journaling
    /// each Expire), then make one revert attempt for every grant needing
    /// one — expiries just reaped and any left stuck by earlier passes.
    pub fn pass(&self, now: SystemTime) -> anyhow::Result<()> {
        let (expired, expired_pending) = self.store.mutate(|doc| {
            let mut registry = GrantRegistry::from_parts(&self.inventory, doc)
                .with_context(|| format!("validating {}", self.store.path().display()))?;
            let expired = registry.reap_to_revert(now);
            // A request whose approval window lapsed unapproved is closed here,
            // fail-closed; it applied nothing, so there is nothing to revert.
            let expired_pending = registry.reap_expired_pending(now);
            *doc = registry.snapshot();
            Ok((expired, expired_pending))
        })?;
        for e in &expired {
            self.journal(
                now,
                &Event::Expire {
                    host: e.host.clone(),
                    channels: e.channels.clone(),
                    opened_at: epoch_secs(e.opened_at),
                    expires_at: epoch_secs(e.expires_at),
                },
            )?;
        }
        for e in &expired_pending {
            self.journal(
                now,
                &Event::RequestExpired {
                    host: e.host.clone(),
                    requested_at: epoch_secs(e.requested_at),
                    approval_deadline: epoch_secs(e.approval_deadline),
                },
            )?;
        }

        // Revert everything needing it, one attempt each. Read the list from
        // committed state so a reaped expiry and an old stuck grant are
        // handled the same way.
        let doc = self.store.read()?;
        let registry = GrantRegistry::from_parts(&self.inventory, &doc)
            .with_context(|| format!("validating {}", self.store.path().display()))?;
        let needing = registry.needing_revert(now);
        drop(registry);
        for (host, channels) in needing {
            self.drive_one_revert(&host, &channels, now)?;
        }

        // A `wait` factor can tip a pending grant over its threshold with no
        // further human action. Re-evaluate every still-pending grant and open
        // the ones that now meet their authority. (Dry-run has no waits.)
        if let Some(model) = &self.approval {
            let awaiting = {
                let doc = self.store.read()?;
                let registry = GrantRegistry::from_parts(&self.inventory, &doc)
                    .with_context(|| format!("validating {}", self.store.path().display()))?;
                registry.awaiting_approval(now)
            };
            for host in awaiting {
                let host_cfg = self.host(&host).expect("awaiting implies a known host");
                let view = match self.with_read_registry(|reg| reg.pending_view(&host, now))? {
                    Ok(v) => v,
                    // Lapsed between the list and here — reaped on a later pass.
                    Err(_) => continue,
                };
                let authority = match self.resolve_authority(model, &host_cfg, &view.profile) {
                    Ok(a) => a,
                    // e.g. a v3-migrated empty profile: it can never open and
                    // simply lapses at its deadline.
                    Err(_) => continue,
                };
                if model
                    .evaluate(&authority, &view.satisfied, view.elapsed)
                    .met
                {
                    self.open_pending_now(&host, &host_cfg, view.requested_at, now)?;
                }
            }
        }

        self.report(now)?;
        Ok(())
    }

    /// Boot recovery, before the listener starts, in two steps over disjoint
    /// states. First a stored `Opening` means a daemon died mid-apply, so every
    /// intended channel is treated as possibly applied and demoted to
    /// needs-revert. Then, for grants that are durably `Open` and not yet
    /// expired, any daemon-held resource (the vnc tunnel, which died with the
    /// old daemon) is re-established so the grant's window is honored across a
    /// restart. Nothing can be legitimately in flight at this point.
    pub fn boot_recover(&self, now: SystemTime) -> anyhow::Result<()> {
        let demoted = self.store.mutate(|doc| {
            let mut registry = GrantRegistry::from_parts(&self.inventory, doc)
                .with_context(|| format!("validating {}", self.store.path().display()))?;
            let demoted = registry.demote_opening(now);
            *doc = registry.snapshot();
            Ok(demoted)
        })?;
        for (host, channels) in &demoted {
            self.journal(
                now,
                &Event::OpenFailed {
                    host: host.clone(),
                    failed: channels.first().copied().unwrap_or(Channel::Ssh),
                    stuck: channels.clone(),
                    error: "daemon restarted mid-open; channels demoted to needs-revert"
                        .to_string(),
                },
            )?;
            println!("lychgated: {host} was mid-open at last shutdown; demoted to needs-revert");
        }
        self.reestablish_open(now)?;
        Ok(())
    }

    /// Re-establish daemon-held resources for durably-open, unexpired grants
    /// after a restart. Only channels with a daemon-held resource have anything
    /// to do (the default `reestablish` just re-reads state); today that is
    /// vnc's tunnel. A grant whose resources cannot be restored is demoted to
    /// needs-revert here — reachability we cannot restore is reachability we
    /// retract, fail-closed. Re-establishment re-asserts reachability only; it
    /// never re-runs apply, so a credential the operator already holds is not
    /// rotated out from under them.
    fn reestablish_open(&self, now: SystemTime) -> anyhow::Result<()> {
        let open: Vec<(String, Vec<Channel>)> = {
            let doc = self.store.read()?;
            let registry = GrantRegistry::from_parts(&self.inventory, &doc)
                .with_context(|| format!("validating {}", self.store.path().display()))?;
            registry.open_channels(now)
        };
        for (host, channels) in open {
            let host_cfg = self.host(&host).expect("open_channels names a known host");
            let outcome = {
                let mut drivers = self.drivers.lock().expect("drivers poisoned");
                reestablish_channels(&mut drivers, &host_cfg, &channels)
            };
            match outcome {
                ReestablishOutcome::Restored => {
                    self.journal(
                        now,
                        &Event::Reestablish {
                            host: host.clone(),
                            channels: channels.clone(),
                        },
                    )?;
                }
                ReestablishOutcome::Lost { lost } => {
                    // Retract: move it to needs-revert so the first pass fully
                    // reverts (killing any partial resource, clearing the
                    // password). begin_revert always accepts an Open grant.
                    self.with_registry(|reg| reg.begin_revert(&host, now))?
                        .expect("an open grant can always begin revert");
                    let stuck: Vec<Channel> = lost.iter().map(|(c, _)| *c).collect();
                    self.journal(
                        now,
                        &Event::OpenFailed {
                            host: host.clone(),
                            failed: stuck.first().copied().unwrap_or(Channel::Vnc),
                            stuck,
                            error: format!(
                                "daemon restarted; could not re-establish {}",
                                lost.iter()
                                    .map(|(c, e)| format!("{c:?}: {e}"))
                                    .collect::<Vec<_>>()
                                    .join("; ")
                            ),
                        },
                    )?;
                    println!(
                        "lychgated: {host} could not be re-established after restart; \
                         reverting"
                    );
                }
            }
        }
        Ok(())
    }

    fn report(&self, now: SystemTime) -> anyhow::Result<()> {
        for line in self.status(now)? {
            let host = &line.host;
            use lychgate_core::proto::GrantState::*;
            match line.state {
                Closed => {}
                AwaitingApproval => println!(
                    "lychgated: {host} awaiting approval, {}s to approve",
                    line.remaining_secs.unwrap_or(0)
                ),
                ApprovalExpired => println!("lychgated: {host} approval expired"),
                Opening => println!("lychgated: {host} opening"),
                Open => println!(
                    "lychgated: {host} open, {}s remaining",
                    line.remaining_secs.unwrap_or(0)
                ),
                Expired => println!("lychgated: {host} expired, revert pending"),
                NeedsRevert => println!(
                    "lychgated: {host} needs revert: {:?}",
                    line.stuck_channels.unwrap_or_default()
                ),
            }
        }
        Ok(())
    }
}

enum RevertProgress {
    Closed,
    Stuck { stuck: Vec<Channel> },
}

/// Human labels for the outstanding factors of an authority — for the operator,
/// never carrying a secret.
fn describe_missing(missing: &[Missing]) -> Vec<String> {
    missing
        .iter()
        .map(|m| match m {
            Missing::Authenticator(id) => format!("a proof from {id:?}"),
            Missing::Group(id) => format!("a grant from {id:?}"),
            Missing::Wait { remaining } => format!("+{}s wait", remaining.as_secs()),
        })
        .collect()
}

#[cfg(test)]
mod tests;
