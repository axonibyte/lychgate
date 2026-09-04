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
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;

use lychgate_core::proto::{status_lines, Op, Response};
use lychgate_core::{
    apply_channels, revert_channels, ApplyOutcome, Channel, DriverSet, GrantRegistry, Host,
    Inventory, RegistryError, RevertOutcome, Ttl,
};

use crate::journal::{Event, Journal};
use crate::store::Store;

pub(crate) fn epoch_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct Daemon {
    pub inventory: Inventory,
    pub store: Store,
    pub journal: Mutex<Journal>,
    pub drivers: Mutex<DriverSet>,
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
            Op::Open { host, ttl } => self.open(host, ttl, now),
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

    fn open(&self, host: &str, ttl_str: &str, now: SystemTime) -> anyhow::Result<Response> {
        let ttl = match Ttl::parse(ttl_str) {
            Ok(t) => t,
            Err(e) => return Ok(Response::refused(e)),
        };
        let declared = self.declared(host);
        let to_apply = self
            .drivers
            .lock()
            .expect("drivers poisoned")
            .drivable(&declared);

        // Step 1: persist the intent, or refuse without writing.
        let expires =
            match self.with_registry(|reg| reg.begin_open(host, now, &ttl, to_apply.clone()))? {
                Ok(expires) => expires,
                Err(refusal) => return Ok(Response::refused(refusal)),
            };

        // Step 2: drivers, with the store lock released.
        let host_cfg = self.host(host).expect("begin_open accepted a known host");
        let outcome = {
            let mut drivers = self.drivers.lock().expect("drivers poisoned");
            apply_channels(&mut drivers, &host_cfg, &to_apply)
        };

        // Step 3: commit the terminal state and journal it.
        match outcome {
            ApplyOutcome::Applied { applied } => {
                self.with_registry(|reg| reg.finish_open(host))?
                    .expect("an opening grant can always finish");
                self.journal(
                    now,
                    &Event::Open {
                        host: host.to_string(),
                        applied: applied.clone(),
                        declared,
                        ttl_secs: ttl.duration().as_secs(),
                        expires_at: epoch_secs(expires),
                    },
                )?;
                Ok(Response {
                    expires_at: Some(epoch_secs(expires)),
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
                self.with_registry(|reg| reg.finish_revert(host))?
                    .expect("a needs-revert grant can always finish");
                self.journal(
                    now,
                    &Event::Close {
                        host: host.to_string(),
                    },
                )?;
                Ok(RevertProgress::Closed)
            }
            RevertOutcome::Stuck { stuck } => {
                let stuck_channels: Vec<Channel> = stuck.iter().map(|(c, _)| *c).collect();
                let changed = self
                    .with_registry(|reg| reg.retain_stuck(host, stuck_channels.clone()))?
                    .expect("a needs-revert grant can always retain");
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
        }
    }

    /// One daemon pass: reap observed expiries into needs-revert (journaling
    /// each Expire), then make one revert attempt for every grant needing
    /// one — expiries just reaped and any left stuck by earlier passes.
    pub fn pass(&self, now: SystemTime) -> anyhow::Result<()> {
        let expired = self.store.mutate(|doc| {
            let mut registry = GrantRegistry::from_parts(&self.inventory, doc)
                .with_context(|| format!("validating {}", self.store.path().display()))?;
            let expired = registry.reap_to_revert(now);
            *doc = registry.snapshot();
            Ok(expired)
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

        self.report(now)?;
        Ok(())
    }

    /// Boot recovery, before the listener starts: a stored `Opening` means a
    /// daemon died mid-apply, so every intended channel is treated as
    /// possibly applied and demoted to needs-revert. Nothing can be
    /// legitimately in flight at this point.
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
        Ok(())
    }

    fn report(&self, now: SystemTime) -> anyhow::Result<()> {
        for line in self.status(now)? {
            let host = &line.host;
            use lychgate_core::proto::GrantState::*;
            match line.state {
                Closed => {}
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

#[cfg(test)]
mod tests;
