//! The simulated-users tier (methodology §15, last): seeded actors drive the
//! real in-process `Daemon` through adversarial sequences — opens, real SSHSIG
//! approvals, renews, closes, time advances, reap passes — while a pure **shadow
//! model** predicts what every observation must be, and a **checker** compares
//! them after every action. A **nemesis** mixes in the hostile moves (a stale
//! approval, acting on an expired grant, a double submit, abandonment), and on a
//! failure a **shrinker** delta-debugs the action log to a minimal reproducer.
//!
//! House fuzz idiom: hand-rolled SplitMix64, committed FIXED_SEEDS, every run
//! prints its seed before using it, `LYCHGATE_SIM_SEED` replays one seed and
//! `LYCHGATE_SIM_ACTIONS` scales the sequence length.
//!
//! The checker is written — and self-tested — first: it is fed the observations
//! and responses a *broken* daemon would produce (a grant open below threshold,
//! a valid tipping proof refused: the shape of the real approve-vs-pass bug) and
//! must complain. A checker never observed complaining measures nothing.
//!
//! The shadow duplicates the policy's semantics *deliberately* (the duplication
//! is the check, per TESTING.md): its threshold arithmetic and boundary rules
//! are written from the spec here, not imported from core.
//!
//! What this tier does NOT cover: thread-interleaving races (Tier 6's threaded
//! harnesses), factor kinds beyond ed25519 (each kind has its own KAT/e2e tier),
//! failing drivers (the channel and drill tiers), and cross-process contention.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lychgate_core::proto::{GrantLine, GrantState, Op, Response, ResponseResult};
use lychgate_core::{DriverSet, Inventory};

use crate::drivers::deadman::DeadmanControl;
use crate::journal::Journal;
use crate::lifecycle::Daemon;
use crate::scratch::{scratch_dir, Scratch};
use crate::store::Store;

// ---------------------------------------------------------------------------
// The cast and the policy
// ---------------------------------------------------------------------------

const ALICE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD3IltXWq786MbRIZ6GbKrfXrMqRrnyqM1MwX7nShsUIwAAAJB1avu2dWr7
tgAAAAtzc2gtZWQyNTUxOQAAACD3IltXWq786MbRIZ6GbKrfXrMqRrnyqM1MwX7nShsUIw
AAAED4ytcis06zxhvHfNLlgVhJdYhWV33Jm1MkJsqa/PDVnvciW1darvzoxtEhnoZsqt9e
sypGufKozUzBfudKGxQjAAAACXNpbS1hbGljZQECAwQ=
-----END OPENSSH PRIVATE KEY-----";
const ALICE_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPciW1darvzoxtEhnoZsqt9esypGufKozUzBfudKGxQj sim-alice";

const BOB_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAzG4O8+/ieNJAXcsmkO0C+OYdcRH5wDXC1EgyfGFT/ewAAAJDd3GNc3dxj
XAAAAAtzc2gtZWQyNTUxOQAAACAzG4O8+/ieNJAXcsmkO0C+OYdcRH5wDXC1EgyfGFT/ew
AAAECEA9agHHkI8b2eDT6WF8pr5jt3lvp64wrLcLSxJftOSzMbg7z7+J40kBdyyaQ7QL45
h1xEfnANcLUSDJ8YVP97AAAAB3NpbS1ib2IBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----";
const BOB_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDMbg7z7+J40kBdyyaQ7QL45h1xEfnANcLUSDJ8YVP97 sim-bob";

/// Charlie is the stranger: a real key that is NOT in the policy.
const CHARLIE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC6kwvzAZkSXb/7pFbVhGHty16Hy8mdp827th3RTNLf1AAAAJDV3fjw1d34
8AAAAAtzc2gtZWQyNTUxOQAAACC6kwvzAZkSXb/7pFbVhGHty16Hy8mdp827th3RTNLf1A
AAAECfpOhzgGdIljgG/S1Zt7TwW+J5JDaryapjBtd4vNDhZLqTC/MBmRJdv/ukVtWEYe3L
XofLyZ2nzbu2HdFM0t/UAAAAC3NpbS1jaGFybGllAQI=
-----END OPENSSH PRIVATE KEY-----";

const HOST: &str = "db-01";
const WAIT_SECS: u64 = 30;
const APPROVAL_WINDOW_SECS: u64 = 300;
const RENEWAL_WINDOW_SECS: u64 = 2 * 60 * 60;

/// The TTL vocabulary. "4h" exceeds the 2h renewal window, so a fresh 4h grant
/// refuses a renew as TooEarly — the boundary the nemesis probes.
const TTLS: &[(&str, u64)] = &[("90s", 90), ("15m", 900), ("1h", 3_600), ("4h", 14_400)];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Actor {
    Alice,
    Bob,
    /// A valid signature from a key the policy does not know.
    Charlie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Profile {
    /// threshold 1 over { alice }.
    Solo,
    /// threshold 2 over { alice, bob }.
    Duo,
    /// threshold 2 over { alice(1), wait 30s(1) } — pass can open it.
    Timed,
}

impl Profile {
    fn id(self) -> &'static str {
        match self {
            Profile::Solo => "solo",
            Profile::Duo => "duo",
            Profile::Timed => "timed",
        }
    }
}

fn inventory() -> Inventory {
    let text = format!(
        r#"
        [[hosts]]
        name = "{HOST}"
        address = "10.0.4.11"
        os = "linux"
        channels = ["ssh"]
        [hosts.ssh]
        agent_user = "root"
        root_posture_default = "no"
        root_posture_emergency = "yes"

        [[approval.authenticator]]
        id = "alice"
        kind = "ed25519"
        public-key = "{ALICE_PUB}"
        [[approval.authenticator]]
        id = "bob"
        kind = "ed25519"
        public-key = "{BOB_PUB}"

        [[approval.profile]]
        id = "solo"
        threshold = 1
        factor = [ {{ authenticator = "alice", weight = 1 }} ]
        [[approval.profile]]
        id = "duo"
        threshold = 2
        factor = [
          {{ authenticator = "alice", weight = 1 }},
          {{ authenticator = "bob",   weight = 1 }},
        ]
        [[approval.profile]]
        id = "timed"
        threshold = 2
        factor = [
          {{ authenticator = "alice", weight = 1 }},
          {{ wait = "{WAIT_SECS}s",   weight = 1 }},
        ]
        "#
    );
    Inventory::parse(&text).expect("the sim inventory parses")
}

// ---------------------------------------------------------------------------
// The shadow model (pure; the deliberate duplication of the spec)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Shadow {
    Closed,
    Pending {
        profile: Profile,
        satisfied: BTreeSet<Actor>,
        requested_at: u64,
        deadline: u64,
        ttl_secs: u64,
    },
    Open {
        expires: u64,
    },
}

impl Shadow {
    /// The weighted evaluation, rewritten from the spec for OUR three profiles.
    fn met(profile: Profile, satisfied: &BTreeSet<Actor>, elapsed: u64) -> bool {
        match profile {
            Profile::Solo => satisfied.contains(&Actor::Alice),
            Profile::Duo => satisfied.contains(&Actor::Alice) && satisfied.contains(&Actor::Bob),
            Profile::Timed => satisfied.contains(&Actor::Alice) && elapsed >= WAIT_SECS,
        }
    }

    /// What `status` must observe at `now`. Expiry is observational and the
    /// boundary is closed: AT the deadline/expiry instant the grant reads
    /// expired, never "zero seconds left".
    pub(crate) fn observed(&self, now: u64) -> (GrantState, Option<u64>) {
        match self {
            Shadow::Closed => (GrantState::Closed, None),
            Shadow::Pending { deadline, .. } => {
                if now >= *deadline {
                    (GrantState::ApprovalExpired, None)
                } else {
                    (GrantState::AwaitingApproval, Some(deadline - now))
                }
            }
            Shadow::Open { expires } => {
                if now >= *expires {
                    (GrantState::Expired, None)
                } else {
                    (GrantState::Open, Some(expires - now))
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Actions and their shadow semantics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProofKind {
    /// Sign the CURRENT pending challenge.
    Fresh,
    /// Sign a challenge from an earlier request — the nemesis replay.
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Open { profile: Profile, ttl_ix: usize },
    Approve { actor: Actor, proof: ProofKind },
    Renew { ttl_ix: usize },
    Close,
    Advance { secs: u64 },
    Pass,
}

/// What the checker expects a response's result to be, decided from the shadow
/// BEFORE the action runs.
fn expected_result(action: &Action, shadow: &Shadow, now: u64) -> ResponseResult {
    match action {
        Action::Open { .. } => match shadow.observed(now).0 {
            // Only a Closed grant may begin pending; an expired pending is
            // refused (AlreadyPending) until a pass reaps it.
            GrantState::Closed => ResponseResult::Ok,
            _ => ResponseResult::Refused,
        },
        Action::Approve { actor, proof } => match shadow {
            Shadow::Pending { deadline, .. } if now < *deadline => {
                match (actor, proof) {
                    // A configured signer over the live challenge is accepted
                    // (idempotently, for a repeat), whether or not it tips the
                    // threshold.
                    (Actor::Alice | Actor::Bob, ProofKind::Fresh) => ResponseResult::Ok,
                    // A stale challenge or a stranger's key is refused.
                    _ => ResponseResult::Refused,
                }
            }
            _ => ResponseResult::Refused,
        },
        Action::Renew { ttl_ix: _ } => match shadow {
            Shadow::Open { expires } if now < *expires => {
                if expires - now <= RENEWAL_WINDOW_SECS {
                    ResponseResult::Ok
                } else {
                    ResponseResult::Refused // TooEarly
                }
            }
            _ => ResponseResult::Refused,
        },
        // Close is universally acknowledged: cancelled / closed / already-closed.
        Action::Close => ResponseResult::Ok,
        Action::Advance { .. } | Action::Pass => ResponseResult::Ok,
    }
}

/// Advance the shadow by the action's semantics (called only when the daemon
/// accepted or the action is local). `now` is the time the action ran at.
fn advance_shadow(shadow: &mut Shadow, action: &Action, now: u64) {
    match action {
        Action::Open { profile, ttl_ix } => {
            if matches!(shadow.observed(now).0, GrantState::Closed) {
                *shadow = Shadow::Pending {
                    profile: *profile,
                    satisfied: BTreeSet::new(),
                    requested_at: now,
                    deadline: now + APPROVAL_WINDOW_SECS,
                    ttl_secs: TTLS[*ttl_ix].1,
                };
            }
        }
        Action::Approve { actor, proof } => {
            if let Shadow::Pending {
                profile,
                satisfied,
                requested_at,
                deadline,
                ttl_secs,
            } = shadow
            {
                let live = now < *deadline;
                let valid =
                    matches!(actor, Actor::Alice | Actor::Bob) && matches!(proof, ProofKind::Fresh);
                if live && valid {
                    satisfied.insert(*actor);
                    let elapsed = now - *requested_at;
                    if Shadow::met(*profile, satisfied, elapsed) {
                        *shadow = Shadow::Open {
                            expires: now + *ttl_secs,
                        };
                    }
                }
            }
        }
        Action::Renew { ttl_ix } => {
            if let Shadow::Open { expires } = shadow {
                if now < *expires && *expires - now <= RENEWAL_WINDOW_SECS {
                    *shadow = Shadow::Open {
                        expires: now + TTLS[*ttl_ix].1,
                    };
                }
            }
        }
        Action::Close => *shadow = Shadow::Closed,
        Action::Advance { .. } => {}
        Action::Pass => {
            match shadow {
                // Reap first: a lapsed pending or an expired open closes (the
                // fake driver reverts synchronously, so one pass lands Closed).
                Shadow::Pending { deadline, .. } if now >= *deadline => *shadow = Shadow::Closed,
                Shadow::Open { expires } if now >= *expires => *shadow = Shadow::Closed,
                // Then the wait evaluation: pass opens only a grant whose wait
                // is load-bearing (met now, not met with zero elapsed) — for our
                // policy that is exactly `timed` with alice in and the wait up.
                Shadow::Pending {
                    profile,
                    satisfied,
                    requested_at,
                    ttl_secs,
                    ..
                } => {
                    let elapsed = now - *requested_at;
                    if Shadow::met(*profile, satisfied, elapsed)
                        && !Shadow::met(*profile, satisfied, 0)
                    {
                        *shadow = Shadow::Open {
                            expires: now + *ttl_secs,
                        };
                    }
                }
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The checker (self-tested below, before the runner exists)
// ---------------------------------------------------------------------------

/// Compare what the daemon reports against what the shadow predicts. Returns the
/// complaint, not a panic, so the self-tests can feed it a broken daemon's
/// output and assert it bites.
pub(crate) fn check_observation(
    lines: &[GrantLine],
    shadow: &Shadow,
    now: u64,
) -> Result<(), String> {
    let line = lines
        .iter()
        .find(|l| l.host == HOST)
        .ok_or_else(|| format!("status is missing host {HOST:?}"))?;
    let (want_state, want_remaining) = shadow.observed(now);
    if line.state != want_state {
        return Err(format!(
            "observed state {:?} but the shadow predicts {:?} at t={now}",
            line.state, want_state
        ));
    }
    if line.remaining_secs != want_remaining {
        return Err(format!(
            "observed remaining {:?} but the shadow predicts {:?} at t={now} in {:?}",
            line.remaining_secs, want_remaining, want_state
        ));
    }
    Ok(())
}

/// Compare a response's result against the expectation. The invariant that
/// rediscovers the approve-vs-pass bug's observable: a valid, live proof must
/// never be refused.
pub(crate) fn check_result(
    action: &Action,
    response: &Response,
    shadow_before: &Shadow,
    now: u64,
) -> Result<(), String> {
    let want = expected_result(action, shadow_before, now);
    if response.result != want {
        return Err(format!(
            "{action:?} returned {:?} but the shadow expects {:?} (state {shadow_before:?}, t={now}); \
             error: {:?}",
            response.result, want, response.error
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The live harness: a real Daemon driven action by action
// ---------------------------------------------------------------------------

struct NoopDeadman;
impl DeadmanControl for NoopDeadman {
    fn install(
        &mut self,
        _host: &lychgate_core::Host,
        _expires_at: SystemTime,
    ) -> Result<(), lychgate_core::DriverError> {
        Ok(())
    }
    fn remove(&mut self, _host: &lychgate_core::Host) -> Result<bool, lychgate_core::DriverError> {
        Ok(false)
    }
}

pub(crate) struct Sim {
    daemon: Daemon,
    shadow: Shadow,
    now: u64,
    /// The live challenge (for Fresh proofs) and every superseded one (for
    /// Stale proofs — the replay nemesis).
    challenge: Option<String>,
    stale: Vec<String>,
    _dir: Scratch,
}

fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn sign(actor: Actor, challenge: &str) -> String {
    let key = match actor {
        Actor::Alice => ALICE_KEY,
        Actor::Bob => BOB_KEY,
        Actor::Charlie => CHARLIE_KEY,
    };
    let key = ssh_key::PrivateKey::from_openssh(key).expect("sim key parses");
    key.sign(
        lychgate_core::APPROVAL_NAMESPACE,
        ssh_key::HashAlg::Sha512,
        challenge.as_bytes(),
    )
    .expect("sim signing succeeds")
    .to_pem(ssh_key::LineEnding::LF)
    .expect("sim signature encodes")
}

impl Sim {
    fn new(label: &str) -> Sim {
        let dir = scratch_dir(label);
        let inventory = inventory();
        let model = inventory
            .approval_model()
            .expect("the sim policy builds")
            .expect("a policy is configured");
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut drivers = DriverSet::new();
        drivers
            .register(lychgate_core::channel::fakes::FakeDriver::new(
                lychgate_core::Channel::Ssh,
                lychgate_core::channel::fakes::Script::Succeed,
                log,
            ))
            .unwrap();
        let daemon = Daemon {
            inventory,
            store: Store::at(dir.join("grants.json")),
            journal: Mutex::new(Journal::open(dir.join("journal.jsonl")).unwrap()),
            drivers: Mutex::new(drivers),
            deadman: Mutex::new(Box::new(NoopDeadman)),
            approval_window: Duration::from_secs(APPROVAL_WINDOW_SECS),
            approval: Some(model),
            totp_secrets: std::collections::BTreeMap::new(),
            totp_ledger: crate::totp_ledger::TotpLedger::at(dir.join("totp-ledger.json")),
            password_hashes: std::collections::BTreeMap::new(),
            hmac_secrets: Default::default(),
            fido2_counters: crate::fido2_counters::Fido2Counters::at(
                dir.join("fido2-counters.json"),
            ),
        };
        Sim {
            daemon,
            shadow: Shadow::Closed,
            now: 1_000_000,
            challenge: None,
            stale: Vec::new(),
            _dir: dir,
        }
    }

    /// Run one action against the daemon AND the shadow, checking the response
    /// and the resulting observation. Returns the first complaint.
    fn step(&mut self, action: &Action) -> Result<(), String> {
        let now = t(self.now);
        let shadow_before = self.shadow.clone();

        let response = match action {
            Action::Open { profile, ttl_ix } => {
                let r = self
                    .daemon
                    .dispatch(
                        &Op::Open {
                            host: HOST.into(),
                            ttl: TTLS[*ttl_ix].0.into(),
                            profile: Some(profile.id().into()),
                        },
                        now,
                    )
                    .map_err(|e| format!("daemon-fatal on {action:?}: {e}"))?;
                if r.result == ResponseResult::Ok {
                    if let Some(p) = &r.pending {
                        if let Some(old) = self.challenge.take() {
                            self.stale.push(old);
                        }
                        self.challenge = Some(p.challenge.clone());
                    }
                }
                Some(r)
            }
            Action::Approve { actor, proof } => {
                let challenge = match proof {
                    ProofKind::Fresh => self
                        .challenge
                        .clone()
                        .unwrap_or_else(|| "lg1.req.NEVER-ISSUED".to_string()),
                    ProofKind::Stale => self
                        .stale
                        .last()
                        .cloned()
                        .unwrap_or_else(|| "lg1.req.NEVER-ISSUED".to_string()),
                };
                let token = sign(*actor, &challenge);
                Some(
                    self.daemon
                        .dispatch(
                            &Op::Approve {
                                host: HOST.into(),
                                token,
                            },
                            now,
                        )
                        .map_err(|e| format!("daemon-fatal on {action:?}: {e}"))?,
                )
            }
            Action::Renew { ttl_ix } => Some(
                self.daemon
                    .dispatch(
                        &Op::Renew {
                            host: HOST.into(),
                            ttl: TTLS[*ttl_ix].0.into(),
                        },
                        now,
                    )
                    .map_err(|e| format!("daemon-fatal on {action:?}: {e}"))?,
            ),
            Action::Close => Some(
                self.daemon
                    .dispatch(&Op::Close { host: HOST.into() }, now)
                    .map_err(|e| format!("daemon-fatal on {action:?}: {e}"))?,
            ),
            Action::Advance { secs } => {
                self.now += secs;
                None
            }
            Action::Pass => {
                self.daemon
                    .pass(now)
                    .map_err(|e| format!("daemon-fatal on {action:?}: {e}"))?;
                None
            }
        };

        // Fresh proofs sign the LIVE challenge; an Open above may have replaced
        // it. An approve consumes nothing (the challenge stays live while
        // pending), so no other bookkeeping.
        if let Some(r) = &response {
            check_result(action, r, &shadow_before, self.now)?;
        }
        advance_shadow(&mut self.shadow, action, self.now);

        // Every action ends with the observation oracle: status must match the
        // shadow exactly.
        let now = t(self.now);
        let status = self
            .daemon
            .dispatch(&Op::Status, now)
            .map_err(|e| format!("daemon-fatal on status: {e}"))?;
        check_observation(
            status.grants.as_deref().unwrap_or(&[]),
            &self.shadow,
            self.now,
        )
    }
}

// ---------------------------------------------------------------------------
// Seeded generation, the runner, and the shrinker
// ---------------------------------------------------------------------------

/// SplitMix64 — the same tiny RNG as the fuzz tier.
pub(crate) struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Boundary-heavy time steps: around the 30s wait, the 300s window, the 90s
/// ttl, and the 2h renewal window.
const ADVANCES: &[u64] = &[
    1, 5, 29, 30, 31, 89, 90, 91, 299, 300, 301, 899, 3_600, 7_200, 14_400,
];

fn gen_action(rng: &mut Rng) -> Action {
    match rng.below(100) {
        0..=17 => Action::Open {
            profile: match rng.below(3) {
                0 => Profile::Solo,
                1 => Profile::Duo,
                _ => Profile::Timed,
            },
            ttl_ix: rng.below(TTLS.len() as u64) as usize,
        },
        // Approvals dominate, mostly honest, with the nemesis mixed in.
        18..=52 => Action::Approve {
            actor: match rng.below(10) {
                0..=4 => Actor::Alice,
                5..=7 => Actor::Bob,
                _ => Actor::Charlie, // the stranger
            },
            proof: if rng.below(5) == 0 {
                ProofKind::Stale // the replayed old challenge
            } else {
                ProofKind::Fresh
            },
        },
        53..=62 => Action::Renew {
            ttl_ix: rng.below(TTLS.len() as u64) as usize,
        },
        63..=72 => Action::Close,
        // Abandonment and act-on-expired emerge from Advance past the window
        // followed by whatever comes next.
        73..=89 => Action::Advance {
            secs: ADVANCES[rng.below(ADVANCES.len() as u64) as usize],
        },
        _ => Action::Pass,
    }
}

/// Replay a full action sequence on a fresh daemon+shadow; the first complaint
/// is returned with its index.
fn replay(label: &str, actions: &[Action]) -> Result<(), (usize, String)> {
    let mut sim = Sim::new(label);
    for (i, action) in actions.iter().enumerate() {
        sim.step(action).map_err(|e| (i, e))?;
    }
    Ok(())
}

/// ddmin-lite: shrink a failing sequence to a locally minimal reproducer by
/// repeatedly dropping chunks (halving the chunk size down to 1) while the
/// failure persists. Bounded by attempts, not wall clock, so a replay is
/// deterministic.
fn shrink(label: &str, mut actions: Vec<Action>) -> (Vec<Action>, String) {
    let mut complaint = match replay(label, &actions) {
        Err((_, c)) => c,
        Ok(()) => unreachable!("shrink is only called on a failing sequence"),
    };
    let mut chunk = actions.len().div_ceil(2).max(1);
    let mut attempts = 0;
    while chunk >= 1 && attempts < 500 {
        let mut i = 0;
        let mut shrunk_this_round = false;
        while i < actions.len() {
            let mut candidate = actions.clone();
            let end = (i + chunk).min(candidate.len());
            candidate.drain(i..end);
            attempts += 1;
            match replay(label, &candidate) {
                Err((_, c)) => {
                    actions = candidate;
                    complaint = c;
                    shrunk_this_round = true;
                    // Do not advance i: the next chunk slid into place.
                }
                Ok(()) => i += chunk,
            }
            if attempts >= 500 {
                break;
            }
        }
        if !shrunk_this_round {
            if chunk == 1 {
                break;
            }
            chunk = (chunk / 2).max(1);
        }
    }
    (actions, complaint)
}

/// Committed seeds run on every invocation. Promote any defect-finding seed
/// here so its regression runs forever.
const FIXED_SEEDS: &[u64] = &[
    0x0FA1_1B0C_5EED_0001,
    0x0FA1_1B0C_5EED_0002,
    0xDEAD_BEEF_0000_0003,
    0x5EED_5EED_5EED_0004,
];

pub(crate) fn run_simulation() {
    let actions_per_seed: usize = std::env::var("LYCHGATE_SIM_ACTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120);
    let seeds: Vec<u64> = match std::env::var("LYCHGATE_SIM_SEED") {
        Ok(v) => vec![v.parse().expect("LYCHGATE_SIM_SEED must be a decimal u64")],
        Err(_) => FIXED_SEEDS.to_vec(),
    };
    for seed in seeds {
        // The seed prints before it is used, so a panic always has it above.
        println!("sim: seed {seed} ({actions_per_seed} actions)");
        let mut rng = Rng(seed);
        let actions: Vec<Action> = (0..actions_per_seed)
            .map(|_| gen_action(&mut rng))
            .collect();
        if let Err((index, complaint)) = replay("sim", &actions) {
            let (minimal, final_complaint) = shrink("sim-shrink", actions);
            panic!(
                "sim seed {seed} failed at action {index}: {complaint}\n\
                 minimal reproducer ({} actions): {minimal:#?}\n\
                 minimal complaint: {final_complaint}\n\
                 replay with LYCHGATE_SIM_SEED={seed}",
                minimal.len(),
            );
        }
    }
}

#[cfg(test)]
mod tests;
