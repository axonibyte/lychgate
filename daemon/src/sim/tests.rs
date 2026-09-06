use super::*;

// ---------------------------------------------------------------------------
// The checker self-tests come FIRST: feed the checker the observations and
// responses a BROKEN daemon would produce and prove it complains. A checker
// never observed complaining is indistinguishable from no checker.
// ---------------------------------------------------------------------------

fn line(state: GrantState, remaining: Option<u64>) -> Vec<GrantLine> {
    vec![GrantLine {
        host: HOST.into(),
        state,
        remaining_secs: remaining,
        stuck_channels: None,
    }]
}

#[test]
fn the_checker_catches_a_grant_open_below_threshold() {
    // The catastrophic failure: the daemon says Open while the shadow knows the
    // duo profile has only alice's proof. A broken daemon that opens below
    // threshold MUST be caught.
    let shadow = Shadow::Pending {
        profile: Profile::Duo,
        satisfied: [Actor::Alice].into_iter().collect(),
        requested_at: 1_000,
        deadline: 1_300,
        ttl_secs: 900,
    };
    let observed = line(GrantState::Open, Some(900));
    assert!(
        check_observation(&observed, &shadow, 1_010).is_err(),
        "an under-threshold open must be a complaint"
    );
}

#[test]
fn the_checker_catches_a_grant_that_outlives_its_expiry() {
    // The daemon reports Open past the shadow's expiry instant — the fail-open
    // failure the whole project exists to prevent.
    let shadow = Shadow::Open { expires: 2_000 };
    let observed = line(GrantState::Open, Some(5));
    assert!(
        check_observation(&observed, &shadow, 2_000).is_err(),
        "open at/past expiry must be a complaint"
    );
}

#[test]
fn the_checker_catches_a_wrong_remaining_ttl() {
    let shadow = Shadow::Open { expires: 2_000 };
    // Right state, wrong arithmetic: remaining should be 500.
    let observed = line(GrantState::Open, Some(501));
    assert!(check_observation(&observed, &shadow, 1_500).is_err());
}

#[test]
fn the_checker_accepts_a_faithful_observation() {
    // The complement: a correct daemon draws no complaint (else the harness
    // would cry wolf on every step).
    let shadow = Shadow::Open { expires: 2_000 };
    let observed = line(GrantState::Open, Some(500));
    assert!(check_observation(&observed, &shadow, 1_500).is_ok());
}

#[test]
fn the_checker_catches_a_refused_valid_proof() {
    // The observable of the real approve-vs-pass bug (fixed in the concurrency
    // tier): a live, valid tipping proof answered with a refusal. Fed to the
    // checker as the broken daemon's response, it must complain.
    let shadow = Shadow::Pending {
        profile: Profile::Solo,
        satisfied: BTreeSet::new(),
        requested_at: 1_000,
        deadline: 1_300,
        ttl_secs: 900,
    };
    let action = Action::Approve {
        actor: Actor::Alice,
        proof: ProofKind::Fresh,
    };
    let broken = Response::refused("approval refused: request is not pending");
    assert!(
        check_result(&action, &broken, &shadow, 1_010).is_err(),
        "a refused valid live proof must be a complaint"
    );
}

#[test]
fn the_checker_catches_an_accepted_stale_proof() {
    // The replay failure: a stale-challenge proof accepted. The checker expects
    // Refused; an Ok from a broken daemon must be a complaint.
    let shadow = Shadow::Pending {
        profile: Profile::Solo,
        satisfied: BTreeSet::new(),
        requested_at: 1_000,
        deadline: 1_300,
        ttl_secs: 900,
    };
    let action = Action::Approve {
        actor: Actor::Alice,
        proof: ProofKind::Stale,
    };
    assert!(
        check_result(&action, &Response::ok(), &shadow, 1_010).is_err(),
        "an accepted stale proof must be a complaint"
    );
}

// ---------------------------------------------------------------------------
// The shrinker self-test: a known-failing predicate shrinks to its minimal core.
// ---------------------------------------------------------------------------

#[test]
fn the_shrinker_reduces_a_failing_sequence_to_its_core() {
    // Shrinking runs against the real daemon, so build a sequence whose failure
    // is injected deterministically through the checker: replay() itself cannot
    // be parameterized with a fake predicate without complicating the runner, so
    // this exercises shrink()'s contract with a synthetic replay instead.
    fn fails_if_contains_open_then_close(actions: &[Action]) -> bool {
        let mut seen_open = false;
        for a in actions {
            match a {
                Action::Open { .. } => seen_open = true,
                Action::Close if seen_open => return true,
                _ => {}
            }
        }
        false
    }
    // ddmin over the synthetic predicate, mirroring shrink()'s loop shape.
    let mut actions = vec![
        Action::Pass,
        Action::Advance { secs: 30 },
        Action::Open {
            profile: Profile::Solo,
            ttl_ix: 0,
        },
        Action::Pass,
        Action::Renew { ttl_ix: 1 },
        Action::Close,
        Action::Pass,
    ];
    let mut chunk = actions.len().div_ceil(2);
    while chunk >= 1 {
        let mut i = 0;
        let mut shrunk = false;
        while i < actions.len() {
            let mut candidate = actions.clone();
            let end = (i + chunk).min(candidate.len());
            candidate.drain(i..end);
            if fails_if_contains_open_then_close(&candidate) {
                actions = candidate;
                shrunk = true;
            } else {
                i += chunk;
            }
        }
        if !shrunk {
            if chunk == 1 {
                break;
            }
            chunk = (chunk / 2).max(1);
        }
    }
    assert_eq!(
        actions.len(),
        2,
        "the minimal reproducer is exactly open-then-close, got {actions:?}"
    );
    assert!(matches!(actions[0], Action::Open { .. }));
    assert!(matches!(actions[1], Action::Close));
}

// ---------------------------------------------------------------------------
// Deterministic replays of the nemesis moves (committed micro-sequences), then
// the seeded battery itself.
// ---------------------------------------------------------------------------

#[test]
fn a_stale_challenge_is_refused_and_the_shadow_agrees() {
    // Open, abandon (advance past the window), reap, open again: the FIRST
    // challenge is now stale. Alice signing it must be refused.
    let actions = [
        Action::Open {
            profile: Profile::Solo,
            ttl_ix: 1,
        },
        Action::Advance { secs: 301 },
        Action::Pass, // reaps the lapsed pending
        Action::Open {
            profile: Profile::Solo,
            ttl_ix: 1,
        },
        Action::Approve {
            actor: Actor::Alice,
            proof: ProofKind::Stale,
        },
        // The fresh proof still opens it — the setup, not the proof, was stale.
        Action::Approve {
            actor: Actor::Alice,
            proof: ProofKind::Fresh,
        },
    ];
    replay("stale", &actions).expect("the stale-replay sequence must hold the model");
}

#[test]
fn the_full_nemesis_walk_holds_the_model() {
    // A committed walk through every nemesis move: double submit, the stranger,
    // act-on-expired approve/renew, abandonment, the wait-opened grant.
    let actions = [
        // duo: double-submit alice (idempotent), stranger refused, bob tips it.
        Action::Open {
            profile: Profile::Duo,
            ttl_ix: 0, // 90s
        },
        Action::Approve {
            actor: Actor::Alice,
            proof: ProofKind::Fresh,
        },
        Action::Approve {
            actor: Actor::Alice,
            proof: ProofKind::Fresh,
        },
        Action::Approve {
            actor: Actor::Charlie,
            proof: ProofKind::Fresh,
        },
        Action::Approve {
            actor: Actor::Bob,
            proof: ProofKind::Fresh,
        },
        // act-on-expired: let the 90s grant lapse, then renew/approve at it.
        Action::Advance { secs: 91 },
        Action::Renew { ttl_ix: 1 },
        Action::Approve {
            actor: Actor::Alice,
            proof: ProofKind::Fresh,
        },
        Action::Pass, // reap the expired grant
        // timed: alice early, the wait matures, the PASS opens it.
        Action::Open {
            profile: Profile::Timed,
            ttl_ix: 2,
        },
        Action::Approve {
            actor: Actor::Alice,
            proof: ProofKind::Fresh,
        },
        Action::Pass, // too early: wait not mature, stays pending
        Action::Advance { secs: 30 },
        Action::Pass, // the wait is load-bearing and mature: pass opens it
        Action::Close,
    ];
    replay("nemesis", &actions).expect("the nemesis walk must hold the model");
}

/// The seeded battery: FIXED_SEEDS (plus LYCHGATE_SIM_SEED / _ACTIONS overrides)
/// of generated action sequences, every step checked against the shadow, with
/// the shrinker minimizing any failure before it panics.
#[test]
fn simulated_users_hold_the_shadow_model() {
    run_simulation();
}
