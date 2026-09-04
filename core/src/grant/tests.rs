use super::*;
use crate::ttl::MAX_TTL_SECS;

use std::time::UNIX_EPOCH;

fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn ttl(secs: u64) -> Ttl {
    Ttl::from_secs(secs).expect("test ttls are legal")
}

fn chans() -> Vec<Channel> {
    vec![Channel::Ssh, Channel::Bmc]
}

/// begin + finish in one step, for tests about the Open state itself.
fn open(g: &mut Grant, now: SystemTime, secs: u64) -> SystemTime {
    let expires = g.begin_open(now, &ttl(secs), chans()).unwrap();
    g.finish_open().unwrap();
    expires
}

#[test]
fn a_new_grant_starts_closed() {
    assert_eq!(Grant::new().status(t(0)), GrantStatus::Closed);
}

#[test]
fn beginning_an_open_records_intent_with_expiry_at_now_plus_ttl() {
    let mut g = Grant::new();
    let expires = g.begin_open(t(1_000), &ttl(600), chans()).unwrap();
    assert_eq!(expires, t(1_600));
    // Intent, not access: the grant observes as mid-open, not open.
    assert_eq!(g.status(t(1_100)), GrantStatus::Opening);
}

#[test]
fn finishing_an_open_makes_the_grant_observable_as_open() {
    let mut g = Grant::new();
    open(&mut g, t(1_000), 600);
    assert_eq!(
        g.status(t(1_400)),
        GrantStatus::Open {
            remaining: Duration::from_secs(200)
        }
    );
}

#[test]
fn a_grant_observed_at_the_exact_expiry_instant_is_expired_rather_than_left_open() {
    let mut g = Grant::new();
    open(&mut g, t(1_000), 600);
    assert_eq!(g.status(t(1_600)), GrantStatus::Expired);
    assert_eq!(g.status(t(9_999)), GrantStatus::Expired);
}

#[test]
fn opening_an_already_open_grant_is_rejected_rather_than_silently_extended() {
    let mut g = Grant::new();
    open(&mut g, t(1_000), 600);
    assert_eq!(
        g.begin_open(t(1_100), &ttl(600), chans()),
        Err(GrantError::AlreadyOpen)
    );
    // The rejection must not have moved the expiry.
    assert_eq!(
        g.status(t(1_100)),
        GrantStatus::Open {
            remaining: Duration::from_secs(500)
        }
    );
}

#[test]
fn opening_over_an_expired_grant_is_rejected_because_its_channels_await_revert() {
    // Semantics changed deliberately in M3: before drivers existed, an
    // expired grant reopened as if closed. Now expiry means applied channels
    // awaiting revert, and reopening over them would lose track of what is
    // on the host.
    let mut g = Grant::new();
    open(&mut g, t(1_000), 600);
    assert_eq!(
        g.begin_open(t(2_000), &ttl(600), chans()),
        Err(GrantError::AlreadyOpen)
    );
}

#[test]
fn opening_over_a_mid_open_grant_is_rejected_as_mid_open() {
    let mut g = Grant::new();
    g.begin_open(t(0), &ttl(600), chans()).unwrap();
    assert_eq!(
        g.begin_open(t(1), &ttl(600), chans()),
        Err(GrantError::MidOpen)
    );
}

#[test]
fn an_expiry_that_would_overflow_the_clock_is_rejected_rather_than_saturated() {
    // Walk to the clock's ceiling, wherever this platform puts it.
    let mut near_the_end = UNIX_EPOCH;
    let mut step = Duration::from_secs(u64::MAX / 2);
    while step.as_secs() > 0 {
        match near_the_end.checked_add(step) {
            Some(later) => near_the_end = later,
            None => step = Duration::from_secs(step.as_secs() / 2),
        }
    }
    let mut g = Grant::new();
    assert_eq!(
        g.begin_open(near_the_end, &ttl(600), chans()),
        Err(GrantError::ClockOverflow)
    );
    // The failed begin must not have left intent behind.
    assert_eq!(g.status(near_the_end), GrantStatus::Closed);
}

#[test]
fn aborting_an_open_returns_cleanly_to_closed() {
    let mut g = Grant::new();
    g.begin_open(t(0), &ttl(600), chans()).unwrap();
    g.abort_open().unwrap();
    assert_eq!(g.status(t(1)), GrantStatus::Closed);
}

#[test]
fn failing_an_open_records_exactly_the_stuck_channels() {
    let mut g = Grant::new();
    g.begin_open(t(0), &ttl(600), chans()).unwrap();
    g.fail_open(vec![Channel::Bmc], t(5)).unwrap();
    assert_eq!(
        g.status(t(6)),
        GrantStatus::NeedsRevert {
            channels: vec![Channel::Bmc]
        }
    );
}

#[test]
fn lifecycle_transitions_from_the_wrong_state_are_refused() {
    let mut g = Grant::new();
    assert_eq!(g.finish_open(), Err(GrantError::NotOpen));
    assert_eq!(g.abort_open(), Err(GrantError::NotOpen));
    assert_eq!(g.fail_open(chans(), t(0)), Err(GrantError::NotOpen));
    assert_eq!(g.finish_revert(), Err(GrantError::NotOpen));
    assert_eq!(g.retain_stuck(chans()), Err(GrantError::NotOpen));
    assert_eq!(g.begin_revert(t(0)), Err(GrantError::NotOpen));
    g.begin_open(t(0), &ttl(600), chans()).unwrap();
    assert_eq!(g.begin_revert(t(1)), Err(GrantError::MidOpen));
}

#[test]
fn beginning_a_revert_records_the_channels_applied_at_open_time() {
    let mut g = Grant::new();
    open(&mut g, t(0), 600);
    let channels = g.begin_revert(t(100)).unwrap();
    assert_eq!(channels, chans());
    assert_eq!(
        g.status(t(100)),
        GrantStatus::NeedsRevert { channels: chans() }
    );
}

#[test]
fn beginning_a_revert_on_a_needs_revert_grant_is_an_idempotent_retry() {
    let mut g = Grant::new();
    open(&mut g, t(0), 600);
    g.begin_revert(t(100)).unwrap();
    g.retain_stuck(vec![Channel::Bmc]).unwrap();
    // The retry returns what still needs reverting, not the original set.
    assert_eq!(g.begin_revert(t(200)).unwrap(), vec![Channel::Bmc]);
}

#[test]
fn an_expired_grant_can_begin_revert_and_its_channels_survive() {
    let mut g = Grant::new();
    open(&mut g, t(0), 600);
    // Long past expiry: begin_revert still knows what was applied.
    assert_eq!(g.begin_revert(t(9_999)).unwrap(), chans());
}

#[test]
fn retain_stuck_reports_whether_the_stuck_set_changed() {
    let mut g = Grant::new();
    open(&mut g, t(0), 600);
    g.begin_revert(t(100)).unwrap();
    assert!(g.retain_stuck(vec![Channel::Bmc]).unwrap());
    // An identical retry is not worth journaling.
    assert!(!g.retain_stuck(vec![Channel::Bmc]).unwrap());
}

#[test]
fn finishing_a_revert_closes_the_grant_for_real() {
    let mut g = Grant::new();
    open(&mut g, t(0), 600);
    g.begin_revert(t(100)).unwrap();
    g.finish_revert().unwrap();
    assert_eq!(g.status(t(101)), GrantStatus::Closed);
    // And a fresh open is now legal.
    assert!(g.begin_open(t(102), &ttl(600), chans()).is_ok());
}

#[test]
fn renewing_with_more_than_the_window_remaining_is_rejected_as_too_early() {
    let mut g = Grant::new();
    open(&mut g, t(0), MAX_TTL_SECS);
    assert_eq!(
        g.renew(t(1), &ttl(MAX_TTL_SECS)),
        Err(GrantError::TooEarly {
            remaining: Duration::from_secs(MAX_TTL_SECS - 1)
        })
    );
}

#[test]
fn renewing_inside_the_final_window_extends_expiry_from_now_not_from_the_old_expiry() {
    let mut g = Grant::new();
    open(&mut g, t(0), MAX_TTL_SECS);
    let now = t(MAX_TTL_SECS - 3_600);
    let expires = g.renew(now, &ttl(MAX_TTL_SECS)).unwrap();
    assert_eq!(expires, now + Duration::from_secs(MAX_TTL_SECS));
}

#[test]
fn renewing_at_exactly_the_window_boundary_is_accepted() {
    let mut g = Grant::new();
    open(&mut g, t(0), MAX_TTL_SECS);
    let now = t(MAX_TTL_SECS - RENEWAL_WINDOW_SECS);
    assert!(g.renew(now, &ttl(3_600)).is_ok());
}

#[test]
fn renewal_preserves_the_channels_applied_at_open_time() {
    let mut g = Grant::new();
    open(&mut g, t(0), 600);
    g.renew(t(500), &ttl(600)).unwrap();
    assert_eq!(g.begin_revert(t(700)).unwrap(), chans());
}

#[test]
fn renewing_anything_but_an_open_grant_is_rejected() {
    let mut g = Grant::new();
    assert_eq!(g.renew(t(0), &ttl(600)), Err(GrantError::NotOpen));
    g.begin_open(t(0), &ttl(600), chans()).unwrap();
    assert_eq!(g.renew(t(1), &ttl(600)), Err(GrantError::NotOpen));
    g.finish_open().unwrap();
    // Expired: refused, so reopening is always explicit.
    assert_eq!(g.renew(t(2_000), &ttl(600)), Err(GrantError::NotOpen));
    g.begin_revert(t(2_000)).unwrap();
    assert_eq!(g.renew(t(2_001), &ttl(600)), Err(GrantError::NotOpen));
}
