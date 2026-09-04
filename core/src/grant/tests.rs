use super::*;
use crate::ttl::MAX_TTL_SECS;

use std::time::UNIX_EPOCH;

fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn ttl(secs: u64) -> Ttl {
    Ttl::from_secs(secs).expect("test ttls are legal")
}

#[test]
fn a_new_grant_starts_closed() {
    assert_eq!(Grant::new().status(t(0)), GrantStatus::Closed);
}

#[test]
fn opening_a_closed_grant_sets_expiry_at_now_plus_ttl() {
    let mut g = Grant::new();
    let expires = g.open(t(1_000), &ttl(600)).unwrap();
    assert_eq!(expires, t(1_600));
}

#[test]
fn a_grant_observed_before_its_expiry_is_open_with_the_remaining_time() {
    let mut g = Grant::new();
    g.open(t(1_000), &ttl(600)).unwrap();
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
    g.open(t(1_000), &ttl(600)).unwrap();
    assert_eq!(g.status(t(1_600)), GrantStatus::Expired);
}

#[test]
fn a_grant_past_its_ttl_is_expired_rather_than_left_open() {
    let mut g = Grant::new();
    g.open(t(1_000), &ttl(600)).unwrap();
    assert_eq!(g.status(t(9_999)), GrantStatus::Expired);
}

#[test]
fn opening_an_already_open_grant_is_rejected_rather_than_silently_extended() {
    let mut g = Grant::new();
    let first_expiry = g.open(t(1_000), &ttl(600)).unwrap();
    assert_eq!(g.open(t(1_100), &ttl(600)), Err(GrantError::AlreadyOpen));
    // ...and the rejection must not have moved the expiry.
    assert_eq!(
        g.status(t(1_000)),
        GrantStatus::Open {
            remaining: first_expiry.duration_since(t(1_000)).unwrap()
        }
    );
}

#[test]
fn opening_a_grant_whose_ttl_has_lapsed_succeeds_as_if_it_were_closed() {
    let mut g = Grant::new();
    g.open(t(1_000), &ttl(600)).unwrap();
    let expires = g.open(t(2_000), &ttl(600)).expect("expired grants reopen");
    assert_eq!(expires, t(2_600));
}

#[test]
fn closing_an_open_grant_returns_it_to_closed() {
    let mut g = Grant::new();
    g.open(t(1_000), &ttl(600)).unwrap();
    assert_eq!(g.close(), CloseOutcome::WasOpen);
    assert_eq!(g.status(t(1_001)), GrantStatus::Closed);
}

#[test]
fn closing_an_already_closed_grant_reports_it_was_already_closed() {
    assert_eq!(Grant::new().close(), CloseOutcome::AlreadyClosed);
}

#[test]
fn renewing_with_more_than_the_window_remaining_is_rejected_as_too_early() {
    let mut g = Grant::new();
    g.open(t(0), &ttl(MAX_TTL_SECS)).unwrap();
    // 24h open, observed 1s in: far more than 2h remain.
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
    g.open(t(0), &ttl(MAX_TTL_SECS)).unwrap();
    // Observe with exactly one hour left — inside the 2h window.
    let now = t(MAX_TTL_SECS - 3_600);
    let expires = g.renew(now, &ttl(MAX_TTL_SECS)).unwrap();
    // Anchored at now: a fresh 24h from the renewal instant, not 24h stacked
    // onto the old expiry.
    assert_eq!(expires, now + Duration::from_secs(MAX_TTL_SECS));
}

#[test]
fn renewing_at_exactly_the_window_boundary_is_accepted() {
    let mut g = Grant::new();
    g.open(t(0), &ttl(MAX_TTL_SECS)).unwrap();
    let now = t(MAX_TTL_SECS - RENEWAL_WINDOW_SECS);
    assert!(g.renew(now, &ttl(3_600)).is_ok());
}

#[test]
fn renewing_an_expired_grant_is_rejected_so_reopening_is_always_explicit() {
    let mut g = Grant::new();
    g.open(t(1_000), &ttl(600)).unwrap();
    assert_eq!(g.renew(t(2_000), &ttl(600)), Err(GrantError::NotOpen));
}

#[test]
fn renewing_a_closed_grant_is_rejected() {
    assert_eq!(
        Grant::new().renew(t(0), &ttl(600)),
        Err(GrantError::NotOpen)
    );
}

#[test]
fn an_expiry_that_would_overflow_the_clock_is_rejected_rather_than_saturated() {
    // Walk to the clock's ceiling, wherever this platform puts it: grow by
    // the largest step that still fits, halving on failure, until no whole
    // second fits.
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
        g.open(near_the_end, &ttl(600)),
        Err(GrantError::ClockOverflow)
    );
    // The failed open must not have left the grant open.
    assert_eq!(g.status(near_the_end), GrantStatus::Closed);
}
