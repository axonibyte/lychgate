use super::*;

use std::time::Duration;

// The RFC 4226 test seed ("12345678901234567890"), base32-encoded — what an
// authenticator app would be given. TOTP is HOTP over the time step, so
// code_at(seed, counter) must equal the published RFC 4226 Appendix D HOTP
// values for that counter.
const RFC_SEED_BASE32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

// RFC 4226 Appendix D, the 6-digit HOTP values for counters 0..9.
const RFC_VECTORS: [&str; 10] = [
    "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
    "520489",
];

fn seed() -> TotpSecret {
    TotpSecret::from_base32(RFC_SEED_BASE32).expect("the RFC seed is valid base32")
}

// --- KAT: the crypto against the published vectors --------------------------

#[test]
fn code_at_matches_the_rfc4226_vectors() {
    let s = seed();
    for (counter, want) in RFC_VECTORS.iter().enumerate() {
        assert_eq!(&code_at(&s, counter as u64), want, "counter {counter}");
    }
}

// --- matches(): window, boundary, and the oracle self-test ------------------

fn at_step(counter: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(counter * STEP_SECS)
}

#[test]
fn matches_finds_the_code_at_the_current_step() {
    let s = seed();
    // At the instant of step 3, its code verifies and reports step 3.
    let now = at_step(3);
    assert_eq!(matches(&s, RFC_VECTORS[3], now, 1), Some(3));
}

#[test]
fn matches_accepts_one_step_of_drift_either_way() {
    let s = seed();
    let now = at_step(5);
    // The previous and next steps' codes are accepted within ±1 skew.
    assert_eq!(matches(&s, RFC_VECTORS[4], now, 1), Some(4));
    assert_eq!(matches(&s, RFC_VECTORS[6], now, 1), Some(6));
}

#[test]
fn matches_rejects_a_code_outside_the_skew_window() {
    // Oracle self-test on the window bounds: a code two steps away is refused
    // at ±1. If the bound comparison were wrong, this would wrongly accept.
    let s = seed();
    let now = at_step(5);
    assert_eq!(matches(&s, RFC_VECTORS[7], now, 1), None); // step 7, center 5, skew 1
    assert_eq!(matches(&s, RFC_VECTORS[3], now, 1), None); // step 3
}

#[test]
fn matches_rejects_a_wrong_code() {
    // Oracle self-test: a code that is not this secret's at any step in the
    // window is refused — proving the positive tests are not vacuous.
    let s = seed();
    let now = at_step(5);
    assert_eq!(matches(&s, "000000", now, 1), None);
}

#[test]
fn matches_rejects_a_malformed_code() {
    let s = seed();
    let now = at_step(5);
    for bad in ["", "12345", "1234567", "12ab56", "abcdef"] {
        assert_eq!(matches(&s, bad, now, 1), None, "{bad:?}");
    }
}

// --- base32 parse -----------------------------------------------------------

#[test]
fn from_base32_is_tolerant_of_case_spaces_and_padding() {
    // Authenticator apps show grouped uppercase; some configs pad or lowercase.
    let a = TotpSecret::from_base32(RFC_SEED_BASE32).unwrap();
    let b = TotpSecret::from_base32("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
    assert_eq!(a, b);
    // Padding is tolerated.
    assert!(TotpSecret::from_base32("MFRGG===").is_ok());
}

#[test]
fn from_base32_refuses_junk_and_empty() {
    assert_eq!(
        TotpSecret::from_base32("not base32!"),
        Err(TotpError::BadBase32)
    );
    assert_eq!(
        TotpSecret::from_base32("10101010"),
        Err(TotpError::BadBase32)
    ); // 0,1,8,9 not in base32
    assert_eq!(TotpSecret::from_base32(""), Err(TotpError::Empty));
}
