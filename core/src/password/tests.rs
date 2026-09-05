use super::*;

// A committed Argon2id PHC hash of PASSWORD under a fixed 16-byte salt (0x0a).
// It pins the format and default params: if either drifts, the vector stops
// verifying. Regenerate deliberately, never to make a red test pass.
const PASSWORD: &str = "correct-horse-battery-staple";
const HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$CgoKCgoKCgoKCgoKCgoKCg$ka5ocowN6VtZBu+X4JTfM8/Qe+xkpHFdMgV62Xf00+s";

// --- KAT: the committed hash verifies, and the oracle self-test -------------

#[test]
fn the_committed_hash_verifies_against_its_password() {
    assert_eq!(verify(HASH, PASSWORD), Ok(true));
}

#[test]
fn a_wrong_password_is_refused() {
    // Oracle self-test: proves the positive KAT is not passing vacuously.
    assert_eq!(verify(HASH, "wrong-password"), Ok(false));
    assert_eq!(verify(HASH, ""), Ok(false));
}

#[test]
fn hashing_is_deterministic_for_a_fixed_salt_and_round_trips() {
    let salt = [0x0au8; 16];
    let phc = hash(PASSWORD, &salt).unwrap();
    // Deterministic: the same input and salt reproduce the committed vector.
    assert_eq!(phc, HASH);
    // And it round-trips through verify.
    assert_eq!(verify(&phc, PASSWORD), Ok(true));
    assert_eq!(verify(&phc, "nope"), Ok(false));
}

#[test]
fn a_different_salt_gives_a_different_hash_that_still_verifies() {
    let a = hash(PASSWORD, &[1u8; 16]).unwrap();
    let b = hash(PASSWORD, &[2u8; 16]).unwrap();
    assert_ne!(a, b, "distinct salts must not collide");
    assert_eq!(verify(&a, PASSWORD), Ok(true));
    assert_eq!(verify(&b, PASSWORD), Ok(true));
}

// --- malformed hashes are refused, not treated as a mismatch ----------------

#[test]
fn a_malformed_hash_is_an_error_not_a_silent_false() {
    for junk in ["", "not a hash", "$argon2id$garbage", "plaintext-password"] {
        match verify(junk, PASSWORD) {
            Err(PasswordError::BadHash(_)) => {}
            other => panic!("wanted BadHash for {junk:?}, got {other:?}"),
        }
        assert!(validate_hash(junk).is_err(), "{junk:?} should not validate");
    }
    assert!(validate_hash(HASH).is_ok());
}
