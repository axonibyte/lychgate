use super::*;

// The committed KAT: a fixed P-256 scalar, its SEC1 public key, and the
// deterministic (RFC 6979) token over a fixed challenge. sign() must reproduce
// TOKEN byte for byte, and verify() must accept it — pinning both directions.
const PRIV: [u8; 32] = [0x44u8; 32];
const CHALLENGE: &str = "lg1.req.TPMCHALLENGE";
const PUB_B64: &str =
    "BFs2iQ2svXyalrt0oe4os9LXW3LgmiDvJc-Ob9ip8DUNDhS-2NRoKjTYNTi9_1uW6JpmZuwNtXRdAvoSEAct91o";
const TOKEN: &str =
    "lgtpm.MEUCIQCWKOLRpDKIktDcNqX4cnXpv7EEz761dokRimoJVlX1VwIgSD3FZjG77edGHbzwFKRYBoIu0NRTvtL_JDb46pz6Log";

fn pub_key() -> Vec<u8> {
    data_encoding::BASE64URL_NOPAD
        .decode(PUB_B64.as_bytes())
        .unwrap()
}

#[test]
fn the_committed_token_verifies() {
    verify(&pub_key(), TOKEN, CHALLENGE).expect("the KAT token verifies");
}

#[test]
fn signing_reproduces_the_committed_token_exactly() {
    // Deterministic ECDSA: the software signer must reproduce the committed
    // vector byte for byte, so the KAT pins the signer too.
    assert_eq!(sign(&PRIV, CHALLENGE).unwrap(), TOKEN);
    assert_eq!(
        data_encoding::BASE64URL_NOPAD.encode(&public_key(&PRIV).unwrap()),
        PUB_B64
    );
}

#[test]
fn a_wrong_challenge_is_refused() {
    assert_eq!(
        verify(&pub_key(), TOKEN, "lg1.req.SOMETHING-ELSE"),
        Err(TpmError::BadSignature)
    );
}

#[test]
fn a_tampered_signature_is_refused() {
    // Flip the final base64url character (guaranteed distinct substitution).
    let mut t = TOKEN.to_string();
    let last = t.pop().unwrap();
    t.push(if last == 'A' { 'B' } else { 'A' });
    assert!(matches!(
        verify(&pub_key(), &t, CHALLENGE),
        Err(TpmError::BadSignature) | Err(TpmError::Malformed(_))
    ));
}

#[test]
fn a_signature_by_the_wrong_key_is_refused() {
    let other = public_key(&[0x55u8; 32]).unwrap();
    assert_eq!(
        verify(&other, TOKEN, CHALLENGE),
        Err(TpmError::BadSignature)
    );
}

#[test]
fn a_malformed_token_is_a_clean_error() {
    for junk in ["", "lgtpm.", "lgtpm.!!!", "not-a-token", "lgtpm.AAAA"] {
        match verify(&pub_key(), junk, CHALLENGE) {
            Err(TpmError::Malformed(_)) | Err(TpmError::BadSignature) => {}
            other => panic!("junk {junk:?} produced {other:?}"),
        }
    }
}

#[test]
fn a_bad_public_key_is_refused_at_check() {
    assert!(check_public_key(b"not a key").is_err());
    assert!(check_public_key(&pub_key()).is_ok());
}
