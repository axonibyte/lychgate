use super::*;

// Committed vectors: assertions built by the software authenticator from fixed
// private keys ([0x11;32] for ES256, [0x22;32] for EdDSA) over a fixed challenge,
// with a fixed credential id ([0xab;16]). Signing is deterministic (RFC 6979 /
// Ed25519), so these are stable; a format or param drift breaks them.
const CHALLENGE: &str = "lg1.req.CHALLENGE";
const ES_PUB: &str =
    "BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q";
const ED_PUB: &str = "oJql9HpnWYAv-VX43C0qFKXJnSO-l_hkEn_5ODRVpPA";
const ES_TOKEN: &str = "lgfido2.eyJjcmVkZW50aWFsSWQiOiJxNnVycTZ1cnE2dXJxNnVycTZ1cnF3IiwiYXV0aGVudGljYXRvckRhdGEiOiJQOXE0UURQWndCdGFuVEVnVkNYaWlyTjI2blZzbUNfUmo5Tm13QUJWMzYwQkFBQUFBQSIsImNsaWVudERhdGFKU09OIjoiZXlKMGVYQmxJam9pZDJWaVlYVjBhRzR1WjJWMElpd2lZMmhoYkd4bGJtZGxJam9pWWtkamVFeHVTbXhqVXpWRVUwVkdUVlJGVms5U01GVWlMQ0p2Y21sbmFXNGlPaUpzZVdOb1oyRjBaU0o5Iiwic2lnbmF0dXJlIjoiTUVZQ0lRQ2VmWW1JMjV5NlFmV2kyT29pUXM4REh6a3pYMlNvZ1VfdGdlSWhkcTl5amdJaEFOX3gwWVhOZzVWWWhSS0lhNE1IQVhpQnVEbmZodk53R3RDb3l2ekJKYXJtIn0";
const ED_TOKEN: &str = "lgfido2.eyJjcmVkZW50aWFsSWQiOiJxNnVycTZ1cnE2dXJxNnVycTZ1cnF3IiwiYXV0aGVudGljYXRvckRhdGEiOiJQOXE0UURQWndCdGFuVEVnVkNYaWlyTjI2blZzbUNfUmo5Tm13QUJWMzYwQkFBQUFBQSIsImNsaWVudERhdGFKU09OIjoiZXlKMGVYQmxJam9pZDJWaVlYVjBhRzR1WjJWMElpd2lZMmhoYkd4bGJtZGxJam9pWWtkamVFeHVTbXhqVXpWRVUwVkdUVlJGVms5U01GVWlMQ0p2Y21sbmFXNGlPaUpzZVdOb1oyRjBaU0o5Iiwic2lnbmF0dXJlIjoiUTBFb3V4SV9SN1I1UWxGTEtuTzhyN3VwSkRtMTQ3NFR0RzBQQXJLZ2N2UXBiVXpOQWdvSlJMMmZmeEp3enFIQ1NCQWRDQ0pONmhibjBkZUJZOElFRHcifQ";

fn cred(alg: Alg, pub_b64: &str) -> Fido2Credential {
    Fido2Credential {
        alg,
        credential_id: vec![0xab; 16],
        public_key: data_encoding::BASE64URL_NOPAD
            .decode(pub_b64.as_bytes())
            .unwrap(),
    }
}

/// Decode a token, let `f` mutate the (authData, clientData, signature) bytes,
/// re-encode. Lets the oracle tests flip a byte precisely.
fn retoken(token: &str, f: impl FnOnce(&mut Vec<u8>, &mut Vec<u8>, &mut Vec<u8>)) -> String {
    let d = |s: &str| data_encoding::BASE64URL_NOPAD.decode(s.as_bytes()).unwrap();
    let e = |b: &[u8]| data_encoding::BASE64URL_NOPAD.encode(b);
    let raw = d(token.strip_prefix(TOKEN_PREFIX).unwrap());
    let mut tok: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let mut auth = d(tok["authenticatorData"].as_str().unwrap());
    let mut cd = d(tok["clientDataJSON"].as_str().unwrap());
    let mut sig = d(tok["signature"].as_str().unwrap());
    f(&mut auth, &mut cd, &mut sig);
    tok["authenticatorData"] = e(&auth).into();
    tok["clientDataJSON"] = e(&cd).into();
    tok["signature"] = e(&sig).into();
    format!("{TOKEN_PREFIX}{}", e(&serde_json::to_vec(&tok).unwrap()))
}

// --- KAT: the committed assertions verify -----------------------------------

#[test]
fn a_committed_es256_assertion_verifies() {
    assert_eq!(
        verify(&cred(Alg::Es256, ES_PUB), ES_TOKEN, CHALLENGE),
        Ok(())
    );
}

#[test]
fn a_committed_eddsa_assertion_verifies() {
    assert_eq!(
        verify(&cred(Alg::EdDsa, ED_PUB), ED_TOKEN, CHALLENGE),
        Ok(())
    );
}

#[test]
fn build_assertion_round_trips_and_is_deterministic() {
    for (alg, priv_bytes, pub_b64, committed) in [
        (Alg::Es256, [0x11u8; 32], ES_PUB, ES_TOKEN),
        (Alg::EdDsa, [0x22u8; 32], ED_PUB, ED_TOKEN),
    ] {
        let token = build_assertion(alg, &priv_bytes, &[0xab; 16], CHALLENGE).unwrap();
        assert_eq!(
            token, committed,
            "deterministic build must reproduce the vector"
        );
        assert_eq!(verify(&cred(alg, pub_b64), &token, CHALLENGE), Ok(()));
        // The derived public key matches the committed one.
        assert_eq!(
            data_encoding::BASE64URL_NOPAD.encode(&public_key(alg, &priv_bytes).unwrap()),
            pub_b64
        );
    }
}

// --- oracle self-tests: each failure mode is refused ------------------------

#[test]
fn a_wrong_challenge_is_refused() {
    assert_eq!(
        verify(&cred(Alg::Es256, ES_PUB), ES_TOKEN, "lg1.req.OTHER"),
        Err(Fido2Error::ChallengeMismatch)
    );
}

#[test]
fn a_tampered_signature_is_refused() {
    let bad = retoken(ES_TOKEN, |_a, _c, sig| sig[10] ^= 0x01);
    assert_eq!(
        verify(&cred(Alg::Es256, ES_PUB), &bad, CHALLENGE),
        Err(Fido2Error::BadSignature)
    );
}

#[test]
fn a_cleared_user_present_flag_is_refused() {
    // The UP check fires before signature verification, so clearing the flag
    // surfaces as UserNotPresent even though the signature no longer matches.
    let bad = retoken(ES_TOKEN, |auth, _c, _s| auth[32] &= !0x01);
    assert_eq!(
        verify(&cred(Alg::Es256, ES_PUB), &bad, CHALLENGE),
        Err(Fido2Error::UserNotPresent)
    );
}

#[test]
fn a_wrong_relying_party_is_refused() {
    let bad = retoken(ES_TOKEN, |auth, _c, _s| auth[0] ^= 0x01);
    assert_eq!(
        verify(&cred(Alg::Es256, ES_PUB), &bad, CHALLENGE),
        Err(Fido2Error::WrongRelyingParty)
    );
}

#[test]
fn a_wrong_credential_id_is_refused() {
    let mut c = cred(Alg::Es256, ES_PUB);
    c.credential_id = vec![0x00; 16];
    assert_eq!(
        verify(&c, ES_TOKEN, CHALLENGE),
        Err(Fido2Error::WrongCredential)
    );
}

#[test]
fn a_valid_signature_by_the_wrong_key_is_refused() {
    // The EdDSA assertion, checked against a different Ed25519 credential.
    let other = public_key(Alg::EdDsa, &[0x33u8; 32]).unwrap();
    let mut c = cred(Alg::EdDsa, ED_PUB);
    c.public_key = other;
    assert_eq!(
        verify(&c, ED_TOKEN, CHALLENGE),
        Err(Fido2Error::BadSignature)
    );
}

#[test]
fn a_malformed_token_is_a_clean_error() {
    let c = cred(Alg::Es256, ES_PUB);
    for junk in ["", "not a token", "lgfido2.not-base64!", "lgfido2.YWJj"] {
        assert!(
            matches!(verify(&c, junk, CHALLENGE), Err(Fido2Error::Malformed(_))),
            "wanted Malformed for {junk:?}"
        );
    }
}
