use super::*;

// The pinned request whose challenge the committed signatures below were made
// over (with `ssh-keygen -Y sign`). If the canonical encoding changes, the
// golden challenge assertion breaks — and every SSHSIG fixture stops matching,
// which is exactly the tripwire we want.
fn fixture_request() -> ApprovalRequest {
    ApprovalRequest::new(
        [7u8; 32],
        "db-01".to_string(),
        3600,
        UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
    )
}

const GOLDEN_CHALLENGE: &str = "lg1.req.bHljaGdhdGUtYXBwcm92YWwAdjEAAAAABWRiLTAxAAAAAAAADhAAAAAAZVPxAAAAACAHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBw";

// The allowed signer's public key and a different key's, for the unknown-signer
// case.
const ALLOWED_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIOBaP66AKPs9nRYDzUrJjGJMYxn0rIWv/tNftYWIu25 lychgate-approver";
const OTHER_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILrGe6MRilIwGN1fO7WrF3hO0dFj/mlkvgrilMzhu6ta wrong-key";

// `ssh-keygen -Y sign -n lychgate-approval` over GOLDEN_CHALLENGE with the
// allowed key — the positive KAT.
const SIG_GOOD: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgg4Fo/roAo+z2dFgPNSsmMYkxjG
fSsha/+01+1hYi7bkAAAARbHljaGdhdGUtYXBwcm92YWwAAAAAAAAABnNoYTUxMgAAAFMA
AAALc3NoLWVkMjU1MTkAAABAq12Oyaj0eBpAWduov9ahGd7mqWFPv2MADtkxto8jGDT9Lg
keZB3Y3cUTgeXwPA/D3zw4Kfwi3Jf6MW5bjMXNCQ==
-----END SSH SIGNATURE-----";

// Allowed key, but signed under the wrong namespace.
const SIG_WRONG_NS: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgg4Fo/roAo+z2dFgPNSsmMYkxjG
fSsha/+01+1hYi7bkAAAAKd3JvbmdzcGFjZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gt
ZWQyNTUxOQAAAECIWs1bg1z5Kx9ls77EHMURLCHoEtgp4/I4EDLxgkBT5GFcjcWzi19Rvv
LCwNa9pWXFYMa6xP+3IjKrqmhqS/wP
-----END SSH SIGNATURE-----";

// Allowed key, right namespace, but signed over a DIFFERENT message (the
// challenge with "TAMPER" appended) — the oracle self-test: a signer that
// signed the wrong bytes must be refused.
const SIG_WRONG_MSG: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgg4Fo/roAo+z2dFgPNSsmMYkxjG
fSsha/+01+1hYi7bkAAAARbHljaGdhdGUtYXBwcm92YWwAAAAAAAAABnNoYTUxMgAAAFMA
AAALc3NoLWVkMjU1MTkAAABABkVOVpOpXL1PLH1Iezq1etoyXytJW1Dy99NOjvNp6aNCHT
wZ7JOHFRPQxgJl/OyGhB6B+YWK4W1LYJiYdrq1CA==
-----END SSH SIGNATURE-----";

// A valid signature over the real challenge, but by a key NOT in the allowed
// set.
const SIG_WRONG_KEY: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgusZ7oxGKUjAY3V87tasXeE7R0W
P+aWS+CuKUzOG7q1oAAAARbHljaGdhdGUtYXBwcm92YWwAAAAAAAAABnNoYTUxMgAAAFMA
AAALc3NoLWVkMjU1MTkAAABASqR5a70UjalCpNTHiRtyzWakr92+bI82QcYz6S5/8TY0u5
t1FskbmNP+ChUsUPm+xYJZSwFL4foSGIN2MnLyCg==
-----END SSH SIGNATURE-----";

fn allowed_verifier() -> SshSigVerifier {
    SshSigVerifier::new(vec![(
        "alice".to_string(),
        parse_ssh_public_key(ALLOWED_PUBKEY).unwrap(),
    )])
}

// --- canonical encoding ----------------------------------------------------

#[test]
fn the_canonical_encoding_is_stable() {
    // The golden challenge the fixtures were signed over. A dropped, reordered,
    // or reframed field changes this string.
    assert_eq!(fixture_request().challenge_string(), GOLDEN_CHALLENGE);
    assert!(fixture_request()
        .canonical_bytes()
        .starts_with(b"lychgate-approval\x00v1\x00"));
}

#[test]
fn every_field_participates_in_the_canonical_bytes() {
    let base = fixture_request();
    let host = ApprovalRequest::new(
        [7u8; 32],
        "db-02".into(),
        3600,
        UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
    );
    let ttl = ApprovalRequest::new(
        [7u8; 32],
        "db-01".into(),
        7200,
        UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
    );
    let when = ApprovalRequest::new(
        [7u8; 32],
        "db-01".into(),
        3600,
        UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_001),
    );
    let nonce = ApprovalRequest::new(
        [9u8; 32],
        "db-01".into(),
        3600,
        UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
    );
    for other in [host, ttl, when, nonce] {
        assert_ne!(base.canonical_bytes(), other.canonical_bytes());
    }
}

#[test]
fn length_prefixing_bounds_the_host_field() {
    // Two hosts differing only in a byte the host "absorbs" cannot produce the
    // same bytes: the u32 length prefix, not a delimiter, ends the field.
    let a = ApprovalRequest::new([0u8; 32], "a".into(), 0, UNIX_EPOCH);
    let b = ApprovalRequest::new([0u8; 32], "ab".into(), 0, UNIX_EPOCH);
    assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    assert_ne!(a.canonical_bytes().len(), b.canonical_bytes().len());
}

// --- SSHSIG verification ---------------------------------------------------

#[test]
fn a_valid_sshsig_over_the_challenge_is_accepted() {
    assert!(allowed_verifier()
        .verify(&fixture_request(), SIG_GOOD)
        .is_ok());
}

#[test]
fn a_signature_over_the_wrong_bytes_is_refused() {
    // Oracle self-test: proves the positive KAT is not passing vacuously.
    match allowed_verifier().verify(&fixture_request(), SIG_WRONG_MSG) {
        Err(ApprovalError::BadSignature) => {}
        other => panic!("wanted BadSignature, got {other:?}"),
    }
}

#[test]
fn a_signature_for_a_different_request_is_refused() {
    // The good signature over the fixture challenge does not approve a request
    // for a different host — the binding is the challenge, checked by the crypto.
    let other = ApprovalRequest::new(
        [7u8; 32],
        "web-02".into(),
        3600,
        UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
    );
    match allowed_verifier().verify(&other, SIG_GOOD) {
        Err(ApprovalError::BadSignature) => {}
        other => panic!("wanted BadSignature, got {other:?}"),
    }
}

#[test]
fn a_signature_under_the_wrong_namespace_is_refused() {
    match allowed_verifier().verify(&fixture_request(), SIG_WRONG_NS) {
        Err(ApprovalError::WrongNamespace(ns)) => assert_eq!(ns, "wrongspace"),
        other => panic!("wanted WrongNamespace, got {other:?}"),
    }
}

#[test]
fn a_signature_from_an_unlisted_signer_is_refused() {
    // A cryptographically valid signature, but the signer is not configured.
    match allowed_verifier().verify(&fixture_request(), SIG_WRONG_KEY) {
        Err(ApprovalError::UnknownApprover(_)) => {}
        other => panic!("wanted UnknownApprover, got {other:?}"),
    }
    // Symmetric: the good signature against an allowed set of only the other key.
    let only_other = SshSigVerifier::new(vec![(
        "bob".into(),
        parse_ssh_public_key(OTHER_PUBKEY).unwrap(),
    )]);
    match only_other.verify(&fixture_request(), SIG_GOOD) {
        Err(ApprovalError::UnknownApprover(_)) => {}
        other => panic!("wanted UnknownApprover, got {other:?}"),
    }
}

#[test]
fn a_malformed_token_is_a_clean_error_not_a_panic() {
    for token in [
        "",
        "not a signature",
        "-----BEGIN SSH SIGNATURE-----\nnope\n-----END SSH SIGNATURE-----",
    ] {
        match allowed_verifier().verify(&fixture_request(), token) {
            Err(ApprovalError::Malformed(_)) => {}
            other => panic!("wanted Malformed for {token:?}, got {other:?}"),
        }
    }
}

// --- AnyOf composite (fail-closed) -----------------------------------------

#[test]
fn an_empty_approver_set_approves_nothing() {
    let any = AnyOf(Vec::new());
    match any.verify(&fixture_request(), SIG_GOOD) {
        Err(ApprovalError::NoApproverConfigured) => {}
        other => panic!("wanted NoApproverConfigured, got {other:?}"),
    }
}

#[test]
fn any_of_accepts_when_one_approver_accepts() {
    // First verifier (only the other key) rejects; second (the allowed key) accepts.
    let any = AnyOf(vec![
        Box::new(SshSigVerifier::new(vec![(
            "bob".into(),
            parse_ssh_public_key(OTHER_PUBKEY).unwrap(),
        )])),
        Box::new(allowed_verifier()),
    ]);
    assert!(any.verify(&fixture_request(), SIG_GOOD).is_ok());
}

#[test]
fn any_of_reports_all_rejections_without_leaking() {
    let any = AnyOf(vec![Box::new(SshSigVerifier::new(vec![(
        "bob".into(),
        parse_ssh_public_key(OTHER_PUBKEY).unwrap(),
    )]))]);
    match any.verify(&fixture_request(), SIG_GOOD) {
        Err(ApprovalError::AllRejected(errs)) => assert_eq!(errs.len(), 1),
        other => panic!("wanted AllRejected, got {other:?}"),
    }
}

// --- config key parsing ----------------------------------------------------

#[test]
fn parse_ssh_public_key_accepts_a_real_key_and_refuses_junk() {
    assert!(parse_ssh_public_key(ALLOWED_PUBKEY).is_ok());
    assert!(matches!(
        parse_ssh_public_key("ssh-ed25519 not-base64"),
        Err(ApprovalError::Malformed(_))
    ));
    assert!(matches!(
        parse_ssh_public_key(""),
        Err(ApprovalError::Malformed(_))
    ));
}
