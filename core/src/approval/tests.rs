use super::*;

// The pinned request whose challenge the committed authority fixtures were made
// over (with `ssh-keygen -Y sign`). If the canonical encoding changes, the
// golden challenge assertion breaks — and every SSHSIG fixture in
// authority/tests.rs stops matching, which is exactly the tripwire we want.
fn fixture_request() -> ApprovalRequest {
    ApprovalRequest::new(
        [7u8; 32],
        "db-01".to_string(),
        3600,
        UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
    )
}

const GOLDEN_CHALLENGE: &str = "lg1.req.bHljaGdhdGUtYXBwcm92YWwAdjEAAAAABWRiLTAxAAAAAAAADhAAAAAAZVPxAAAAACAHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBw";

const ALLOWED_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIOBaP66AKPs9nRYDzUrJjGJMYxn0rIWv/tNftYWIu25 lychgate-approver";

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
