use super::*;

// Mutation notes (each observed failing): bind verify to an empty challenge
// (drop mac.update) → the RFC 4231 KAT and the challenge-binding test fail;
// skip the 32-byte length check → the truncated-mac case passes as Mismatch
// instead of Malformed (and a doctored short-mac acceptance would hide);
// swap verify_slice for a prefix compare → the KAT's negative arm fails.

/// RFC 4231 test case 2: the external, independent oracle for the crypto.
#[test]
fn the_rfc_4231_kat_pins_the_mac() {
    let secret = b"Jefe";
    let challenge = "what do ya want for nothing?";
    let expected_mac = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    let token = sign(secret, challenge);
    let mac_b64 = token.strip_prefix(TOKEN_PREFIX).unwrap();
    let mac = data_encoding::BASE64URL_NOPAD
        .decode(mac_b64.as_bytes())
        .unwrap();
    let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, expected_mac);
    verify(secret, &token, challenge).unwrap();
    // The negative arm: one flipped MAC bit refuses.
    let mut bytes = mac.clone();
    bytes[0] ^= 1;
    let bad = format!(
        "{TOKEN_PREFIX}{}",
        data_encoding::BASE64URL_NOPAD.encode(&bytes)
    );
    assert_eq!(verify(secret, &bad, challenge), Err(HmacError::Mismatch));
}

#[test]
fn the_committed_cross_language_vector_matches() {
    // wire/vectors/lghmac_v1.kat is consumed by the AVR C tests too.
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../wire/vectors/lghmac_v1.kat");
    let secret =
        check_secret("2222222222222222222222222222222222222222222222222222222222222222").unwrap();
    let challenge = "lg1.req.CHALLENGE-EXAMPLE";
    let token = sign(&secret, challenge);
    let generated = format!(
        "# lghmac KAT — shared by core and the AVR C library. Regenerate:\n\
         # LYCHGATE_HMAC_REGEN=1 cargo test -p lychgate-core hmac.\n\n\
         name = lghmac-basic\nsecret = {}\nchallenge = {challenge}\ntoken = {token}\n",
        "22".repeat(32),
    );
    if std::env::var_os("LYCHGATE_HMAC_REGEN").is_some() {
        std::fs::write(&path, &generated).unwrap();
        return;
    }
    let committed =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("missing lghmac_v1.kat ({e})"));
    assert_eq!(
        committed, generated,
        "lghmac drifted from the committed vector"
    );
}

#[test]
fn a_token_is_bound_to_its_challenge() {
    let secret = [7u8; 32];
    let token = sign(&secret, "challenge-one");
    verify(&secret, &token, "challenge-one").unwrap();
    // The same valid token against a DIFFERENT challenge: refused — the
    // per-request nonce is the anti-replay, and this is it working.
    assert_eq!(
        verify(&secret, &token, "challenge-two"),
        Err(HmacError::Mismatch)
    );
}

#[test]
fn malformed_tokens_are_named_not_mismatched() {
    let secret = [7u8; 32];
    assert_eq!(
        verify(&secret, "lgfido2.whatever", "c"),
        Err(HmacError::Malformed)
    );
    assert_eq!(
        verify(&secret, "lghmac.!!!", "c"),
        Err(HmacError::Malformed)
    );
    // A truncated (but valid-b64) MAC is malformed, not merely mismatched.
    let short = format!(
        "{TOKEN_PREFIX}{}",
        data_encoding::BASE64URL_NOPAD.encode(&[0u8; 16])
    );
    assert_eq!(verify(&secret, &short, "c"), Err(HmacError::Malformed));
}

#[test]
fn secrets_are_exactly_32_hex_bytes() {
    assert!(check_secret(&"ab".repeat(32)).is_ok());
    assert!(check_secret("  abcd  ").is_err());
    assert!(check_secret(&"zz".repeat(32)).is_err());
    assert_eq!(check_secret(&"ab".repeat(32)).unwrap().len(), 32);
}
