//! KAT-driven tests for the wire contract.
//!
//! The committed files under `vectors/` are the cross-language contract: this
//! module regenerates every one from first principles and asserts byte
//! equality, so the vectors, the encoder, and the deterministic signers pin
//! each other. Ports (the AVR C library, the FPGA testbench) consume the same
//! files. Regenerate deliberately with:
//!   LYCHGATE_WIRE_REGEN=1 cargo test -p lychgate-wire -- regenerate
//!
//! Mutation checklist (each observed failing while writing this suite):
//! - drop a canonical-encoding check in cbor.rs (minimal-int, key order,
//!   trailing bytes, bstr length) → the matching reject vector passes
//!   verification and `reject_vectors_are_refused` fails;
//! - remove the prefix from the signed message in token.rs → the cross-type
//!   vectors verify and `reject_vectors_are_refused` fails;
//! - stub `verify_sig` to Ok → every bad-signature vector fails the suite;
//! - widen an integer encoding (canonical head) → `positive vectors` byte
//!   mismatch;
//! - swap the ver/key-mismatch check for Ok → the mismatch vectors fail.

use super::*;
use std::fmt::Write as _;
use std::string::String;
use std::vec::Vec;

const ED25519_SEED: [u8; 32] = [0x11; 32];
const P256_SCALAR: [u8; 32] = [0x22; 32];

const DEVICE_ID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const NONCE: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];

fn ed25519_public() -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&ED25519_SEED)
        .verifying_key()
        .to_bytes()
}

fn p256_public_sec1() -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;
    let sk = p256::ecdsa::SigningKey::from_slice(&P256_SCALAR).unwrap();
    sk.verifying_key()
        .as_affine()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// The flat KAT format: blank-line-separated records of `key = value` lines,
/// `#` comments ignored. Duplicated deliberately in every consumer (this
/// parser, the C test harness, the FPGA memory-image generator) — the format
/// is part of the contract.
fn parse_kat(text: &str) -> Vec<std::collections::BTreeMap<String, String>> {
    let mut records = Vec::new();
    let mut current = std::collections::BTreeMap::new();
    for line in text.lines().chain(std::iter::once("")) {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !current.is_empty() {
                records.push(std::mem::take(&mut current));
            }
            continue;
        }
        let (k, v) = line.split_once('=').expect("kat line without '='");
        current.insert(k.trim().to_string(), v.trim().to_string());
    }
    records
}

fn err_label(e: WireError) -> String {
    match e {
        WireError::BadPrefix => "bad-prefix".into(),
        WireError::BadBase64 => "bad-base64".into(),
        WireError::Malformed(r) => format!("malformed:{r}"),
        WireError::UnknownVersion => "unknown-version".into(),
        WireError::VersionKeyMismatch => "version-key-mismatch".into(),
        WireError::BadKey => "bad-key".into(),
        WireError::BadSignature => "bad-signature".into(),
        WireError::BufferTooSmall => "buffer-too-small".into(),
    }
}

fn cap(ver: u8, seq: u64) -> Capability {
    Capability {
        ver,
        device_id: DEVICE_ID,
        grant_nonce: NONCE,
        capability: 1,
        ttl_secs: 900,
        issued_seq: seq,
    }
}

fn rvk(ver: u8, seq: u64) -> Revocation {
    Revocation {
        ver,
        device_id: DEVICE_ID,
        grant_nonce: NONCE,
        issued_seq: seq,
    }
}

fn signer(ver: u8) -> SigningKey<'static> {
    match ver {
        VER_ED25519 => SigningKey::Ed25519Seed(&ED25519_SEED),
        VER_P256 => SigningKey::P256Scalar(&P256_SCALAR),
        _ => unreachable!(),
    }
}

// --- positive vector generation --------------------------------------------

fn positive_record(kind: &str, ver: u8, name: &str, seq: u64) -> String {
    let mut payload = [0u8; MAX_PAYLOAD_LEN];
    let (payload_len, token) = match kind {
        "cap" => {
            let c = cap(ver, seq);
            let len = encode_capability(&c, &mut payload).unwrap();
            (len, sign_capability_token(&signer(ver), &c).unwrap())
        }
        "rvk" => {
            let r = rvk(ver, seq);
            let len = encode_revocation(&r, &mut payload).unwrap();
            (len, sign_revocation_token(&signer(ver), &r).unwrap())
        }
        _ => unreachable!(),
    };
    let (keyfield, keyval, public) = match ver {
        VER_ED25519 => ("seed", hex(&ED25519_SEED), hex(&ed25519_public())),
        VER_P256 => ("scalar", hex(&P256_SCALAR), hex(&p256_public_sec1())),
        _ => unreachable!(),
    };
    let mut rec = String::new();
    writeln!(rec, "name = {name}").unwrap();
    writeln!(rec, "kind = {kind}").unwrap();
    writeln!(rec, "ver = {ver}").unwrap();
    writeln!(rec, "{keyfield} = {keyval}").unwrap();
    writeln!(rec, "public = {public}").unwrap();
    writeln!(rec, "device_id = {}", hex(&DEVICE_ID)).unwrap();
    writeln!(rec, "grant_nonce = {}", hex(&NONCE)).unwrap();
    if kind == "cap" {
        writeln!(rec, "capability = 1").unwrap();
        writeln!(rec, "ttl_secs = 900").unwrap();
    }
    writeln!(rec, "issued_seq = {seq}").unwrap();
    writeln!(rec, "payload = {}", hex(&payload[..payload_len])).unwrap();
    if ver == VER_P256 {
        // What a tier-A device hashes before delegating to the SE's Verify:
        // SHA-256(prefix ++ payload). Emitted for the v2 files so the AVR C
        // tests can pin their digest path against the same records.
        use sha2::Digest as _;
        let prefix = if kind == "cap" {
            CAP_PREFIX
        } else {
            RVK_PREFIX
        };
        let mut hasher = sha2::Sha256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(&payload[..payload_len]);
        writeln!(rec, "signed_sha256 = {}", hex(&hasher.finalize())).unwrap();
    }
    writeln!(rec, "token = {token}").unwrap();
    rec
}

fn positive_file(kind: &str, ver: u8) -> String {
    let mut out = String::from(
        "# lychgate wire KAT — generated by wire/src/tests.rs (LYCHGATE_WIRE_REGEN=1).\n\
         # These vectors are the cross-language contract; a change here is a\n\
         # breaking protocol change by definition.\n\n",
    );
    // Three seq values exercise the three uint widths a seq can take.
    for (name_seq, seq) in [
        ("small", 7u64),
        ("u16", 4242),
        ("u64", 0x0102_0304_0506_0708),
    ] {
        out.push_str(&positive_record(
            kind,
            ver,
            &format!("{kind}-v{ver}-{name_seq}"),
            seq,
        ));
        out.push('\n');
    }
    out
}

// --- reject vector generation ----------------------------------------------

/// Sign arbitrary payload bytes as a well-formed token (the signature is over
/// the raw bytes, so structurally-broken payloads still get valid signatures
/// — that is what lets a vector exercise the decoder past the crypto).
fn sign_raw(prefix: &str, ver: u8, payload: &[u8]) -> String {
    use data_encoding::BASE64URL_NOPAD;
    let mut msg = Vec::from(prefix.as_bytes());
    msg.extend_from_slice(payload);
    let sig: [u8; SIG_LEN] = match ver {
        VER_ED25519 => {
            let sk = ed25519_dalek::SigningKey::from_bytes(&ED25519_SEED);
            ed25519_dalek::Signer::sign(&sk, &msg).to_bytes()
        }
        VER_P256 => {
            use p256::ecdsa::signature::Signer as _;
            let sk = p256::ecdsa::SigningKey::from_slice(&P256_SCALAR).unwrap();
            let sig: p256::ecdsa::Signature = sk.sign(&msg);
            let mut out = [0u8; SIG_LEN];
            out.copy_from_slice(&sig.to_bytes());
            out
        }
        _ => unreachable!(),
    };
    format!(
        "{prefix}{}.{}",
        BASE64URL_NOPAD.encode(payload),
        BASE64URL_NOPAD.encode(&sig)
    )
}

/// Hand-rolled payload variants, each breaking exactly one deterministic-CBOR
/// rule. Byte-level on purpose: the encoder cannot emit these, which is the
/// point — the decoder must refuse what the encoder cannot produce.
fn structural_variants() -> Vec<(&'static str, Vec<u8>, &'static str)> {
    let mut canonical = [0u8; MAX_PAYLOAD_LEN];
    let len = encode_capability(&cap(VER_ED25519, 7), &mut canonical).unwrap();
    let canonical = &canonical[..len];

    let mut variants = Vec::new();

    // ver=3 — well-formed CBOR, unknown version.
    let mut v = canonical.to_vec();
    assert_eq!(v[1..3], [0x00, 0x01], "layout drifted: ver entry");
    v[2] = 0x03;
    variants.push(("unknown-ver", v, "unknown-version"));

    // Non-minimal integer: ver encoded as 18 01 (u8 head for a value < 24).
    let mut v = canonical.to_vec();
    v.remove(2);
    v.insert(2, 0x01);
    v.insert(2, 0x18);
    variants.push(("non-minimal-int", v, "malformed:non-minimal integer"));

    // Out-of-order keys: swap the two bstr entries (key 2 before key 1).
    let mut v = Vec::new();
    v.extend_from_slice(&canonical[..3]); // map head + ver entry
    v.extend_from_slice(&canonical[21..39]); // key 2 entry
    v.extend_from_slice(&canonical[3..21]); // key 1 entry
    v.extend_from_slice(&canonical[39..]);
    variants.push(("key-order", v, "malformed:unexpected map key"));

    // Wrong byte-string length: device_id truncated to 15 with its head fixed.
    let mut v = canonical.to_vec();
    assert_eq!(v[4], 0x50, "layout drifted: device_id bstr head");
    v[4] = 0x4f;
    v.remove(5);
    variants.push(("bstr-short", v, "malformed:wrong byte-string length"));

    // Wrong byte-string length the other way: 17 bytes claimed and present.
    let mut v = canonical.to_vec();
    v[4] = 0x51;
    v.insert(5, 0xee);
    variants.push(("bstr-long", v, "malformed:wrong byte-string length"));

    // Indefinite-length map.
    let mut v = canonical.to_vec();
    v[0] = 0xbf;
    variants.push((
        "indefinite-map",
        v,
        "malformed:indefinite or reserved length",
    ));

    // Trailing byte after a complete payload.
    let mut v = canonical.to_vec();
    v.push(0x00);
    variants.push(("trailing-byte", v, "malformed:trailing bytes"));

    // A revocation-shaped map presented as a capability (wrong map size).
    let mut small = [0u8; MAX_PAYLOAD_LEN];
    let rlen = encode_revocation(&rvk(VER_ED25519, 7), &mut small).unwrap();
    variants.push((
        "map-size",
        small[..rlen].to_vec(),
        "malformed:wrong map size",
    ));

    // Truncated mid-field.
    let v = canonical[..canonical.len() - 4].to_vec();
    variants.push(("truncated", v, "malformed:truncated"));

    variants
}

fn reject_file() -> String {
    let mut out = String::from(
        "# lychgate wire reject KAT — every record must REFUSE with the named\n\
         # error. Generated by wire/src/tests.rs (LYCHGATE_WIRE_REGEN=1).\n\n",
    );
    let mut push = |name: &str, kind: &str, keykind: &str, token: &str, expect: &str| {
        writeln!(out, "name = {name}").unwrap();
        writeln!(out, "kind = {kind}").unwrap();
        writeln!(out, "keykind = {keykind}").unwrap();
        writeln!(out, "token = {token}").unwrap();
        writeln!(out, "expect = {expect}").unwrap();
        out.push('\n');
    };

    let good_v1 = sign_capability_token(&signer(VER_ED25519), &cap(VER_ED25519, 7)).unwrap();
    let good_v2 = sign_capability_token(&signer(VER_P256), &cap(VER_P256, 7)).unwrap();
    let good_rvk_v1 = sign_revocation_token(&signer(VER_ED25519), &rvk(VER_ED25519, 7)).unwrap();

    // Signature bit flipped (last sig char changed to a different b64 char).
    for (ver, tok) in [(1u8, &good_v1), (2, &good_v2)] {
        let mut t = tok.clone();
        let last = t.pop().unwrap();
        t.push(if last == 'A' { 'B' } else { 'A' });
        push(
            &format!("flipped-sig-v{ver}"),
            "cap",
            if ver == 1 { "ed25519" } else { "p256" },
            &t,
            "bad-signature",
        );
    }

    // Verified against the wrong key of the SAME kind (key substitution).
    let other_seed = [0x33u8; 32];
    let other = ed25519_dalek::SigningKey::from_bytes(&other_seed);
    let tok = {
        let c = cap(VER_ED25519, 7);
        let mut payload = [0u8; MAX_PAYLOAD_LEN];
        let len = encode_capability(&c, &mut payload).unwrap();
        let mut msg = Vec::from(CAP_PREFIX.as_bytes());
        msg.extend_from_slice(&payload[..len]);
        let sig = ed25519_dalek::Signer::sign(&other, &msg).to_bytes();
        use data_encoding::BASE64URL_NOPAD;
        format!(
            "{CAP_PREFIX}{}.{}",
            BASE64URL_NOPAD.encode(&payload[..len]),
            BASE64URL_NOPAD.encode(&sig)
        )
    };
    push("wrong-key", "cap", "ed25519", &tok, "bad-signature");

    // Cross-type: a genuine capability presented under the revocation prefix.
    // The signature covers "lgcap." ++ payload, so this is the domain-
    // separation oracle: remove the prefix from the signed message and this
    // vector verifies.
    let cross = format!("{RVK_PREFIX}{}", good_v1.strip_prefix(CAP_PREFIX).unwrap());
    push("cross-type", "rvk", "ed25519", &cross, "bad-signature");

    // Cross-version: payload claims v2 but is signed (validly) by the v1 key
    // and verified with the v1 key — the ver/key agreement check must refuse.
    let mut payload = [0u8; MAX_PAYLOAD_LEN];
    let len = encode_capability(&cap(VER_P256, 7), &mut payload).unwrap();
    let tok = sign_raw(CAP_PREFIX, VER_ED25519, &payload[..len]);
    push(
        "cross-version",
        "cap",
        "ed25519",
        &tok,
        "version-key-mismatch",
    );

    // A revocation verified as a capability (prefix mismatch).
    push(
        "prefix-mismatch",
        "cap",
        "ed25519",
        &good_rvk_v1,
        "bad-prefix",
    );

    // Structural CBOR breaks, each validly signed so the decoder is what
    // refuses.
    for (name, payload, expect) in structural_variants() {
        let tok = sign_raw(CAP_PREFIX, VER_ED25519, &payload);
        push(name, "cap", "ed25519", &tok, expect);
    }

    // base64 junk in each segment.
    push(
        "junk-b64-payload",
        "cap",
        "ed25519",
        "lgcap.!!!!.AAAA",
        "bad-base64",
    );
    let (head, _) = good_v1.rsplit_once('.').unwrap();
    push(
        "junk-b64-sig",
        "cap",
        "ed25519",
        &format!("{head}.@@@@"),
        "bad-base64",
    );
    push("no-dot", "cap", "ed25519", "lgcap.AAAA", "bad-base64");

    out
}

fn ttl_bound_file() -> String {
    // A TTL beyond MAX_TTL_SECS deliberately PARSES: the wire format is
    // policy-free and enforcement lives in the consumers (the device refuses,
    // the daemon caps). Every port must agree, so it is pinned as a vector.
    let mut c = cap(VER_ED25519, 7);
    c.ttl_secs = 999_999;
    let token = sign_capability_token(&signer(VER_ED25519), &c).unwrap();
    format!(
        "# A ttl_secs beyond MAX_TTL_SECS ({}) PARSES — wire is policy-free;\n\
         # consumers enforce. Generated by wire/src/tests.rs.\n\n\
         name = ttl-over-cap\nkind = cap\nver = 1\npublic = {}\nttl_secs = 999999\ntoken = {}\nverdict = ok-parse\n",
        MAX_TTL_SECS,
        hex(&ed25519_public()),
        token
    )
}

fn vector_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vectors")
        .join(name)
}

fn check_or_regen(name: &str, generated: String) {
    let path = vector_path(name);
    if std::env::var_os("LYCHGATE_WIRE_REGEN").is_some() {
        std::fs::write(&path, &generated).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing vector file {name} ({e}); see module doc"));
    assert_eq!(
        committed, generated,
        "{name} drifted from regeneration — a vector change is a breaking protocol change"
    );
}

// --- the tests -------------------------------------------------------------

#[test]
fn regenerate_and_pin_vectors() {
    check_or_regen("lgcap_v1.kat", positive_file("cap", VER_ED25519));
    check_or_regen("lgcap_v2.kat", positive_file("cap", VER_P256));
    check_or_regen("lgrvk_v1.kat", positive_file("rvk", VER_ED25519));
    check_or_regen("lgrvk_v2.kat", positive_file("rvk", VER_P256));
    check_or_regen("lgcap_reject.kat", reject_file());
    check_or_regen("ttl_bound.kat", ttl_bound_file());
}

fn public_for(rec: &std::collections::BTreeMap<String, String>) -> (Vec<u8>, bool) {
    let public = unhex(&rec["public"]);
    let is_ed = rec["ver"] == "1";
    (public, is_ed)
}

#[test]
fn positive_vectors_verify_and_match_fields() {
    for file in ["lgcap_v1.kat", "lgcap_v2.kat"] {
        let text = std::fs::read_to_string(vector_path(file)).unwrap();
        for rec in parse_kat(&text) {
            let (public, is_ed) = public_for(&rec);
            let ed_arr: [u8; 32];
            let key = if is_ed {
                ed_arr = public.clone().try_into().unwrap();
                PublicKey::Ed25519(&ed_arr)
            } else {
                PublicKey::P256Sec1(&public)
            };
            let c = verify_capability(&key, &rec["token"])
                .unwrap_or_else(|e| panic!("{file}/{}: {e}", rec["name"]));
            assert_eq!(hex(&c.device_id), rec["device_id"]);
            assert_eq!(hex(&c.grant_nonce), rec["grant_nonce"]);
            assert_eq!(c.capability.to_string(), rec["capability"]);
            assert_eq!(c.ttl_secs.to_string(), rec["ttl_secs"]);
            assert_eq!(c.issued_seq.to_string(), rec["issued_seq"]);
            // The committed payload bytes are exactly what re-encoding emits.
            let mut buf = [0u8; MAX_PAYLOAD_LEN];
            let len = encode_capability(&c, &mut buf).unwrap();
            assert_eq!(hex(&buf[..len]), rec["payload"]);
        }
    }
    for file in ["lgrvk_v1.kat", "lgrvk_v2.kat"] {
        let text = std::fs::read_to_string(vector_path(file)).unwrap();
        for rec in parse_kat(&text) {
            let (public, is_ed) = public_for(&rec);
            let ed_arr: [u8; 32];
            let key = if is_ed {
                ed_arr = public.clone().try_into().unwrap();
                PublicKey::Ed25519(&ed_arr)
            } else {
                PublicKey::P256Sec1(&public)
            };
            let r = verify_revocation(&key, &rec["token"])
                .unwrap_or_else(|e| panic!("{file}/{}: {e}", rec["name"]));
            assert_eq!(hex(&r.device_id), rec["device_id"]);
            assert_eq!(r.issued_seq.to_string(), rec["issued_seq"]);
        }
    }
}

#[test]
fn reject_vectors_are_refused() {
    let text = std::fs::read_to_string(vector_path("lgcap_reject.kat")).unwrap();
    let ed = ed25519_public();
    let p2 = p256_public_sec1();
    let records = parse_kat(&text);
    assert!(records.len() >= 15, "reject corpus shrank");
    for rec in records {
        let key = match rec["keykind"].as_str() {
            "ed25519" => PublicKey::Ed25519(&ed),
            "p256" => PublicKey::P256Sec1(&p2),
            other => panic!("unknown keykind {other}"),
        };
        let err = match rec["kind"].as_str() {
            "cap" => verify_capability(&key, &rec["token"]).unwrap_err(),
            "rvk" => verify_revocation(&key, &rec["token"]).unwrap_err(),
            other => panic!("unknown kind {other}"),
        };
        assert_eq!(
            err_label(err),
            rec["expect"],
            "vector {} refused for the wrong reason",
            rec["name"]
        );
    }
}

#[test]
fn ttl_beyond_cap_parses_and_policy_is_the_consumers() {
    let text = std::fs::read_to_string(vector_path("ttl_bound.kat")).unwrap();
    let rec = &parse_kat(&text)[0];
    let ed = ed25519_public();
    let c = verify_capability(&PublicKey::Ed25519(&ed), &rec["token"]).unwrap();
    assert!(
        c.ttl_secs > MAX_TTL_SECS,
        "vector no longer exercises the bound"
    );
}

#[test]
fn round_trips_are_identities() {
    for ver in [VER_ED25519, VER_P256] {
        for seq in [0u64, 23, 24, 0xff, 0x100, 0xffff, 0x10000, u64::MAX] {
            let mut c = cap(ver, seq);
            c.capability = u32::MAX;
            c.ttl_secs = u32::MAX;
            let mut buf = [0u8; MAX_PAYLOAD_LEN];
            let len = encode_capability(&c, &mut buf).unwrap();
            assert_eq!(decode_capability(&buf[..len]).unwrap(), c);

            let r = rvk(ver, seq);
            let len = encode_revocation(&r, &mut buf).unwrap();
            assert_eq!(decode_revocation(&buf[..len]).unwrap(), r);
        }
    }
}

#[test]
fn max_field_token_fits_the_const_buffers() {
    // MAX_PAYLOAD_LEN / MAX_TOKEN_LEN sufficiency: every integer at max width.
    let c = Capability {
        ver: VER_ED25519,
        device_id: [0xff; 16],
        grant_nonce: [0xff; 16],
        capability: u32::MAX,
        ttl_secs: u32::MAX,
        issued_seq: u64::MAX,
    };
    let mut buf = [0u8; MAX_TOKEN_LEN];
    let tok = sign_capability_into(&SigningKey::Ed25519Seed(&ED25519_SEED), &c, &mut buf).unwrap();
    assert!(tok.len() <= MAX_TOKEN_LEN);
    let ed = ed25519_public();
    assert_eq!(verify_capability(&PublicKey::Ed25519(&ed), tok).unwrap(), c);
}

#[test]
fn signing_refuses_a_ver_key_mismatch() {
    let c = cap(VER_P256, 7);
    let err = sign_capability_token(&SigningKey::Ed25519Seed(&ED25519_SEED), &c).unwrap_err();
    assert_eq!(err, WireError::VersionKeyMismatch);
}

#[test]
fn junk_never_panics_and_never_verifies() {
    // Deterministic xorshift junk + every truncation of a valid token: the
    // decoder must refuse (never panic, never accept).
    let ed = ed25519_public();
    let key = PublicKey::Ed25519(&ed);
    let good = sign_capability_token(&signer(VER_ED25519), &cap(VER_ED25519, 7)).unwrap();

    for cut in 0..good.len() {
        assert!(
            verify_capability(&key, &good[..cut]).is_err(),
            "truncation at {cut} accepted"
        );
    }

    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut junk = String::new();
    for _ in 0..10_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        junk.clear();
        junk.push_str("lgcap.");
        let n = (state % 80) as usize;
        for i in 0..n {
            let b = (state.rotate_left(i as u32) & 0x7f) as u8;
            junk.push(if b.is_ascii_graphic() { b as char } else { '.' });
        }
        assert!(verify_capability(&key, &junk).is_err());
    }
}

#[test]
fn tampered_payload_field_fails_the_signature() {
    // Flip one payload character (not the sig): the signature must catch it.
    let good = sign_capability_token(&signer(VER_ED25519), &cap(VER_ED25519, 7)).unwrap();
    let ed = ed25519_public();
    let mut chars: Vec<char> = good.chars().collect();
    let i = CAP_PREFIX.len() + 10;
    chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    assert!(matches!(
        verify_capability(&PublicKey::Ed25519(&ed), &tampered),
        Err(WireError::BadSignature) | Err(WireError::Malformed(_)) | Err(WireError::BadBase64)
    ));
}

// --- line protocol (E4) ----------------------------------------------------
//
// Mutation notes: drop parse_state's unknown-trailer refusal → the
// newer-dialect line below parses and `line_junk_and_dialect_refusals`
// fails; drop the saw_seq requirement → the seq-less STATE parses; break
// hex_nonce/parse_hex_nonce symmetry → the round trip fails.

mod line_protocol {
    use crate::line::*;
    use crate::WireError;

    const NONCE: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];

    #[test]
    fn pinned_lines_render_exactly() {
        // Pinned strings: the protocol's KAT. A change here is a breaking
        // dialect change; docs/EMBEDDED.md carries the same examples.
        let mut buf = [0u8; MAX_LINE_LEN];
        assert_eq!(
            render_command(&Command::Token("lgcap.AA.BB"), &mut buf).unwrap(),
            "TOK lgcap.AA.BB"
        );
        let mut buf = [0u8; MAX_LINE_LEN];
        assert_eq!(render_command(&Command::Status, &mut buf).unwrap(), "STAT");
        let mut buf = [0u8; MAX_LINE_LEN];
        assert_eq!(
            render_reply(
                &Reply::AckOpen {
                    nonce: NONCE,
                    remaining_secs: 900
                },
                &mut buf
            )
            .unwrap(),
            "ACK a0a1a2a3a4a5a6a7a8a9aaabacadaeaf 900"
        );
        let mut buf = [0u8; MAX_LINE_LEN];
        assert_eq!(
            render_reply(
                &Reply::State(Report {
                    open: Some((NONCE, 887)),
                    seq: 42,
                    load: Some(true),
                    fail: Some(FailState::Energized),
                    reason: None,
                }),
                &mut buf
            )
            .unwrap(),
            "STATE open a0a1a2a3a4a5a6a7a8a9aaabacadaeaf 887 seq=42 load=on fail=energized"
        );
        let mut buf = [0u8; MAX_LINE_LEN];
        assert_eq!(
            render_reply(
                &Reply::State(Report {
                    open: None,
                    seq: 7,
                    load: None,
                    fail: None,
                    reason: Some(CloseReason::Boot),
                }),
                &mut buf
            )
            .unwrap(),
            "STATE closed seq=7 reason=boot"
        );
    }

    #[test]
    fn every_command_and_reply_round_trips() {
        let commands = [
            Command::Token("lgcap.x.y"),
            Command::Revoke("lgrvk.x.y"),
            Command::Status,
            Command::SePubkey,
            Command::SeSign("lg1.req.CHALLENGE"),
        ];
        for cmd in commands {
            let mut buf = [0u8; MAX_LINE_LEN];
            let rendered = render_command(&cmd, &mut buf).unwrap();
            assert_eq!(parse_command(rendered).unwrap(), cmd, "{rendered}");
        }
        let replies = [
            Reply::AckOpen {
                nonce: NONCE,
                remaining_secs: 0,
            },
            Reply::AckClosed,
            Reply::Nak("replay"),
            Reply::State(Report {
                open: Some((NONCE, u64::MAX)),
                seq: u64::MAX,
                load: Some(false),
                fail: Some(FailState::DeEnergized),
                reason: Some(CloseReason::Expiry),
            }),
            Reply::State(Report {
                open: None,
                seq: 0,
                load: None,
                fail: None,
                reason: None,
            }),
            Reply::Pubkey("04ab"),
            Reply::Sig("lgtpm.MEUC"),
        ];
        for reply in replies {
            let mut buf = [0u8; MAX_LINE_LEN];
            let rendered = render_reply(&reply, &mut buf).unwrap();
            assert_eq!(parse_reply(rendered).unwrap(), reply, "{rendered}");
        }
    }

    #[test]
    fn crlf_and_newline_endings_are_tolerated() {
        assert_eq!(parse_command("STAT\r\n").unwrap(), Command::Status);
        assert_eq!(parse_reply("ACK closed\n").unwrap(), Reply::AckClosed);
    }

    #[test]
    fn line_junk_and_dialect_refusals() {
        // Unknown command/reply words, a newer-dialect trailer, a seq-less
        // STATE, a malformed nonce, a non-numeric remaining: each refused
        // with a named reason — never half-understood.
        assert!(parse_command("FROB x").is_err());
        assert!(parse_reply("YO").is_err());
        assert!(matches!(
            parse_reply("STATE open a0a1a2a3a4a5a6a7a8a9aaabacadaeaf 887 seq=1 sparkle=yes"),
            Err(WireError::Malformed("unknown trailer"))
        ));
        assert!(matches!(
            parse_reply("STATE closed"),
            Err(WireError::Malformed("STATE lacks seq="))
        ));
        assert!(parse_reply("ACK zz 900").is_err());
        assert!(parse_reply("ACK a0a1a2a3a4a5a6a7a8a9aaabacadaeaf abc").is_err());
        assert!(parse_reply("STATE sideways seq=1").is_err());
    }

    #[test]
    fn line_junk_never_panics() {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut junk = std::string::String::new();
        for _ in 0..5_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            junk.clear();
            for prefix in ["", "ACK ", "STATE ", "TOK "] {
                junk.push_str(prefix);
                let n = (state % 40) as usize;
                for i in 0..n {
                    let b = (state.rotate_left(i as u32) & 0x7f) as u8;
                    junk.push(if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    });
                }
                let _ = parse_command(&junk);
                let _ = parse_reply(&junk);
            }
        }
    }

    #[test]
    fn a_max_length_token_command_fits_the_line_buffer() {
        let long = "x".repeat(crate::MAX_TOKEN_LEN);
        let mut buf = [0u8; MAX_LINE_LEN];
        render_command(&Command::Token(&long), &mut buf).unwrap();
    }
}

// --- p256 raw -> DER (E5) --------------------------------------------------
//
// Mutation notes: drop the 0x00 high-bit prefix rule → the cross-check
// against the p256 crate's own DER fails on high-bit halves; keep leading
// zeros (skip the significant-bytes trim) → the same cross-check fails on
// small halves.

mod p256_der {
    use crate::p256der::{p256_raw_sig_to_der, MAX_P256_DER_LEN};

    /// The oracle is the p256 crate's own DER encoder: real signatures over
    /// varied messages exercise high-bit and short halves statistically, and
    /// two synthetic edge signatures pin the corners deterministically.
    #[test]
    fn matches_the_p256_crates_der_for_real_signatures() {
        use p256::ecdsa::signature::Signer as _;
        let sk = p256::ecdsa::SigningKey::from_slice(&[0x22; 32]).unwrap();
        for i in 0..32u8 {
            let sig: p256::ecdsa::Signature = sk.sign(&[i; 40]);
            let raw: [u8; 64] = sig.to_bytes().into();
            let mut out = [0u8; MAX_P256_DER_LEN];
            let len = p256_raw_sig_to_der(&raw, &mut out).unwrap();
            assert_eq!(&out[..len], sig.to_der().as_bytes(), "message {i}");
        }
    }

    #[test]
    fn synthetic_edges_encode_minimally() {
        // r tiny (1), s with the high bit set: r drops 31 zeros, s gains a
        // 0x00 prefix.
        let mut rs = [0u8; 64];
        rs[31] = 0x01;
        rs[32] = 0x80;
        let mut out = [0u8; MAX_P256_DER_LEN];
        let len = p256_raw_sig_to_der(&rs, &mut out).unwrap();
        let expected: &[u8] = &[
            0x30, 0x26, // SEQUENCE: (2+1) + (2+33) = 0x26 bytes
            0x02, 0x01, 0x01, // INTEGER r = 1
            0x02, 0x21, 0x00, 0x80, // INTEGER s = 0x8000...00 with prefix
        ];
        assert_eq!(&out[..9], expected);
        assert_eq!(len, 2 + 3 + 2 + 33);
        // The pathological zero half still encodes as INTEGER 0.
        let rs = [0u8; 64];
        let len = p256_raw_sig_to_der(&rs, &mut out).unwrap();
        assert_eq!(
            &out[..len],
            &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]
        );
    }
}
