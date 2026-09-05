use super::*;

use std::time::{Duration, UNIX_EPOCH};

// A real ed25519 public key and a signature over a known challenge, reused from
// the approval fixtures: the same key/challenge/SSHSIG the approval tier pins.
const ALLOWED_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIOBaP66AKPs9nRYDzUrJjGJMYxn0rIWv/tNftYWIu25 lychgate-approver";
const OTHER_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILrGe6MRilIwGN1fO7WrF3hO0dFj/mlkvgrilMzhu6ta wrong-key";

const SIG_GOOD: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgg4Fo/roAo+z2dFgPNSsmMYkxjG
fSsha/+01+1hYi7bkAAAARbHljaGdhdGUtYXBwcm92YWwAAAAAAAAABnNoYTUxMgAAAFMA
AAALc3NoLWVkMjU1MTkAAABAq12Oyaj0eBpAWduov9ahGd7mqWFPv2MADtkxto8jGDT9Lg
keZB3Y3cUTgeXwPA/D3zw4Kfwi3Jf6MW5bjMXNCQ==
-----END SSH SIGNATURE-----";

const SIG_WRONG_KEY: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgusZ7oxGKUjAY3V87tasXeE7R0W
P+aWS+CuKUzOG7q1oAAAARbHljaGdhdGUtYXBwcm92YWwAAAAAAAAABnNoYTUxMgAAAFMA
AAALc3NoLWVkMjU1MTkAAABASqR5a70UjalCpNTHiRtyzWakr92+bI82QcYz6S5/8TY0u5
t1FskbmNP+ChUsUPm+xYJZSwFL4foSGIN2MnLyCg==
-----END SSH SIGNATURE-----";

fn fixture_request() -> ApprovalRequest {
    ApprovalRequest::new(
        [7u8; 32],
        "db-01".to_string(),
        3600,
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    )
}

fn model(toml_text: &str) -> Result<AuthorityModel, AuthorityError> {
    let spec: ApprovalSpec = toml::from_str(toml_text).expect("spec should be valid TOML");
    AuthorityModel::from_spec(&spec)
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| s.to_string()).collect()
}

// The worked example, built from ed25519 authenticators standing in for the
// fido/totp/password leaves (evaluate() keys on the satisfied id set, not the
// authenticator kind). This is the golden KAT.
fn worked_example() -> AuthorityModel {
    let toml_text = format!(
        r#"
        [[authenticator]]
        id = "s-fido"
        kind = "ed25519"
        public-key = "{k}"
        [[authenticator]]
        id = "s-ed"
        kind = "ed25519"
        public-key = "{k}"
        [[authenticator]]
        id = "s-totp"
        kind = "ed25519"
        public-key = "{k}"
        [[authenticator]]
        id = "j-pass"
        kind = "ed25519"
        public-key = "{k}"
        [[authenticator]]
        id = "j-totp"
        kind = "ed25519"
        public-key = "{k}"
        [[authenticator]]
        id = "l-pass"
        kind = "ed25519"
        public-key = "{k}"

        [[group]]
        id = "SYSADMIN"
        threshold = 3
        factor = [
          {{ authenticator = "s-fido", weight = 1 }},
          {{ authenticator = "s-ed",   weight = 1 }},
          {{ authenticator = "s-totp", weight = 1 }},
        ]
        [[group]]
        id = "JUNIOR_SYSADMIN"
        threshold = 2
        factor = [
          {{ authenticator = "j-pass", weight = 1 }},
          {{ authenticator = "j-totp", weight = 1 }},
        ]
        [[group]]
        id = "SENIOR_LEADERSHIP"
        threshold = 1
        factor = [ {{ authenticator = "l-pass", weight = 1 }} ]

        [[profile]]
        id = "claude"
        threshold = 5
        factor = [
          {{ group = "SYSADMIN",          weight = 3 }},
          {{ group = "JUNIOR_SYSADMIN",   weight = 1 }},
          {{ wait  = "1h",                weight = 1 }},
          {{ group = "SENIOR_LEADERSHIP", weight = 2 }},
        ]
        "#,
        k = ALLOWED_PUBKEY
    );
    model(&toml_text).expect("the worked example should build")
}

fn eval(m: &AuthorityModel, satisfied: &BTreeSet<String>, elapsed: Duration) -> Outcome {
    m.evaluate(m.profile("claude").unwrap(), satisfied, elapsed)
}

const SYSADMIN: &[&str] = &["s-fido", "s-ed", "s-totp"];
const JUNIOR: &[&str] = &["j-pass", "j-totp"];
const SENIOR: &[&str] = &["l-pass"];
const HOUR: Duration = Duration::from_secs(3600);

// --- the golden KAT: both paths to 5, and the near-misses -------------------

#[test]
fn path_a_sysadmin_plus_junior_plus_wait_opens() {
    let m = worked_example();
    let mut s = set(SYSADMIN);
    s.extend(set(JUNIOR));
    // SYSADMIN(3) + JUNIOR(1) = 4 before the wait: not yet.
    assert!(!eval(&m, &s, Duration::ZERO).met);
    // + the 1h wait tips it to 5.
    let out = eval(&m, &s, HOUR);
    assert_eq!(out.weight, 5);
    assert!(out.met);
}

#[test]
fn path_b_sysadmin_plus_senior_opens_with_no_wait() {
    let m = worked_example();
    let mut s = set(SYSADMIN);
    s.extend(set(SENIOR));
    let out = eval(&m, &s, Duration::ZERO);
    assert_eq!(out.weight, 5); // 3 + 2
    assert!(out.met);
}

#[test]
fn one_weight_short_does_not_open() {
    // Oracle self-test: SYSADMIN(3) + the wait(1) = 4, one short of 5. If this
    // opened, the threshold comparison would be meaningless.
    let m = worked_example();
    let s = set(SYSADMIN);
    let out = eval(&m, &s, HOUR);
    assert_eq!(out.weight, 4);
    assert!(!out.met);
}

#[test]
fn an_unmet_subgroup_contributes_nothing() {
    // Only two of SYSADMIN's three factors: the group is not met, so its whole
    // weight (3) is withheld — not a partial 2.
    let m = worked_example();
    let mut s = set(&["s-fido", "s-ed"]); // SYSADMIN 2/3 → not met
    s.extend(set(SENIOR)); // SENIOR met → 2
    let out = eval(&m, &s, HOUR); // + wait → 1
    assert_eq!(out.weight, 3); // 0 + 2 + 1, NOT 2+2+1
    assert!(!out.met);
}

#[test]
fn the_wait_is_satisfied_exactly_at_its_boundary() {
    let m = worked_example();
    let s = set(SYSADMIN); // 3; needs the wait's 1 plus more, so isolate the wait
                           // by checking the wait factor's contribution via weight.
    let just_before = eval(&m, &s, HOUR - Duration::from_secs(1));
    let at = eval(&m, &s, HOUR);
    assert_eq!(just_before.weight, 3, "wait not yet earned");
    assert_eq!(at.weight, 4, "wait earned at exactly 1h");
}

#[test]
fn missing_names_the_outstanding_factors() {
    let m = worked_example();
    let s = set(SYSADMIN);
    let out = eval(&m, &s, Duration::ZERO);
    // SYSADMIN satisfied; JUNIOR, SENIOR and the wait are outstanding.
    assert!(out
        .missing
        .contains(&Missing::Group("JUNIOR_SYSADMIN".into())));
    assert!(out
        .missing
        .contains(&Missing::Group("SENIOR_LEADERSHIP".into())));
    assert!(out
        .missing
        .iter()
        .any(|m| matches!(m, Missing::Wait { remaining } if *remaining == HOUR)));
}

#[test]
fn max_wait_is_the_longest_wait_in_the_graph() {
    let m = worked_example();
    assert_eq!(m.max_wait(m.profile("claude").unwrap()), HOUR);
}

// --- config validation refusals (each names the offender) -------------------

fn one_authenticator(extra: &str) -> String {
    format!(
        r#"
        [[authenticator]]
        id = "k"
        kind = "ed25519"
        public-key = "{ALLOWED_PUBKEY}"
        {extra}
        "#
    )
}

#[test]
fn a_policy_with_no_profile_is_refused() {
    let toml_text = one_authenticator(
        r#"[[group]]
        id = "g"
        threshold = 1
        factor = [ { authenticator = "k", weight = 1 } ]"#,
    );
    assert!(matches!(model(&toml_text), Err(AuthorityError::NoProfiles)));
}

#[test]
fn a_zero_threshold_would_open_for_free_and_is_refused() {
    let toml_text = one_authenticator(
        r#"[[profile]]
        id = "p"
        threshold = 0
        factor = [ { authenticator = "k", weight = 1 } ]"#,
    );
    assert!(matches!(
        model(&toml_text),
        Err(AuthorityError::ZeroThreshold { .. })
    ));
}

#[test]
fn a_zero_weight_factor_is_refused_as_dead_config() {
    let toml_text = one_authenticator(
        r#"[[profile]]
        id = "p"
        threshold = 1
        factor = [ { authenticator = "k", weight = 0 } ]"#,
    );
    assert!(matches!(
        model(&toml_text),
        Err(AuthorityError::ZeroWeight { .. })
    ));
}

#[test]
fn a_profile_with_no_factors_is_refused() {
    let toml_text = one_authenticator(
        r#"[[profile]]
        id = "p"
        threshold = 1
        factor = []"#,
    );
    assert!(matches!(
        model(&toml_text),
        Err(AuthorityError::NoFactors { .. })
    ));
}

#[test]
fn a_factor_naming_none_or_many_kinds_is_refused() {
    let none = one_authenticator(
        r#"[[profile]]
        id = "p"
        threshold = 1
        factor = [ { weight = 1 } ]"#,
    );
    assert!(matches!(
        model(&none),
        Err(AuthorityError::BadFactor { .. })
    ));
    let many = one_authenticator(
        r#"[[profile]]
        id = "p"
        threshold = 1
        factor = [ { authenticator = "k", wait = "1h", weight = 1 } ]"#,
    );
    assert!(matches!(
        model(&many),
        Err(AuthorityError::BadFactor { .. })
    ));
}

#[test]
fn an_unsatisfiable_threshold_is_refused() {
    let toml_text = one_authenticator(
        r#"[[profile]]
        id = "p"
        threshold = 5
        factor = [ { authenticator = "k", weight = 2 } ]"#,
    );
    match model(&toml_text) {
        Err(AuthorityError::Unsatisfiable {
            threshold,
            available,
            ..
        }) => {
            assert_eq!(threshold, 5);
            assert_eq!(available, 2);
        }
        other => panic!("wanted Unsatisfiable, got {other:?}"),
    }
}

#[test]
fn a_dangling_authenticator_reference_is_refused() {
    let toml_text = one_authenticator(
        r#"[[profile]]
        id = "p"
        threshold = 1
        factor = [ { authenticator = "nope", weight = 1 } ]"#,
    );
    assert!(matches!(
        model(&toml_text),
        Err(AuthorityError::DanglingAuthenticator { .. })
    ));
}

#[test]
fn a_dangling_group_reference_is_refused() {
    let toml_text = one_authenticator(
        r#"[[profile]]
        id = "p"
        threshold = 1
        factor = [ { group = "nope", weight = 1 } ]"#,
    );
    assert!(matches!(
        model(&toml_text),
        Err(AuthorityError::DanglingGroup { .. })
    ));
}

#[test]
fn a_group_cycle_is_refused() {
    // a → b → a, each referencing the other; both satisfiable in isolation.
    let toml_text = one_authenticator(
        r#"[[group]]
        id = "a"
        threshold = 1
        factor = [ { group = "b", weight = 1 } ]
        [[group]]
        id = "b"
        threshold = 1
        factor = [ { group = "a", weight = 1 } ]
        [[profile]]
        id = "p"
        threshold = 1
        factor = [ { group = "a", weight = 1 } ]"#,
    );
    assert!(matches!(
        model(&toml_text),
        Err(AuthorityError::GroupCycle { .. })
    ));
}

#[test]
fn an_unimplemented_kind_is_refused_naming_its_milestone() {
    for (kind, milestone) in [("totp", "M8a.3"), ("password", "M8a.4"), ("fido2", "M8a.5")] {
        let toml_text = format!(
            r#"
            [[authenticator]]
            id = "x"
            kind = "{kind}"
            [[profile]]
            id = "p"
            threshold = 1
            factor = [ {{ authenticator = "x", weight = 1 }} ]
            "#
        );
        match model(&toml_text) {
            Err(AuthorityError::UnimplementedKind {
                kind: k,
                milestone: m,
                ..
            }) => {
                assert_eq!(k, kind);
                assert_eq!(m, milestone);
            }
            other => panic!("wanted UnimplementedKind for {kind}, got {other:?}"),
        }
    }
}

#[test]
fn an_ed25519_without_a_public_key_is_refused() {
    let toml_text = r#"
        [[authenticator]]
        id = "k"
        kind = "ed25519"
        [[profile]]
        id = "p"
        threshold = 1
        factor = [ { authenticator = "k", weight = 1 } ]
    "#;
    assert!(matches!(
        model(toml_text),
        Err(AuthorityError::MissingMaterial { .. })
    ));
}

#[test]
fn a_bad_public_key_is_refused_at_load() {
    let toml_text = r#"
        [[authenticator]]
        id = "k"
        kind = "ed25519"
        public-key = "ssh-ed25519 not-base64"
        [[profile]]
        id = "p"
        threshold = 1
        factor = [ { authenticator = "k", weight = 1 } ]
    "#;
    assert!(matches!(
        model(toml_text),
        Err(AuthorityError::BadPublicKey { .. })
    ));
}

#[test]
fn a_wait_that_does_not_parse_is_refused() {
    let toml_text = one_authenticator(
        r#"[[profile]]
        id = "p"
        threshold = 1
        factor = [ { wait = "soon", weight = 1 } ]"#,
    );
    assert!(matches!(
        model(&toml_text),
        Err(AuthorityError::BadWait { .. })
    ));
}

#[test]
fn duplicate_ids_are_refused_per_namespace() {
    let dup_auth = format!(
        r#"
        [[authenticator]]
        id = "k"
        kind = "ed25519"
        public-key = "{ALLOWED_PUBKEY}"
        [[authenticator]]
        id = "k"
        kind = "ed25519"
        public-key = "{ALLOWED_PUBKEY}"
        [[profile]]
        id = "p"
        threshold = 1
        factor = [ {{ authenticator = "k", weight = 1 }} ]
        "#
    );
    assert!(matches!(
        model(&dup_auth),
        Err(AuthorityError::DuplicateAuthenticator(_))
    ));
}

// --- Ed25519 verify → AuthId (reusing the approval fixtures) ----------------

fn ed25519_model(id: &str, pubkey: &str) -> AuthorityModel {
    let toml_text = format!(
        r#"
        [[authenticator]]
        id = "{id}"
        kind = "ed25519"
        public-key = "{pubkey}"
        [[profile]]
        id = "p"
        threshold = 1
        factor = [ {{ authenticator = "{id}", weight = 1 }} ]
        "#
    );
    model(&toml_text).unwrap()
}

#[test]
fn a_valid_sshsig_resolves_to_its_authenticator_id() {
    let m = ed25519_model("alice", ALLOWED_PUBKEY);
    assert_eq!(
        m.verify_ed25519(&fixture_request(), SIG_GOOD).unwrap(),
        "alice"
    );
}

#[test]
fn a_signature_for_a_different_request_is_refused() {
    // Oracle self-test: the good signature does not verify over another host's
    // challenge — the binding is the challenge, enforced by the crypto.
    let m = ed25519_model("alice", ALLOWED_PUBKEY);
    let other = ApprovalRequest::new(
        [7u8; 32],
        "web-02".into(),
        3600,
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    );
    assert!(matches!(
        m.verify_ed25519(&other, SIG_GOOD),
        Err(ApprovalError::BadSignature)
    ));
}

#[test]
fn a_signature_from_an_unconfigured_key_is_refused() {
    let m = ed25519_model("alice", ALLOWED_PUBKEY);
    assert!(matches!(
        m.verify_ed25519(&fixture_request(), SIG_WRONG_KEY),
        Err(ApprovalError::UnknownApprover(_))
    ));
    // Symmetric: the good signature against a model holding only the other key.
    let only_other = ed25519_model("bob", OTHER_PUBKEY);
    assert!(matches!(
        only_other.verify_ed25519(&fixture_request(), SIG_GOOD),
        Err(ApprovalError::UnknownApprover(_))
    ));
}

#[test]
fn a_malformed_token_is_a_clean_error() {
    let m = ed25519_model("alice", ALLOWED_PUBKEY);
    assert!(matches!(
        m.verify_ed25519(&fixture_request(), "not a signature"),
        Err(ApprovalError::Malformed(_))
    ));
}
