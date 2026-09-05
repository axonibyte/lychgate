use super::*;

#[test]
fn a_secret_never_reveals_itself_through_debug_or_display() {
    let s = Secret::new("hunter2-the-real-password".to_string());
    assert_eq!(format!("{s:?}"), "Secret(redacted)");
    assert_eq!(format!("{s}"), "<redacted>");
    // The genuine bytes are only reachable through reveal().
    assert_eq!(s.reveal(), "hunter2-the-real-password");
}

#[test]
fn generated_passwords_use_only_the_safe_alphabet_and_the_full_length() {
    // Every byte value maps into the alphabet; the length matches the input.
    let bytes: Vec<u8> = (0..=255u8).collect();
    let secret = password_from_bytes(&bytes);
    assert_eq!(secret.reveal().len(), 256);
    for c in secret.reveal().bytes() {
        assert!(
            PASSWORD_ALPHABET.contains(&c),
            "char {:?} is outside the alphabet",
            c as char
        );
    }
    // The alphabet excludes the visually ambiguous 0/O/1/I/l and every
    // character that could break out of a JSON string or a shell word.
    for bad in br#""\'`$ 0O1lI"# {
        assert!(
            !PASSWORD_ALPHABET.contains(bad),
            "{:?} should be excluded",
            *bad as char
        );
    }
}

#[test]
fn the_account_path_names_the_slot() {
    assert_eq!(account_path("3"), "/redfish/v1/AccountService/Accounts/3");
}

#[test]
fn the_enable_body_sets_username_password_and_enabled_together() {
    let secret = Secret::new("s3cr3t-value".to_string());
    let body = enable_body("breakglass", &secret);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["UserName"], "breakglass");
    assert_eq!(v["Password"], "s3cr3t-value");
    assert_eq!(v["Enabled"], true);
    // Exactly those three fields — nothing extra leaks in.
    assert_eq!(v.as_object().unwrap().len(), 3);
}

#[test]
fn the_disable_body_touches_only_enabled() {
    let v: serde_json::Value = serde_json::from_str(&disable_body()).unwrap();
    assert_eq!(v["Enabled"], false);
    assert_eq!(v.as_object().unwrap().len(), 1);
    // The password is never in a disable body.
    assert!(v.get("Password").is_none());
}

#[test]
fn an_enabled_account_for_the_right_user_parses_as_enabled() {
    let body = r#"{"UserName":"breakglass","Enabled":true,"RoleId":"Administrator"}"#;
    assert_eq!(
        parse_account(body, "breakglass").unwrap(),
        AccountState::Enabled
    );
}

#[test]
fn a_disabled_account_parses_as_disabled() {
    let body = r#"{"UserName":"breakglass","Enabled":false}"#;
    assert_eq!(
        parse_account(body, "breakglass").unwrap(),
        AccountState::Disabled
    );
}

#[test]
fn an_empty_slot_is_claimable_by_the_expected_user() {
    // A fresh iDRAC slot has an empty UserName; a first open may take it.
    let body = r#"{"UserName":"","Enabled":false}"#;
    assert_eq!(
        parse_account(body, "breakglass").unwrap(),
        AccountState::Disabled
    );
}

#[test]
fn a_slot_held_by_a_different_user_is_refused_rather_than_hijacked() {
    let body = r#"{"UserName":"root","Enabled":true}"#;
    assert_eq!(
        parse_account(body, "breakglass"),
        Err(BmcError::WrongAccount {
            expected: "breakglass".into(),
            found: "root".into()
        })
    );
}

#[test]
fn a_response_without_a_boolean_enabled_is_unparseable() {
    for body in [
        r#"{"UserName":"breakglass"}"#, // no Enabled
        r#"{"Enabled":"true"}"#,        // Enabled is a string
        r#"not json at all"#,
        r#"[]"#,
    ] {
        assert!(
            matches!(
                parse_account(body, "breakglass"),
                Err(BmcError::Unparseable(_))
            ),
            "{body:?} should be unparseable"
        );
    }
}

#[test]
fn parse_account_never_panics_on_arbitrary_input() {
    // The response arrives from a BMC over the network: hostile by default.
    for body in ["", "{", "\u{0}", "{\"Enabled\":null}", "{\"Enabled\":1}"] {
        let _ = parse_account(body, "breakglass");
    }
}

#[test]
fn generate_len_defaults_to_delegating_to_generate() {
    // The bmc generator is fixed-length: the default generate_len ignores the
    // requested length. (The vnc generator overrides this; proven there.)
    struct Fixed;
    impl PasswordGen for Fixed {
        fn generate(&mut self) -> Secret {
            Secret::new("FIXED".to_string())
        }
    }
    let mut g = Fixed;
    assert_eq!(g.generate_len(4).reveal(), "FIXED");
    assert_eq!(g.generate_len(64).reveal(), "FIXED");
}
