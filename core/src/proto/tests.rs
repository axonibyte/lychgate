use super::*;
use crate::inventory::Inventory;
use crate::ttl::Ttl;

use std::time::{Duration, UNIX_EPOCH};

fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn inventory() -> Inventory {
    Inventory::parse(
        r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "freebsd"
        channels = ["vnc"]

        [hosts.vnc]
        agent_user = "lychgate"
        rfb_port = 5900
        local_port = 5959
        target = "db"
        set_password_cmd = "set {target} {password_file}"
        clear_password_cmd = "clear {target}"

        [[hosts]]
        name = "web-02"
        address = "10.0.4.12"
        os = "linux"
        channels = ["vnc"]

        [hosts.vnc]
        agent_user = "lychgate"
        rfb_port = 5900
        local_port = 5960
        target = "web"
        set_password_cmd = "set {target} {password_file}"
        clear_password_cmd = "clear {target}"
        "#,
    )
    .expect("test inventory is legal")
}

// --- decoding --------------------------------------------------------------

#[test]
fn every_wire_op_decodes_to_its_variant() {
    // The wire vocabulary, spelled out rather than round-tripped through
    // encode_request: the duplication is the check.
    let cases = [
        (
            r#"{"proto":4,"op":"open","host":"db-01","ttl":"4h"}"#,
            Op::Open {
                host: "db-01".into(),
                ttl: "4h".into(),
                profile: None,
            },
        ),
        (
            r#"{"proto":4,"op":"close","host":"db-01"}"#,
            Op::Close {
                host: "db-01".into(),
            },
        ),
        (
            r#"{"proto":4,"op":"renew","host":"db-01","ttl":"1h"}"#,
            Op::Renew {
                host: "db-01".into(),
                ttl: "1h".into(),
            },
        ),
        (r#"{"proto":4,"op":"status"}"#, Op::Status),
    ];
    for (line, want) in cases {
        assert_eq!(decode_request(line).unwrap(), want, "{line}");
    }
}

#[test]
fn encoded_requests_decode_back_to_the_same_op() {
    for op in [
        Op::Open {
            host: "db-01".into(),
            ttl: "4h".into(),
            profile: None,
        },
        Op::Close {
            host: "db-01".into(),
        },
        Op::Renew {
            host: "db-01".into(),
            ttl: "1h".into(),
        },
        Op::Status,
    ] {
        assert_eq!(decode_request(&encode_request(&op)).unwrap(), op);
    }
}

#[test]
fn a_request_from_any_other_protocol_version_is_refused_naming_both() {
    // v1 requests are refused too: the v2 vocabulary (new grant states)
    // means a v1 speaker would misread responses.
    for theirs in [1u32, 2, 9] {
        let line = format!(r#"{{"proto":{theirs},"op":"status"}}"#);
        let err = decode_request(&line).unwrap_err();
        assert_eq!(err, ProtoError::VersionMismatch { theirs });
        let msg = err.to_string();
        assert!(
            msg.contains(&theirs.to_string()) && msg.contains('4'),
            "{msg}"
        );
    }
}

#[test]
fn a_request_without_a_version_is_refused_rather_than_assumed_current() {
    let err = decode_request(r#"{"op":"status"}"#).unwrap_err();
    assert!(matches!(err, ProtoError::Malformed(_)));
    assert!(err.to_string().contains("proto"), "{err}");
}

#[test]
fn the_version_refusal_wins_over_unknown_field_refusals() {
    // A newer protocol may carry fields this decoder refuses; the sender
    // needs "wrong version", not "unknown field".
    let err = decode_request(r#"{"proto":9,"op":"open","host":"h","ttl":"1h","nonce":"abc"}"#)
        .unwrap_err();
    assert_eq!(err, ProtoError::VersionMismatch { theirs: 9 });
}

#[test]
fn an_unknown_field_on_the_current_protocol_is_refused_rather_than_ignored() {
    let err = decode_request(r#"{"proto":4,"op":"status","nonce":"abc"}"#).unwrap_err();
    assert!(matches!(err, ProtoError::Malformed(_)), "{err}");
}

#[test]
fn an_op_missing_its_required_fields_is_refused_naming_the_field() {
    let cases = [
        (r#"{"proto":4,"op":"open","ttl":"4h"}"#, "host"),
        (r#"{"proto":4,"op":"open","host":"h"}"#, "ttl"),
        (r#"{"proto":4,"op":"close"}"#, "host"),
        (r#"{"proto":4,"op":"renew","host":"h"}"#, "ttl"),
    ];
    for (line, field) in cases {
        let err = decode_request(line).unwrap_err();
        assert!(err.to_string().contains(field), "{line}: {err}");
    }
}

#[test]
fn an_unknown_op_is_refused_by_name() {
    let err = decode_request(r#"{"proto":4,"op":"detonate"}"#).unwrap_err();
    assert_eq!(err, ProtoError::UnknownOp("detonate".into()));
    assert!(err.to_string().contains("detonate"));
}

#[test]
fn a_request_over_the_line_cap_is_refused_unread() {
    let line = format!(
        r#"{{"proto":4,"op":"open","host":"{}","ttl":"1h"}}"#,
        "x".repeat(MAX_LINE_BYTES)
    );
    let err = decode_request(&line).unwrap_err();
    assert!(matches!(err, ProtoError::TooLarge { .. }), "{err}");
}

#[test]
fn non_json_input_is_a_malformed_refusal_not_a_panic() {
    for line in ["", "{", "null", "[1,2]", "\"open\"", "{\"proto\":\"one\"}"] {
        let err = decode_request(line).unwrap_err();
        assert!(!err.to_string().is_empty(), "{line:?}");
    }
}

// --- status rendering ------------------------------------------------------

#[test]
fn status_lines_render_every_lifecycle_state_with_its_fields() {
    let inv = inventory();
    let mut reg = GrantRegistry::new(&inv);
    let ttl = Ttl::from_secs(600).unwrap();
    reg.begin_open("db-01", t(0), &ttl, vec![Channel::Ssh, Channel::Bmc])
        .unwrap();

    // Opening.
    assert_eq!(
        status_lines(&reg, t(100))[0],
        GrantLine {
            host: "db-01".into(),
            state: GrantState::Opening,
            remaining_secs: None,
            stuck_channels: None,
        }
    );

    // Open, with remaining time; web-02 closed alongside.
    reg.finish_open("db-01").unwrap();
    let lines = status_lines(&reg, t(100));
    assert_eq!(
        lines,
        vec![
            GrantLine {
                host: "db-01".into(),
                state: GrantState::Open,
                remaining_secs: Some(500),
                stuck_channels: None,
            },
            GrantLine {
                host: "web-02".into(),
                state: GrantState::Closed,
                remaining_secs: None,
                stuck_channels: None,
            },
        ]
    );

    // Expired.
    assert_eq!(status_lines(&reg, t(9_999))[0].state, GrantState::Expired);

    // NeedsRevert carries its stuck channels.
    reg.begin_revert("db-01", t(9_999)).unwrap();
    reg.retain_stuck("db-01", vec![Channel::Bmc]).unwrap();
    let line = &status_lines(&reg, t(9_999))[0];
    assert_eq!(line.state, GrantState::NeedsRevert);
    assert_eq!(line.stuck_channels, Some(vec![Channel::Bmc]));
}

#[test]
fn wire_state_names_are_kebab_case() {
    // Spelled out deliberately: the CLI and any future client parse these.
    let line = GrantLine {
        host: "h".into(),
        state: GrantState::NeedsRevert,
        remaining_secs: None,
        stuck_channels: Some(vec![Channel::AuthorizedKeys]),
    };
    assert_eq!(
        serde_json::to_string(&line).unwrap(),
        r#"{"host":"h","state":"needs-revert","stuck_channels":["authorized-keys"]}"#
    );
}

// --- responses -------------------------------------------------------------

#[test]
fn responses_round_trip_through_their_wire_form() {
    let resp = Response {
        expires_at: Some(1_700_000_000),
        ..Response::refused("nope")
    };
    let decoded = Response::decode(&resp.encode()).unwrap();
    assert_eq!(decoded, resp);
    // Refusal text passes through verbatim: the operator reads the daemon's
    // words.
    assert_eq!(decoded.error.as_deref(), Some("nope"));
}

#[test]
fn responses_carry_the_current_protocol_version() {
    let ok = Response {
        outcome: Some("closed".into()),
        ..Response::refused("x")
    };
    let v: serde_json::Value = serde_json::from_str(&ok.encode()).unwrap();
    assert_eq!(v["proto"], 4);
}

#[test]
fn a_response_secret_label_round_trips_and_is_omitted_when_absent() {
    let mut r = Response::ok();
    r.secret = Some("pw".to_string());
    r.secret_label = Some("one-time VNC password".to_string());
    let line = r.encode();
    assert!(
        line.contains("\"secret_label\":\"one-time VNC password\""),
        "{line}"
    );
    assert_eq!(
        Response::decode(&line).unwrap().secret_label.as_deref(),
        Some("one-time VNC password")
    );

    // Absent by default: the field must not appear, so a daemon that never
    // sets it prints exactly as before (the bmc acceptance greps that line).
    assert!(!Response::ok().encode().contains("secret_label"));
}

// --- approve op + approval status states (M8) ------------------------------

#[test]
fn the_protocol_version_is_four() {
    assert_eq!(PROTO_VERSION, 4);
}

#[test]
fn approve_decodes_with_host_and_token_and_round_trips() {
    let line = r#"{"proto":4,"op":"approve","host":"db-01","token":"lg1.sig"}"#;
    assert_eq!(
        decode_request(line).unwrap(),
        Op::Approve {
            host: "db-01".into(),
            token: "lg1.sig".into()
        }
    );
    let op = Op::Approve {
        host: "db-01".into(),
        token: "tok".into(),
    };
    assert_eq!(decode_request(&encode_request(&op)).unwrap(), op);
}

#[test]
fn approve_missing_host_or_token_is_refused_naming_the_field() {
    let no_token = decode_request(r#"{"proto":4,"op":"approve","host":"h"}"#).unwrap_err();
    assert!(no_token.to_string().contains("token"), "{no_token}");
    let no_host = decode_request(r#"{"proto":4,"op":"approve","token":"t"}"#).unwrap_err();
    assert!(no_host.to_string().contains("host"), "{no_host}");
}

#[test]
fn the_new_status_states_use_kebab_case_names_and_round_trip() {
    for (state, name) in [
        (GrantState::AwaitingApproval, "awaiting-approval"),
        (GrantState::ApprovalExpired, "approval-expired"),
    ] {
        let line = GrantLine {
            host: "h".into(),
            state: state.clone(),
            remaining_secs: None,
            stuck_channels: None,
        };
        let json = serde_json::to_string(&line).unwrap();
        assert!(json.contains(name), "{json}");
        assert_eq!(
            serde_json::from_str::<GrantLine>(&json).unwrap().state,
            state
        );
    }
}
