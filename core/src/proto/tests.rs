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
        channels = ["ssh", "bmc"]

        [[hosts]]
        name = "web-02"
        address = "10.0.4.12"
        os = "linux"
        channels = ["vnc"]
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
            r#"{"proto":2,"op":"open","host":"db-01","ttl":"4h"}"#,
            Op::Open {
                host: "db-01".into(),
                ttl: "4h".into(),
            },
        ),
        (
            r#"{"proto":2,"op":"close","host":"db-01"}"#,
            Op::Close {
                host: "db-01".into(),
            },
        ),
        (
            r#"{"proto":2,"op":"renew","host":"db-01","ttl":"1h"}"#,
            Op::Renew {
                host: "db-01".into(),
                ttl: "1h".into(),
            },
        ),
        (r#"{"proto":2,"op":"status"}"#, Op::Status),
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
    for theirs in [1u32, 3, 9] {
        let line = format!(r#"{{"proto":{theirs},"op":"status"}}"#);
        let err = decode_request(&line).unwrap_err();
        assert_eq!(err, ProtoError::VersionMismatch { theirs });
        let msg = err.to_string();
        assert!(
            msg.contains(&theirs.to_string()) && msg.contains('2'),
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
    let err = decode_request(r#"{"proto":2,"op":"status","nonce":"abc"}"#).unwrap_err();
    assert!(matches!(err, ProtoError::Malformed(_)), "{err}");
}

#[test]
fn an_op_missing_its_required_fields_is_refused_naming_the_field() {
    let cases = [
        (r#"{"proto":2,"op":"open","ttl":"4h"}"#, "host"),
        (r#"{"proto":2,"op":"open","host":"h"}"#, "ttl"),
        (r#"{"proto":2,"op":"close"}"#, "host"),
        (r#"{"proto":2,"op":"renew","host":"h"}"#, "ttl"),
    ];
    for (line, field) in cases {
        let err = decode_request(line).unwrap_err();
        assert!(err.to_string().contains(field), "{line}: {err}");
    }
}

#[test]
fn an_unknown_op_is_refused_by_name() {
    let err = decode_request(r#"{"proto":2,"op":"detonate"}"#).unwrap_err();
    assert_eq!(err, ProtoError::UnknownOp("detonate".into()));
    assert!(err.to_string().contains("detonate"));
}

#[test]
fn a_request_over_the_line_cap_is_refused_unread() {
    let line = format!(
        r#"{{"proto":2,"op":"open","host":"{}","ttl":"1h"}}"#,
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
    assert_eq!(v["proto"], 2);
}
