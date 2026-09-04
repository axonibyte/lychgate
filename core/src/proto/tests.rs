use super::*;
use crate::inventory::Inventory;
use crate::ttl::{MAX_TTL_SECS, RENEWAL_WINDOW_SECS};

use std::time::Duration;

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
        channels = ["ssh"]
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
            r#"{"proto":1,"op":"open","host":"db-01","ttl":"4h"}"#,
            Op::Open {
                host: "db-01".into(),
                ttl: "4h".into(),
            },
        ),
        (
            r#"{"proto":1,"op":"close","host":"db-01"}"#,
            Op::Close {
                host: "db-01".into(),
            },
        ),
        (
            r#"{"proto":1,"op":"renew","host":"db-01","ttl":"1h"}"#,
            Op::Renew {
                host: "db-01".into(),
                ttl: "1h".into(),
            },
        ),
        (r#"{"proto":1,"op":"status"}"#, Op::Status),
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
fn a_request_from_a_newer_protocol_is_refused_naming_both_versions() {
    let err = decode_request(r#"{"proto":2,"op":"status"}"#).unwrap_err();
    assert_eq!(err, ProtoError::VersionMismatch { theirs: 2 });
    let msg = err.to_string();
    assert!(msg.contains('2') && msg.contains('1'), "{msg}");
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
    let err = decode_request(r#"{"proto":1,"op":"status","nonce":"abc"}"#).unwrap_err();
    assert!(matches!(err, ProtoError::Malformed(_)), "{err}");
}

#[test]
fn an_op_missing_its_required_fields_is_refused_naming_the_field() {
    let cases = [
        (r#"{"proto":1,"op":"open","ttl":"4h"}"#, "host"),
        (r#"{"proto":1,"op":"open","host":"h"}"#, "ttl"),
        (r#"{"proto":1,"op":"close"}"#, "host"),
        (r#"{"proto":1,"op":"renew","host":"h"}"#, "ttl"),
    ];
    for (line, field) in cases {
        let err = decode_request(line).unwrap_err();
        assert!(err.to_string().contains(field), "{line}: {err}");
    }
}

#[test]
fn an_unknown_op_is_refused_by_name() {
    let err = decode_request(r#"{"proto":1,"op":"detonate"}"#).unwrap_err();
    assert_eq!(err, ProtoError::UnknownOp("detonate".into()));
    assert!(err.to_string().contains("detonate"));
}

#[test]
fn a_request_over_the_line_cap_is_refused_unread() {
    let line = format!(
        r#"{{"proto":1,"op":"open","host":"{}","ttl":"1h"}}"#,
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

// --- the contract table: op x state -> response + transition ---------------

#[test]
fn the_apply_contract_holds_for_every_op_against_every_grant_state() {
    // Rows: (label, state-setup, op, expected response fragments, expected
    // transition). now is t(0) for closed-state rows; open rows opened at
    // t(0) with a 4h ttl and are observed at the row's `now`.
    let ttl_4h = "4h";
    let open_expiry = 4 * 3600;

    struct Row {
        label: &'static str,
        opened: bool,
        now: u64,
        op: Op,
        want_result: ResponseResult,
        want_error_contains: Option<&'static str>,
        want_expires_at: Option<u64>,
        want_outcome: Option<&'static str>,
        want_transition: bool,
    }

    let rows = [
        Row {
            label: "open a closed grant",
            opened: false,
            now: 0,
            op: Op::Open {
                host: "db-01".into(),
                ttl: ttl_4h.into(),
            },
            want_result: ResponseResult::Ok,
            want_error_contains: None,
            want_expires_at: Some(open_expiry),
            want_outcome: None,
            want_transition: true,
        },
        Row {
            label: "open an open grant",
            opened: true,
            now: 60,
            op: Op::Open {
                host: "db-01".into(),
                ttl: ttl_4h.into(),
            },
            want_result: ResponseResult::Refused,
            want_error_contains: Some("already open"),
            want_expires_at: None,
            want_outcome: None,
            want_transition: false,
        },
        Row {
            label: "open with an over-cap ttl",
            opened: false,
            now: 0,
            op: Op::Open {
                host: "db-01".into(),
                ttl: "25h".into(),
            },
            want_result: ResponseResult::Refused,
            want_error_contains: Some("cap"),
            want_expires_at: None,
            want_outcome: None,
            want_transition: false,
        },
        Row {
            label: "open an unknown host",
            opened: false,
            now: 0,
            op: Op::Open {
                host: "ghost".into(),
                ttl: ttl_4h.into(),
            },
            want_result: ResponseResult::Refused,
            want_error_contains: Some("ghost"),
            want_expires_at: None,
            want_outcome: None,
            want_transition: false,
        },
        Row {
            label: "renew inside the window",
            opened: true,
            // 4h grant observed with 1h remaining: inside the 2h window.
            now: open_expiry - 3600,
            op: Op::Renew {
                host: "db-01".into(),
                ttl: ttl_4h.into(),
            },
            want_result: ResponseResult::Ok,
            want_error_contains: None,
            want_expires_at: Some(open_expiry - 3600 + open_expiry),
            want_outcome: None,
            want_transition: true,
        },
        Row {
            label: "renew too early",
            opened: true,
            now: 60,
            op: Op::Renew {
                host: "db-01".into(),
                ttl: ttl_4h.into(),
            },
            want_result: ResponseResult::Refused,
            want_error_contains: Some("renewal"),
            want_expires_at: None,
            want_outcome: None,
            want_transition: false,
        },
        Row {
            label: "renew a closed grant",
            opened: false,
            now: 0,
            op: Op::Renew {
                host: "db-01".into(),
                ttl: ttl_4h.into(),
            },
            want_result: ResponseResult::Refused,
            want_error_contains: Some("not open"),
            want_expires_at: None,
            want_outcome: None,
            want_transition: false,
        },
        Row {
            label: "close an open grant",
            opened: true,
            now: 60,
            op: Op::Close {
                host: "db-01".into(),
            },
            want_result: ResponseResult::Ok,
            want_error_contains: None,
            want_expires_at: None,
            want_outcome: Some("was-open"),
            want_transition: true,
        },
        Row {
            label: "close a closed grant",
            opened: false,
            now: 0,
            op: Op::Close {
                host: "db-01".into(),
            },
            want_result: ResponseResult::Ok,
            want_error_contains: None,
            want_expires_at: None,
            want_outcome: Some("already-closed"),
            want_transition: false,
        },
        Row {
            label: "close an unknown host",
            opened: false,
            now: 0,
            op: Op::Close {
                host: "ghost".into(),
            },
            want_result: ResponseResult::Refused,
            want_error_contains: Some("ghost"),
            want_expires_at: None,
            want_outcome: None,
            want_transition: false,
        },
    ];

    let inv = inventory();
    for row in rows {
        let mut reg = GrantRegistry::new(&inv);
        if row.opened {
            reg.open("db-01", t(0), &Ttl::from_secs(4 * 3600).unwrap())
                .unwrap();
        }
        let (resp, transition) = apply(&mut reg, &row.op, t(row.now));
        assert_eq!(resp.result, row.want_result, "{}", row.label);
        assert_eq!(resp.proto, PROTO_VERSION, "{}", row.label);
        match row.want_error_contains {
            Some(needle) => {
                let e = resp.error.as_deref().unwrap_or("");
                assert!(e.contains(needle), "{}: error {e:?}", row.label);
            }
            None => assert_eq!(resp.error, None, "{}", row.label),
        }
        assert_eq!(resp.expires_at, row.want_expires_at, "{}", row.label);
        assert_eq!(resp.outcome.as_deref(), row.want_outcome, "{}", row.label);
        assert_eq!(transition.is_some(), row.want_transition, "{}", row.label);
    }
}

#[test]
fn status_reports_every_host_with_state_and_remaining_time() {
    let inv = Inventory::parse(
        r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "freebsd"
        channels = ["ssh"]

        [[hosts]]
        name = "web-02"
        address = "10.0.4.12"
        os = "linux"
        channels = ["vnc"]
        "#,
    )
    .unwrap();
    let mut reg = GrantRegistry::new(&inv);
    reg.open("db-01", t(0), &Ttl::from_secs(600).unwrap())
        .unwrap();

    let (resp, transition) = apply(&mut reg, &Op::Status, t(100));
    assert_eq!(transition, None, "status is never a transition");
    assert_eq!(
        resp.grants,
        Some(vec![
            GrantLine {
                host: "db-01".into(),
                state: GrantState::Open,
                remaining_secs: Some(500),
            },
            GrantLine {
                host: "web-02".into(),
                state: GrantState::Closed,
                remaining_secs: None,
            },
        ])
    );

    // And an expired-but-unreaped grant reads as expired, not open.
    let (resp, _) = apply(&mut reg, &Op::Status, t(9_999));
    assert_eq!(resp.grants.unwrap()[0].state, GrantState::Expired);
}

#[test]
fn open_transitions_carry_the_ttl_and_expiry_the_journal_needs() {
    let inv = inventory();
    let mut reg = GrantRegistry::new(&inv);
    let (_, transition) = apply(
        &mut reg,
        &Op::Open {
            host: "db-01".into(),
            ttl: "2h".into(),
        },
        t(1_000),
    );
    assert_eq!(
        transition,
        Some(Transition::Opened {
            host: "db-01".into(),
            ttl_secs: 2 * 3600,
            expires_at: t(1_000 + 2 * 3600),
        })
    );
}

#[test]
fn renew_transitions_carry_the_new_expiry_anchored_at_now() {
    let inv = inventory();
    let mut reg = GrantRegistry::new(&inv);
    reg.open("db-01", t(0), &Ttl::from_secs(4 * 3600).unwrap())
        .unwrap();
    let now = t(4 * 3600 - 60); // one minute before expiry: inside the window
    let (_, transition) = apply(
        &mut reg,
        &Op::Renew {
            host: "db-01".into(),
            ttl: "2h".into(),
        },
        now,
    );
    assert_eq!(
        transition,
        Some(Transition::Renewed {
            host: "db-01".into(),
            ttl_secs: 2 * 3600,
            expires_at: now + Duration::from_secs(2 * 3600),
        })
    );
}

#[test]
fn responses_round_trip_through_their_wire_form() {
    let resp = Response {
        expires_at: Some(1_700_000_000),
        ..Response::refused("nope")
    };
    let decoded = Response::decode(&resp.encode()).unwrap();
    assert_eq!(decoded, resp);
    // Refusal text passes through verbatim: the operator reads core's words.
    assert_eq!(decoded.error.as_deref(), Some("nope"));
}

#[test]
fn ttl_policy_errors_reach_the_wire_verbatim() {
    let inv = inventory();
    let mut reg = GrantRegistry::new(&inv);
    let (resp, _) = apply(
        &mut reg,
        &Op::Open {
            host: "db-01".into(),
            ttl: "25h".into(),
        },
        t(0),
    );
    let want = Ttl::parse("25h").unwrap_err().to_string();
    assert_eq!(resp.error.as_deref(), Some(want.as_str()));
    // The cap constant really is in that text (guards a silent rewording
    // that drops the number an operator needs).
    assert!(want.contains(&MAX_TTL_SECS.to_string()));
    let _ = RENEWAL_WINDOW_SECS; // window text is asserted in the table row
}
