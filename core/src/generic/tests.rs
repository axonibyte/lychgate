use super::*;

// Mutation notes: make `match_state`'s (true, true) arm return Open and
// `both_markers_matching_is_an_error_not_a_state` fails (the fail-open
// catch); make (false, false) return Closed and the neither test fails;
// return Ok(()) from forbid_placeholders and the placeholder tests fail.

#[test]
fn open_marker_alone_reads_open_and_closed_marker_alone_reads_closed() {
    assert_eq!(
        match_state("state: maint-on, uptime 4h", "maint-on", "maint-off"),
        Ok(ChannelState::Open)
    );
    assert_eq!(
        match_state("state: maint-off", "maint-on", "maint-off"),
        Ok(ChannelState::Closed)
    );
}

#[test]
fn neither_marker_matching_is_unverifiable_not_a_state() {
    assert_eq!(
        match_state("hello world", "maint-on", "maint-off"),
        Err(MatchError::Neither)
    );
}

#[test]
fn both_markers_matching_is_an_error_not_a_state() {
    // The classic footgun: closed_marker is a substring of open_marker (or the
    // body echoes both). Guessing either way could report a fail-open as
    // reverted; refusing is the only honest answer.
    assert_eq!(
        match_state("maint-on maint-off", "maint-on", "maint-off"),
        Err(MatchError::Both)
    );
    assert_eq!(
        match_state("debug_uart_enabled", "debug_uart", "debug_uart_enabled"),
        Err(MatchError::Both)
    );
}

#[test]
fn a_placeholder_run_is_refused_and_named() {
    assert_eq!(
        forbid_placeholders("turn {token} on"),
        Err(GenericTemplateError::Placeholder("token".to_string()))
    );
}

#[test]
fn json_bodies_and_shell_shapes_are_not_placeholders() {
    // The vnc scanner's definition on purpose: JSON bodies, empty braces,
    // brace expansion and ${var} pass untouched.
    for ok in [
        r#"{"debug_uart": true}"#,
        "{}",
        "{a,b}",
        "{1..3}",
        "echo ${HOME}",
        "no braces at all",
    ] {
        assert_eq!(forbid_placeholders(ok), Ok(()), "refused: {ok}");
    }
}
