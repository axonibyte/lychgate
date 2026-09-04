use super::*;

#[test]
fn a_ttl_of_zero_seconds_is_rejected() {
    assert_eq!(Ttl::from_secs(0), Err(TtlError::Zero));
}

#[test]
fn a_ttl_at_the_cap_is_accepted() {
    let ttl = Ttl::from_secs(MAX_TTL_SECS).expect("the cap itself is legal");
    assert_eq!(ttl.duration(), Duration::from_secs(MAX_TTL_SECS));
}

#[test]
fn a_ttl_one_second_over_the_cap_is_rejected() {
    assert_eq!(
        Ttl::from_secs(MAX_TTL_SECS + 1),
        Err(TtlError::ExceedsCap {
            secs: MAX_TTL_SECS + 1
        })
    );
}

#[test]
fn a_ttl_string_with_hours_minutes_or_seconds_units_parses_to_the_right_duration() {
    assert_eq!(
        Ttl::parse("90s").unwrap().duration(),
        Duration::from_secs(90)
    );
    assert_eq!(
        Ttl::parse("15m").unwrap().duration(),
        Duration::from_secs(15 * 60)
    );
    assert_eq!(
        Ttl::parse("2h").unwrap().duration(),
        Duration::from_secs(2 * 60 * 60)
    );
}

#[test]
fn a_ttl_string_without_a_unit_is_rejected_rather_than_defaulted() {
    assert_eq!(Ttl::parse("90"), Err(TtlError::Unparseable("90".into())));
}

#[test]
fn an_empty_ttl_string_is_rejected() {
    assert_eq!(Ttl::parse(""), Err(TtlError::Unparseable("".into())));
}

#[test]
fn a_bare_unit_with_no_count_is_rejected() {
    assert_eq!(Ttl::parse("h"), Err(TtlError::Unparseable("h".into())));
}

#[test]
fn a_negative_ttl_string_is_rejected() {
    assert_eq!(Ttl::parse("-5m"), Err(TtlError::Unparseable("-5m".into())));
}

#[test]
fn a_ttl_string_ending_in_a_multibyte_character_is_rejected_rather_than_panicking() {
    assert_eq!(Ttl::parse("5é"), Err(TtlError::Unparseable("5é".into())));
}

#[test]
fn a_ttl_whose_seconds_would_overflow_is_rejected_rather_than_wrapped() {
    // u64::MAX hours cannot be represented in seconds; wrapping would turn it
    // into a small, legal-looking TTL.
    assert_eq!(Ttl::parse("18446744073709551615h"), Err(TtlError::Overflow));
}

#[test]
fn a_ttl_over_the_cap_is_rejected_through_the_string_form_too() {
    assert_eq!(
        Ttl::parse("25h"),
        Err(TtlError::ExceedsCap { secs: 25 * 60 * 60 })
    );
}
