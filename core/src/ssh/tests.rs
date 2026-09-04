use super::*;

// --- posture vocabulary ----------------------------------------------------

#[test]
fn posture_tokens_round_trip_and_accept_the_legacy_spelling() {
    for (posture, token) in [
        (Posture::No, "no"),
        (Posture::ProhibitPassword, "prohibit-password"),
        (Posture::Yes, "yes"),
    ] {
        assert_eq!(posture.sshd_token(), token);
        assert_eq!(Posture::from_sshd_token(token), Some(posture));
    }
    // Older sshd vocabulary for the same setting.
    assert_eq!(
        Posture::from_sshd_token("without-password"),
        Some(Posture::ProhibitPassword)
    );
    assert_eq!(Posture::from_sshd_token("maybe"), None);
}

#[test]
fn the_dropin_names_its_owner_and_sets_exactly_one_directive() {
    let dropin = render_dropin(Posture::ProhibitPassword);
    assert!(dropin.contains("Managed by lychgated"), "{dropin}");
    let directives: Vec<&str> = dropin
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .collect();
    assert_eq!(directives, ["PermitRootLogin prohibit-password"]);
    assert!(dropin.ends_with('\n'));
}

#[test]
fn effective_posture_is_read_from_sshd_t_output() {
    let output =
        "port 22\naddressfamily any\npermitrootlogin prohibit-password\nsyslogfacility AUTH\n";
    assert_eq!(
        parse_effective_posture(output),
        Some(Posture::ProhibitPassword)
    );
    // sshd -T uses lowercase keys; a config-style mixed-case line also reads.
    assert_eq!(
        parse_effective_posture("PermitRootLogin yes\n"),
        Some(Posture::Yes)
    );
    // Absent or unparseable: None, never a guess.
    assert_eq!(parse_effective_posture("port 22\n"), None);
    assert_eq!(parse_effective_posture("permitrootlogin sometimes\n"), None);
    // A key that merely contains the word must not match.
    assert_eq!(parse_effective_posture("xpermitrootloginx yes\n"), None);
}

// --- fence: the contract ---------------------------------------------------

const HUMAN_KEYS: &str = "\
ssh-ed25519 AAAAC3Nza human@laptop
# a comment a human left
ssh-rsa AAAB3N backup@nas
";

fn keys(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn upsert_into_a_file_with_no_fence_appends_the_block_and_preserves_every_human_byte() {
    let out = fence_upsert(HUMAN_KEYS, &keys(&["ssh-ed25519 EMERG claude-breakglass"])).unwrap();
    assert!(out.starts_with(HUMAN_KEYS), "human bytes changed:\n{out}");
    assert!(out.contains(FENCE_BEGIN));
    assert!(out.contains("ssh-ed25519 EMERG claude-breakglass"));
    assert!(out.ends_with(&format!("{FENCE_END}\n")));
}

#[test]
fn upsert_over_an_existing_fence_replaces_only_the_block() {
    let first = fence_upsert(HUMAN_KEYS, &keys(&["key-one A"])).unwrap();
    let second = fence_upsert(&first, &keys(&["key-two B"])).unwrap();
    assert!(second.starts_with(HUMAN_KEYS), "human bytes changed");
    assert!(second.contains("key-two B"));
    assert!(!second.contains("key-one A"), "old fence content survived");
    // Exactly one fence.
    assert_eq!(second.matches(FENCE_BEGIN).count(), 1);
}

#[test]
fn upsert_preserves_human_keys_that_follow_the_fence() {
    let fenced = fence_upsert("top@key A\n", &keys(&["emerg B"])).unwrap();
    let with_tail = format!("{fenced}late-addition C\n");
    let updated = fence_upsert(&with_tail, &keys(&["emerg D"])).unwrap();
    assert!(updated.contains("top@key A"));
    assert!(updated.contains("late-addition C"));
    assert!(updated.contains("emerg D"));
    assert!(!updated.contains("emerg B"));
}

#[test]
fn remove_strips_the_block_wholly_and_only_the_block() {
    let fenced = fence_upsert(HUMAN_KEYS, &keys(&["emerg X"])).unwrap();
    let removed = fence_remove(&fenced).unwrap();
    assert_eq!(
        removed, HUMAN_KEYS,
        "close must restore the file byte-for-byte"
    );
}

#[test]
fn removing_from_a_file_with_no_fence_changes_nothing() {
    assert_eq!(fence_remove(HUMAN_KEYS).unwrap(), HUMAN_KEYS);
    assert_eq!(fence_remove("").unwrap(), "");
}

#[test]
fn a_fence_that_filled_the_whole_file_removes_to_empty() {
    let fenced = fence_upsert("", &keys(&["only key"])).unwrap();
    assert_eq!(fence_remove(&fenced).unwrap(), "");
}

#[test]
fn malformed_fences_are_refused_rather_than_clobbered() {
    let cases = [
        (format!("{FENCE_BEGIN}\nkey\n"), "without END"),
        (format!("key\n{FENCE_END}\n"), "without BEGIN"),
        (format!("{FENCE_END}\n{FENCE_BEGIN}\n"), "precedes"),
        (
            format!("{FENCE_BEGIN}\n{FENCE_END}\n{FENCE_BEGIN}\n{FENCE_END}\n"),
            "duplicated",
        ),
    ];
    for (file, needle) in cases {
        for result in [
            fence_upsert(&file, &keys(&["k A"])).map(|_| ()),
            fence_remove(&file).map(|_| ()),
        ] {
            let err = result.expect_err(&format!("{file:?} must be refused"));
            assert!(err.to_string().contains(needle), "{file:?}: {err}");
            assert!(err.to_string().contains("refusing"), "{err}");
        }
    }
}

// --- fence: the hostile corpus ---------------------------------------------

#[test]
fn a_key_comment_that_merely_contains_marker_like_text_is_not_a_marker() {
    // Markers match whole lines only; a substring in a comment is a key line
    // like any other.
    let sneaky = "ssh-ed25519 AAA note-about-LYCHGATE-BEGIN-style-markers human@x\n";
    // ...but as an *emergency key* it is refused (it could later be mistaken
    // for fence content by a human); as an existing human line it is
    // preserved untouched.
    let out = fence_upsert(sneaky, &keys(&["emerg K"])).unwrap();
    assert!(out.starts_with(sneaky));
    let removed = fence_remove(&out).unwrap();
    assert_eq!(removed, sneaky);
}

#[test]
fn emergency_keys_with_line_breaks_marker_text_or_nothing_are_refused() {
    for bad in [
        "two\nlines",
        "carriage\rreturn",
        "",
        "   ",
        "key with LYCHGATE inside",
    ] {
        let err = fence_upsert("", &keys(&[bad])).unwrap_err();
        assert!(matches!(err, FenceError::BadKey { .. }), "{bad:?}: {err}");
    }
}

#[test]
fn astral_plane_text_in_key_comments_survives_the_round_trip() {
    let file = "ssh-ed25519 AAA 𝔥𝔲𝔪𝔞𝔫@𝖑𝖆𝖕𝖙𝖔𝖕 🗝️\n";
    let fenced = fence_upsert(file, &keys(&["emerg 🚨 café"])).unwrap();
    assert!(fenced.contains("𝔥𝔲𝔪𝔞𝔫@𝖑𝖆𝖕𝖙𝖔𝖕 🗝️"));
    assert!(fenced.contains("emerg 🚨 café"));
    assert_eq!(fence_remove(&fenced).unwrap(), file);
}

#[test]
fn a_file_without_a_trailing_newline_still_round_trips_its_content() {
    let file = "no-trailing-newline@key A";
    let fenced = fence_upsert(file, &keys(&["emerg B"])).unwrap();
    assert!(fenced.contains("no-trailing-newline@key A"));
    let removed = fence_remove(&fenced).unwrap();
    // Content preserved; the file is normalized to end with a newline (the
    // one byte-level change the fence round trip may make, stated here).
    assert_eq!(removed, "no-trailing-newline@key A\n");
}
