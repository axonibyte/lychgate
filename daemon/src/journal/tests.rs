use super::*;
use crate::scratch::scratch_dir;

use std::time::Duration;

fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn lines(path: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("every journal line parses"))
        .collect()
}

#[test]
fn every_entry_is_a_single_well_formed_json_line() {
    let dir = scratch_dir("wellformed");
    let path = dir.join("journal.jsonl");
    let mut j = Journal::open(&path).unwrap();
    j.record(
        t(1_700_000_000),
        &Event::DaemonStart {
            inventory: "inv.toml".into(),
            hosts: 2,
        },
    )
    .unwrap();
    j.record(t(1_700_000_005), &Event::DaemonStop).unwrap();

    let entries = lines(&path);
    assert_eq!(entries.len(), 2);
    for e in &entries {
        assert!(e["ts"].is_u64());
        assert!(e["pid"].is_u64());
        assert!(e["seq"].is_u64());
        assert!(e["event"].is_string());
    }
    assert_eq!(entries[0]["ts"], 1_700_000_000_u64);
    assert_eq!(entries[0]["event"], "daemon-start");
    assert_eq!(entries[0]["hosts"], 2);
    assert_eq!(entries[1]["event"], "daemon-stop");
}

#[test]
fn entries_append_across_reopens_rather_than_rewriting() {
    let dir = scratch_dir("append");
    let path = dir.join("journal.jsonl");
    {
        let mut j = Journal::open(&path).unwrap();
        j.record(
            t(1),
            &Event::DaemonStart {
                inventory: "inv".into(),
                hosts: 0,
            },
        )
        .unwrap();
        j.record(t(2), &Event::DaemonStop).unwrap();
    }
    // A new process (simulated by reopening) must extend, never rewrite.
    let mut j = Journal::open(&path).unwrap();
    j.record(
        t(3),
        &Event::DaemonStart {
            inventory: "inv".into(),
            hosts: 0,
        },
    )
    .unwrap();

    let entries = lines(&path);
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["ts"], 1_u64);
    assert_eq!(entries[2]["ts"], 3_u64);
}

#[test]
fn sequence_numbers_count_up_from_zero_without_gaps() {
    let dir = scratch_dir("seq");
    let path = dir.join("journal.jsonl");
    let mut j = Journal::open(&path).unwrap();
    for i in 0..4 {
        j.record(t(i), &Event::DaemonStop).unwrap();
    }
    let seqs: Vec<u64> = lines(&path)
        .iter()
        .map(|e| e["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, vec![0, 1, 2, 3]);
}

#[test]
fn an_expire_entry_names_the_host_its_channels_and_both_instants() {
    let dir = scratch_dir("expire");
    let path = dir.join("journal.jsonl");
    let mut j = Journal::open(&path).unwrap();
    j.record(
        t(2_000),
        &Event::Expire {
            host: "db-01".into(),
            channels: vec![Channel::Ssh, Channel::AuthorizedKeys],
            opened_at: 1_000,
            expires_at: 1_600,
        },
    )
    .unwrap();

    let e = &lines(&path)[0];
    assert_eq!(e["event"], "expire");
    assert_eq!(e["host"], "db-01");
    // Kebab-case on the wire: the same vocabulary the inventory uses.
    assert_eq!(e["channels"], serde_json::json!(["ssh", "authorized-keys"]));
    assert_eq!(e["opened_at"], 1_000_u64);
    assert_eq!(e["expires_at"], 1_600_u64);
}

#[test]
fn a_journal_that_cannot_be_opened_is_an_error_naming_the_path() {
    let dir = scratch_dir("unopenable");
    // The "journal" is a directory, so opening it as a file must fail.
    let path = dir.join("journal.jsonl");
    std::fs::create_dir(&path).unwrap();
    let e = Journal::open(&path).expect_err("a directory is not a journal");
    assert!(e.to_string().contains("journal.jsonl"), "{e}");
}
