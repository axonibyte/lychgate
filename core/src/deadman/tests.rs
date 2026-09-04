use super::*;
use crate::inventory::Inventory;

use std::time::Duration;

fn host(os: &str, reload_override: Option<&str>) -> Host {
    let reload = reload_override
        .map(|r| format!("reload_cmd = \"{r}\"\n"))
        .unwrap_or_default();
    Inventory::parse(&format!(
        r#"
        [[hosts]]
        name = "db-01"
        address = "10.0.4.11"
        os = "{os}"
        channels = ["ssh", "authorized-keys"]

        [hosts.ssh]
        agent_user = "root"
        root_posture_default = "no"
        root_posture_emergency = "yes"
        emergency_keys = ["ssh-ed25519 EMERG breakglass"]
        {reload}
        "#
    ))
    .unwrap()
    .hosts
    .remove(0)
}

#[test]
fn the_deadline_renders_as_whole_epoch_seconds() {
    let t = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    assert_eq!(render_deadline(t), "1700000000\n");
}

#[test]
fn the_cron_line_runs_the_script_every_minute_and_carries_the_marker() {
    let line = cron_line();
    assert!(line.starts_with("* * * * * "), "{line}");
    assert!(line.contains(SCRIPT_PATH), "{line}");
    assert!(line.ends_with(CRON_MARKER), "{line}");
}

#[test]
fn crontab_upsert_appends_once_and_preserves_every_existing_byte() {
    let existing = "0 3 * * * /usr/local/bin/backup.sh\n";
    let with = crontab_with_deadman(existing);
    assert!(
        with.starts_with(existing),
        "existing bytes changed:\n{with}"
    );
    assert!(with.contains(CRON_MARKER));
    // Idempotent: a second upsert changes nothing.
    assert_eq!(crontab_with_deadman(&with), with);
}

#[test]
fn crontab_upsert_handles_an_empty_crontab_and_a_missing_trailing_newline() {
    let from_empty = crontab_with_deadman("");
    assert_eq!(from_empty, cron_line() + "\n");
    let ragged = crontab_with_deadman("0 1 * * * job");
    assert!(ragged.contains("0 1 * * * job\n"), "{ragged}");
}

#[test]
fn crontab_remove_drops_only_marker_lines() {
    let existing = format!("0 3 * * * backup\n{}\n30 4 * * * other\n", cron_line());
    let without = crontab_without_deadman(&existing);
    assert_eq!(without, "0 3 * * * backup\n30 4 * * * other\n");
    // Removing from a marker-free crontab changes nothing; an all-marker
    // crontab empties cleanly.
    assert_eq!(crontab_without_deadman(&without), without);
    assert_eq!(crontab_without_deadman(&(cron_line() + "\n")), "");
}

#[test]
fn the_script_bakes_in_every_revert_ingredient_for_the_host() {
    let script = render_script(&host("freebsd", None)).unwrap();
    assert!(script.contains(&format!("rm -f '{}'", crate::ssh::DEFAULT_DROPIN)));
    assert!(script.contains("service sshd reload || true"), "{script}");
    assert!(script.contains("akeys='/root/.ssh/authorized_keys'"));
    assert!(script.contains(FENCE_BEGIN));
    assert!(script.contains(FENCE_END));
    assert!(script.contains(DEADLINE_PATH));
    assert!(script.contains(FIRED_PATH));
    // The firing direction, pinned textually: at-or-past the deadline. The
    // semantics are proven by the guest tier's revert-under-kill.
    assert!(script.contains(r#""${now}" -ge "${deadline}""#), "{script}");
    // And the linux default reload differs.
    let linux = render_script(&host("linux", None)).unwrap();
    assert!(linux.contains("systemctl reload sshd"), "{linux}");
    // A per-host override wins.
    let custom = render_script(&host("freebsd", Some("/usr/local/bin/kick-sshd"))).unwrap();
    assert!(
        custom.contains("/usr/local/bin/kick-sshd || true"),
        "{custom}"
    );
}

#[test]
fn the_script_leaves_the_fired_marker_but_cleans_its_own_schedule() {
    let script = render_script(&host("freebsd", None)).unwrap();
    // Fires the marker for the daemon to find...
    assert!(script.contains(&format!(": > {FIRED_PATH}")));
    // ...and removes its own crontab line and deadline, but NOT the marker.
    assert!(script.contains("grep -v 'LYCHGATE-DEADMAN'"));
    assert!(script.contains(&format!("rm -f {DEADLINE_PATH}")));
    // The fired path appears exactly once — its creation. Any second
    // occurrence would be something deleting it.
    assert_eq!(script.matches(FIRED_PATH).count(), 1, "{script}");
}

#[test]
fn a_host_without_ssh_config_renders_no_script() {
    let inv = Inventory::parse(
        r#"
        [[hosts]]
        name = "web"
        address = "10.0.4.12"
        os = "linux"
        channels = ["vnc"]
        "#,
    )
    .unwrap();
    assert_eq!(render_script(&inv.hosts[0]), None);
}

#[test]
fn paths_with_single_quotes_are_refused_rather_than_corrupting_the_script() {
    let mut h = host("freebsd", None);
    h.ssh.as_mut().unwrap().authorized_keys_path = "/tmp/it's-a-trap".to_string();
    assert_eq!(render_script(&h), None);
}

#[test]
fn the_fence_markers_carry_no_single_quotes() {
    // The script embeds them single-quoted; an apostrophe would break out.
    assert!(!FENCE_BEGIN.contains('\''));
    assert!(!FENCE_END.contains('\''));
}

#[cfg(unix)]
#[test]
fn the_rendered_script_is_valid_sh() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    for os in ["freebsd", "linux"] {
        let script = render_script(&host(os, None)).unwrap();
        let mut child = Command::new("sh")
            .arg("-n")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sh -n");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "sh -n rejected the {os} script:\n{}\n---\n{script}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
