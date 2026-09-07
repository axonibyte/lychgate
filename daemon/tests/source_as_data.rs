//! The source-as-data tier (methodology §15): the same vocabulary appears in
//! more than one artifact — an enum, a registry, a wire match, the docs — and
//! nothing but convention keeps them agreeing. These tests parse the source and
//! assert the sets agree.
//!
//! Two rules from TESTING.md, applied throughout:
//!  - **The mapping is duplicated deliberately.** Each test hard-codes the
//!    expected vocabulary (and any case conversion) rather than importing it
//!    from the code under test — a check derived from the structure it checks
//!    would agree with itself no matter what. The duplication IS the check.
//!  - **The checked content is excluded from the searched corpus.** The expected
//!    set never comes from the same file being scanned for it.
//!
//! These are text-level assertions on purpose: dumb parsers rot more loudly
//! than clever ones. If an enum is reshaped and a regex here stops matching,
//! the test fails toward "come look", never toward silently passing.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The repo root, from the daemon crate's manifest dir.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("daemon/ has a parent")
        .to_path_buf()
}

fn read(rel: &str) -> String {
    let path = root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// Extract the variant identifiers of `pub enum <name>` from source text —
/// the block from the enum header to its closing brace, keeping only lines
/// that are bare `Ident,` variants (fields and attributes are skipped by the
/// unit-variant shape; none of the checked enums has data variants).
fn unit_variants(source: &str, name: &str) -> BTreeSet<String> {
    let header = format!("pub enum {name} {{");
    let start = source
        .find(&header)
        .unwrap_or_else(|| panic!("no `{header}` in the source"));
    let body = &source[start + header.len()..];
    let end = body.find("\n}").expect("the enum closes");
    body[..end]
        .lines()
        .filter_map(|l| {
            let l = l.trim().trim_end_matches(',');
            (!l.is_empty()
                && l.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                && l.chars().all(|c| c.is_ascii_alphanumeric()))
            .then(|| l.to_string())
        })
        .collect()
}

/// The kebab-case serde derives, duplicated here deliberately: `AuthorizedKeys`
/// -> `authorized-keys`. If serde's convention and this one drift, the tests
/// comparing wire names to docs fail — which is the point.
fn kebab(ident: &str) -> String {
    let mut out = String::new();
    for (i, c) in ident.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('-');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

// ---------------------------------------------------------------------------
// Channel vocabulary: enum <-> driver registry <-> README
// ---------------------------------------------------------------------------

/// The channel vocabulary, stated here by hand — the deliberate duplicate that
/// every artifact is compared against.
const CHANNELS: &[&str] = &[
    "ssh",
    "authorized-keys",
    "bmc",
    "vnc",
    "http",
    "mqtt",
    "serial",
];

/// Channels whose schema has landed ahead of their driver, stated BY HAND so
/// the gap is a named decision, not an accident (the pre-M4 shape: the
/// channel parses, and an open on it is refused for want of a driver —
/// fail-closed). The E2 driver commits empty this list; a name lingering
/// here after its driver lands is a bug in this list.
const UNDRIVEN_CHANNELS: &[&str] = &["mqtt", "serial"];

#[test]
fn the_channel_enum_matches_the_stated_vocabulary() {
    let variants = unit_variants(&read("core/src/inventory.rs"), "Channel");
    let wire: BTreeSet<String> = variants.iter().map(|v| kebab(v)).collect();
    assert_eq!(
        wire,
        set(CHANNELS),
        "core's Channel enum drifted from the stated channel vocabulary"
    );
}

#[test]
fn every_channel_has_a_registered_production_driver() {
    // The rot this catches: a fifth channel added to the enum whose driver is
    // never registered — every grant on it would open as bookkeeping only.
    // The channel -> driver-type mapping is duplicated here by hand.
    let main = read("daemon/src/main.rs");
    let drivers: &[(&str, &str)] = &[
        ("ssh", "drivers::ssh::SshPostureDriver"),
        ("authorized-keys", "drivers::ssh::AuthorizedKeysDriver"),
        ("bmc", "drivers::bmc::BmcDriver"),
        ("vnc", "drivers::vnc::VncDriver"),
        ("http", "drivers::http::HttpDriver"),
    ];
    assert_eq!(
        drivers.len() + UNDRIVEN_CHANNELS.len(),
        CHANNELS.len(),
        "the driver map plus the named undriven allowance must cover the stated channel vocabulary"
    );
    for undriven in UNDRIVEN_CHANNELS {
        assert!(
            CHANNELS.contains(undriven) && !drivers.iter().any(|(c, _)| c == undriven),
            "UNDRIVEN_CHANNELS entry {undriven:?} is stale: not a channel, or already driven"
        );
    }
    for (channel, driver) in drivers {
        assert!(
            main.contains(&format!(".register({driver}")),
            "channel {channel:?}: no `.register({driver}...)` in daemon/src/main.rs"
        );
    }
}

#[test]
fn every_channel_is_documented_in_the_readme() {
    let readme = read("README.md");
    for channel in CHANNELS {
        assert!(
            readme.contains(channel),
            "channel {channel:?} is not mentioned in README.md"
        );
    }
}

// ---------------------------------------------------------------------------
// Op vocabulary: wire match <-> CLI subcommands <-> README
// ---------------------------------------------------------------------------

/// The daemon-backed op vocabulary, stated by hand.
const OPS: &[&str] = &["open", "approve", "close", "renew", "status", "drill"];

/// CLI subcommands that are LOCAL (no daemon round trip) — the allowed
/// difference between the Command enum and the op vocabulary, stated by hand.
const LOCAL_COMMANDS: &[&str] = &[
    "HashPassword",
    "Fido2Register",
    "Fido2Assert",
    "TpmProbe",
    "TpmRegister",
    "TpmSign",
    "TpmSeal",
];

#[test]
fn the_wire_decoder_speaks_exactly_the_stated_ops() {
    // Every `"name" => Ok(Op::...)` arm in decode_request, scraped textually.
    let proto = read("core/src/proto.rs");
    let start = proto
        .find("pub fn decode_request")
        .expect("decode_request exists");
    let body = &proto[start..start + proto[start..].find("\npub fn ").unwrap_or(2_000)];
    let decoded: BTreeSet<String> = body
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let name = l.strip_prefix('"')?.split('"').next()?;
            l.contains("=> Ok(Op::").then(|| name.to_string())
        })
        .collect();
    assert_eq!(
        decoded,
        set(OPS),
        "decode_request's wire vocabulary drifted from the stated ops"
    );
}

#[test]
fn the_cli_offers_every_op_and_only_the_stated_locals_besides() {
    // The CLI/daemon parity check: the Command enum is the op vocabulary
    // (PascalCased) plus exactly the stated local commands.
    let cli = read("cli/src/main.rs");
    let commands = unit_variants(&read_enum_with_fields(&cli, "Command"), "Command");
    let mut expected: BTreeSet<String> = OPS
        .iter()
        .map(|op| {
            // kebab -> Pascal, duplicated by hand (the inverse of `kebab`).
            op.split('-')
                .map(|part| {
                    let mut c = part.chars();
                    c.next()
                        .map(|f| f.to_ascii_uppercase())
                        .into_iter()
                        .collect::<String>()
                        + c.as_str()
                })
                .collect::<String>()
        })
        .collect();
    expected.extend(LOCAL_COMMANDS.iter().map(|s| s.to_string()));
    assert_eq!(
        commands, expected,
        "the CLI Command enum drifted from ops + stated local commands"
    );
}

/// The Command enum has data variants; flatten each `Ident {`/`Ident,` header
/// into a unit variant so `unit_variants` can read it. Textual on purpose.
fn read_enum_with_fields(source: &str, name: &str) -> String {
    let header = format!("enum {name} {{");
    let start = source.find(&header).expect("the enum exists");
    let body = &source[start..];
    let end = body.find("\n}").expect("the enum closes");
    let mut depth = 0usize;
    let mut flat = format!("pub enum {name} {{\n");
    for line in body[header.len()..end].lines() {
        let t = line.trim();
        if depth == 0 {
            if let Some(ident) = t.strip_suffix(" {") {
                if ident.chars().all(|c| c.is_ascii_alphanumeric()) && !ident.is_empty() {
                    flat.push_str(&format!("    {ident},\n"));
                }
            } else if t.ends_with(',')
                && t.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                && t.trim_end_matches(',')
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric())
            {
                flat.push_str(&format!("    {t}\n"));
            }
        }
        depth += t.matches('{').count();
        depth = depth.saturating_sub(t.matches('}').count());
    }
    flat.push_str("\n}");
    flat
}

#[test]
fn every_op_is_documented_in_the_readme_usage() {
    let readme = read("README.md");
    for op in OPS {
        assert!(
            readme.contains(&format!("lychgate {op}")),
            "op {op:?} has no `lychgate {op}` usage line in README.md"
        );
    }
}

// ---------------------------------------------------------------------------
// Authenticator kinds: enum <-> README
// ---------------------------------------------------------------------------

const AUTH_KINDS: &[&str] = &["ed25519", "totp", "password", "fido2", "tpm"];

#[test]
fn the_authenticator_kinds_match_the_stated_vocabulary_and_the_readme() {
    let variants = unit_variants(&read("core/src/authority.rs"), "AuthKind");
    let wire: BTreeSet<String> = variants.iter().map(|v| kebab(v)).collect();
    assert_eq!(
        wire,
        set(AUTH_KINDS),
        "core's AuthKind drifted from the stated kinds"
    );
    let readme = read("README.md");
    for kind in AUTH_KINDS {
        assert!(
            readme.contains(&format!("kind = \"{kind}\"")),
            "authenticator kind {kind:?} has no `kind = \"{kind}\"` example in README.md"
        );
    }
}

// ---------------------------------------------------------------------------
// Journal events the RUNBOOK tells operators to alert on
// ---------------------------------------------------------------------------

/// The alertable events, stated by hand. The RUNBOOK names them for operators;
/// each must exist as a journal Event variant, or the runbook promises an alert
/// the daemon never writes.
const ALERT_EVENTS: &[&str] = &["approval-denied", "mcp-refused", "drill-failed"];

#[test]
fn every_runbook_alert_event_exists_in_the_journal_and_is_named_there() {
    let journal = read("daemon/src/journal.rs");
    let runbook = read("docs/RUNBOOK.md");
    for event in ALERT_EVENTS {
        // Pascal-case the kebab name by hand (the serde tag convention inverted).
        let variant: String = event
            .split('-')
            .map(|part| {
                let mut c = part.chars();
                c.next()
                    .map(|f| f.to_ascii_uppercase())
                    .into_iter()
                    .collect::<String>()
                    + c.as_str()
            })
            .collect();
        assert!(
            journal.contains(&format!("{variant} {{")),
            "alert event {event:?}: no `{variant}` variant in daemon/src/journal.rs"
        );
        assert!(
            runbook.contains(&format!("\"{event}\"")),
            "alert event {event:?} is not named in docs/RUNBOOK.md"
        );
    }
}

// ---------------------------------------------------------------------------
// MCP tools: listed <-> dispatched
// ---------------------------------------------------------------------------

const MCP_TOOLS: &[&str] = &[
    "open_grant",
    "grant_status",
    "renew_grant",
    "close_grant",
    "access_handle",
];

#[test]
fn every_mcp_tool_is_both_listed_and_dispatched() {
    // The rot this catches: a tool advertised in tools/list that tools/call
    // cannot dispatch (or the reverse) — the two halves live in one file and
    // nothing else ties them together.
    let tools = read("mcp/src/tools.rs");
    for tool in MCP_TOOLS {
        assert!(
            tools.contains(&format!("\"name\": \"{tool}\"")),
            "tool {tool:?} is not in the tools/list schemas"
        );
        assert!(
            tools.contains(&format!("\"{tool}\" =>")),
            "tool {tool:?} is not dispatched in call()"
        );
    }
    // And nothing extra is dispatched: every dispatch arm is a stated tool.
    let dispatched: BTreeSet<String> = tools
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let name = l.strip_prefix('"')?.split('"').next()?;
            (l.contains("\" => ") && l.contains('(')).then(|| name.to_string())
        })
        .collect();
    assert_eq!(
        dispatched,
        set(MCP_TOOLS),
        "call()'s dispatch arms drifted from the stated tool set"
    );
}

// ---------------------------------------------------------------------------
// The e2e battery: every acceptance script is wired into run.sh
// ---------------------------------------------------------------------------

/// Acceptance scripts deliberately NOT in the battery, stated by hand with the
/// reason. Anything else unwired is rot: a suite that silently stopped running.
const UNWIRED: &[&str] = &["fido2-hardware.sh"]; // manual/simulated tier; needs a key

#[test]
fn every_acceptance_script_is_wired_into_the_battery() {
    let run = read("e2e/run.sh");
    let dir = root().join("e2e");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("e2e/ lists") {
        let name = entry.expect("entry").file_name();
        let name = name.to_string_lossy().into_owned();
        let is_acceptance = name.ends_with("-acceptance.sh") || name == "fido2-hardware.sh";
        if !is_acceptance || UNWIRED.contains(&name.as_str()) {
            continue;
        }
        assert!(
            run.contains(&format!("e2e/{name}")),
            "{name} is an acceptance script but e2e/run.sh never runs it"
        );
        checked += 1;
    }
    assert!(
        checked >= 10,
        "only {checked} acceptance scripts found — the discovery glob itself may have rotted"
    );
}
