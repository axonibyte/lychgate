//! Tier 2: seeded fuzz over every externally-reachable decoder.
//!
//! Targets: the wire-protocol request decoder, the TTL parser, and the
//! inventory parser. The oracle is the methodology's: no panic, and every
//! rejection is a well-formed error (non-empty Display). The targets are
//! pure functions, so "the daemon is still alive afterwards" reduces to "the
//! call returned"; the daemon-level version of that claim lives in the
//! end-to-end battery.
//!
//! Determinism is the whole game:
//! - Every run prints its seeds before using them (a panic message therefore
//!   always has the seed above it).
//! - `LYCHGATE_FUZZ_SEED` replays exactly one seed.
//! - `LYCHGATE_FUZZ_ITERS` raises the per-seed iteration count for hunting
//!   runs; the default is small so the suite's cost is known.
//! - Any seed that ever found a defect gets promoted into FIXED_SEEDS
//!   permanently, with a comment naming what it found.

use std::time::UNIX_EPOCH;

use lychgate_core::approval::{
    parse_ssh_public_key, ApprovalRequest, ApprovalVerifier, SshSigVerifier,
};
use lychgate_core::bmc::parse_account;
use lychgate_core::proto::decode_request;
use lychgate_core::ssh::{fence_remove, fence_upsert, parse_effective_posture};
use lychgate_core::{Inventory, Ttl};

/// Committed seeds run on every invocation. Promote defect-finding seeds
/// here; never remove one.
const FIXED_SEEDS: &[u64] = &[
    0x1ce9_e66d_1b2c_a55e,
    0x5eed_5eed_5eed_5eed,
    0xdead_10cc_c0ff_ee00,
    3,
    1_700_000_000,
];

const DEFAULT_ITERS: u32 = 500;

/// SplitMix64: tiny, seedable, and good enough to shuffle bytes. A crate
/// dependency for this would be dead weight.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
}

/// Tokens that steer inputs toward the seams: field names, ops, units,
/// boundary numbers, JSON punctuation, and text that is only a problem if
/// something mishandles it.
const TOKENS: &[&str] = &[
    "{",
    "}",
    "[",
    "]",
    ":",
    ",",
    "\"",
    "\\",
    "proto",
    "op",
    "host",
    "ttl",
    "open",
    "close",
    "renew",
    "status",
    "hosts",
    "name",
    "address",
    "os",
    "channels",
    "freebsd",
    "linux",
    "ssh",
    "bmc",
    "vnc",
    "authorized-keys",
    "set_password_cmd",
    "clear_password_cmd",
    "local_port",
    "rfb_port",
    "target",
    "{target}",
    "{password_file}",
    "[hosts.vnc]",
    "approve",
    "token",
    "[approval]",
    "ssh-ed25519 ",
    "lg1.req.",
    "-----BEGIN SSH SIGNATURE-----",
    "U1NIU0lH",
    "0",
    "1",
    "2",
    "99",
    "-1",
    "18446744073709551615",
    "86400",
    "86401",
    "s",
    "m",
    "h",
    "24h",
    "25h",
    "1e309",
    "null",
    "true",
    "[[hosts]]",
    "=",
    "é",
    "𝄞",
    "\u{0}",
    "\n",
    " ",
];

fn random_bytes(rng: &mut Rng) -> String {
    let len = rng.below(200) as usize;
    let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn token_soup(rng: &mut Rng) -> String {
    let n = rng.below(40) as usize;
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(TOKENS[rng.below(TOKENS.len() as u64) as usize]);
    }
    s
}

fn mutated_valid(rng: &mut Rng) -> String {
    let valid = [
        r#"{"proto":3,"op":"open","host":"db-01","ttl":"4h"}"#,
        r#"{"proto":3,"op":"close","host":"db-01"}"#,
        r#"{"proto":3,"op":"renew","host":"db-01","ttl":"90s"}"#,
        r#"{"proto":3,"op":"status"}"#,
        "[[hosts]]\nname = \"a\"\naddress = \"b\"\nos = \"linux\"\nchannels = [\"ssh\"]\n",
        "15m",
    ];
    let mut s = valid[rng.below(valid.len() as u64) as usize].to_string();
    for _ in 0..=rng.below(4) {
        match rng.below(3) {
            // Truncate somewhere.
            0 => {
                let cut = rng.below(s.len() as u64 + 1) as usize;
                while !s.is_char_boundary(cut.min(s.len())) {
                    s.pop();
                }
                s.truncate(cut.min(s.len()));
            }
            // Splice a token in at a char boundary.
            1 => {
                let mut at = rng.below(s.len() as u64 + 1) as usize;
                while !s.is_char_boundary(at) {
                    at -= 1;
                }
                s.insert_str(at, TOKENS[rng.below(TOKENS.len() as u64) as usize]);
            }
            // Flip one byte, keeping the string valid UTF-8 by lossy round-trip.
            _ => {
                let mut bytes = s.into_bytes();
                if !bytes.is_empty() {
                    let at = rng.below(bytes.len() as u64) as usize;
                    bytes[at] ^= 1 << rng.below(8);
                }
                s = String::from_utf8_lossy(&bytes).into_owned();
            }
        }
    }
    s
}

fn one_input(rng: &mut Rng) -> String {
    match rng.below(3) {
        0 => random_bytes(rng),
        1 => token_soup(rng),
        _ => mutated_valid(rng),
    }
}

/// The oracle: the call returns (no panic), and a rejection carries a
/// non-empty, printable error.
fn check(input: &str) {
    if let Err(e) = decode_request(input) {
        assert!(!e.to_string().is_empty(), "empty proto error for {input:?}");
    }
    if let Err(e) = Ttl::parse(input) {
        assert!(!e.to_string().is_empty(), "empty ttl error for {input:?}");
    }
    if let Err(e) = Inventory::parse(input) {
        assert!(
            !e.to_string().is_empty(),
            "empty inventory error for {input:?}"
        );
    }
    // The fence functions chew on authorized_keys content fetched from
    // remote hosts: hostile by definition.
    if let Err(e) = fence_upsert(input, &["ssh-ed25519 FUZZ key".to_string()]) {
        assert!(!e.to_string().is_empty(), "empty fence error for {input:?}");
    }
    if let Err(e) = fence_remove(input) {
        assert!(!e.to_string().is_empty(), "empty fence error for {input:?}");
    }
    // And sshd -T output likewise arrives over the transport.
    let _ = parse_effective_posture(input);
    // BMC AccountService responses arrive from the iDRAC over the network.
    if let Err(e) = parse_account(input, "breakglass") {
        assert!(!e.to_string().is_empty(), "empty bmc error for {input:?}");
    }
    // Approval material — a configured key and a pasted SSHSIG token — arrives
    // as operator-supplied strings: hostile by definition.
    if let Err(e) = parse_ssh_public_key(input) {
        assert!(
            !e.to_string().is_empty(),
            "empty approval key error for {input:?}"
        );
    }
    let verifier = SshSigVerifier::new(vec![(
        "fuzz".to_string(),
        parse_ssh_public_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIOBaP66AKPs9nRYDzUrJjGJMYxn0rIWv/tNftYWIu25",
        )
        .expect("a valid fixed key"),
    )]);
    let req = ApprovalRequest::new([0u8; 32], "h".to_string(), 3600, UNIX_EPOCH);
    if let Err(e) = verifier.verify(&req, input) {
        assert!(
            !e.to_string().is_empty(),
            "empty approval verify error for {input:?}"
        );
    }
}

fn iters() -> u32 {
    std::env::var("LYCHGATE_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_ITERS)
}

fn run_seed(seed: u64, iters: u32) {
    // Printed before the work, so a panic always has its seed above it.
    eprintln!(
        "fuzz: seed {seed:#018x} ({iters} iterations); replay with LYCHGATE_FUZZ_SEED={seed}"
    );
    let mut rng = Rng(seed);
    for _ in 0..iters {
        check(&one_input(&mut rng));
    }
}

#[test]
fn no_decoder_panics_and_every_rejection_is_well_formed() {
    if let Ok(seed) = std::env::var("LYCHGATE_FUZZ_SEED") {
        let seed: u64 = seed.parse().expect("LYCHGATE_FUZZ_SEED must be a u64");
        run_seed(seed, iters());
        return;
    }
    for &seed in FIXED_SEEDS {
        run_seed(seed, iters());
    }
}

/// Self-test for the harness itself: a generator that only ever produced
/// empty or trivially-invalid strings would make the suite pass vacuously.
/// Prove the generators actually reach the interesting space: over a fixed
/// seed, some inputs decode successfully and some fail, for each target.
#[test]
fn the_generators_reach_both_accepting_and_rejecting_inputs() {
    let mut rng = Rng(FIXED_SEEDS[0]);
    let (mut proto_ok, mut proto_err, mut ttl_ok, mut ttl_err) = (0u32, 0u32, 0u32, 0u32);
    for _ in 0..5_000 {
        let input = one_input(&mut rng);
        match decode_request(&input) {
            Ok(_) => proto_ok += 1,
            Err(_) => proto_err += 1,
        }
        match Ttl::parse(&input) {
            Ok(_) => ttl_ok += 1,
            Err(_) => ttl_err += 1,
        }
    }
    assert!(
        proto_ok > 0 && proto_err > 0,
        "proto generator is one-sided: {proto_ok} ok / {proto_err} err"
    );
    assert!(
        ttl_ok > 0 && ttl_err > 0,
        "ttl generator is one-sided: {ttl_ok} ok / {ttl_err} err"
    );
}
