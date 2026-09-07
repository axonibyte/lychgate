//! The device-engine matrix: real signed tokens against fake HAL traits.
//!
//! Mutation notes (each observed failing): remove the gate.set_open(false)
//! from new() → a_reboot_boots_closed_and_keeps_the_seq fails; remove the
//! expiry check from tick() → the_ttl_expires_on_the_uptime_clock fails
//! (assert-the-absence, with time passing on the fake clock); drop the
//! seq <= stored refusal → a_superseded_token_is_dead fails; make idempotent
//! redelivery re-anchor → redelivery_does_not_extend_the_deadline fails;
//! drop the busy refusal → a_second_grant_while_open_is_refused_busy fails;
//! store the seq AFTER opening the gate → a_store_failure_refuses fails.

use super::*;
use std::cell::Cell;
use std::rc::Rc;
use std::string::String;
use std::vec::Vec;

const SEED: [u8; 32] = [0x11; 32];
const DEVICE_ID: [u8; 16] = [7; 16];
const NONCE_A: [u8; 16] = [0xaa; 16];
const NONCE_B: [u8; 16] = [0xbb; 16];

#[derive(Clone)]
struct FakeClock(Rc<Cell<u64>>);

impl UptimeClock for FakeClock {
    fn uptime_ms(&self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone)]
struct FakeSeq {
    value: Rc<Cell<u64>>,
    fail_store: Rc<Cell<bool>>,
    stores: Rc<Cell<u64>>,
}

impl SeqStore for FakeSeq {
    fn load(&mut self) -> Result<u64, StoreError> {
        Ok(self.value.get())
    }
    fn store(&mut self, seq: u64) -> Result<(), StoreError> {
        if self.fail_store.get() {
            return Err(StoreError);
        }
        self.value.set(seq);
        self.stores.set(self.stores.get() + 1);
        Ok(())
    }
}

#[derive(Clone)]
struct FakeGate {
    open: Rc<Cell<bool>>,
    log: Rc<std::cell::RefCell<Vec<bool>>>,
}

impl Gate for FakeGate {
    fn set_open(&mut self, open: bool) {
        self.open.set(open);
        self.log.borrow_mut().push(open);
    }
}

struct Rig {
    engine: DeviceEngine<FakeClock, FakeSeq, FakeGate>,
    clock: Rc<Cell<u64>>,
    seq: FakeSeq,
    gate_open: Rc<Cell<bool>>,
}

fn rig() -> Rig {
    let clock = Rc::new(Cell::new(0));
    let seq = FakeSeq {
        value: Rc::new(Cell::new(0)),
        fail_store: Rc::new(Cell::new(false)),
        stores: Rc::new(Cell::new(0)),
    };
    let gate_open = Rc::new(Cell::new(true)); // Starts electrically open; boot must close it.
    let gate = FakeGate {
        open: Rc::clone(&gate_open),
        log: Rc::new(std::cell::RefCell::new(Vec::new())),
    };
    let engine = DeviceEngine::new(
        DEVICE_ID,
        TrustRoot::Ed25519(
            ed25519_dalek::SigningKey::from_bytes(&SEED)
                .verifying_key()
                .to_bytes(),
        ),
        FakeClock(Rc::clone(&clock)),
        seq.clone(),
        gate,
    );
    Rig {
        engine,
        clock,
        seq,
        gate_open,
    }
}

fn cap_token(nonce: [u8; 16], ttl_secs: u32, seq: u64) -> String {
    lychgate_wire::sign_capability_token(
        &lychgate_wire::SigningKey::Ed25519Seed(&SEED),
        &lychgate_wire::Capability {
            ver: lychgate_wire::VER_ED25519,
            device_id: DEVICE_ID,
            grant_nonce: nonce,
            capability: 1,
            ttl_secs,
            issued_seq: seq,
        },
    )
    .unwrap()
}

fn rvk_token(nonce: [u8; 16], seq: u64) -> String {
    lychgate_wire::sign_revocation_token(
        &lychgate_wire::SigningKey::Ed25519Seed(&SEED),
        &lychgate_wire::Revocation {
            ver: lychgate_wire::VER_ED25519,
            device_id: DEVICE_ID,
            grant_nonce: nonce,
            issued_seq: seq,
        },
    )
    .unwrap()
}

fn send(rig: &mut Rig, line: &str) -> String {
    let mut buf = [0u8; line::MAX_LINE_LEN];
    rig.engine.handle_line(line, &mut buf).to_string()
}

#[test]
fn a_valid_token_opens_the_gate_and_anchors_the_ttl() {
    let mut r = rig();
    assert!(!r.gate_open.get(), "boot must close the gate");
    let reply = send(&mut r, &format!("TOK {}", cap_token(NONCE_A, 900, 1)));
    assert!(reply.starts_with("ACK "), "{reply}");
    assert!(reply.contains("900"), "{reply}");
    assert!(r.gate_open.get());
    let stat = send(&mut r, "STAT");
    assert!(stat.starts_with("STATE open"), "{stat}");
    assert!(stat.contains("seq=1"), "{stat}");
}

#[test]
fn the_ttl_expires_on_the_uptime_clock() {
    // Assert the absence with time passing: before the deadline the gate is
    // up; at it, the gate drops with reason=expiry — no daemon involved.
    let mut r = rig();
    send(&mut r, &format!("TOK {}", cap_token(NONCE_A, 900, 1)));
    r.clock.set(899_999);
    r.engine.tick();
    assert!(r.gate_open.get(), "one ms early must still be open");
    r.clock.set(900_000);
    r.engine.tick();
    assert!(!r.gate_open.get(), "the deadline must drop the gate");
    let stat = send(&mut r, "STAT");
    assert!(
        stat.contains("closed") && stat.contains("reason=expiry"),
        "{stat}"
    );
}

#[test]
fn expiry_is_a_property_of_observation_not_just_the_tick() {
    let mut r = rig();
    send(&mut r, &format!("TOK {}", cap_token(NONCE_A, 900, 1)));
    r.clock.set(2_000_000);
    // No tick() — the STAT itself must notice.
    let stat = send(&mut r, "STAT");
    assert!(stat.contains("closed"), "{stat}");
    assert!(!r.gate_open.get());
}

#[test]
fn a_reboot_boots_closed_and_keeps_the_seq() {
    let mut r = rig();
    send(&mut r, &format!("TOK {}", cap_token(NONCE_A, 900, 1)));
    assert!(r.gate_open.get());

    // "Reboot": a new engine over the SAME seq store and gate line.
    let gate_open = Rc::new(Cell::new(true));
    let mut engine2 = DeviceEngine::new(
        DEVICE_ID,
        TrustRoot::Ed25519(
            ed25519_dalek::SigningKey::from_bytes(&SEED)
                .verifying_key()
                .to_bytes(),
        ),
        FakeClock(Rc::new(Cell::new(0))),
        r.seq.clone(),
        FakeGate {
            open: Rc::clone(&gate_open),
            log: Rc::new(std::cell::RefCell::new(Vec::new())),
        },
    );
    assert!(!gate_open.get(), "boot must drive the gate closed");
    let mut buf = [0u8; line::MAX_LINE_LEN];
    let stat = engine2.handle_line("STAT", &mut buf).to_string();
    assert!(
        stat.contains("closed") && stat.contains("reason=boot") && stat.contains("seq=1"),
        "the grant is gone but the anti-replay mark survived: {stat}"
    );
    // The pre-reboot token is now dead (seq 1 <= mark 1) even though its
    // TTL never expired — replay across a power cycle is the exact attack.
    let reply = engine2.handle_line(&format!("TOK {}", cap_token(NONCE_A, 900, 1)), &mut buf);
    assert_eq!(reply, "NAK replay");
}

#[test]
fn a_superseded_token_is_dead() {
    let mut r = rig();
    send(&mut r, &format!("TOK {}", cap_token(NONCE_A, 900, 1)));
    send(&mut r, &format!("RVK {}", rvk_token(NONCE_A, 2)));
    assert!(!r.gate_open.get());
    // The captured (seq-1) token cannot reopen.
    let reply = send(&mut r, &format!("TOK {}", cap_token(NONCE_A, 900, 1)));
    assert_eq!(reply, "NAK replay");
}

#[test]
fn redelivery_does_not_extend_the_deadline_but_renewal_does() {
    let mut r = rig();
    send(&mut r, &format!("TOK {}", cap_token(NONCE_A, 900, 1)));
    r.clock.set(600_000);
    // Redelivery of the SAME token: acknowledged, but the deadline stands —
    // a replayed still-current token must not become a keep-alive.
    let reply = send(&mut r, &format!("TOK {}", cap_token(NONCE_A, 900, 1)));
    assert!(reply.starts_with("ACK "), "{reply}");
    assert!(
        reply.contains(" 300"),
        "remaining must reflect the ORIGINAL anchor: {reply}"
    );
    // A renewal (same nonce, HIGHER seq) re-anchors.
    let reply = send(&mut r, &format!("TOK {}", cap_token(NONCE_A, 900, 2)));
    assert!(reply.contains(" 900"), "renewal must re-anchor: {reply}");
    r.clock.set(600_000 + 899_000);
    r.engine.tick();
    assert!(r.gate_open.get(), "renewed grant outlives the old deadline");
}

#[test]
fn a_second_grant_while_open_is_refused_busy() {
    let mut r = rig();
    send(&mut r, &format!("TOK {}", cap_token(NONCE_A, 900, 1)));
    let reply = send(&mut r, &format!("TOK {}", cap_token(NONCE_B, 900, 2)));
    assert_eq!(reply, "NAK busy");
    assert!(r.gate_open.get(), "the original grant is undisturbed");
}

#[test]
fn refusal_matrix_names_each_reason() {
    let mut r = rig();
    // Wrong device.
    let other = lychgate_wire::sign_capability_token(
        &lychgate_wire::SigningKey::Ed25519Seed(&SEED),
        &lychgate_wire::Capability {
            ver: lychgate_wire::VER_ED25519,
            device_id: [9; 16],
            grant_nonce: NONCE_A,
            capability: 1,
            ttl_secs: 900,
            issued_seq: 1,
        },
    )
    .unwrap();
    assert_eq!(send(&mut r, &format!("TOK {other}")), "NAK wrong-device");
    // Garbage.
    assert_eq!(send(&mut r, "TOK lgcap.junk"), "NAK bad-token");
    assert_eq!(send(&mut r, "FROB"), "NAK bad-command");
    // Over-cap ttl parses at the wire but the DEVICE refuses (policy here).
    let long = cap_token(NONCE_A, lychgate_wire::MAX_TTL_SECS + 1, 1);
    assert_eq!(send(&mut r, &format!("TOK {long}")), "NAK ttl");
    // A tampered signature.
    let mut t = cap_token(NONCE_A, 900, 1);
    let last = t.pop().unwrap();
    t.push(if last == 'A' { 'B' } else { 'A' });
    assert_eq!(send(&mut r, &format!("TOK {t}")), "NAK bad-token");
    // SE commands are honest about being absent here.
    assert_eq!(send(&mut r, "SE-PUBKEY?"), "NAK unsupported");
    assert!(!r.gate_open.get(), "nothing above may have opened the gate");
}

#[test]
fn a_stale_revocation_cannot_close_a_newer_grant() {
    let mut r = rig();
    send(&mut r, &format!("TOK {}", cap_token(NONCE_A, 900, 1)));
    send(&mut r, &format!("RVK {}", rvk_token(NONCE_A, 2)));
    send(&mut r, &format!("TOK {}", cap_token(NONCE_B, 900, 3)));
    assert!(r.gate_open.get());
    // A captured old revocation (seq 2): dead by seq ordering.
    let reply = send(&mut r, &format!("RVK {}", rvk_token(NONCE_A, 2)));
    assert_eq!(reply, "NAK replay");
    assert!(r.gate_open.get(), "the newer grant is undisturbed");
    // A FRESH revocation naming the wrong grant: refused by name.
    let reply = send(&mut r, &format!("RVK {}", rvk_token(NONCE_A, 4)));
    assert_eq!(reply, "NAK wrong-grant");
    assert!(r.gate_open.get());
}

#[test]
fn a_store_failure_refuses_and_the_gate_stays_closed() {
    // Fail closed: a token whose seq cannot be made durable must not open
    // anything — else the replay mark falls behind the tokens in the wild.
    let mut r = rig();
    r.seq.fail_store.set(true);
    let reply = send(&mut r, &format!("TOK {}", cap_token(NONCE_A, 900, 1)));
    assert_eq!(reply, "NAK store-failed");
    assert!(!r.gate_open.get());
}

#[test]
fn revocation_is_idempotent_when_nothing_is_open() {
    let mut r = rig();
    let reply = send(&mut r, &format!("RVK {}", rvk_token(NONCE_A, 1)));
    assert_eq!(reply, "ACK closed");
}
