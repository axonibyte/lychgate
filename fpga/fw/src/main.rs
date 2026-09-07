//! The soft-core verifier: the SAME `lychgate_wire::verify_capability` the
//! daemon signs against and the device firmware compiles, running on a
//! picorv32 behind the formally-proved lg_gate. The core's entire authority
//! is: verify a token, then LOAD the counter (or refuse); the gate's enable
//! is combinational on the counter and owes this code nothing — which the
//! verilator harness demonstrates by watching the gate drop while this loop
//! is still running.
//!
//! Trust root and identity are the bench constants shared with the wire KAT
//! vectors, so the harness feeds the committed vectors verbatim.

#![no_std]
#![no_main]

use lychgate_wire::{verify_capability, PublicKey};

const MMIO: usize = 0x1000_0000;
const REG_TOKEN_READY: usize = MMIO;
const REG_TOKEN_LEN: usize = MMIO + 0x4;
const REG_RESULT: usize = MMIO + 0x8;
const REG_GATE_LOAD: usize = MMIO + 0xc;
const TOKEN_BASE: usize = MMIO + 0x400;

/// The wire KAT bench identity (device_id 000102…0f) and the public half of
/// the 0x11-seed signing key — the committed vectors verify against these.
const DEVICE_ID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const PUBKEY: [u8; 32] = [
    0xd0, 0x4a, 0xb2, 0x32, 0x74, 0x2b, 0xb4, 0xab, 0x3a, 0x13, 0x68, 0xbd, 0x46, 0x15, 0xe4,
    0xe6, 0xd0, 0x22, 0x4a, 0xb7, 0x1a, 0x01, 0x6b, 0xaf, 0x85, 0x20, 0xa3, 0x32, 0xc9, 0x77,
    0x87, 0x37,
];

const RESULT_LOADED: u32 = 1;
const RESULT_REFUSED: u32 = 2;
const RESULT_PANIC: u32 = 3;

#[inline(always)]
fn mmio_read(addr: usize) -> u32 {
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

#[inline(always)]
fn mmio_write(addr: usize, value: u32) {
    unsafe { core::ptr::write_volatile(addr as *mut u32, value) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    mmio_write(REG_RESULT, RESULT_PANIC);
    loop {}
}

core::arch::global_asm!(
    ".section .text._start",
    ".globl _start",
    "_start:",
    // The stack pointer: STACKADDR is the top of RAM; picorv32 does not set
    // registers, so do it here before any Rust runs.
    "li sp, 0x00100000",
    "call main",
    "1: j 1b",
);

#[no_mangle]
extern "C" fn main() {
    // Wait for the harness to raise a token.
    while mmio_read(REG_TOKEN_READY) == 0 {}

    let len = mmio_read(REG_TOKEN_LEN) as usize;
    let mut buf = [0u8; 256];
    if len > buf.len() {
        mmio_write(REG_RESULT, RESULT_REFUSED);
        return;
    }
    for (i, slot) in buf.iter_mut().take(len).enumerate() {
        *slot = mmio_read(TOKEN_BASE + 4 * i) as u8;
    }

    let verdict = core::str::from_utf8(&buf[..len])
        .ok()
        .and_then(|token| verify_capability(&PublicKey::Ed25519(&PUBKEY), token).ok())
        .filter(|cap| cap.device_id == DEVICE_ID);

    match verdict {
        Some(cap) => {
            // Load the gate; the counter takes it from here — this loop has
            // no further influence on gate_en, by construction and by proof.
            mmio_write(REG_GATE_LOAD, cap.ttl_secs.min(0x1_ffff));
            mmio_write(REG_RESULT, RESULT_LOADED);
        }
        None => {
            mmio_write(REG_RESULT, RESULT_REFUSED);
        }
    }
    // Keep running (the harness watches the gate drop with the core alive).
}
