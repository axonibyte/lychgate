#!/bin/sh
# lychgate gate: everything that can be checked without a network or a
# hypervisor. This is what a commit is expected to pass. It deliberately runs
# every phase rather than stopping at the first failure, because knowing that
# three things broke is worth more than knowing that one did.

set -u

failed=0

run() {
    label=$1
    shift
    echo "==> ${label}"
    if "$@"; then
        echo "    ok"
    else
        echo "    FAILED: ${label}"
        failed=1
    fi
}

run "rust fmt" cargo fmt --check

# Strict flags get their own target dir so they do not thrash the ordinary
# build cache.
run "rust clippy" env CARGO_TARGET_DIR=target/clippy \
    cargo clippy --workspace --all-targets --locked -- -D warnings

run "rust tests" cargo test --workspace --locked

run "shell lint" ./tools/lint-shell.sh

run "service installer" ./tools/install-service-test.sh

# The Windows client is the one target nothing else here compiles, and a
# unix-only API in the cli breaks it invisibly (it did once — an ungated chmod
# shipped an entire milestone before CI surfaced it). `cargo check` needs the
# target's rust-std but no linker, so it runs wherever that std exists (rustup
# hosts, the Ubuntu guest's build container) and is skipped LOUDLY elsewhere —
# the guest battery and CI still enforce it on every run.
windows_client_check() {
    sysroot=$(rustc --print sysroot 2>/dev/null)
    if [ -n "${sysroot}" ] && [ -d "${sysroot}/lib/rustlib/x86_64-pc-windows-gnu" ]; then
        env CARGO_TARGET_DIR=target/windows-check \
            cargo check -p lychgate --target x86_64-pc-windows-gnu --locked
    else
        echo "    SKIPPED here: no x86_64-pc-windows-gnu rust-std in this toolchain."
        echo "    The check runs in the Ubuntu guest's build container (reaper test)"
        echo "    and CI builds the target fully; do not close a cli-touching"
        echo "    milestone without one of those."
    fi
}
run "windows client check" windows_client_check

# lychgate-wire is compiled into firmware: its load-bearing code must stay
# no_std. Without default features the crate's #![no_std] is active, so any
# std leakage fails this cheap host check — no cross toolchain needed. The
# real embedded target (riscv32imc) is checked below where its rust-std
# exists, and enforced in the Ubuntu guest container and CI regardless.
run "wire no_std check" env CARGO_TARGET_DIR=target/nostd-check \
    cargo check -p lychgate-wire -p lychgate-embed --no-default-features --locked

wire_embedded_target_check() {
    sysroot=$(rustc --print sysroot 2>/dev/null)
    if [ -n "${sysroot}" ] && [ -d "${sysroot}/lib/rustlib/riscv32imc-unknown-none-elf" ]; then
        env CARGO_TARGET_DIR=target/riscv-check \
            cargo check -p lychgate-wire -p lychgate-embed --no-default-features \
            --target riscv32imc-unknown-none-elf --locked
    else
        echo "    SKIPPED here: no riscv32imc-unknown-none-elf rust-std in this toolchain."
        echo "    The check runs in the Ubuntu guest's build container (reaper test)"
        echo "    and in CI; do not close a wire-touching milestone without one."
    fi
}
run "wire embedded target check" wire_embedded_target_check

# The reference firmware is its own excluded workspace. Its pure logic crate
# (the flash seq-record codec) host-tests everywhere; the riscv app compile
# runs where the target's rust-std exists (same probe as above).
firmware_logic_test() {
    host=$(rustc -vV | sed -n 's/host: //p')
    env CARGO_TARGET_DIR=target/fw-logic cargo test \
        --manifest-path firmware/esp32c3/Cargo.toml -p lychgate-esp32c3-logic \
        --target "${host}" --locked --quiet
}
run "firmware logic tests" firmware_logic_test

firmware_app_check() {
    sysroot=$(rustc --print sysroot 2>/dev/null)
    if [ -n "${sysroot}" ] && [ -d "${sysroot}/lib/rustlib/riscv32imc-unknown-none-elf" ]; then
        env CARGO_TARGET_DIR=target/fw-check \
            cargo check --manifest-path firmware/esp32c3/Cargo.toml --target riscv32imc-unknown-none-elf --locked &&
        env CARGO_TARGET_DIR=target/fw-check \
            cargo check --manifest-path firmware/esp32c3/Cargo.toml --target riscv32imc-unknown-none-elf --features se --locked
    else
        echo "    SKIPPED here: no riscv32imc-unknown-none-elf rust-std in this toolchain."
        echo "    The check runs in the Ubuntu guest's build container (reaper test)"
        echo "    and in CI; do not close a firmware-touching milestone without one."
    fi
}
run "firmware app check" firmware_app_check

# The tier-A C library: the shared-vector KAT harness runs wherever a host C
# compiler exists (everywhere we build); the atmega328p compile runs where
# avr-gcc is installed and is enforced in the Ubuntu guest container and CI.
run "avr library tests" make -C avr test

avr_check() {
    if command -v avr-gcc >/dev/null 2>&1; then
        make -C avr avr-check
    else
        echo "    SKIPPED here: no avr-gcc in PATH."
        echo "    The check runs in the Ubuntu guest's build container (reaper test)"
        echo "    and in CI; do not close an avr-touching milestone without one."
    fi
}
run "avr target check" avr_check

# The FPGA gate (E9): simulation + its broken-gate oracle self-test run
# wherever iverilog exists; the FORMAL pair (k-induction proof + the prover
# catching the committed mutation) runs where SymbiYosys exists — Debian
# packages no sby, so CI carries only the sim pair and the formal claim is
# enforced on sby hosts (this is a named narrowing, recorded in TESTING.md).
fpga_sim() {
    if command -v iverilog >/dev/null 2>&1; then
        make -C fpga sim && make -C fpga sim-mutation
    else
        echo "    SKIPPED here: no iverilog in PATH."
        echo "    CI and the Ubuntu guest container run the sim pair."
    fi
}
run "fpga gate sim" fpga_sim

fpga_formal() {
    if command -v sby >/dev/null 2>&1; then
        make -C fpga formal && make -C fpga formal-mutation
    else
        echo "    SKIPPED here: no SymbiYosys (sby) in PATH."
        echo "    Debian/CI package no sby; the formal proof is enforced on sby"
        echo "    hosts (this workstation has one) — do not close an rtl-touching"
        echo "    change without a formal run somewhere."
    fi
}
run "fpga gate formal" fpga_formal

if [ "${failed}" -ne 0 ]; then
    echo "gate: FAILED"
    exit 1
fi
echo "gate: ok"
