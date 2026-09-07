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

if [ "${failed}" -ne 0 ]; then
    echo "gate: FAILED"
    exit 1
fi
echo "gate: ok"
