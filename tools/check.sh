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

if [ "${failed}" -ne 0 ]; then
    echo "gate: FAILED"
    exit 1
fi
echo "gate: ok"
