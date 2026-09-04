#!/bin/sh
# The Tier-4 battery, run as root on a reaper guest (or any disposable
# host). Every phase runs; failures are aggregated, never masked. This is
# also the tenant [run] command — no pipes anywhere near an exit status.
#
# Env: LYCHGATE_BIN_DIR overrides where the binaries are; otherwise
# $REAPER_CACHE_TARGET/debug (a reaper session) or ./target/debug.

set -u

cd "$(dirname "$0")/.." || exit 2

if [ -z "${LYCHGATE_BIN_DIR:-}" ]; then
    if [ -n "${REAPER_CACHE_TARGET:-}" ]; then
        LYCHGATE_BIN_DIR="${REAPER_CACHE_TARGET}/debug"
    else
        LYCHGATE_BIN_DIR="./target/debug"
    fi
fi
export LYCHGATE_BIN_DIR

failed=0
phase() {
    label=$1
    shift
    echo ""
    echo "=== ${label} ==="
    if "$@"; then
        echo "=== ${label}: ok ==="
    else
        echo "=== ${label}: FAILED ==="
        failed=1
    fi
}

# Unit suites: run here when a toolchain exists (the FreeBSD guest); on the
# Ubuntu guest they already ran inside the pinned build container — said
# loudly, not skipped silently.
if command -v cargo >/dev/null 2>&1; then
    phase "workspace unit suites" cargo test --workspace --locked --quiet
else
    echo "=== workspace unit suites: ran in the build container (no host toolchain) ==="
fi

phase "ssh acceptance" sh e2e/ssh-acceptance.sh

# The oracle self-test: with the dead-man sabotaged away, revert-under-kill
# MUST fail. A harness that passes here detects nothing.
echo ""
echo "=== revert-under-kill oracle self-test (sabotaged; must fail) ==="
if sh e2e/revert-under-kill.sh --sabotage; then
    echo "=== oracle self-test: FAILED (the harness missed a dead backstop) ==="
    failed=1
else
    echo "=== oracle self-test: ok (the harness caught the missing backstop) ==="
fi

phase "revert-under-kill" sh e2e/revert-under-kill.sh

phase "service start/stop" sh e2e/service-start.sh

echo ""
if [ "${failed}" -ne 0 ]; then
    echo "e2e battery: FAILED"
    exit 1
fi
echo "e2e battery: ok"
