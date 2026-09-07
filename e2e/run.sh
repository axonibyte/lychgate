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

# The dead-man rides cron on the managed host. FreeBSD ships it in base;
# stock Ubuntu server does not, so install and start it here. A managed host
# without cron is a real, documented prerequisite — the daemon fails an open
# closed when it is missing (see README), and these guests must provide it.
ensure_cron() {
    if command -v crontab >/dev/null 2>&1; then
        return 0
    fi
    echo "=== provisioning cron (the dead-man's scheduler) ==="
    if command -v apt-get >/dev/null 2>&1; then
        apt-get -qq update >/dev/null 2>&1 || true
        apt-get -qq install -y cron >/dev/null 2>&1 || true
        systemctl enable --now cron >/dev/null 2>&1 || service cron start >/dev/null 2>&1 || true
    fi
    command -v crontab >/dev/null 2>&1
}

# The BMC acceptance's Redfish mock is Python. FreeBSD base has no python3;
# install it (Ubuntu ships it). Best-effort — the acceptance skips loudly if
# it is still missing.
ensure_python() {
    command -v python3 >/dev/null 2>&1 && return 0
    if command -v pkg >/dev/null 2>&1; then pkg install -y python3 >/dev/null 2>&1 || true; fi
    if command -v apt-get >/dev/null 2>&1; then apt-get -qq install -y python3 >/dev/null 2>&1 || true; fi
    command -v python3 >/dev/null 2>&1
}

# The Ubuntu container build produces tpm-feature binaries (linking libtss2),
# so the host needs the runtime libs and swtpm for the tpm acceptance. Best
# effort where apt exists; the FreeBSD guest runs default binaries and the tpm
# phase skips there instead.
ensure_tpm() {
    if command -v apt-get >/dev/null 2>&1; then
        apt-get -qq install -y libtss2-dev swtpm >/dev/null 2>&1 || true
    fi
}

# The mqtt acceptance needs a broker and its clients; best-effort on both
# package systems, and the phase is tri-state skippable if neither lands.
ensure_mosquitto() {
    if command -v mosquitto >/dev/null 2>&1; then
        return
    fi
    if command -v apt-get >/dev/null 2>&1; then
        apt-get -qq update >/dev/null 2>&1 || true
        apt-get -qq install -y mosquitto mosquitto-clients >/dev/null 2>&1 || true
        # Debian auto-starts the system broker; the test runs its own on a
        # dedicated port, so the service is stopped where possible.
        service mosquitto stop >/dev/null 2>&1 || true
    elif command -v pkg >/dev/null 2>&1; then
        pkg install -qy mosquitto >/dev/null 2>&1 || true
    fi
}

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

# A phase whose script may legitimately not apply on this guest: exit 2 means
# SKIPPED (the script says why, loudly) and does not fail the battery; any
# other nonzero is a real failure. Tri-state on purpose — a skip must never
# be mistakable for a pass, nor punish a guest that cannot run the phase.
phase_skippable() {
    label=$1
    shift
    echo ""
    echo "=== ${label} ==="
    "$@"
    rc=$?
    if [ "${rc}" -eq 0 ]; then
        echo "=== ${label}: ok ==="
    elif [ "${rc}" -eq 2 ]; then
        echo "=== ${label}: SKIPPED on this guest (see above) ==="
    else
        echo "=== ${label}: FAILED ==="
        failed=1
    fi
}

if ! ensure_cron; then
    echo "e2e battery: FAILED (could not provision cron; the dead-man cannot run)"
    exit 1
fi
ensure_python || echo "=== python3 unavailable; the bmc acceptance will skip ==="
ensure_tpm

# Unit suites: run here when a toolchain exists (the FreeBSD guest); on the
# Ubuntu guest they already ran inside the pinned build container — said
# loudly, not skipped silently.
if command -v cargo >/dev/null 2>&1; then
    phase "workspace unit suites" cargo test --workspace --locked --quiet
else
    echo "=== workspace unit suites: ran in the build container (no host toolchain) ==="
fi

phase "ssh acceptance" sh e2e/ssh-acceptance.sh

phase "bmc acceptance" sh e2e/bmc-acceptance.sh

phase "vnc acceptance" sh e2e/vnc-acceptance.sh

phase "approval acceptance" sh e2e/approval-acceptance.sh

phase "authority acceptance" sh e2e/authority-acceptance.sh

phase "totp acceptance" sh e2e/totp-acceptance.sh

phase "password acceptance" sh e2e/password-acceptance.sh

phase "hmac acceptance" sh e2e/hmac-acceptance.sh

phase "fido2 acceptance" sh e2e/fido2-acceptance.sh

phase "mcp acceptance" sh e2e/mcp-acceptance.sh

phase "drill acceptance" sh e2e/drill-acceptance.sh

phase "http acceptance" sh e2e/http-acceptance.sh

phase "serial acceptance" sh e2e/serial-acceptance.sh

ensure_mosquitto
phase_skippable "mqtt acceptance" sh e2e/mqtt-acceptance.sh

phase_skippable "device acceptance" sh e2e/device-acceptance.sh

phase_skippable "actuator acceptance" sh e2e/actuator-acceptance.sh

phase_skippable "tpm acceptance" sh e2e/tpm-acceptance.sh

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
