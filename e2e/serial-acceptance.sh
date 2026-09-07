#!/bin/sh
# E2 acceptance: the generic serial channel against a pty-backed mock device,
# end to end through the real binaries and the REAL fd/termios transport (the
# same code path that will drive a physical tty — baud-set on the pty is the
# tolerated no-op). The mock's state file is the ground-truth oracle.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
here="$(dirname "$0")"
# shellcheck source=e2e/lib.sh
. "${here}/lib.sh"
work="$(mktemp -d /tmp/lychgate-serial-XXXXXX)"
state="${work}/state"
mkdir -p "${state}"

failed=0
fail() { echo "FAIL: $1" >&2; failed=1; }
note() { echo "==> $1"; }

for f in "${bin}/lychgated" "${bin}/lychgate"; do
    [ -x "${f}" ] || { echo "missing binary ${f}" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || {
    echo "python3 not found: the pty mock needs it (skipping is not failing)" >&2
    exit 2
}

cleanup() {
    [ -n "${daemon_pid:-}" ] && kill "${daemon_pid}" 2>/dev/null
    [ -n "${mock_pid:-}" ] && kill "${mock_pid}" 2>/dev/null
    rm -rf "${work}"
}
trap cleanup EXIT INT TERM

note "starting the pty device mock"
python3 "${here}/serial-mock.py" "${work}" &
mock_pid=$!
i=0
while [ ! -f "${work}/pts" ]; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "mock never announced its pty"; exit 1; }
    sleep 0.1
done
pts="$(cat "${work}/pts")"
note "device at ${pts}"

cat > "${work}/inventory.toml" <<EOF
[[hosts]]
name = "bench-1"
address = "local-serial"
os = "embedded"
channels = ["serial"]

[hosts.serial]
device = "${pts}"
baud = 115200
timeout_secs = 5

[hosts.serial.open]
send = "maint on\n"
expect = "OK MAINT ON"

[hosts.serial.revert]
send = "maint off\n"
expect = "OK MAINT OFF"

[hosts.serial.verify]
send = "maint?\n"
open_marker = "MAINT ON"
closed_marker = "MAINT OFF"
EOF
approval_keygen "${work}/approver"
approval_block "${work}/approver" >> "${work}/inventory.toml"

note "starting lychgated"
"${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" \
    --interval 600 > "${work}/daemon.log" 2>&1 &
daemon_pid=$!
i=0
while ! "${bin}/lychgate" --socket "${state}/lychgated.sock" status >/dev/null 2>&1; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "daemon never served"; cat "${work}/daemon.log"; exit 1; }
    sleep 0.1
done

note "opening the grant flips the device over the real tty path"
out="$(open_and_approve "${state}/lychgated.sock" bench-1 15m "${work}/approver")" \
    || { fail "open/approve refused: ${out}"; cat "${work}/daemon.log"; }
grep -q '"maint": true' "${work}/state.json" \
    || fail "device state not flipped open: $(cat "${work}/state.json")"

note "closing the grant reverts it"
"${bin}/lychgate" --socket "${state}/lychgated.sock" close --host bench-1 >/dev/null \
    || { fail "close refused"; cat "${work}/daemon.log"; }
grep -q '"maint": false' "${work}/state.json" \
    || fail "device state not reverted: $(cat "${work}/state.json")"

note "a dead device fails the open (silence is a timeout, not a state)"
kill "${mock_pid}" 2>/dev/null && wait "${mock_pid}" 2>/dev/null
mock_pid=""
if open_and_approve "${state}/lychgated.sock" bench-1 15m "${work}/approver" >/dev/null 2>&1; then
    fail "open succeeded against a dead device"
else
    note "dead device refused"
fi

kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

echo
if [ "${failed}" -ne 0 ]; then
    echo "serial-acceptance: FAILED"
    cat "${work}/daemon.log"
    exit 1
fi
echo "serial-acceptance: ok"
