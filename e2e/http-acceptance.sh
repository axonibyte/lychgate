#!/bin/sh
# E2 acceptance: the generic http channel against a mock device, end to end
# through the real binaries and the real curl transport. Proves the
# open/verify/close lifecycle reads ACTUAL device state (the mock's state
# file is the ground-truth oracle), and that a verify = "none" host surfaces
# its narrowing in the CLI output at open time.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
here="$(dirname "$0")"
# shellcheck source=e2e/lib.sh
. "${here}/lib.sh"
work="$(mktemp -d /tmp/lychgate-http-XXXXXX)"
state="${work}/state"
mkdir -p "${state}"

failed=0
fail() { echo "FAIL: $1" >&2; failed=1; }
note() { echo "==> $1"; }

for f in "${bin}/lychgated" "${bin}/lychgate"; do
    [ -x "${f}" ] || { echo "missing binary ${f}" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || {
    echo "python3 not found: the device mock needs it (skipping is not failing)" >&2
    exit 2
}

port=8760
mock_state="${work}/device.json"
echo '{"debug_uart": false}' > "${mock_state}"

cleanup() {
    [ -n "${daemon_pid:-}" ] && kill "${daemon_pid}" 2>/dev/null
    [ -n "${mock_pid:-}" ] && kill "${mock_pid}" 2>/dev/null
    rm -rf "${work}"
}
trap cleanup EXIT INT TERM

note "starting the http device mock on 127.0.0.1:${port}"
python3 "${here}/http-device-mock.py" "${port}" "${mock_state}" &
mock_pid=$!
i=0
while ! curl -s -o /dev/null "http://127.0.0.1:${port}/api/maint"; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "mock never came up"; exit 1; }
    sleep 0.1
done

cat > "${work}/inventory.toml" <<EOF
[[hosts]]
name = "cam-1"
address = "127.0.0.1"
os = "embedded"
channels = ["http"]

[hosts.http]
endpoint = "http://127.0.0.1:${port}"
tls = { mode = "insecure" }

[hosts.http.open]
method = "POST"
path = "/api/maint"
body = '{"debug_uart": true}'
expect_status = 200

[hosts.http.revert]
method = "POST"
path = "/api/maint"
body = '{"debug_uart": false}'
expect_status = 200

[hosts.http.verify]
method = "GET"
path = "/api/maint"
expect_status = 200
open_marker = '"debug_uart": true'
closed_marker = '"debug_uart": false'

# The same device again as a verify = "none" host: its open must carry the
# narrowing all the way to the CLI output.
[[hosts]]
name = "cam-blind"
address = "127.0.0.1"
os = "embedded"
channels = ["http"]

[hosts.http]
endpoint = "http://127.0.0.1:${port}"
tls = { mode = "insecure" }
verify = "none"

[hosts.http.open]
method = "POST"
path = "/api/maint"
body = '{"debug_uart": true}'
expect_status = 200

[hosts.http.revert]
method = "POST"
path = "/api/maint"
body = '{"debug_uart": false}'
expect_status = 200
EOF
approval_keygen "${work}/approver"
approval_block "${work}/approver" >> "${work}/inventory.toml"

note "starting lychgated"
"${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" \
    --interval 600 > "${work}/daemon.log" 2>&1 &
daemon_pid=$!
# Readiness = a status round trip, not a socket file (the M8a.4 lesson).
i=0
while ! "${bin}/lychgate" --socket "${state}/lychgated.sock" status >/dev/null 2>&1; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "daemon never served"; cat "${work}/daemon.log"; exit 1; }
    sleep 0.1
done

note "opening the verified grant (open -> sign -> approve)"
out="$(open_and_approve "${state}/lychgated.sock" cam-1 15m "${work}/approver")" \
    || { fail "open/approve refused: ${out}"; cat "${work}/daemon.log"; }
grep -q '"debug_uart": true' "${mock_state}" \
    || fail "device state not flipped open: $(cat "${mock_state}")"
if echo "${out}" | grep -q "NARROWING:"; then
    fail "a fully-verified open must not print a narrowing"
fi

note "closing the grant reverts the device"
"${bin}/lychgate" --socket "${state}/lychgated.sock" close --host cam-1 >/dev/null \
    || { fail "close refused"; cat "${work}/daemon.log"; }
grep -q '"debug_uart": false' "${mock_state}" \
    || fail "device state not reverted: $(cat "${mock_state}")"

note "a verify = none open surfaces its narrowing in the CLI output"
out="$(open_and_approve "${state}/lychgated.sock" cam-blind 15m "${work}/approver")" \
    || { fail "open/approve on cam-blind refused: ${out}"; cat "${work}/daemon.log"; }
echo "${out}" | grep -q 'NARROWING:.*verify = "none"' \
    || fail "the verify-none narrowing did not reach the operator: ${out}"
"${bin}/lychgate" --socket "${state}/lychgated.sock" close --host cam-blind >/dev/null \
    || fail "close on cam-blind refused"

note "a dead device fails the open instead of pretending"
kill "${mock_pid}" 2>/dev/null && wait "${mock_pid}" 2>/dev/null
mock_pid=""
if open_and_approve "${state}/lychgated.sock" cam-1 15m "${work}/approver" >/dev/null 2>&1; then
    fail "open succeeded against a dead device"
else
    note "dead device refused"
fi

kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

echo
if [ "${failed}" -ne 0 ]; then
    echo "http-acceptance: FAILED"
    cat "${work}/daemon.log"
    exit 1
fi
echo "http-acceptance: ok"
