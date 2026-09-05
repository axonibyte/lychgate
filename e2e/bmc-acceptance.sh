#!/bin/sh
# M6 acceptance: the BMC driver against a real (mock) Redfish AccountService
# over HTTP, end to end through the real binaries and the real curl
# transport. Not a bench iDRAC — a minimal mock we control — but it proves
# curl + Basic auth + GET/PATCH + the full open/close lifecycle, which no
# fixture or scripted-transport test reaches.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
here="$(dirname "$0")"
# shellcheck source=e2e/lib.sh
. "${here}/lib.sh"
work="$(mktemp -d /tmp/lychgate-bmc-XXXXXX)"
state="${work}/state"
mkdir -p "${state}"

failed=0
fail() { echo "FAIL: $1" >&2; failed=1; }
note() { echo "==> $1"; }

for f in "${bin}/lychgated" "${bin}/lychgate"; do
    [ -x "${f}" ] || { echo "missing binary ${f}" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || {
    echo "python3 not found: the Redfish mock needs it (skipping is not failing)" >&2
    exit 2
}

port=8730
mock_state="${work}/redfish.json"
echo '{"UserName":"breakglass","Enabled":false}' > "${mock_state}"
echo "s3cr3t-auth" > "${work}/bmc.pw"

cleanup() {
    [ -n "${daemon_pid:-}" ] && kill "${daemon_pid}" 2>/dev/null
    [ -n "${mock_pid:-}" ] && kill "${mock_pid}" 2>/dev/null
    rm -rf "${work}"
}
trap cleanup EXIT INT TERM

note "starting the Redfish mock on 127.0.0.1:${port}"
python3 "${here}/redfish-mock.py" "${port}" "${mock_state}" admin s3cr3t-auth 4 &
mock_pid=$!
# Wait for it to accept.
i=0
while ! curl -s -o /dev/null "http://127.0.0.1:${port}/redfish/v1/AccountService/Accounts/4"; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "mock never came up"; exit 1; }
    sleep 0.1
done

cat > "${work}/inventory.toml" <<EOF
[[hosts]]
name = "idrac"
address = "unused"
os = "linux"
channels = ["bmc"]

[hosts.bmc]
endpoint = "http://127.0.0.1:${port}"
method = "redfish"
account_user = "breakglass"
account_id = "4"
auth_user = "admin"
auth_password_file = "${work}/bmc.pw"
tls = { mode = "insecure" }
EOF
approval_keygen "${work}/approver"
approval_block "${work}/approver" >> "${work}/inventory.toml"

note "starting lychgated"
"${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" \
    --interval 600 > "${work}/daemon.log" 2>&1 &
daemon_pid=$!
i=0
while [ ! -S "${state}/lychgated.sock" ]; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "daemon never bound"; cat "${work}/daemon.log"; exit 1; }
    sleep 0.1
done

note "opening the grant (open -> sign -> approve)"
out="$(open_and_approve "${state}/lychgated.sock" idrac 15m "${work}/approver")" \
    || { fail "open/approve refused: ${out}"; cat "${work}/daemon.log"; }

# The account is enabled on the mock...
grep -q '"Enabled": true' "${mock_state}" || fail "account not enabled after open: $(cat "${mock_state}")"
# ...its password was rotated to a fresh value (not the seed, which had none)...
python3 -c "import json,sys; sys.exit(0 if json.load(open('${mock_state}')).get('Password') else 1)" \
    || fail "account password was not set"
# ...the CLI showed the password exactly once...
echo "${out}" | grep -q "break-glass BMC password (shown once):" \
    || fail "the CLI did not surface the break-glass password"
# ...and it is nowhere in the journal.
shown="$(echo "${out}" | sed -n 's/.*shown once): //p')"
if [ -n "${shown}" ] && grep -qF "${shown}" "${state}/journal.jsonl"; then
    fail "the break-glass password leaked into the journal"
else
    note "password shown once and absent from the journal"
fi

note "closing the grant"
"${bin}/lychgate" --socket "${state}/lychgated.sock" close --host idrac >/dev/null \
    || { fail "close refused"; cat "${work}/daemon.log"; }
grep -q '"Enabled": false' "${mock_state}" || fail "account not disabled after close: $(cat "${mock_state}")"

# A slot held by a stranger is refused, touching nothing. Since M8 the driver
# runs at approve, not open, so the refusal now surfaces there — open_and_approve
# returns non-zero either way.
echo '{"UserName":"root","Enabled":true}' > "${mock_state}"
if open_and_approve "${state}/lychgated.sock" idrac 15m "${work}/approver" >/dev/null 2>&1; then
    fail "open/approve succeeded against a slot held by a stranger"
else
    grep -q '"UserName": "root"' "${mock_state}" || fail "the stranger's account was modified"
    note "a stranger-held slot is refused, untouched"
fi

kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

echo
if [ "${failed}" -ne 0 ]; then
    echo "bmc-acceptance: FAILED"
    cat "${work}/daemon.log"
    exit 1
fi
echo "bmc-acceptance: ok"
