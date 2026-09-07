#!/bin/sh
# E7a acceptance: the lghmac authenticator kind end to end — a "device"
# (python3 standing in for the AVR + shared secret) computes
# HMAC-SHA256(secret, challenge) and the daemon accepts exactly the right
# one. The challenge binding IS the anti-replay (no ledger), so the closing
# act replays a stale-but-valid token against a fresh request and watches it
# refuse.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
here="$(dirname "$0")"
# shellcheck source=e2e/lib.sh
. "${here}/lib.sh"
work="$(mktemp -d /tmp/lychgate-hmac-XXXXXX)"
state="${work}/state"
mkdir -p "${state}"

failed=0
fail() { echo "FAIL: $1" >&2; failed=1; }
note() { echo "==> $1"; }

for f in "${bin}/lychgated" "${bin}/lychgate"; do
    [ -x "${f}" ] || { echo "missing binary ${f}" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || {
    echo "python3 not found: the device-side HMAC needs it (skipping is not failing)" >&2
    exit 2
}

cleanup() {
    [ -n "${daemon_pid:-}" ] && kill "${daemon_pid}" 2>/dev/null
    rm -rf "${work}"
}
trap cleanup EXIT INT TERM

secret_hex="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
printf '%s' "${secret_hex}" > "${work}/fixture.hmac"
chmod 600 "${work}/fixture.hmac"

cat > "${work}/inventory.toml" <<EOF
[[hosts]]
name = "db-01"
address = "10.0.4.11"
os = "linux"
channels = ["ssh"]
[hosts.ssh]
agent_user = "root"
root_posture_default = "no"
root_posture_emergency = "yes"

[[approval.authenticator]]
id = "fixture"
kind = "hmac"
secret-file = "${work}/fixture.hmac"

[[approval.profile]]
id = "device"
threshold = 1
factor = [ { authenticator = "fixture", weight = 1 } ]
EOF

# The "device": HMAC-SHA256 over the challenge, base64url-nopad, lghmac. prefix.
device_sign() {
    python3 -c "
import hmac, hashlib, base64, sys
secret = bytes.fromhex('${secret_hex}')
mac = hmac.new(secret, sys.argv[1].encode(), hashlib.sha256).digest()
print('lghmac.' + base64.urlsafe_b64encode(mac).decode().rstrip('='))
" "$1"
}

# NOTE: --dry-run does NO proof verification, so it cannot host this test
# (the M8a.5 lesson). The daemon runs for real: the ssh channel will fail to
# open against the fake address, but the APPROVAL verdicts — what this
# acceptance tests — are rendered before any driving.
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

grep_challenge() {
    "${bin}/lychgate" --socket "${state}/lychgated.sock" open --host db-01 --ttl 1h --as device 2>&1
}

note "a correct device MAC satisfies the factor"
out="$(grep_challenge)"
challenge="$(echo "${out}" | grep -oE 'lg1\.req\.[A-Za-z0-9_-]+' | head -1)"
[ -n "${challenge}" ] || { fail "no challenge in open output: ${out}"; exit 1; }
token="$(device_sign "${challenge}")"
stale_token="${token}"
approve_out="$(printf '%s' "${token}" | "${bin}/lychgate" --socket "${state}/lychgated.sock" approve --host db-01 2>&1)" \
    || true
# The approval must be ACCEPTED (the grant then tries to open its ssh channel
# against a dead host and fails — that is the driver's business, not the
# factor's; an approval refusal would say "refused" before any driving).
case "${approve_out}" in
    *"proof refused"*|*"approval refused"*) fail "a correct MAC was refused: ${approve_out}" ;;
    *) note "MAC accepted (driver outcome: irrelevant here)" ;;
esac
"${bin}/lychgate" --socket "${state}/lychgated.sock" close --host db-01 >/dev/null 2>&1 || true

note "a wrong-secret MAC is refused"
out="$(grep_challenge)"
challenge="$(echo "${out}" | grep -oE 'lg1\.req\.[A-Za-z0-9_-]+' | head -1)"
bad="$(python3 -c "
import hmac, hashlib, base64, sys
mac = hmac.new(b'not-the-secret', sys.argv[1].encode(), hashlib.sha256).digest()
print('lghmac.' + base64.urlsafe_b64encode(mac).decode().rstrip('='))
" "${challenge}")"
if printf '%s' "${bad}" | "${bin}/lychgate" --socket "${state}/lychgated.sock" approve --host db-01 >/dev/null 2>&1; then
    fail "a wrong-secret MAC was accepted"
else
    note "wrong secret refused"
fi

note "a stale-but-valid token from an earlier challenge is refused (challenge binding = anti-replay)"
if printf '%s' "${stale_token}" | "${bin}/lychgate" --socket "${state}/lychgated.sock" approve --host db-01 >/dev/null 2>&1; then
    fail "a stale token was accepted against a fresh challenge"
else
    note "stale token refused"
fi

kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

echo
if [ "${failed}" -ne 0 ]; then
    echo "hmac-acceptance: FAILED"
    cat "${work}/daemon.log"
    exit 1
fi
echo "hmac-acceptance: ok"
