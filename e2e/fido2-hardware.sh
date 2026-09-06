#!/bin/sh
# M8a.5 hardware acceptance: the CTAP2 client (the `fido2-client` cargo feature)
# driving a REAL authenticator over USB-HID, verified by the daemon. This is the
# one path with no default-CI oracle — there is no FIDO2 hardware on the build
# guests. It is exercised two ways, both manual:
#
#   1. against a physical key (a one-time ceremony per key model), and
#   2. against a VIRTUAL authenticator over USB/IP — the simulated tier that
#      makes this runnable without hardware. See TESTING.md for standing up the
#      virtual-fido device; once `/dev/hidraw*` shows a FIDO device, this script
#      is identical whether the key is silicon or software.
#
# It drives the REAL vnc channel (as fido2-acceptance.sh does), NOT --dry-run:
# --dry-run keeps grants as bookkeeping and does not verify the proof, so it
# would never exercise the assertion. Run as root on a DISPOSABLE host: it
# touches root's authorized_keys, restoring it on the way out.
#
# It needs binaries built WITH the feature:
#     cargo build -p lychgate  --features fido2-client   # unix; needs hidapi
#     cargo build -p lychgated                            # default
#
# The policy: profile "hw" — threshold 1 over a single fido2 credential. Claims:
#   1. a stale-challenge assertion is refused (the challenge binding) and leaves
#      the grant pending;
#   2. the genuine assertion over the pending challenge opens the grant — the
#      daemon verified a real hardware assertion.
#
# Exit codes: 0 pass, 1 a real failure, 2 SKIPPED (feature not built, or no
# authenticator attached) — 2 is loud on purpose, never mistaken for a pass.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug); FIDO2_ALG (es256|eddsa,
# default es256); FIDO2_PIN (optional, for a key that requires one).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
alg="${FIDO2_ALG:-es256}"
here="$(dirname "$0")"
work="$(mktemp -d /tmp/lychgate-fido2hw-XXXXXX)"
state="${work}/state"
sock="${state}/lychgated.sock"
mkdir -p "${state}"

failed=0
fail() { echo "FAIL: $1" >&2; failed=1; }
note() { echo "==> $1"; }
skip() { echo "fido2-hardware: SKIPPED ($1)"; exit 2; }

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root on a disposable host" >&2
    exit 2
fi
for f in "${bin}/lychgated" "${bin}/lychgate"; do
    [ -x "${f}" ] || { echo "missing binary ${f}" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || { echo "python3 not found: the RFB mock needs it" >&2; exit 2; }

pin_args=""
[ -n "${FIDO2_PIN:-}" ] && pin_args="--pin ${FIDO2_PIN}"

akeys="/root/.ssh/authorized_keys"
mkdir -p /root/.ssh
touch "${akeys}"
cp "${akeys}" "${work}/authorized_keys.orig"

cleanup() {
    [ -n "${daemon_pid:-}" ] && kill -9 "${daemon_pid}" 2>/dev/null
    [ -n "${mock_pid:-}" ] && kill "${mock_pid}" 2>/dev/null
    pkill -f "ssh -N.*ExitOnForwardFailure" 2>/dev/null
    cp "${work}/authorized_keys.orig" "${akeys}" 2>/dev/null
    rm -rf "${work}"
}
trap cleanup EXIT INT TERM

# --- register on the attached authenticator, distinguishing the skip cases ----

note "registering a ${alg} credential on the attached authenticator (touch it)"
# shellcheck disable=SC2086
if ! "${bin}/lychgate" fido2-register --alg "${alg}" ${pin_args} \
        > "${work}/block" 2> "${work}/reg.err"; then
    grep -q "no hardware FIDO2 support" "${work}/reg.err" \
        && skip "binaries not built with --features fido2-client"
    grep -qi "no FIDO2 authenticator found" "${work}/reg.err" \
        && skip "no FIDO2 authenticator attached"
    echo "--- register stderr ---" >&2
    cat "${work}/reg.err" >&2
    fail "registration failed"
    exit 1
fi
field() { sed -n "s/^$1 = \"\\(.*\\)\"\$/\\1/p" "${work}/block"; }
cred="$(field credential-id)"
pub="$(field public-key)"
[ -n "${cred}" ] && [ -n "${pub}" ] || { echo "register block missing fields" >&2; cat "${work}/block" >&2; exit 1; }
note "registered credential-id=${cred}"

# --- a real (vnc) channel so the daemon verifies the proof and drives an open -

ssh-keygen -q -t ed25519 -N "" -C "agent" -f "${work}/agent" </dev/null
cat "${work}/agent.pub" >> "${akeys}"
ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "${work}/agent" \
    root@127.0.0.1 true || { echo "cannot ssh to self; aborting" >&2; exit 2; }

free_port() {
    python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}
rfb_port="$(free_port)"
local_port="$(free_port)"

cat > "${work}/set-vnc-pw.sh" <<EOF
#!/bin/sh
printf 'set %s\n' "\$1" >> "${work}/witness.log"
EOF
cat > "${work}/clear-vnc-pw.sh" <<EOF
#!/bin/sh
printf 'clear %s\n' "\$1" >> "${work}/witness.log"
EOF
chmod +x "${work}/set-vnc-pw.sh" "${work}/clear-vnc-pw.sh"

os="linux"
[ "$(uname -s)" = "FreeBSD" ] && os="freebsd"

cat > "${work}/inventory.toml" <<EOF
[[hosts]]
name = "hv"
address = "127.0.0.1"
os = "${os}"
channels = ["vnc"]

[hosts.vnc]
agent_user = "root"
identity_file = "${work}/agent"
rfb_host = "127.0.0.1"
rfb_port = ${rfb_port}
local_port = ${local_port}
target = "acc-vm"
set_password_cmd = "${work}/set-vnc-pw.sh {target} {password_file}"
clear_password_cmd = "${work}/clear-vnc-pw.sh {target}"
password_file = "${work}/staged.pw"

[hosts.access]
profiles = ["hw"]

[[approval.authenticator]]
id = "key"
kind = "fido2"
alg = "${alg}"
credential-id = "${cred}"
public-key = "${pub}"

[[approval.profile]]
id = "hw"
threshold = 1
factor = [ { authenticator = "key", weight = 1 } ]
EOF

note "starting the RFB mock on 127.0.0.1:${rfb_port}"
python3 "${here}/rfb-mock.py" "${rfb_port}" &
mock_pid=$!

note "starting lychgated (real vnc channel + fido2)"
"${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" \
    --interval 600 --approval-window 120 > "${work}/daemon.log" 2>&1 &
daemon_pid=$!
i=0
while [ ! -S "${sock}" ]; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "daemon never bound"; cat "${work}/daemon.log"; exit 1; }
    sleep 0.1
done

is_open() {
    "${bin}/lychgate" --socket "${sock}" status | grep -qE '^hv[[:space:]]+open'
}

# One grant, two approvals on the same pending request: a refused proof does not
# consume the pending, so the challenge binding and the accept are proven on a
# single open.
challenge="$("${bin}/lychgate" --socket "${sock}" open --host hv --ttl 15m --as hw \
    | sed -n 's/^challenge: //p')"
[ -n "${challenge}" ] || fail "open returned no challenge"

# --- 1: an assertion for a DIFFERENT challenge is refused (challenge binding) --

note "a stale-challenge assertion is refused (touch the key)"
# shellcheck disable=SC2086
stale="$("${bin}/lychgate" fido2-assert --challenge 'lg1.req.STALE-NONCE' \
    --credential-id "${cred}" ${pin_args} 2>/dev/null)"
if printf '%s' "${stale}" | "${bin}/lychgate" --socket "${sock}" approve --host hv >/dev/null 2>&1; then
    fail "a stale-challenge hardware assertion was accepted"
elif is_open; then
    fail "the grant opened on a stale-challenge assertion"
else
    note "the stale-challenge assertion was refused; the grant stays pending"
fi

# --- 2: the genuine assertion over THIS challenge opens the grant -------------

note "asserting over the pending challenge (touch the key)"
# shellcheck disable=SC2086
token="$("${bin}/lychgate" fido2-assert --challenge "${challenge}" \
    --credential-id "${cred}" ${pin_args} 2> "${work}/assert.err")"
case "${token}" in
    lgfido2.*) : ;;
    *) fail "assertion did not produce an lgfido2 token"; cat "${work}/assert.err" >&2 ;;
esac
if printf '%s' "${token}" | "${bin}/lychgate" --socket "${sock}" approve --host hv >/dev/null 2>&1; then
    if is_open; then
        note "the hardware assertion opened the grant (the daemon verified it)"
    else
        fail "approve ok but not open"
    fi
else
    fail "the hardware assertion was refused"
    cat "${work}/daemon.log" >&2
fi

kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

echo
if [ "${failed}" -ne 0 ]; then
    echo "fido2-hardware: FAILED"
    exit 1
fi
echo "fido2-hardware: ok"
