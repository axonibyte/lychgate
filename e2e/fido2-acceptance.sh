#!/bin/sh
# M8a.5 acceptance: the FIDO2 authenticator end to end through the real
# binaries, using the DEFAULT-BUILD software authenticator (no hardware, no
# CTAP dependency) — `lychgate fido2-register` mints the credential and
# `lychgate fido2-assert` produces the challenge-bound assertion the daemon
# verifies. Run as root on a DISPOSABLE host (a reaper guest): it touches
# root's authorized_keys, restoring it on the way out.
#
# The policy:
#   profile "es":  threshold 1 over { fido2 es256 key }
#   profile "ed":  threshold 1 over { fido2 eddsa key }
#   profile "mfa": threshold 2 over { fido2 es256 key (1), password pw (1) }
#
# Claims:
#   1. a software ES256 assertion from the real CLI opens the single-factor
#      es profile;
#   2. a software EdDSA assertion opens the ed profile (both algorithms verify
#      end to end);
#   3. an assertion signed for a DIFFERENT challenge does not open a grant
#      pending under this one (the challenge binding), and a byte-corrupted
#      token is refused;
#   4. the mfa profile opens only after BOTH a FIDO2 assertion and the
#      password — one alone leaves it pending.
#
# What it does NOT prove: the hardware CTAP2 client (the fido2-client feature,
# no hardware on the guests — its assertion format is exactly what the software
# path here and the verify KAT pin). The vnc channel is just the thing the
# grant opens. See TESTING.md.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
here="$(dirname "$0")"
work="$(mktemp -d /tmp/lychgate-m8a5-XXXXXX)"
state="${work}/state"
sock="${state}/lychgated.sock"
mkdir -p "${state}"

failed=0
fail() { echo "FAIL: $1" >&2; failed=1; }
note() { echo "==> $1"; }

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root on a disposable host" >&2
    exit 2
fi
for f in "${bin}/lychgated" "${bin}/lychgate"; do
    [ -x "${f}" ] || { echo "missing binary ${f}" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || {
    echo "python3 not found: the RFB mock needs it" >&2
    exit 2
}

akeys="/root/.ssh/authorized_keys"
mkdir -p /root/.ssh
touch "${akeys}"
cp "${akeys}" "${work}/authorized_keys.orig"

cleanup() {
    note "cleaning up"
    [ -n "${daemon_pid:-}" ] && kill -9 "${daemon_pid}" 2>/dev/null
    [ -n "${mock_pid:-}" ] && kill "${mock_pid}" 2>/dev/null
    pkill -f "ssh -N.*ExitOnForwardFailure" 2>/dev/null
    cp "${work}/authorized_keys.orig" "${akeys}" 2>/dev/null
    rm -rf "${work}"
}
trap cleanup EXIT INT TERM

ssh-keygen -q -t ed25519 -N "" -C "agent" -f "${work}/agent" </dev/null
cat "${work}/agent.pub" >> "${akeys}"
ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "${work}/agent" \
    root@127.0.0.1 true || { echo "cannot ssh to self; aborting" >&2; exit 2; }

# Register two software authenticators through the real CLI. Each write is a
# mode-600 key file; the printed [[approval.authenticator]] block carries the
# credential id and public key we embed below (parsed from the CLI's own
# output, not hand-computed — the operator's workflow, verified).
field() { sed -n "s/^$1 = \"\\(.*\\)\"\$/\\1/p"; }
"${bin}/lychgate" fido2-register --alg es256 --software-key "${work}/es.key" \
    > "${work}/es.block" || { echo "es256 register failed" >&2; exit 2; }
"${bin}/lychgate" fido2-register --alg eddsa --software-key "${work}/ed.key" \
    > "${work}/ed.block" || { echo "eddsa register failed" >&2; exit 2; }
es_cred="$(field credential-id < "${work}/es.block")"
es_pub="$(field public-key < "${work}/es.block")"
ed_cred="$(field credential-id < "${work}/ed.block")"
ed_pub="$(field public-key < "${work}/ed.block")"
if [ -z "${es_cred}" ] || [ -z "${es_pub}" ]; then
    echo "es256 block missing fields" >&2
    exit 2
fi
if [ -z "${ed_cred}" ] || [ -z "${ed_pub}" ]; then
    echo "eddsa block missing fields" >&2
    exit 2
fi

# The break-glass password for the MFA leg (not purely numeric — an all-digit
# password would be routed to the TOTP path by the daemon's proof dispatch).
password="correct-horse-42"
printf '%s' "${password}" | "${bin}/lychgate" hash-password > "${work}/pw.hash" \
    || { echo "hash-password failed" >&2; exit 2; }
chmod 600 "${work}/pw.hash"

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
profiles = ["es", "ed", "mfa"]

[[approval.authenticator]]
id = "esk"
kind = "fido2"
alg = "es256"
credential-id = "${es_cred}"
public-key = "${es_pub}"
[[approval.authenticator]]
id = "edk"
kind = "fido2"
alg = "eddsa"
credential-id = "${ed_cred}"
public-key = "${ed_pub}"
[[approval.authenticator]]
id = "pw"
kind = "password"
hash-file = "${work}/pw.hash"

[[approval.profile]]
id = "es"
threshold = 1
factor = [ { authenticator = "esk", weight = 1 } ]

[[approval.profile]]
id = "ed"
threshold = 1
factor = [ { authenticator = "edk", weight = 1 } ]

[[approval.profile]]
id = "mfa"
threshold = 2
factor = [
  { authenticator = "esk", weight = 1 },
  { authenticator = "pw",  weight = 1 },
]
EOF

note "starting the RFB mock on 127.0.0.1:${rfb_port}"
python3 "${here}/rfb-mock.py" "${rfb_port}" &
mock_pid=$!

note "starting lychgated (real drivers + fido2)"
"${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" \
    --interval 600 --approval-window 60 > "${work}/daemon.log" 2>&1 &
daemon_pid=$!
i=0
while [ ! -S "${sock}" ]; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "daemon never bound"; cat "${work}/daemon.log"; exit 1; }
    sleep 0.1
done

challenge=""
do_open() {
    challenge="$("${bin}/lychgate" --socket "${sock}" open --host hv --ttl 15m --as "$1" \
        | sed -n 's/^challenge: //p')"
}
assert_key() {
    # $1 = key file, $2 = challenge to sign
    "${bin}/lychgate" fido2-assert --software-key "$1" --challenge "$2"
}
approve_token() {
    printf '%s' "$1" | "${bin}/lychgate" --socket "${sock}" approve --host hv >/dev/null 2>&1
}
is_open() {
    "${bin}/lychgate" --socket "${sock}" status | grep -qE '^hv[[:space:]]+open'
}
close_hv() {
    i=0
    while [ "${i}" -lt 100 ]; do
        "${bin}/lychgate" --socket "${sock}" close --host hv >/dev/null 2>&1
        "${bin}/lychgate" --socket "${sock}" status | grep -qE '^hv[[:space:]]+closed' && return 0
        i=$((i + 1))
        sleep 0.2
    done
    return 1
}

# --- 1: an ES256 software assertion opens the es profile --------------------

note "opening the single-factor es256 profile"
do_open es
[ -n "${challenge}" ] || fail "open did not return a challenge"
if approve_token "$(assert_key "${work}/es.key" "${challenge}")"; then
    if is_open; then
        note "the es256 assertion opened the grant"
    else
        fail "es256 approve ok but not open"
    fi
else
    fail "the es256 assertion was refused"
    cat "${work}/daemon.log"
fi
close_hv || fail "close did not settle"

# --- 2: an EdDSA software assertion opens the ed profile --------------------

note "opening the single-factor eddsa profile"
do_open ed
if approve_token "$(assert_key "${work}/ed.key" "${challenge}")"; then
    if is_open; then
        note "the eddsa assertion opened the grant"
    else
        fail "eddsa approve ok but not open"
    fi
else
    fail "the eddsa assertion was refused"
    cat "${work}/daemon.log"
fi
close_hv || fail "close did not settle"

# --- 3: challenge binding, and a corrupted token, are refused ---------------

note "an assertion for a different challenge does not open this grant"
do_open es
# Sign a plausible-looking but WRONG challenge (a different nonce).
wrong="$(assert_key "${work}/es.key" 'lg1.req.NOT-THE-PENDING-NONCE')"
if approve_token "${wrong}"; then
    fail "an assertion for another challenge was accepted"
elif is_open; then
    fail "opened on a mismatched-challenge assertion"
else
    note "the mismatched-challenge assertion was refused"
fi

note "a byte-corrupted assertion for THIS challenge is refused"
good="$(assert_key "${work}/es.key" "${challenge}")"
# Flip the final base64url character of the token body — the signature is the
# last JSON field, so this corrupts the assertion the daemon must reject.
body="${good#lgfido2.}"
n=${#body}
head_part="$(printf '%s' "${body}" | cut -c"1-$((n - 1))")"
last="$(printf '%s' "${body}" | cut -c"${n}-${n}")"
case "${last}" in A) newc=B ;; *) newc=A ;; esac
if approve_token "lgfido2.${head_part}${newc}"; then
    fail "a corrupted assertion was accepted"
elif is_open; then
    fail "opened on a corrupted assertion"
else
    note "the corrupted assertion was refused"
fi
# The pristine assertion still opens it — proving the corruption, not the setup,
# was what the daemon rejected.
if approve_token "${good}" && is_open; then
    note "the pristine assertion for the same challenge opens it"
else
    fail "the pristine assertion was refused after the corrupted one"
fi
close_hv || fail "close did not settle"

# --- 4: genuine MFA — a FIDO2 assertion AND the password --------------------

note "opening the two-factor mfa profile"
do_open mfa
approve_token "$(assert_key "${work}/es.key" "${challenge}")" \
    || fail "the fido2 proof was refused"
is_open && fail "opened on the fido2 factor alone (threshold is 2)"
if approve_token "${password}"; then
    if is_open; then
        note "the grant opened only after BOTH factors (real MFA)"
    else
        fail "both factors submitted but not open"
    fi
else
    fail "the mfa password proof was refused"
    cat "${work}/daemon.log"
fi
close_hv || fail "close did not settle"

kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

echo
if [ "${failed}" -ne 0 ]; then
    echo "fido2-acceptance: FAILED"
    echo "--- daemon log ---"
    cat "${work}/daemon.log"
    exit 1
fi
echo "fido2-acceptance: ok"
