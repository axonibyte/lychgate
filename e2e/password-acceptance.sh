#!/bin/sh
# M8a.4 acceptance: the password authenticator end to end through the real
# binaries, including `lychgate hash-password` producing the hash file and a
# genuine two-factor open (a password AND an Ed25519 signature). Run as root on
# a DISPOSABLE host (a reaper guest): it touches root's authorized_keys,
# restoring it on the way out.
#
# The policy:
#   profile "solo": threshold 1 over { password pw }
#   profile "mfa":  threshold 2 over { ed25519 key (1), password pw (1) }
#
# Claims:
#   1. `lychgate hash-password` produces a hash the daemon verifies: the correct
#      password opens the single-factor profile;
#   2. a password is REUSABLE — the same secret opens a second grant (no ledger,
#      the weakest factor by design);
#   3. a wrong password is refused;
#   4. the MFA profile opens only after BOTH an Ed25519 signature and the
#      password — one alone leaves it pending.
#
# What it does NOT prove: FIDO2 (later); a real bhyve/cbsd. The vnc channel is
# just the thing the grant opens. See TESTING.md.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
here="$(dirname "$0")"
work="$(mktemp -d /tmp/lychgate-m8a4-XXXXXX)"
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
ssh-keygen -q -t ed25519 -N "" -C "approver" -f "${work}/approver" </dev/null
cat "${work}/agent.pub" >> "${akeys}"
ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "${work}/agent" \
    root@127.0.0.1 true || { echo "cannot ssh to self; aborting" >&2; exit 2; }

# The break-glass password (not purely numeric — an all-digit password would be
# routed to the TOTP path by the daemon's proof dispatch). Hashed by the real
# `lychgate hash-password` into a mode-600 file — the operator's own workflow.
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
profiles = ["solo", "mfa"]

[[approval.authenticator]]
id = "pw"
kind = "password"
hash-file = "${work}/pw.hash"
[[approval.authenticator]]
id = "key"
kind = "ed25519"
public-key = "$(cat "${work}/approver.pub")"

[[approval.profile]]
id = "solo"
threshold = 1
factor = [ { authenticator = "pw", weight = 1 } ]

[[approval.profile]]
id = "mfa"
threshold = 2
factor = [
  { authenticator = "key", weight = 1 },
  { authenticator = "pw",  weight = 1 },
]
EOF

note "starting the RFB mock on 127.0.0.1:${rfb_port}"
python3 "${here}/rfb-mock.py" "${rfb_port}" &
mock_pid=$!

note "starting lychgated (real drivers + password)"
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
approve_token() {
    printf '%s' "$1" | "${bin}/lychgate" --socket "${sock}" approve --host hv >/dev/null 2>&1
}
sign_challenge() {
    printf '%s' "${challenge}" | ssh-keygen -Y sign -n lychgate-approval -f "$1" 2>/dev/null
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

# --- 1 & 2: the password opens the solo profile, and is reusable ------------

note "opening the single-factor password profile"
do_open solo
[ -n "${challenge}" ] || fail "open did not return a challenge"
if approve_token "${password}"; then
    if is_open; then
        note "the hashed password opened the grant"
    else
        fail "approve ok but not open"
    fi
else
    fail "the correct password was refused"
    cat "${work}/daemon.log"
fi
close_hv || fail "close did not settle"

note "the same password opens a second grant (reusable, no ledger)"
do_open solo
if approve_token "${password}"; then
    if is_open; then
        note "reused password opened again"
    else
        fail "reuse: approve ok but not open"
    fi
else
    fail "the password was refused on reuse"
fi
close_hv || fail "close did not settle"

# --- 3: a wrong password is refused -----------------------------------------

note "a wrong password is refused"
do_open solo
if approve_token "wrong-horse-99"; then
    fail "a wrong password was accepted"
elif is_open; then
    fail "opened on a wrong password"
else
    note "the wrong password was refused"
fi
close_hv || fail "close did not settle"

# --- 4: genuine MFA — an Ed25519 signature AND the password -----------------

note "opening the two-factor mfa profile"
do_open mfa
sign_challenge "${work}/approver" | "${bin}/lychgate" --socket "${sock}" approve --host hv \
    >/dev/null 2>&1 || fail "the ed25519 proof was refused"
is_open && fail "opened on the ed25519 factor alone (threshold is 2)"
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
    echo "password-acceptance: FAILED"
    echo "--- daemon log ---"
    cat "${work}/daemon.log"
    exit 1
fi
echo "password-acceptance: ok"
