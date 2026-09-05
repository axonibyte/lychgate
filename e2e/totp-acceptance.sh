#!/bin/sh
# M8a.3 acceptance: the TOTP authenticator end to end through the real binaries,
# with real RFC 6238 codes the daemon verifies, and a genuine two-factor open
# (an Ed25519 signature AND a TOTP code). Run as root on a DISPOSABLE host (a
# reaper guest): it touches root's authorized_keys, restoring it on the way out.
#
# The codes are computed by a ~15-line python3 TOTP (python3 is already required
# for the RFB mock, so no new guest dependency). Two distinct TOTP secrets are
# used so the single-factor tests and the MFA test never share a counter — a
# code spent by one cannot collide with the other in the single-use ledger.
#
# The policy:
#   profile "solo": threshold 1 over { totp t-solo }
#   profile "mfa":  threshold 2 over { ed25519 key (1), totp t-mfa (1) }
#
# Claims:
#   1. a real TOTP code opens the single-factor profile;
#   2. that same code, replayed, is refused (the single-use ledger) — even
#      though it is still within its time window;
#   3. a wrong code is refused;
#   4. the MFA profile opens only after BOTH an Ed25519 signature and a TOTP
#      code — one alone leaves it pending.
#
# What it does NOT prove: password/FIDO2 factors (later); a real bhyve/cbsd. The
# vnc channel is just the thing the grant opens. See TESTING.md.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
here="$(dirname "$0")"
work="$(mktemp -d /tmp/lychgate-m8a3-XXXXXX)"
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
    echo "python3 not found: the RFB mock and the TOTP helper need it" >&2
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

# The agent key reaches the hypervisor (self); the approver key is the Ed25519
# factor for the MFA profile.
ssh-keygen -q -t ed25519 -N "" -C "agent" -f "${work}/agent" </dev/null
ssh-keygen -q -t ed25519 -N "" -C "approver" -f "${work}/approver" </dev/null
cat "${work}/agent.pub" >> "${akeys}"
ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "${work}/agent" \
    root@127.0.0.1 true || { echo "cannot ssh to self; aborting" >&2; exit 2; }

# A small RFC 6238 TOTP in python3: prints the current 6-digit code for a base32
# secret. Matches the daemon's SHA-1 / 30s / 6-digit / dynamic-truncation.
cat > "${work}/totp.py" <<'PY'
import sys, time, hmac, hashlib, base64, struct
s = sys.argv[1].upper().replace(" ", "")
s += "=" * ((8 - len(s) % 8) % 8)
key = base64.b32decode(s)
counter = int(time.time()) // 30
h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
o = h[19] & 0x0f
print("%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000))
PY
code_for() { python3 "${work}/totp.py" "$1"; }

# Two distinct base32 secrets in mode-600 files.
python3 -c 'import os,base64;print(base64.b32encode(os.urandom(20)).decode())' > "${work}/t-solo.secret"
python3 -c 'import os,base64;print(base64.b32encode(os.urandom(20)).decode())' > "${work}/t-mfa.secret"
chmod 600 "${work}/t-solo.secret" "${work}/t-mfa.secret"

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
id = "t-solo"
kind = "totp"
secret-file = "${work}/t-solo.secret"
[[approval.authenticator]]
id = "t-mfa"
kind = "totp"
secret-file = "${work}/t-mfa.secret"
[[approval.authenticator]]
id = "key"
kind = "ed25519"
public-key = "$(cat "${work}/approver.pub")"

[[approval.profile]]
id = "solo"
threshold = 1
factor = [ { authenticator = "t-solo", weight = 1 } ]

[[approval.profile]]
id = "mfa"
threshold = 2
factor = [
  { authenticator = "key",   weight = 1 },
  { authenticator = "t-mfa", weight = 1 },
]
EOF

note "starting the RFB mock on 127.0.0.1:${rfb_port}"
python3 "${here}/rfb-mock.py" "${rfb_port}" &
mock_pid=$!

note "starting lychgated (real drivers + TOTP)"
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

# --- 1 & 2: a TOTP code opens the solo profile; the replay is refused --------

note "opening under the single-factor totp profile"
do_open solo
[ -n "${challenge}" ] || fail "open did not return a challenge"
solo_code="$(code_for "$(cat "${work}/t-solo.secret")")"
if approve_token "${solo_code}"; then
    if is_open; then
        note "a real TOTP code opened the grant"
    else
        fail "approve ok but not open"
    fi
else
    fail "a valid TOTP code was refused"
    cat "${work}/daemon.log"
fi
close_hv || fail "close did not settle"

note "the same code, replayed on a fresh grant, is refused"
do_open solo
if approve_token "${solo_code}"; then
    fail "a spent TOTP code was accepted again"
elif is_open; then
    fail "the grant opened on a replayed code"
else
    note "the replayed code was refused and the grant stayed pending"
fi
close_hv || fail "close did not settle"

# --- 3: a wrong code is refused ---------------------------------------------

note "a wrong TOTP code is refused"
do_open solo
if approve_token "000000"; then
    fail "a wrong TOTP code was accepted"
elif is_open; then
    fail "opened on a wrong code"
else
    note "the wrong code was refused"
fi
close_hv || fail "close did not settle"

# --- 4: genuine MFA — an Ed25519 signature AND a TOTP code ------------------

note "opening under the two-factor mfa profile"
do_open mfa
# One factor alone must not open it.
sign_challenge "${work}/approver" | "${bin}/lychgate" --socket "${sock}" approve --host hv \
    >/dev/null 2>&1 || fail "the ed25519 proof was refused"
is_open && fail "opened on the ed25519 factor alone (threshold is 2)"
mfa_code="$(code_for "$(cat "${work}/t-mfa.secret")")"
if approve_token "${mfa_code}"; then
    if is_open; then
        note "the grant opened only after BOTH factors (real MFA)"
    else
        fail "both factors submitted but not open"
    fi
else
    fail "the mfa totp proof was refused"
    cat "${work}/daemon.log"
fi
close_hv || fail "close did not settle"

kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

echo
if [ "${failed}" -ne 0 ]; then
    echo "totp-acceptance: FAILED"
    echo "--- daemon log ---"
    cat "${work}/daemon.log"
    exit 1
fi
echo "totp-acceptance: ok"
