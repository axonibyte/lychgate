#!/bin/sh
# M8 acceptance: the operator approval flow end to end through the real
# binaries, with a real `ssh-keygen -Y sign` SSHSIG the daemon verifies. Run as
# root on a DISPOSABLE host (a reaper guest): it touches root's
# authorized_keys and known_hosts, restoring them on the way out.
#
# It uses the vnc channel (a daemon-held tunnel + a rotated password over
# ssh-to-self and a bare RFB mock) as the thing the grant opens, so that after
# a verified approval the grant genuinely reaches Open — but the claims here are
# about approval:
#   1. a request is pending, not open, until approved;
#   2. a real SSHSIG over the daemon's challenge, from the configured key,
#      approves it and the grant opens;
#   3. a signature from an unconfigured key is refused (the grant stays pending);
#   4. an approval after the window has lapsed is refused.
#
# What it does NOT prove: TOTP or FIDO2 approvers (later sub-milestones); a real
# bhyve/cbsd. See TESTING.md.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
here="$(dirname "$0")"
work="$(mktemp -d /tmp/lychgate-m8-XXXXXX)"
state="${work}/state"
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
    echo "python3 not found: the RFB mock needs it (skipping is not failing)" >&2
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

# The agent key reaches the hypervisor (self); the approver key is the
# operator's, whose signatures the daemon accepts. A THIRD key is the wrong
# signer.
ssh-keygen -q -t ed25519 -N "" -C "agent" -f "${work}/agent" </dev/null
ssh-keygen -q -t ed25519 -N "" -C "approver" -f "${work}/approver" </dev/null
ssh-keygen -q -t ed25519 -N "" -C "stranger" -f "${work}/stranger" </dev/null
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
pw="\$(cat "\$2")"; printf 'set %s\n' "\$1" >> "${work}/witness.log"
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

[approval]
[[approval.ed25519]]
key-id = "operator"
public-key = "$(cat "${work}/approver.pub")"
EOF

note "starting the RFB mock on 127.0.0.1:${rfb_port}"
python3 "${here}/rfb-mock.py" "${rfb_port}" &
mock_pid=$!

note "starting lychgated (real drivers + approval; a short window for the lapse test)"
"${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" \
    --interval 600 --approval-window 5 > "${work}/daemon.log" 2>&1 &
daemon_pid=$!
i=0
while [ ! -S "${state}/lychgated.sock" ]; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "daemon never bound"; cat "${work}/daemon.log"; exit 1; }
    sleep 0.1
done

# The challenge string the daemon shows; the operator signs exactly this.
challenge_of() {
    "${bin}/lychgate" --socket "${state}/lychgated.sock" open --host hv --ttl 15m \
        | sed -n 's/^challenge: //p'
}
approve_with() {
    # $1 = key file. Sign the challenge and approve, reading the token on stdin.
    printf '%s' "$2" | ssh-keygen -Y sign -n lychgate-approval -f "$1" 2>/dev/null \
        | "${bin}/lychgate" --socket "${state}/lychgated.sock" approve --host hv
}
is_open() {
    "${bin}/lychgate" --socket "${state}/lychgated.sock" status \
        | grep -qE '^hv[[:space:]]+open'
}

# --- 1 & 2: pending until a real approval opens it --------------------------

note "opening (should go pending, not open)"
challenge="$(challenge_of)"
[ -n "${challenge}" ] || fail "open did not return a challenge"
is_open && fail "the grant opened without approval"
"${bin}/lychgate" --socket "${state}/lychgated.sock" status | grep -q "awaiting-approval" \
    || fail "the grant is not awaiting approval"

note "approving with the configured operator key"
if approve_with "${work}/approver" "${challenge}" >/dev/null 2>&1; then
    if is_open; then
        note "a valid SSHSIG opened the grant"
    else
        fail "approve succeeded but the grant is not open"
    fi
else
    fail "a valid approval was refused"
    cat "${work}/daemon.log"
fi

"${bin}/lychgate" --socket "${state}/lychgated.sock" close --host hv >/dev/null

# --- 3: a stranger's signature is refused -----------------------------------

note "a signature from an unconfigured key is refused"
challenge="$(challenge_of)"
if approve_with "${work}/stranger" "${challenge}" >/dev/null 2>&1; then
    fail "a stranger's signature was accepted"
elif is_open; then
    fail "the grant opened despite a refused approval"
else
    note "the stranger was refused and the grant stayed pending"
fi
"${bin}/lychgate" --socket "${state}/lychgated.sock" close --host hv >/dev/null 2>&1

# --- 4: an approval after the window has lapsed is refused ------------------

note "an approval after the 5s window is refused"
challenge="$(challenge_of)"
sleep 6
if approve_with "${work}/approver" "${challenge}" >/dev/null 2>&1; then
    fail "an approval after the window was accepted"
else
    note "the lapsed-window approval was refused"
fi

kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

echo
if [ "${failed}" -ne 0 ]; then
    echo "approval-acceptance: FAILED"
    echo "--- daemon log ---"
    cat "${work}/daemon.log"
    exit 1
fi
echo "approval-acceptance: ok"
