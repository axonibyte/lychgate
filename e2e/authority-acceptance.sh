#!/bin/sh
# M8a.2 acceptance: the weighted-threshold authority model end to end through
# the real binaries, with real `ssh-keygen -Y sign` proofs the daemon verifies
# and a real elapsed `wait`. Run as root on a DISPOSABLE host (a reaper guest):
# it touches root's authorized_keys, restoring it on the way out.
#
# The policy (ed25519 stands in for every factor kind, since only ed25519 is
# built; the engine keys on the satisfied id set, not the kind):
#
#   profile "claude": threshold 3
#     group "OPS" (weight 2)   = threshold 2 over { k1, k2 }
#     authenticator k3 (weight 1)
#     wait "3s" (weight 1)
#
# So claude opens either by proofs alone — k1 + k2 (OPS met → 2) + k3 (→ 3) — or
# by k1 + k2 (→ 2) plus the 3s wait maturing on a daemon pass (→ 3), no third
# proof. The claims:
#   1. accumulation: neither one proof nor OPS alone opens it; the third factor
#      (k3) tips it over and the grant opens;
#   2. open-on-wait: with OPS satisfied but no k3, the daemon's own pass loop
#      opens the grant once the 3s wait elapses — no further human action;
#   3. a signature from an unconfigured key is refused, the grant left pending.
#
# What it does NOT prove: TOTP/password/FIDO2 factors (later sub-milestones); a
# real bhyve/cbsd. The vnc channel is just the thing the grant opens. See TESTING.md.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
here="$(dirname "$0")"
work="$(mktemp -d /tmp/lychgate-m8a2-XXXXXX)"
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

# The agent key reaches the hypervisor (self, for the vnc tunnel + pw commands);
# k1/k2/k3 are the operator factors; stranger is an unconfigured signer.
for name in agent k1 k2 k3 stranger; do
    ssh-keygen -q -t ed25519 -N "" -C "${name}" -f "${work}/${name}" </dev/null
done
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

[[approval.authenticator]]
id = "k1"
kind = "ed25519"
public-key = "$(cat "${work}/k1.pub")"
[[approval.authenticator]]
id = "k2"
kind = "ed25519"
public-key = "$(cat "${work}/k2.pub")"
[[approval.authenticator]]
id = "k3"
kind = "ed25519"
public-key = "$(cat "${work}/k3.pub")"

[[approval.group]]
id = "OPS"
threshold = 2
factor = [ { authenticator = "k1", weight = 1 }, { authenticator = "k2", weight = 1 } ]

[[approval.profile]]
id = "claude"
threshold = 3
factor = [
  { group = "OPS", weight = 2 },
  { authenticator = "k3", weight = 1 },
  { wait = "3s", weight = 1 },
]
EOF

note "starting the RFB mock on 127.0.0.1:${rfb_port}"
python3 "${here}/rfb-mock.py" "${rfb_port}" &
mock_pid=$!

# A short interval so the pass loop re-evaluates the wait promptly; a window
# comfortably longer than the 3s wait.
note "starting lychgated (real drivers + authority policy)"
"${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" \
    --interval 1 --approval-window 60 > "${work}/daemon.log" 2>&1 &
daemon_pid=$!
i=0
while [ ! -S "${sock}" ]; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "daemon never bound"; cat "${work}/daemon.log"; exit 1; }
    sleep 0.1
done

challenge=""
do_open() {
    challenge="$("${bin}/lychgate" --socket "${sock}" open --host hv --ttl 15m --as claude \
        | sed -n 's/^challenge: //p')"
}
# Sign the current challenge with key $1 and submit the proof. Returns the
# approve exit code (non-zero only on a refused proof).
approve_key() {
    printf '%s' "${challenge}" \
        | ssh-keygen -Y sign -n lychgate-approval -f "$1" 2>/dev/null \
        | "${bin}/lychgate" --socket "${sock}" approve --host hv >/dev/null 2>&1
}
is_open() {
    "${bin}/lychgate" --socket "${sock}" status | grep -qE '^hv[[:space:]]+open'
}
# Close and wait until the grant has actually settled closed. A close that lands
# during the brief Opening window (a wait maturing on a pass) is refused MidOpen
# by design, so retry until status reports closed — the operator's real move.
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

# --- 1. accumulation: OPS + k3 reaches the threshold ------------------------

note "opening under profile claude (threshold 3)"
do_open
[ -n "${challenge}" ] || fail "open did not return a challenge"
is_open && fail "the grant opened with no proof"

approve_key "${work}/k1" || fail "k1 proof was refused"
is_open && fail "opened after one proof (OPS needs two)"
approve_key "${work}/k2" || fail "k2 proof was refused"
is_open && fail "opened at weight 2 (threshold is 3)"
approve_key "${work}/k3" || fail "k3 proof was refused"
if is_open; then
    note "OPS(2) + k3(1) reached the threshold and the grant opened"
else
    fail "the grant did not open at the threshold"
    cat "${work}/daemon.log"
fi
close_hv || fail "close did not settle"

# --- 2. open-on-wait: OPS satisfied, the 3s wait tips it over ---------------

note "opening again; OPS then the wait (no k3)"
do_open
approve_key "${work}/k1" || fail "k1 proof was refused (wait path)"
approve_key "${work}/k2" || fail "k2 proof was refused (wait path)"
is_open && fail "opened before the wait matured"
note "waiting for the 3s wait to accrue on a daemon pass"
opened=0
i=0
while [ "${i}" -lt 100 ]; do
    if is_open; then opened=1; break; fi
    i=$((i + 1))
    sleep 0.2
done
if [ "${opened}" -eq 1 ]; then
    note "the matured wait opened the grant with no further proof"
else
    fail "the wait never opened the grant"
    cat "${work}/daemon.log"
fi
close_hv || fail "close did not settle"

# --- 3. a stranger's proof is refused ---------------------------------------

note "a signature from an unconfigured key is refused"
do_open
if approve_key "${work}/stranger"; then
    fail "a stranger's signature was accepted"
elif is_open; then
    fail "the grant opened despite a refused proof"
else
    note "the stranger was refused and the grant stayed pending"
fi
close_hv || fail "close did not settle"

kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

echo
if [ "${failed}" -ne 0 ]; then
    echo "authority-acceptance: FAILED"
    echo "--- daemon log ---"
    cat "${work}/daemon.log"
    exit 1
fi
echo "authority-acceptance: ok"
