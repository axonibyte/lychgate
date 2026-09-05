#!/bin/sh
# M7 acceptance: the VNC driver end to end through the real binaries, against
# this host's real sshd (the tunnel and the password commands both ride ssh)
# and a bare TCP stand-in for the VM's RFB server. Run as root on a DISPOSABLE
# host (a reaper guest): it touches root's authorized_keys and known_hosts,
# restoring them on the way out, but a failure can leave them changed.
#
# The claims, precondition before success indicator, two oracles where it
# matters:
#   1. open makes the forwarded local port reachable through to the RFB mock
#      AND rotates the VNC password (set command ran with the target), the
#      password shown once and absent from the journal, and never on an argv;
#   2. close tears the forward down (local port unreachable) AND clears the
#      password (clear command ran);
#   3. a second open while one is held is refused;
#   4. SIGKILL of the daemon kills the tunnel with it (fail-closed): the local
#      port stops accepting — the pdeathsig proof, which has no in-process
#      oracle and is OS-specific, so it runs here on each guest.
#
# What this does NOT prove: a real bhyve/cbsd; the RFB mock is a bare TCP
# acceptor, not a one-client RFB server, so real RFB auth and the single-viewer
# rule are out of reach. See TESTING.md.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
here="$(dirname "$0")"
# shellcheck source=e2e/lib.sh
. "${here}/lib.sh"
work="$(mktemp -d /tmp/lychgate-m7-XXXXXX)"
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
    # Kill any surviving tunnel child (a failed pdeathsig would leave one).
    pkill -f "ssh -N.*ExitOnForwardFailure" 2>/dev/null
    cp "${work}/authorized_keys.orig" "${akeys}" 2>/dev/null
    rm -rf "${work}"
}
trap cleanup EXIT INT TERM

# ssh-to-self for both the tunnel and the password commands.
ssh-keygen -q -t ed25519 -N "" -C "lychgate-m7-agent" -f "${work}/agent" </dev/null
cat "${work}/agent.pub" >> "${akeys}"
approval_keygen "${work}/approver"
ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "${work}/agent" \
    root@127.0.0.1 true || { echo "cannot ssh to self; aborting" >&2; exit 2; }

# Free ports for the RFB mock (tunnel's remote side) and the forward (local).
free_port() {
    python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}
rfb_port="$(free_port)"
local_port="$(free_port)"
staged="${work}/staged.pw"

# The agnostic password commands: they receive the target and a *file* holding
# the fresh password (never the password on an argv). They witness what ran and
# — the set command — record their own argv so the test can prove the password
# is not on it.
cat > "${work}/set-vnc-pw.sh" <<EOF
#!/bin/sh
# args: <target> <password_file>
echo "argv: \$*" >> "${work}/argv.log"
pw="\$(cat "\$2")"
printf 'set %s len=%s\n' "\$1" "\${#pw}" >> "${work}/witness.log"
EOF
cat > "${work}/clear-vnc-pw.sh" <<EOF
#!/bin/sh
# args: <target>
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
password_file = "${staged}"
EOF
approval_block "${work}/approver" >> "${work}/inventory.toml"

reachable() {
    python3 -c "import socket,sys
try:
    socket.create_connection(('127.0.0.1', ${local_port}), 2).close()
except Exception:
    sys.exit(1)"
}

note "starting the RFB mock on 127.0.0.1:${rfb_port}"
python3 "${here}/rfb-mock.py" "${rfb_port}" &
mock_pid=$!

start_daemon() {
    "${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" \
        --interval 600 > "${work}/daemon.log" 2>&1 &
    daemon_pid=$!
    i=0
    while [ ! -S "${state}/lychgated.sock" ]; do
        i=$((i + 1))
        [ "${i}" -gt 100 ] && { fail "daemon never bound"; cat "${work}/daemon.log"; exit 1; }
        sleep 0.1
    done
}

note "starting lychgated"
start_daemon

# --- 1. open: reachable, password rotated, shown once, journal-clean --------

note "opening the grant (open -> sign -> approve)"
out="$(open_and_approve "${state}/lychgated.sock" hv 15m "${work}/approver")" \
    || { fail "open/approve refused: ${out}"; cat "${work}/daemon.log"; }

if reachable; then
    note "the forwarded port reaches the RFB mock"
else
    fail "127.0.0.1:${local_port} is not reachable after open"
fi
echo "${out}" | grep -q "one-time VNC password (shown once):" \
    || fail "the CLI did not surface the one-time VNC password"
echo "${out}" | grep -q "vnc console at 127.0.0.1:${local_port}" \
    || fail "the CLI did not print the console endpoint"
grep -q "^set acc-vm " "${work}/witness.log" 2>/dev/null \
    || fail "the set-password command did not run: $(cat "${work}/witness.log" 2>/dev/null)"
[ -f "${staged}" ] && fail "the staged password file was left behind"

shown="$(echo "${out}" | sed -n 's/.*shown once): //p')"
if [ -n "${shown}" ]; then
    grep -qF "${shown}" "${state}/journal.jsonl" && fail "the VNC password leaked into the journal"
    grep -qF "${shown}" "${work}/argv.log" && fail "the VNC password reached the set command's argv"
    note "password shown once, absent from the journal and off the command line"
else
    fail "could not capture the shown password"
fi

# --- 2. close: forward down, password cleared -------------------------------

note "closing the grant"
"${bin}/lychgate" --socket "${state}/lychgated.sock" close --host hv >/dev/null \
    || { fail "close refused"; cat "${work}/daemon.log"; }
if reachable; then
    fail "127.0.0.1:${local_port} still reachable after close"
else
    note "the forward is gone after close"
fi
grep -q "^clear acc-vm" "${work}/witness.log" || fail "the clear-password command did not run"

# --- 3. a second open while one is held is refused --------------------------

open_and_approve "${state}/lychgated.sock" hv 15m "${work}/approver" >/dev/null \
    || { fail "re-open/approve refused unexpectedly"; }
# A second open while one is held is refused at the open step (no pending is
# even created), before any approval is in play.
if "${bin}/lychgate" --socket "${state}/lychgated.sock" open --host hv --ttl 15m >/dev/null 2>&1; then
    fail "a second open on an already-open console was accepted"
else
    note "a second open on an open console is refused"
fi

# --- 4. pdeathsig: SIGKILL the daemon, the tunnel dies with it --------------

note "SIGKILL the daemon (pid ${daemon_pid}); the tunnel must die with it"
reachable || fail "precondition: the forward should be up before the kill"
kill -9 "${daemon_pid}"
wait "${daemon_pid}" 2>/dev/null
daemon_pid=""
gone=0
i=0
while [ "${i}" -lt 100 ]; do
    reachable || { gone=1; break; }
    i=$((i + 1))
    sleep 0.1
done
if [ "${gone}" -eq 1 ]; then
    note "the tunnel died with the daemon (fail-closed)"
else
    fail "the forwarded port outlived the daemon: the tunnel orphaned (fail-open)"
fi

# Reconcile the leftover grant so cleanup starts from a settled state.
"${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" --once \
    >/dev/null 2>&1 || true

echo
if [ "${failed}" -ne 0 ]; then
    echo "vnc-acceptance: FAILED"
    echo "--- daemon log ---"
    cat "${work}/daemon.log"
    exit 1
fi
echo "vnc-acceptance: ok"
