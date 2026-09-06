#!/bin/sh
# M8c acceptance: drill mode — the standing revert oracle — end to end through
# the real binaries. `lychgate drill --host canary` opens-and-reverts a canary
# over the real vnc channel; a healthy revert passes (exit 0), and a SABOTAGED
# revert (a clear command that fails) makes the drill fail loudly (non-zero exit
# + DrillFailed). The sabotage arm is the oracle self-test: a drill that passed
# with a broken revert would be measuring nothing. Run as root on a DISPOSABLE
# host (a reaper guest): it touches root's authorized_keys, restoring it.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
here="$(dirname "$0")"
work="$(mktemp -d /tmp/lychgate-m8c-XXXXXX)"
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
command -v python3 >/dev/null 2>&1 || { echo "python3 not found: the RFB mock needs it" >&2; exit 2; }

akeys="/root/.ssh/authorized_keys"
mkdir -p /root/.ssh
touch "${akeys}"
cp "${akeys}" "${work}/authorized_keys.orig"

cleanup() {
    note "cleaning up"
    rm -f "${work}/sabotage"
    [ -n "${daemon_pid:-}" ] && kill -9 "${daemon_pid}" 2>/dev/null
    [ -n "${mock_pid:-}" ] && kill "${mock_pid}" 2>/dev/null
    pkill -f "ssh -N.*ExitOnForwardFailure" 2>/dev/null
    cp "${work}/authorized_keys.orig" "${akeys}" 2>/dev/null
    rm -rf "${work}"
}
trap cleanup EXIT INT TERM

ssh-keygen -q -t ed25519 -N "" -C "agent" -f "${work}/agent" </dev/null
ssh-keygen -q -t ed25519 -N "" -C "op" -f "${work}/op" </dev/null
cat "${work}/agent.pub" >> "${akeys}"
ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "${work}/agent" \
    root@127.0.0.1 true || { echo "cannot ssh to self; aborting" >&2; exit 2; }
op_pub="$(cat "${work}/op.pub")"

free_port() {
    python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}
rfb_port="$(free_port)"
local_port="$(free_port)"

cat > "${work}/set-vnc-pw.sh" <<EOF
#!/bin/sh
printf 'set %s\n' "\$1" >> "${work}/witness.log"
EOF
# The clear command is the sabotage point: if the marker exists, it FAILS, so
# the vnc channel cannot revert and the drill must report failure.
cat > "${work}/clear-vnc-pw.sh" <<EOF
#!/bin/sh
if [ -e "${work}/sabotage" ]; then
    echo "sabotaged clear" >&2
    exit 1
fi
printf 'clear %s\n' "\$1" >> "${work}/witness.log"
EOF
chmod +x "${work}/set-vnc-pw.sh" "${work}/clear-vnc-pw.sh"

os="linux"
[ "$(uname -s)" = "FreeBSD" ] && os="freebsd"

cat > "${work}/inventory.toml" <<EOF
[[hosts]]
name = "canary"
address = "127.0.0.1"
os = "${os}"
channels = ["vnc"]
drill = true

[hosts.vnc]
agent_user = "root"
identity_file = "${work}/agent"
rfb_host = "127.0.0.1"
rfb_port = ${rfb_port}
local_port = ${local_port}
target = "canary-vm"
set_password_cmd = "${work}/set-vnc-pw.sh {target} {password_file}"
clear_password_cmd = "${work}/clear-vnc-pw.sh {target}"
password_file = "${work}/staged.pw"

# A daemon outside --dry-run needs an [approval] policy to start; the drill
# bypasses it (the canary is drilled, not opened by an operator).
[[approval.authenticator]]
id = "op"
kind = "ed25519"
public-key = "${op_pub}"
[[approval.profile]]
id = "human"
threshold = 1
factor = [ { authenticator = "op", weight = 1 } ]
EOF

note "starting the RFB mock on 127.0.0.1:${rfb_port}"
python3 "${here}/rfb-mock.py" "${rfb_port}" &
mock_pid=$!

note "starting lychgated"
"${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" \
    --interval 600 --approval-window 60 > "${work}/daemon.log" 2>&1 &
daemon_pid=$!
i=0
while [ ! -S "${sock}" ]; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "daemon never bound"; cat "${work}/daemon.log"; exit 1; }
    sleep 0.1
done

drilled_passed() { grep -q '"event":"drill-passed"' "${state}/journal.jsonl"; }
drilled_failed() { grep -q '"event":"drill-failed"' "${state}/journal.jsonl"; }

# --- 1: a healthy canary drill passes ---------------------------------------

note "a healthy drill opens and fully reverts the canary"
if "${bin}/lychgate" --socket "${sock}" drill --host canary > "${work}/drill1.out" 2>&1; then
    if grep -q "drill passed" "${work}/drill1.out"; then
        note "drill passed (exit 0)"
    else
        fail "drill exited 0 but did not report passing: $(cat "${work}/drill1.out")"
    fi
else
    fail "a healthy drill failed: $(cat "${work}/drill1.out")"
    cat "${work}/daemon.log"
fi
drilled_passed || fail "no drill-passed journal entry"
# The channel really was driven and reverted: witness shows a set then a clear.
grep -q '^set ' "${work}/witness.log" || fail "the drill did not apply the vnc channel"
grep -q '^clear ' "${work}/witness.log" || fail "the drill did not revert the vnc channel"

# --- 2: a sabotaged revert makes the drill FAIL loudly ----------------------

note "sabotaging the canary's revert; the drill must fail (the oracle self-test)"
touch "${work}/sabotage"
if "${bin}/lychgate" --socket "${sock}" drill --host canary > "${work}/drill2.out" 2>&1; then
    fail "the drill passed despite a broken revert — the oracle is blind"
    cat "${work}/drill2.out"
else
    if grep -q "drill FAILED" "${work}/drill2.out"; then
        note "the drill failed loudly (non-zero exit) on the broken revert"
    else
        fail "the drill exited non-zero but without a drill-FAILED message: $(cat "${work}/drill2.out")"
    fi
fi
drilled_failed || fail "no drill-failed journal entry"
rm -f "${work}/sabotage"

kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

echo
if [ "${failed}" -ne 0 ]; then
    echo "drill-acceptance: FAILED"
    echo "--- daemon log ---"
    cat "${work}/daemon.log"
    exit 1
fi
echo "drill-acceptance: ok"
