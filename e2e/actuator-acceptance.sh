#!/bin/sh
# E8 acceptance: an actuator device as a drill canary — the standing
# HARDWARE oracle. A healthy drill passes; then the relay is stuck (the
# command moves, the load does not — the exact silent revert-path failure
# drills exist to catch) and the drill FAILS LOUDLY, naming the load. The
# reason=boot/fail-energized exception is pinned at the driver unit tier;
# this script's business is the drill loop end to end.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
here="$(dirname "$0")"
# shellcheck source=e2e/lib.sh
. "${here}/lib.sh"
work="$(mktemp -d /tmp/lychgate-actuator-XXXXXX)"
state="${work}/state"
sim="${work}/sim"
mkdir -p "${state}" "${sim}"

failed=0
fail() { echo "FAIL: $1" >&2; failed=1; }
note() { echo "==> $1"; }

for f in "${bin}/lychgated" "${bin}/lychgate"; do
    [ -x "${f}" ] || { echo "missing binary ${f}" >&2; exit 2; }
done
devsim="${bin}/lychgate-devsim"
lgcap="${bin}/examples/lgcap-sign"
for f in "${devsim}" "${lgcap}"; do
    [ -x "${f}" ] || {
        echo "actuator-acceptance: SKIPPED (${f} is not built — a release-artifact battery has no dev tools)" >&2
        exit 2
    }
done

cleanup() {
    [ -n "${daemon_pid:-}" ] && kill "${daemon_pid}" 2>/dev/null
    [ -n "${sim_pid:-}" ] && kill "${sim_pid}" 2>/dev/null
    rm -rf "${work}"
}
trap cleanup EXIT INT TERM

device_id="101112131415161718191a1b1c1d1e1f"
seed="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
printf '%s' "${seed}" > "${work}/signing.hex"
chmod 600 "${work}/signing.hex"
pubkey="$("${lgcap}" public --seed "${seed}")"

note "starting the actuator sim (fail de-energized, current sense on)"
"${devsim}" --pubkey "${pubkey}" --device-id "${device_id}" \
    --workdir "${sim}" --actuator de-energized > "${work}/sim.log" 2>&1 &
sim_pid=$!
i=0
while [ ! -f "${sim}/announce.json" ]; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "sim never announced"; cat "${work}/sim.log"; exit 1; }
    sleep 0.1
done
pts="$(sed -n 's/.*"pts":"\([^"]*\)".*/\1/p' "${sim}/announce.json")"

cat > "${work}/inventory.toml" <<EOF
[signing]
key_file = "${work}/signing.hex"

[[hosts]]
name = "pdu-1"
address = "local-serial"
os = "embedded"
channels = ["device"]
drill = true

[hosts.device]
device_id = "${device_id}"
transport = "serial"

[hosts.device.serial]
device = "${pts}"
timeout_secs = 5

[hosts.device.actuator]
fail_state = "de-energized"
current_sense = true
EOF
approval_keygen "${work}/approver"
approval_block "${work}/approver" >> "${work}/inventory.toml"

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

note "a healthy drill passes (the relay actuates and reverts, load observed both ways)"
if "${bin}/lychgate" --socket "${state}/lychgated.sock" drill --host pdu-1 > "${work}/drill1.log" 2>&1; then
    note "drill passed"
else
    fail "healthy drill failed: $(cat "${work}/drill1.log")"
fi
grep -q '"event":"drill-passed"' "${state}/journal.jsonl" || fail "no drill-passed journal entry"
grep -q '"load":false' "${sim}/state.json" || fail "load did not end de-energized after the drill"

note "with the relay STUCK, the drill fails loudly and names the load"
echo "stick-relay on" > "${sim}/ctl"
sleep 0.3
if "${bin}/lychgate" --socket "${state}/lychgated.sock" drill --host pdu-1 > "${work}/drill2.log" 2>&1; then
    fail "the drill passed with a stuck relay — the hardware oracle is blind"
else
    grep -qi "load" "${work}/drill2.log" \
        || fail "the failed drill's diagnosis does not name the load: $(cat "${work}/drill2.log")"
    note "stuck relay caught: $(head -2 "${work}/drill2.log" | tail -1)"
fi
grep -q '"event":"drill-failed"' "${state}/journal.jsonl" || fail "no drill-failed journal entry"

note "freeing the relay clears the drill again (the canary is reusable)"
echo "stick-relay off" > "${sim}/ctl"
sleep 0.3
# The stuck drill may have left the grant needing revert; give the daemon a
# close to settle, then drill clean.
"${bin}/lychgate" --socket "${state}/lychgated.sock" close --host pdu-1 >/dev/null 2>&1 || true
if "${bin}/lychgate" --socket "${state}/lychgated.sock" drill --host pdu-1 > "${work}/drill3.log" 2>&1; then
    note "drill passes again"
else
    fail "drill did not recover after freeing the relay: $(cat "${work}/drill3.log")"
fi

kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

echo
if [ "${failed}" -ne 0 ]; then
    echo "actuator-acceptance: FAILED"
    echo "--- daemon log ---"; cat "${work}/daemon.log"
    echo "--- sim state ---"; cat "${sim}/state.json" 2>/dev/null; echo
    exit 1
fi
echo "actuator-acceptance: ok"
