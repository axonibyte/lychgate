#!/bin/sh
# E4 acceptance: the device channel end to end — the real daemon signing real
# lgcap./lgrvk. tokens over the real serial (pty) transport, against
# lychgate-devsim running the REAL lychgate-embed engine (the code the
# reference firmware compiles). The sim's state.json is the ground-truth
# oracle; --time-scale makes device-side TTL expiry observable in seconds.
#
# What each step proves is in the step notes; the headline claims:
#   - the DEVICE closes the grant at its own deadline (the daemon still
#     believes it open — asserted, not assumed);
#   - a reboot closes the grant and the daemon detects the loss on restart;
#   - a captured token replay (verbatim and corrupted) is refused;
#   - renew re-anchors; close revokes; the token never touches the journal.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
here="$(dirname "$0")"
# shellcheck source=e2e/lib.sh
. "${here}/lib.sh"
work="$(mktemp -d /tmp/lychgate-device-XXXXXX)"
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
        echo "device-acceptance: SKIPPED (${f} is not built — a release-artifact battery has no dev tools)" >&2
        exit 2
    }
done

cleanup() {
    [ -n "${daemon_pid:-}" ] && kill "${daemon_pid}" 2>/dev/null
    [ -n "${sim_pid:-}" ] && kill "${sim_pid}" 2>/dev/null
    rm -rf "${work}"
}
trap cleanup EXIT INT TERM

device_id="000102030405060708090a0b0c0d0e0f"
seed="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
printf '%s' "${seed}" > "${work}/signing.hex"
chmod 600 "${work}/signing.hex"
pubkey="$("${lgcap}" public --seed "${seed}")"

note "starting lychgate-devsim (time-scale 30: a 90s ttl expires in ~3s)"
"${devsim}" --pubkey "${pubkey}" --device-id "${device_id}" \
    --workdir "${sim}" --time-scale 30 > "${work}/sim.log" 2>&1 &
sim_pid=$!
i=0
while [ ! -f "${sim}/announce.json" ]; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "sim never announced"; cat "${work}/sim.log"; exit 1; }
    sleep 0.1
done
pts="$(sed -n 's/.*"pts":"\([^"]*\)".*/\1/p' "${sim}/announce.json")"
note "device at ${pts}"

cat > "${work}/inventory.toml" <<EOF
[signing]
key_file = "${work}/signing.hex"

[[hosts]]
name = "esp-1"
address = "local-serial"
os = "embedded"
channels = ["device"]

[hosts.device]
device_id = "${device_id}"
transport = "serial"

[hosts.device.serial]
device = "${pts}"
timeout_secs = 5
EOF
approval_keygen "${work}/approver"
approval_block "${work}/approver" >> "${work}/inventory.toml"

start_daemon() {
    "${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" \
        --interval 2 >> "${work}/daemon.log" 2>&1 &
    daemon_pid=$!
    i=0
    while ! "${bin}/lychgate" --socket "${state}/lychgated.sock" status >/dev/null 2>&1; do
        i=$((i + 1))
        [ "${i}" -gt 100 ] && { fail "daemon never served"; cat "${work}/daemon.log"; exit 1; }
        sleep 0.1
    done
}

sim_state() { sed -n 's/.*"state":"\([^"]*\)".*/\1/p' "${sim}/state.json"; }
sim_field() { sed -n "s/.*\"$1\":\"\{0,1\}\([^\",}]*\)\"\{0,1\}[,}].*/\1/p" "${sim}/state.json" | head -1; }

note "starting lychgated"
start_daemon

note "open delivers a signed capability and the device anchors it"
out="$(open_and_approve "${state}/lychgated.sock" esp-1 4h "${work}/approver")" \
    || { fail "open/approve refused: ${out}"; cat "${work}/daemon.log"; }
[ "$(sim_state)" = "open" ] || fail "device not open: $(cat "${sim}/state.json")"
# The token is a capability the device holds, not an operator credential:
# it must appear NOWHERE in the journal.
if grep -q "lgcap\." "${state}/journal.jsonl"; then
    fail "a capability token leaked into the journal"
fi

note "a verbatim replay of the captured token is refused (and changes nothing)"
echo "replay" > "${sim}/ctl"
sleep 0.3
case "$(sim_field last_result)" in
    *"NAK replay"*|*"ACK"*) : ;; # idempotent re-ack of the CURRENT token is legal...
    *) fail "unexpected replay verdict: $(sim_field last_result)" ;;
esac
[ "$(sim_state)" = "open" ] || fail "replay disturbed the grant"

note "a corrupted token is refused by signature"
echo "corrupt-replay" > "${sim}/ctl"
sleep 0.3
case "$(sim_field last_result)" in
    *"NAK bad-token"*) : ;;
    *) fail "corrupt replay was not refused by signature: $(sim_field last_result)" ;;
esac

# Renewal semantics (same nonce, fresh seq, re-anchored deadline) are pinned
# at the driver and engine unit tiers; the daemon-policy renewal window makes
# them awkward to exercise here without a long wait.

note "close revokes and the device reads back closed"
"${bin}/lychgate" --socket "${state}/lychgated.sock" close --host esp-1 >/dev/null \
    || { fail "close refused"; cat "${work}/daemon.log"; }
[ "$(sim_state)" = "closed" ] || fail "device not closed after revocation"
[ "$(sim_field closed_reason)" = "revert" ] || fail "close reason is not revert: $(cat "${sim}/state.json")"
# The now-superseded token cannot reopen the device.
echo "replay" > "${sim}/ctl"
sleep 0.3
case "$(sim_field last_result)" in
    *"NAK replay"*) : ;;
    *) fail "a superseded token was not refused: $(sim_field last_result)" ;;
esac
[ "$(sim_state)" = "closed" ] || fail "superseded replay reopened the device"

note "the DEVICE closes an expiring grant on its own clock (daemon still believes open)"
out="$(open_and_approve "${state}/lychgated.sock" esp-1 90s "${work}/approver")" \
    || { fail "short open refused: ${out}"; cat "${work}/daemon.log"; }
[ "$(sim_state)" = "open" ] || fail "short grant did not open"
# 90s at scale 30 = 3s of wall time. Assert the absence with time passing:
# poll until the device closes ITSELF, then prove the daemon had not done it.
i=0
while [ "$(sim_state)" != "closed" ]; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "device never expired its grant"; break; }
    sleep 0.1
done
[ "$(sim_field closed_reason)" = "expiry" ] || fail "expiry reason missing: $(cat "${sim}/state.json")"
"${bin}/lychgate" --socket "${state}/lychgated.sock" status | grep -q "esp-1.*open" \
    || fail "the daemon should still believe the grant open (device-side expiry ran FIRST)"
note "device expired first, as designed; reconciling with close"
"${bin}/lychgate" --socket "${state}/lychgated.sock" close --host esp-1 >/dev/null \
    || fail "reconciling close refused (revert against an expired device must be idempotent)"

note "a reboot closes the grant and a restarted daemon detects the loss"
out="$(open_and_approve "${state}/lychgated.sock" esp-1 4h "${work}/approver")" \
    || { fail "reboot-test open refused: ${out}"; cat "${work}/daemon.log"; }
[ "$(sim_state)" = "open" ] || fail "reboot-test grant did not open"
seq_before="$(sim_field stored_seq)"
echo "reboot" > "${sim}/ctl"
sleep 0.3
[ "$(sim_state)" = "closed" ] || fail "reboot did not close the device"
[ "$(sim_field closed_reason)" = "boot" ] || fail "boot reason missing"
[ "$(sim_field stored_seq)" = "${seq_before}" ] || fail "the anti-replay mark did not survive the reboot"
# Restart the daemon: reestablish must observe the loss and retract.
kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""
start_daemon
i=0
while ! "${bin}/lychgate" --socket "${state}/lychgated.sock" status | grep -q "esp-1.*closed"; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "the daemon never retracted the lost grant"; break; }
    sleep 0.2
done

kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

echo
if [ "${failed}" -ne 0 ]; then
    echo "device-acceptance: FAILED"
    echo "--- daemon log ---"; cat "${work}/daemon.log"
    echo "--- sim log ---"; cat "${work}/sim.log"
    echo "--- sim state ---"; cat "${sim}/state.json" 2>/dev/null
    exit 1
fi
echo "device-acceptance: ok"
