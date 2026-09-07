#!/bin/sh
# E2 acceptance: the generic mqtt channel against a real mosquitto broker,
# end to end through the real binaries and the real mosquitto_pub/_sub exec
# transport. A background subscriber plays the device: it applies commands
# from the cmd topic and publishes its state RETAINED on the state topic, so
# the driver's one-shot verify read answers immediately. The retained state
# topic doubles as the ground-truth oracle.
#
# Skips (exit 2) when mosquitto or its clients are not installed — run.sh
# wires this through phase_skippable, and ensure_mosquitto tries to
# provision them first.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
here="$(dirname "$0")"
# shellcheck source=e2e/lib.sh
. "${here}/lib.sh"
work="$(mktemp -d /tmp/lychgate-mqtt-XXXXXX)"
state="${work}/state"
mkdir -p "${state}"

failed=0
fail() { echo "FAIL: $1" >&2; failed=1; }
note() { echo "==> $1"; }

for f in "${bin}/lychgated" "${bin}/lychgate"; do
    [ -x "${f}" ] || { echo "missing binary ${f}" >&2; exit 2; }
done
for tool in mosquitto mosquitto_pub mosquitto_sub; do
    command -v "${tool}" >/dev/null 2>&1 || {
        echo "mqtt-acceptance: SKIPPED (${tool} is not installed on this guest)" >&2
        exit 2
    }
done

port=18830

cleanup() {
    [ -n "${daemon_pid:-}" ] && kill "${daemon_pid}" 2>/dev/null
    [ -n "${device_pid:-}" ] && kill "${device_pid}" 2>/dev/null
    [ -n "${broker_pid:-}" ] && kill "${broker_pid}" 2>/dev/null
    rm -rf "${work}"
}
trap cleanup EXIT INT TERM

note "starting mosquitto on 127.0.0.1:${port}"
cat > "${work}/mosquitto.conf" <<EOF
listener ${port} 127.0.0.1
allow_anonymous true
EOF
mosquitto -c "${work}/mosquitto.conf" > "${work}/broker.log" 2>&1 &
broker_pid=$!
i=0
while ! mosquitto_pub -h 127.0.0.1 -p "${port}" -t probe -m up 2>/dev/null; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "broker never came up"; cat "${work}/broker.log"; exit 1; }
    sleep 0.1
done

note "starting the subscriber device"
# Seed the retained state before anything reads it.
mosquitto_pub -h 127.0.0.1 -p "${port}" -t dev/7/state -m maint-off -r
mosquitto_sub -h 127.0.0.1 -p "${port}" -t dev/7/cmd | while read -r cmd; do
    case "${cmd}" in
        maint-on)  mosquitto_pub -h 127.0.0.1 -p "${port}" -t dev/7/state -m maint-on -r ;;
        maint-off) mosquitto_pub -h 127.0.0.1 -p "${port}" -t dev/7/state -m maint-off -r ;;
    esac
done &
device_pid=$!

cat > "${work}/inventory.toml" <<EOF
[[hosts]]
name = "iot-7"
address = "127.0.0.1"
os = "embedded"
channels = ["mqtt"]

[hosts.mqtt]
broker = "127.0.0.1:${port}"

[hosts.mqtt.open]
topic = "dev/7/cmd"
payload = "maint-on"

[hosts.mqtt.revert]
topic = "dev/7/cmd"
payload = "maint-off"

[hosts.mqtt.verify]
topic = "dev/7/state"
open_marker = "maint-on"
closed_marker = "maint-off"
timeout_secs = 5
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

read_state() {
    mosquitto_sub -h 127.0.0.1 -p "${port}" -t dev/7/state -C 1 -W 3 2>/dev/null
}

note "opening the grant drives the device over the broker"
out="$(open_and_approve "${state}/lychgated.sock" iot-7 15m "${work}/approver")" \
    || { fail "open/approve refused: ${out}"; cat "${work}/daemon.log"; }
[ "$(read_state)" = "maint-on" ] || fail "retained state is not maint-on after open"

note "closing the grant reverts it"
"${bin}/lychgate" --socket "${state}/lychgated.sock" close --host iot-7 >/dev/null \
    || { fail "close refused"; cat "${work}/daemon.log"; }
[ "$(read_state)" = "maint-off" ] || fail "retained state is not maint-off after close"

note "a dead device leaves verify silent, and silence refuses the open"
kill "${device_pid}" 2>/dev/null
device_pid=""
# Clear the retained message so the verify read genuinely hears NOTHING —
# the assert-the-absence case, with the timeout allowed to pass.
mosquitto_pub -h 127.0.0.1 -p "${port}" -t dev/7/state -r -n
if open_and_approve "${state}/lychgated.sock" iot-7 15m "${work}/approver" >/dev/null 2>&1; then
    fail "open succeeded though verify heard nothing (silence became a state)"
else
    note "unverified open refused"
fi

kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

echo
if [ "${failed}" -ne 0 ]; then
    echo "mqtt-acceptance: FAILED"
    cat "${work}/daemon.log"
    exit 1
fi
echo "mqtt-acceptance: ok"
