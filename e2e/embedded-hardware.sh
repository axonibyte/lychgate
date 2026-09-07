#!/bin/sh
# MANUAL hardware-in-the-loop tier (the fido2-hardware.sh pattern): the
# reference ESP32-C3 firmware on a REAL board, driven over its USB serial
# port with bench tokens from lgcap-sign — no daemon in the loop, so this
# runs before/without any lychgate deployment. NOT part of e2e/run.sh
# (listed as a manual exception in source-as-data); documented in TESTING.md.
#
# What only this tier proves: real crystal timing, real flash persistence
# across a physical power cycle, real GPIO behavior, real USB-serial framing.
# What it assumes proven elsewhere: every engine rule (the embed matrix and
# the device acceptance run the same code).
#
# Usage:
#   EMBED_TTY=/dev/ttyACM0 sh e2e/embedded-hardware.sh
#
# The board must run firmware/esp32c3 built with its BENCH constants (the
# committed DEVICE_ID and the KAT seed's public key). Flash it with:
#   cd firmware/esp32c3 && cargo run --release   # espflash runner
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug); EMBED_TTY (the board).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
lgcap="${bin}/examples/lgcap-sign"
tty="${EMBED_TTY:-}"

failed=0
fail() { echo "FAIL: $1" >&2; failed=1; }
note() { echo "==> $1"; }

[ -x "${lgcap}" ] || {
    echo "embedded-hardware: SKIPPED (build lgcap-sign first: cargo build -p lychgate-wire --example lgcap-sign)" >&2
    exit 2
}
[ -n "${tty}" ] && [ -e "${tty}" ] || {
    echo "embedded-hardware: SKIPPED (set EMBED_TTY to the board's serial device)" >&2
    exit 2
}

# The BENCH identity baked into the reference firmware.
device_id="000102030405060708090a0b0c0d0e0f"
seed="1111111111111111111111111111111111111111111111111111111111111111"
nonce="a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
nonce2="b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"

# One transaction: send a line, read one reply line (3s budget via stty +
# head). Raw mode so the tty does not echo or cook.
txn() {
    stty -f "${tty}" raw -echo 115200 2>/dev/null || stty -F "${tty}" raw -echo 115200
    printf '%s\n' "$1" > "${tty}"
    head -n 1 < "${tty}"
}

note "the board answers STAT"
out="$(txn "STAT")"
case "${out}" in
    STATE*) note "  ${out}" ;;
    *) echo "embedded-hardware: SKIPPED (no STATE reply from ${tty}: ${out:-nothing})" >&2; exit 2 ;;
esac

# Fresh seqs: read the board's mark and go above it, so this script is
# re-runnable without reflashing.
mark="$(echo "${out}" | sed -n 's/.*seq=\([0-9]*\).*/\1/p')"
seq1=$((mark + 1)); seq2=$((mark + 2)); seq3=$((mark + 3))

note "a valid token opens the gate (watch the LED on GPIO4)"
tok="$("${lgcap}" cap --seed "${seed}" --device-id "${device_id}" --nonce "${nonce}" --ttl-secs 60 --seq "${seq1}")"
out="$(txn "TOK ${tok}")"
case "${out}" in
    "ACK ${nonce} "*) : ;;
    *) fail "token not accepted: ${out}" ;;
esac
txn "STAT" | grep -q "open ${nonce}" || fail "STAT does not read open"

note "idempotent redelivery acks without extending"
out="$(txn "TOK ${tok}")"
case "${out}" in
    "ACK ${nonce} "*) : ;;
    *) fail "redelivery not acknowledged: ${out}" ;;
esac

note "a replayed older token is refused"
old="$("${lgcap}" cap --seed "${seed}" --device-id "${device_id}" --nonce "${nonce2}" --ttl-secs 60 --seq "${seq1}")"
out="$(txn "TOK ${old}")"
[ "${out}" = "NAK busy" ] || [ "${out}" = "NAK replay" ] || fail "stale/other grant not refused: ${out}"

note "revocation closes the gate"
rvk="$("${lgcap}" rvk --seed "${seed}" --device-id "${device_id}" --nonce "${nonce}" --seq "${seq2}")"
out="$(txn "RVK ${rvk}")"
[ "${out}" = "ACK closed" ] || fail "revocation not acknowledged: ${out}"
txn "STAT" | grep -q "closed" || fail "STAT does not read closed after revocation"

note "a short TTL expires on the BOARD's clock (assert the absence, ~5s)"
tok="$("${lgcap}" cap --seed "${seed}" --device-id "${device_id}" --nonce "${nonce2}" --ttl-secs 5 --seq "${seq3}")"
out="$(txn "TOK ${tok}")"
case "${out}" in
    "ACK ${nonce2} "*) : ;;
    *) fail "short token not accepted: ${out}" ;;
esac
sleep 6
txn "STAT" | grep -q "closed.*reason=expiry" || fail "the board did not expire the grant itself"

echo
echo "OPERATOR STEP: power-cycle the board now, then press enter."
read -r _ignored
out="$(txn "STAT")"
echo "  ${out}"
echo "${out}" | grep -q "closed" || fail "the board did not boot closed"
echo "${out}" | grep -q "reason=boot" || fail "boot reason missing after power cycle"
new_mark="$(echo "${out}" | sed -n 's/.*seq=\([0-9]*\).*/\1/p')"
[ "${new_mark}" = "${seq3}" ] || fail "the anti-replay mark did not survive the power cycle (seq=${new_mark}, expected ${seq3})"
note "replaying the pre-power-cycle token must fail even though its TTL is irrelevant now"
out="$(txn "TOK ${tok}")"
[ "${out}" = "NAK replay" ] || fail "the flash-surviving mark did not kill the old token: ${out}"

echo
if [ "${failed}" -ne 0 ]; then
    echo "embedded-hardware: FAILED"
    exit 1
fi
echo "embedded-hardware: ok (hardware tier verified on ${tty})"
