#!/bin/sh
# Register a device's secure element as a lychgate approval factor.
#
# Talks to a board running the reference firmware's `se` feature over its
# serial port, asks the ATECC608 for its public key, and prints the
# ready-to-paste [[approval.authenticator]] block. The kind is "tpm" on
# purpose: that kind means "a non-exportable P-256 signer", and a TPM 2.0,
# an ATECC608, and the ESP32 DS peripheral are all instances of it
# (docs/EMBEDDED.md §4) — the daemon verifies them identically.
#
# At approve time the device signs the challenge with:
#   SE-SIGN <challenge>        -> SIG lgtpm.<...>
# and the SIG token is what gets piped into `lychgate approve`.
#
# Usage: EMBED_TTY=/dev/ttyACM0 sh tools/se-register.sh [--id <name>]

set -u

tty="${EMBED_TTY:-}"
id="se-device"
[ "${1:-}" = "--id" ] && id="${2:?--id needs a value}"

[ -n "${tty}" ] && [ -e "${tty}" ] || {
    echo "se-register: set EMBED_TTY to the board's serial device" >&2
    exit 2
}
command -v python3 >/dev/null 2>&1 || {
    echo "se-register: python3 is required (hex -> base64url conversion)" >&2
    exit 2
}

stty -f "${tty}" raw -echo 115200 2>/dev/null || stty -F "${tty}" raw -echo 115200

printf 'SE-PUBKEY?\n' > "${tty}"
reply="$(head -n 1 < "${tty}")"
case "${reply}" in
    "PUBKEY 04"*) ;;
    *)
        echo "se-register: the board did not answer with a public key: ${reply:-nothing}" >&2
        echo "se-register: is the firmware built with --features se, and the ATECC608 wired?" >&2
        exit 1
        ;;
esac

hex="$(printf '%s' "${reply}" | sed 's/^PUBKEY //' | tr -d '\r')"
b64="$(python3 -c "
import base64, sys
raw = bytes.fromhex('${hex}')
assert len(raw) == 65 and raw[0] == 4, 'expected an uncompressed SEC1 point'
sys.stdout.write(base64.urlsafe_b64encode(raw).decode().rstrip('='))
")" || exit 1

cat <<EOF
# The ${id} secure element (ATECC608 slot 0; the private key never leaves
# the chip). Paste into the inventory's [approval] section:

[[approval.authenticator]]
id = "${id}"
kind = "tpm"
public-key = "${b64}"
EOF
