#!/bin/sh
# M9 acceptance: the TPM factor and TPM-sealed secrets, end to end against a
# real (software) TPM — swtpm is to the TPM what virtual-fido is to FIDO2. Run
# as root on a DISPOSABLE host (a reaper guest): it touches root's
# authorized_keys, restoring it on the way out.
#
# Needs binaries built WITH the tpm features (the Ubuntu container build does
# this; FreeBSD's guest runs default binaries) and swtpm on the host. Exit 2 =
# SKIPPED, loudly, when either is missing — run.sh's phase_skippable renders
# that as a named skip, never a pass.
#
# Claims:
#   1. `lychgate tpm-probe` passes against the TPM (the compatibility check);
#   2. a tpm-signed challenge opens a single-factor tpm profile over the real
#      vnc channel, and a stale-challenge signature is refused first (the
#      challenge binding);
#   3. a TOTP secret sealed with `lychgate tpm-seal` is unsealed by
#      `lychgated --tpm-unseal` at startup, proven by a code computed from the
#      PLAINTEXT secret being accepted;
#   4. fail-closed: the same daemon WITHOUT --tpm-unseal refuses to start on
#      the sealed file (it is not valid base32), never silently misreading it.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
here="$(dirname "$0")"
work="$(mktemp -d /tmp/lychgate-m9-XXXXXX)"
state="${work}/state"
sock="${state}/lychgated.sock"
mkdir -p "${state}"

failed=0
fail() { echo "FAIL: $1" >&2; failed=1; }
note() { echo "==> $1"; }
skip() { echo "tpm-acceptance: SKIPPED ($1)"; exit 2; }

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root on a disposable host" >&2
    exit 2
fi
for f in "${bin}/lychgated" "${bin}/lychgate"; do
    [ -x "${f}" ] || { echo "missing binary ${f}" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || { echo "python3 not found" >&2; exit 2; }
command -v swtpm >/dev/null 2>&1 || skip "swtpm is not installed on this guest"
if "${bin}/lychgate" tpm-probe --tcti "device:/nonexistent" 2>&1 | grep -q "no TPM support"; then
    skip "binaries built without the tpm-client feature"
fi

akeys="/root/.ssh/authorized_keys"
mkdir -p /root/.ssh
touch "${akeys}"
cp "${akeys}" "${work}/authorized_keys.orig"

cleanup() {
    note "cleaning up"
    [ -n "${daemon_pid:-}" ] && kill -9 "${daemon_pid}" 2>/dev/null
    [ -n "${mock_pid:-}" ] && kill "${mock_pid}" 2>/dev/null
    [ -n "${swtpm_pid:-}" ] && kill "${swtpm_pid}" 2>/dev/null
    pkill -f "ssh -N.*ExitOnForwardFailure" 2>/dev/null
    cp "${work}/authorized_keys.orig" "${akeys}" 2>/dev/null
    rm -rf "${work}"
}
trap cleanup EXIT INT TERM

free_port() {
    python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}

# --- a fresh software TPM for this run --------------------------------------

# The swtpm TCTI hardcodes the control socket at data-port+1, so the two ports
# must be adjacent; a random pair is not. Try a few base ports until both bind.
mkdir -p "${work}/tpmstate"
tpm_port=""
for _try in 1 2 3 4 5; do
    candidate="$(free_port)"
    swtpm socket --tpm2 --tpmstate "dir=${work}/tpmstate" \
        --server "type=tcp,port=${candidate}" \
        --ctrl "type=tcp,port=$((candidate + 1))" \
        --flags not-need-init,startup-clear &
    swtpm_pid=$!
    sleep 1
    if kill -0 "${swtpm_pid}" 2>/dev/null; then
        tpm_port="${candidate}"
        break
    fi
    wait "${swtpm_pid}" 2>/dev/null
done
[ -n "${tpm_port}" ] || { fail "swtpm never bound an adjacent port pair"; exit 1; }
tcti="swtpm:host=127.0.0.1,port=${tpm_port}"

# --- 1: the compatibility probe ---------------------------------------------

note "tpm-probe against ${tcti}"
if "${bin}/lychgate" tpm-probe --tcti "${tcti}" > "${work}/probe.out" 2>&1; then
    grep -q "seal/unseal round trip: ok" "${work}/probe.out" \
        || fail "probe passed but did not report the seal round trip"
    note "probe ok: $(grep manufacturer "${work}/probe.out")"
else
    fail "tpm-probe failed: $(cat "${work}/probe.out")"
    echo "tpm-acceptance: FAILED"; exit 1
fi

# --- the harness: real vnc channel, tpm + totp authenticators ---------------

ssh-keygen -q -t ed25519 -N "" -C "agent" -f "${work}/agent" </dev/null
cat "${work}/agent.pub" >> "${akeys}"
ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "${work}/agent" \
    root@127.0.0.1 true || { echo "cannot ssh to self; aborting" >&2; exit 2; }

note "tpm-register: deriving the TPM's signing key"
"${bin}/lychgate" tpm-register --tcti "${tcti}" > "${work}/block" 2>&1 \
    || { fail "tpm-register failed: $(cat "${work}/block")"; exit 1; }
tpm_pub="$(sed -n 's/^public-key = "\(.*\)"$/\1/p' "${work}/block")"
[ -n "${tpm_pub}" ] || { fail "no public-key in the register block"; exit 1; }

# A TOTP secret, sealed to this TPM. The PLAINTEXT never reaches the daemon's
# config — only the sealed blob does.
totp_plain="JBSWY3DPEHPK3PXP"
printf '%s' "${totp_plain}" > "${work}/totp.plain"
"${bin}/lychgate" tpm-seal --file "${work}/totp.plain" --tcti "${tcti}" \
    > "${work}/totp.sealed" || { fail "tpm-seal failed"; exit 1; }

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
profiles = ["tpm", "totp"]

[[approval.authenticator]]
id = "host-tpm"
kind = "tpm"
public-key = "${tpm_pub}"
[[approval.authenticator]]
id = "phone"
kind = "totp"
secret-file = "${work}/totp.sealed"

[[approval.profile]]
id = "tpm"
threshold = 1
factor = [ { authenticator = "host-tpm", weight = 1 } ]
[[approval.profile]]
id = "totp"
threshold = 1
factor = [ { authenticator = "phone", weight = 1 } ]
EOF

note "starting the RFB mock on 127.0.0.1:${rfb_port}"
python3 "${here}/rfb-mock.py" "${rfb_port}" &
mock_pid=$!

# --- 4 first (fail-closed): no --tpm-unseal + a sealed secret file ----------

note "fail-closed: without --tpm-unseal the sealed TOTP file refuses the start"
if "${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" \
    --interval 600 --approval-window 120 > "${work}/noflag.log" 2>&1; then
    fail "the daemon started while misreading a sealed blob as base32"
else
    note "refused, as it must (a sealed blob is not a TOTP secret)"
fi

# --- 2 & 3: the real daemon, unsealing at startup ---------------------------

note "starting lychgated with --tpm-unseal ${tcti}"
"${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" \
    --tpm-unseal "${tcti}" --interval 600 --approval-window 120 \
    > "${work}/daemon.log" 2>&1 &
daemon_pid=$!
# Wait for a real status round trip, not the socket file: the fail-closed run
# above leaves a STALE socket behind (it binds before the secret load refuses
# it), and this daemon unseals via the TPM before it serves — the M8a.4 lesson.
i=0
until "${bin}/lychgate" --socket "${sock}" status >/dev/null 2>&1; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "daemon never served"; cat "${work}/daemon.log"; exit 1; }
    sleep 0.2
done

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

note "the tpm factor: a stale-challenge signature is refused, the fresh one opens"
challenge="$("${bin}/lychgate" --socket "${sock}" open --host hv --ttl 15m --as tpm \
    | sed -n 's/^challenge: //p')"
[ -n "${challenge}" ] || fail "open returned no challenge"
stale="$("${bin}/lychgate" tpm-sign --challenge 'lg1.req.STALE-NONCE' --tcti "${tcti}")"
if printf '%s' "${stale}" | "${bin}/lychgate" --socket "${sock}" approve --host hv >/dev/null 2>&1; then
    fail "a stale-challenge tpm signature was accepted"
elif is_open; then
    fail "opened on a stale-challenge tpm signature"
else
    note "the stale signature was refused; the grant stays pending"
fi
fresh="$("${bin}/lychgate" tpm-sign --challenge "${challenge}" --tcti "${tcti}")"
if printf '%s' "${fresh}" | "${bin}/lychgate" --socket "${sock}" approve --host hv >/dev/null 2>&1; then
    if is_open; then
        note "the TPM-resident key opened the grant"
    else
        fail "tpm approve ok but not open"
    fi
else
    fail "the fresh tpm signature was refused"
    cat "${work}/daemon.log"
fi
close_hv || fail "close did not settle"

note "the sealed TOTP secret: a code from the PLAINTEXT opens the totp profile"
"${bin}/lychgate" --socket "${sock}" open --host hv --ttl 15m --as totp >/dev/null
code="$(python3 - "$totp_plain" <<'PY'
import base64, hashlib, hmac, struct, sys, time
secret = base64.b32decode(sys.argv[1])
counter = int(time.time()) // 30
mac = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
off = mac[-1] & 0x0F
print(f"{(struct.unpack('>I', mac[off:off+4])[0] & 0x7FFFFFFF) % 1000000:06d}")
PY
)"
if printf '%s' "${code}" | "${bin}/lychgate" --socket "${sock}" approve --host hv >/dev/null 2>&1; then
    if is_open; then
        note "the unsealed secret verified the code — seal/unseal is byte-exact"
    else
        fail "totp approve ok but not open"
    fi
else
    fail "the TOTP code was refused — the unseal did not recover the secret"
    cat "${work}/daemon.log"
fi
close_hv || fail "close did not settle"

kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

echo
if [ "${failed}" -ne 0 ]; then
    echo "tpm-acceptance: FAILED"
    echo "--- daemon log ---"
    cat "${work}/daemon.log"
    exit 1
fi
echo "tpm-acceptance: ok"
