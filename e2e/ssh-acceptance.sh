#!/bin/sh
# M4 acceptance: the SSH drivers against this host's real sshd, end to end
# through the real binaries. Run as root on a DISPOSABLE host (a reaper
# guest): it edits sshd configuration and root's authorized_keys, restoring
# both on the way out, but a failure can leave either changed.
#
# The claims, in order (precondition before success indicator, two oracles
# for the ones that matter):
#   1. open flips the effective posture (sshd -T) to the emergency value
#      AND a real connection with the emergency key succeeds;
#   2. a hand-added key survives the whole cycle untouched;
#   3. close restores authorized_keys byte-for-byte and the default posture,
#      AND the emergency key stops working.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug) locates the binaries.

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
# shellcheck source=e2e/lib.sh
. "$(dirname "$0")/lib.sh"
work="$(mktemp -d /tmp/lychgate-m4-XXXXXX)"
state="${work}/state"
mkdir -p "${state}"

failed=0
fail() {
    echo "FAIL: $1" >&2
    failed=1
}
note() {
    echo "==> $1"
}

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root on a disposable host" >&2
    exit 2
fi
for f in "${bin}/lychgated" "${bin}/lychgate"; do
    if [ ! -x "${f}" ]; then
        echo "missing binary ${f}; build first or set LYCHGATE_BIN_DIR" >&2
        exit 2
    fi
done

# The dead-man rides cron; a managed host without it cannot hold a grant.
command -v crontab >/dev/null 2>&1 || {
    echo "crontab not found: cron must be installed and running on the target" >&2
    exit 2
}

# --- prerequisites on the disposable host ----------------------------------

akeys="/root/.ssh/authorized_keys"
mkdir -p /root/.ssh
touch "${akeys}"
cp "${akeys}" "${work}/authorized_keys.orig"

# The Include directive the drop-in needs; appended only if absent. This is
# the documented operator prerequisite, performed here because the host is
# disposable.
sshd_config="/etc/ssh/sshd_config"
mkdir -p /etc/ssh/sshd_config.d
if ! grep -q 'Include /etc/ssh/sshd_config.d/\*.conf' "${sshd_config}"; then
    # Prepend: sshd honors the first obtained value, so the Include must come
    # before any PermitRootLogin in the main config.
    printf 'Include /etc/ssh/sshd_config.d/*.conf\n%s\n' "$(cat ${sshd_config})" > "${sshd_config}.new"
    cp "${sshd_config}" "${work}/sshd_config.orig"
    mv "${sshd_config}.new" "${sshd_config}"
fi

cleanup() {
    note "cleaning up"
    [ -n "${daemon_pid:-}" ] && kill "${daemon_pid}" 2>/dev/null
    cp "${work}/authorized_keys.orig" "${akeys}" 2>/dev/null
    [ -f "${work}/sshd_config.orig" ] && cp "${work}/sshd_config.orig" "${sshd_config}"
    rm -f /etc/ssh/sshd_config.d/00-lychgate.conf
    if [ "$(uname -s)" = "FreeBSD" ]; then service sshd reload >/dev/null 2>&1
    else systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null; fi
    rm -rf "${work}"
}
trap cleanup EXIT INT TERM

# Keys: the agent key (how the daemon reaches "the host"), a human key (must
# survive untouched), and the emergency key (installed by the grant).
for name in agent human emergency; do
    ssh-keygen -q -t ed25519 -N "" -C "lychgate-m4-${name}" -f "${work}/${name}" </dev/null
done
approval_keygen "${work}/approver"
{
    cat "${work}/agent.pub"
    cat "${work}/human.pub"
} >> "${akeys}"

# The current effective posture is the inventory's declared default; the
# emergency posture is anything else.
current="$(sshd -T 2>/dev/null | awk '$1 == "permitrootlogin" { print $2 }')"
[ "${current}" = "without-password" ] && current="prohibit-password"
case "${current}" in
    yes) emergency="prohibit-password" ;;
    *) emergency="yes" ;;
esac
note "default posture ${current}, emergency ${emergency}"

os="linux"
[ "$(uname -s)" = "FreeBSD" ] && os="freebsd"

cat > "${work}/inventory.toml" <<EOF
[[hosts]]
name = "self"
address = "127.0.0.1"
os = "${os}"
channels = ["ssh", "authorized-keys"]

[hosts.ssh]
agent_user = "root"
root_posture_default = "${current}"
root_posture_emergency = "${emergency}"
identity_file = "${work}/agent"
emergency_keys = ["$(cat "${work}/emergency.pub")"]
EOF
approval_block "${work}/approver" >> "${work}/inventory.toml"

# Accept our own host key for 127.0.0.1 up front so BatchMode never prompts.
ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "${work}/agent" \
    root@127.0.0.1 true || {
    echo "cannot ssh to 127.0.0.1 as root with the agent key; aborting" >&2
    exit 2
}

# --- the cycle --------------------------------------------------------------

note "starting lychgated"
"${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" \
    --interval 600 > "${work}/daemon.log" 2>&1 &
daemon_pid=$!
i=0
while [ ! -S "${state}/lychgated.sock" ]; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "daemon never bound its socket"; cat "${work}/daemon.log"; exit 1; }
    sleep 0.1
done

note "opening the grant (open -> sign -> approve)"
if ! open_and_approve "${state}/lychgated.sock" self 15m "${work}/approver" >/dev/null; then
    fail "open/approve refused"
    cat "${work}/daemon.log"
fi

# Oracle 1a: effective posture flipped.
now="$(sshd -T 2>/dev/null | awk '$1 == "permitrootlogin" { print $2 }')"
[ "${now}" = "without-password" ] && now="prohibit-password"
[ "${now}" = "${emergency}" ] || fail "posture after open is ${now}, wanted ${emergency}"

# Oracle 1b: the emergency key actually works (precondition asserted now,
# before the closing half of the claim later).
if ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "${work}/emergency" \
    root@127.0.0.1 true; then
    note "emergency key connects while the grant is open"
else
    fail "emergency key refused while the grant is open"
fi

note "closing the grant"
if ! "${bin}/lychgate" --socket "${state}/lychgated.sock" close --host self; then
    fail "close refused"
    cat "${work}/daemon.log"
fi

# Oracle 3a: authorized_keys byte-for-byte (with our agent+human additions).
{
    cp "${work}/authorized_keys.orig" "${work}/expected"
    cat "${work}/agent.pub" >> "${work}/expected"
    cat "${work}/human.pub" >> "${work}/expected"
}
if cmp -s "${akeys}" "${work}/expected"; then
    note "authorized_keys restored byte-for-byte; hand-added key intact"
else
    fail "authorized_keys after close differs from the pre-open file"
    diff "${work}/expected" "${akeys}" >&2 || true
fi

# Oracle 3b: posture restored.
after="$(sshd -T 2>/dev/null | awk '$1 == "permitrootlogin" { print $2 }')"
[ "${after}" = "without-password" ] && after="prohibit-password"
[ "${after}" = "${current}" ] || fail "posture after close is ${after}, wanted ${current}"

# Oracle 3c: the emergency key stopped working.
if ssh -o BatchMode=yes -i "${work}/emergency" root@127.0.0.1 true 2>/dev/null; then
    fail "emergency key still connects after close"
else
    note "emergency key refused after close"
fi

# The hand-added human key still works end to end.
if ssh -o BatchMode=yes -i "${work}/human" root@127.0.0.1 true; then
    note "hand-added key survives the whole cycle"
else
    fail "the hand-added human key stopped working"
fi

kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

echo
if [ "${failed}" -ne 0 ]; then
    echo "ssh-acceptance: FAILED"
    echo "--- daemon log ---"
    cat "${work}/daemon.log"
    exit 1
fi
echo "ssh-acceptance: ok"
