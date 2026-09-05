#!/bin/sh
# M5 acceptance: revert-under-kill. Open a grant, SIGKILL the daemon, and
# prove the target's own dead-man closes everything anyway. Run as root on a
# DISPOSABLE host; it edits sshd config, root's authorized_keys and crontab,
# restoring them on the way out, but a failure can leave them changed.
#
# --sabotage removes the installed dead-man externally (a broken backstop)
# before the kill; the run is then EXPECTED TO FAIL — that inverted run is
# the oracle self-test, driven by run.sh. An oracle that cannot detect a
# missing backstop is not measuring anything.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

sabotage=0
[ "${1:-}" = "--sabotage" ] && sabotage=1

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
# shellcheck source=e2e/lib.sh
. "$(dirname "$0")/lib.sh"
work="$(mktemp -d /tmp/lychgate-m5-XXXXXX)"
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
    [ -x "${f}" ] || { echo "missing binary ${f}" >&2; exit 2; }
done

# The dead-man rides cron; a managed host without it cannot hold a grant.
command -v crontab >/dev/null 2>&1 || {
    echo "crontab not found: cron must be installed and running on the target" >&2
    exit 2
}

akeys="/root/.ssh/authorized_keys"
mkdir -p /root/.ssh
touch "${akeys}"
cp "${akeys}" "${work}/authorized_keys.orig"

sshd_config="/etc/ssh/sshd_config"
mkdir -p /etc/ssh/sshd_config.d
if ! grep -q 'Include /etc/ssh/sshd_config.d/\*.conf' "${sshd_config}"; then
    printf 'Include /etc/ssh/sshd_config.d/*.conf\n%s\n' "$(cat ${sshd_config})" > "${sshd_config}.new"
    cp "${sshd_config}" "${work}/sshd_config.orig"
    mv "${sshd_config}.new" "${sshd_config}"
fi

reload_sshd() {
    if [ "$(uname -s)" = "FreeBSD" ]; then service sshd reload >/dev/null 2>&1
    else systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null; fi
}

cleanup() {
    note "cleaning up"
    [ -n "${daemon_pid:-}" ] && kill -9 "${daemon_pid}" 2>/dev/null
    cp "${work}/authorized_keys.orig" "${akeys}" 2>/dev/null
    [ -f "${work}/sshd_config.orig" ] && cp "${work}/sshd_config.orig" "${sshd_config}"
    rm -f /etc/ssh/sshd_config.d/00-lychgate.conf
    rm -f /etc/lychgate.deadman.sh /etc/lychgate.deadman.deadline /etc/lychgate.deadman.fired
    ( crontab -l 2>/dev/null | grep -v 'LYCHGATE-DEADMAN' | crontab - ) 2>/dev/null
    reload_sshd
    rm -rf "${work}"
}
trap cleanup EXIT INT TERM

for name in agent human emergency; do
    ssh-keygen -q -t ed25519 -N "" -C "lychgate-m5-${name}" -f "${work}/${name}" </dev/null
done
approval_keygen "${work}/approver"
{
    cat "${work}/agent.pub"
    cat "${work}/human.pub"
} >> "${akeys}"

posture() {
    p="$(sshd -T 2>/dev/null | awk '$1 == "permitrootlogin" { print $2 }')"
    [ "${p}" = "without-password" ] && p="prohibit-password"
    echo "${p}"
}

current="$(posture)"
case "${current}" in
    yes) emergency="prohibit-password" ;;
    *) emergency="yes" ;;
esac
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

ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "${work}/agent" \
    root@127.0.0.1 true || { echo "cannot ssh to self; aborting" >&2; exit 2; }

# --- open with a short ttl --------------------------------------------------

note "starting lychgated"
"${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" \
    --interval 600 > "${work}/daemon.log" 2>&1 &
daemon_pid=$!
i=0
while [ ! -S "${state}/lychgated.sock" ]; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "daemon never bound its socket"; exit 1; }
    sleep 0.1
done

deadline_at=$(( $(date +%s) + 90 ))
note "opening a 90s grant (open -> sign -> approve)"
open_and_approve "${state}/lychgated.sock" self 90s "${work}/approver" >/dev/null \
    || { fail "open/approve refused"; cat "${work}/daemon.log"; exit 1; }

# --- preconditions, asserted before the kill --------------------------------

[ "$(posture)" = "${emergency}" ] || fail "posture after open is $(posture), wanted ${emergency}"
ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "${work}/emergency" \
    root@127.0.0.1 true || fail "emergency key refused while the grant is open"
crontab -l 2>/dev/null | grep -q 'LYCHGATE-DEADMAN' || fail "dead-man schedule missing after open"
[ -f /etc/lychgate.deadman.sh ] || fail "dead-man script missing after open"
[ -f /etc/lychgate.deadman.deadline ] || fail "dead-man deadline missing after open"
[ "${failed}" -eq 0 ] || { cat "${work}/daemon.log"; exit 1; }
note "preconditions hold: access open, backstop armed"

if [ "${sabotage}" -eq 1 ]; then
    note "SABOTAGE: removing the dead-man externally"
    ( crontab -l 2>/dev/null | grep -v 'LYCHGATE-DEADMAN' | crontab - ) || true
    rm -f /etc/lychgate.deadman.sh /etc/lychgate.deadman.deadline
fi

# --- the kill ---------------------------------------------------------------

note "SIGKILL the daemon (pid ${daemon_pid})"
kill -9 "${daemon_pid}"
wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

# --- the wait: the target must close itself ---------------------------------

# Cron granularity is one minute; allow the deadline plus a generous margin.
# The single dead-man invocation reverts access AND cleans up its own
# schedule and deadline before exiting; wait for the whole thing so the
# hygiene asserts below do not race its final rm.
note "waiting for the dead-man (deadline in $(( deadline_at - $(date +%s) ))s)"
reverted=0
while [ "$(date +%s)" -lt $(( deadline_at + 150 )) ]; do
    if [ "$(posture)" = "${current}" ] \
        && ! grep -q 'LYCHGATE BEGIN' "${akeys}" \
        && [ ! -f /etc/lychgate.deadman.deadline ] \
        && ! { crontab -l 2>/dev/null | grep -q 'LYCHGATE-DEADMAN'; }; then
        reverted=1
        break
    fi
    sleep 5
done
[ "${reverted}" -eq 1 ] || fail "the target never fully reverted itself: posture $(posture)"

# --- post oracles -----------------------------------------------------------

if ssh -o BatchMode=yes -i "${work}/emergency" root@127.0.0.1 true 2>/dev/null; then
    fail "emergency key still connects after the dead-man fired"
else
    note "emergency key refused after the dead-man fired"
fi

{
    cp "${work}/authorized_keys.orig" "${work}/expected"
    cat "${work}/agent.pub" >> "${work}/expected"
    cat "${work}/human.pub" >> "${work}/expected"
}
cmp -s "${akeys}" "${work}/expected" || fail "authorized_keys not restored byte-for-byte"
crontab -l 2>/dev/null | grep -q 'LYCHGATE-DEADMAN' && fail "the dead-man left its schedule behind"
[ -f /etc/lychgate.deadman.deadline ] && fail "the dead-man left its deadline behind"
[ -f /etc/lychgate.deadman.fired ] || fail "no fired marker: who reverted this host?"

# --- the daemon returns and reconciles --------------------------------------

# The dead-man has already reverted the host; what remains is the daemon's
# bookkeeping — observe the expiry, undo its own record, journal the close.
# The daemon does this on a loop, and a revert step left stuck by a transient
# (a dropped ssh connection under load) is retried on the next pass, by
# design (see lifecycle drive_one_revert: "retried on every pass"). Production
# supervises the daemon so it reconciles across passes; cron does the same via
# --once each minute. Model that here: rerun the pass until the close lands,
# rather than demanding it in exactly one pass, which the daemon never
# promises. The fired marker persists until a *successful* removal, so the
# close still records deadman_fired=true whichever pass completes it. A revert
# that never closes across the whole window fails loudly below — this loosens
# the pass count, never the claim.
note "restarting the daemon to reconcile (reverts retried across passes)"
rm -f "${state}/lychgated.sock"
closed=0
passes=0
while [ "${passes}" -lt 15 ]; do
    passes=$((passes + 1))
    "${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" --once \
        > "${work}/daemon2.log" 2>&1 \
        || { fail "post-kill pass ${passes} exited nonzero"; break; }
    if grep -q '"event":"close".*"deadman_fired":true' "${state}/journal.jsonl"; then
        closed=1
        break
    fi
    sleep 1
done

grep -q '"event":"expire"' "${state}/journal.jsonl" || fail "no expire event journaled"
[ "${closed}" -eq 1 ] \
    || fail "the close never recorded the dead-man firing across ${passes} passes"

# Idempotence: a further boot over the settled state changes nothing and
# succeeds.
"${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" --once \
    >/dev/null 2>&1 || fail "a settled-state pass failed"

echo
if [ "${failed}" -ne 0 ]; then
    # A safety test that fails opaquely cannot be acted on. Dump the evidence
    # the trap is about to delete: the reconcile's own log and journal say
    # whether a revert got stuck (grant retained needs-revert, no close event)
    # or closed recording the wrong thing, and the host state says what was
    # left behind. Printed only on failure, so a green run stays quiet.
    echo "---- DIAGNOSTICS (revert-under-kill failed) ----" >&2
    echo "-- journal.jsonl --" >&2
    cat "${state}/journal.jsonl" >&2 2>/dev/null || echo "(no journal)" >&2
    echo "-- reconcile pass (daemon2.log) --" >&2
    cat "${work}/daemon2.log" >&2 2>/dev/null || echo "(no daemon2.log)" >&2
    echo "-- open-time daemon.log (tail) --" >&2
    tail -20 "${work}/daemon.log" >&2 2>/dev/null || echo "(no daemon.log)" >&2
    echo "-- host state --" >&2
    ls -la /etc/lychgate.deadman.* >&2 2>/dev/null || echo "(no deadman files)" >&2
    { crontab -l 2>/dev/null | grep 'LYCHGATE-DEADMAN'; } >&2 || echo "(no deadman cron line)" >&2
    echo "posture now: $(posture); default: ${current}" >&2
    echo "------------------------------------------------" >&2
    echo "revert-under-kill: FAILED"
    exit 1
fi
echo "revert-under-kill: ok"
