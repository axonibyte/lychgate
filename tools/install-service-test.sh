#!/bin/sh
# Battery for install-service.sh: DESTDIR staging installs for each OS land
# the right file at the right path with the right mode, and an unsupported
# OS is refused. Runs unprivileged (DESTDIR installs need no root).
#
# What this does NOT prove: that rc(8) or systemd actually start the daemon
# from these files. That claim belongs to the full-stack tier on the reaper
# guests (M5); see TESTING.md.

set -u

cd "$(dirname "$0")/.." || exit 2

scratch="${TMPDIR:-/tmp}/lychgate-install-test-$$"
trap 'rm -rf "${scratch}"' EXIT INT TERM
rm -rf "${scratch}"
mkdir -p "${scratch}"

failed=0

fail() {
    echo "FAIL: $1" >&2
    failed=1
}

mode_of() {
    # BSD stat and GNU stat disagree on flags; try both.
    stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1" 2>/dev/null
}

# --- FreeBSD staging install -----------------------------------------------
dest="${scratch}/freebsd"
if DESTDIR="${dest}" LYCHGATE_INSTALL_OS=FreeBSD ./tools/install-service.sh >/dev/null; then
    f="${dest}/usr/local/etc/rc.d/lychgated"
    [ -f "${f}" ] || fail "FreeBSD: ${f} not installed"
    [ "$(mode_of "${f}")" = "555" ] || fail "FreeBSD: ${f} mode $(mode_of "${f}"), wanted 555"
else
    fail "FreeBSD staging install exited nonzero"
fi

# --- Linux staging install -------------------------------------------------
dest="${scratch}/linux"
if DESTDIR="${dest}" LYCHGATE_INSTALL_OS=Linux ./tools/install-service.sh >/dev/null; then
    f="${dest}/etc/systemd/system/lychgated.service"
    [ -f "${f}" ] || fail "Linux: ${f} not installed"
    [ "$(mode_of "${f}")" = "644" ] || fail "Linux: ${f} mode $(mode_of "${f}"), wanted 644"
else
    fail "Linux staging install exited nonzero"
fi

# --- Unsupported OS is refused, naming it ----------------------------------
dest="${scratch}/plan9"
err="${scratch}/plan9.err"
if DESTDIR="${dest}" LYCHGATE_INSTALL_OS=Plan9 ./tools/install-service.sh >/dev/null 2>"${err}"; then
    fail "Plan9 install succeeded; unsupported OS must be refused"
else
    grep -q "Plan9" "${err}" || fail "refusal does not name the OS: $(cat "${err}")"
fi
[ -d "${dest}" ] && fail "refusal left a staging tree behind"

if [ "${failed}" -ne 0 ]; then
    echo "install-service-test: FAILED"
    exit 1
fi
echo "install-service-test: ok"
