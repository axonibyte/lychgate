#!/bin/sh
# Install the lychgated service file for this operating system.
#
# Installs service files ONLY — never the binary, and it neither enables nor
# starts anything; it prints the next steps instead. Honors DESTDIR for
# staging (and for the test battery); a staging install touches nothing
# outside DESTDIR, so root is required only when DESTDIR is empty.
#
# LYCHGATE_INSTALL_OS overrides uname -s, for staging a tree for another OS
# and for testing the refusal path.

set -u

cd "$(dirname "$0")/.." || exit 2

os="${LYCHGATE_INSTALL_OS:-$(uname -s)}"
destdir="${DESTDIR:-}"

if [ -z "${destdir}" ] && [ "$(id -u)" -ne 0 ]; then
    echo "install-service: installing to / requires root; set DESTDIR to stage elsewhere" >&2
    exit 1
fi

case "${os}" in
    FreeBSD)
        target="${destdir}/usr/local/etc/rc.d/lychgated"
        install -d "${destdir}/usr/local/etc/rc.d"
        install -m 555 rc.d/lychgated "${target}"
        echo "installed ${target}"
        echo "next steps:"
        echo "  sysrc lychgated_enable=YES"
        echo "  install lychgated at /usr/local/sbin/lychgated"
        echo "  place the inventory at /usr/local/etc/lychgate/inventory.toml"
        echo "  service lychgated start"
        ;;
    Linux)
        target="${destdir}/etc/systemd/system/lychgated.service"
        install -d "${destdir}/etc/systemd/system"
        install -m 644 systemd/lychgated.service "${target}"
        echo "installed ${target}"
        echo "next steps:"
        echo "  install lychgated at /usr/local/sbin/lychgated"
        echo "  place the inventory at /etc/lychgate/inventory.toml"
        echo "  systemctl daemon-reload && systemctl enable --now lychgated"
        ;;
    *)
        echo "install-service: no service integration for ${os}; FreeBSD and Linux are supported" >&2
        exit 1
        ;;
esac
