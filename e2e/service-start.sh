#!/bin/sh
# The deferred service-file claim: rc(8)/systemd actually start and stop the
# daemon from the shipped service files. Run as root on a DISPOSABLE host.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
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
[ -x "${bin}/lychgated" ] || { echo "missing ${bin}/lychgated" >&2; exit 2; }

os="$(uname -s)"

wait_socket() {
    i=0
    while [ ! -S "$1" ]; do
        i=$((i + 1))
        [ "${i}" -gt 100 ] && return 1
        sleep 0.1
    done
    return 0
}

install -m 755 "${bin}/lychgated" /usr/local/sbin/lychgated

if [ "${os}" = "FreeBSD" ]; then
    statedir="/var/db/lychgate"
    inv="/usr/local/etc/lychgate/inventory.toml"
    cleanup() {
        service lychgated stop >/dev/null 2>&1
        sysrc -x lychgated_enable lychgated_inventory >/dev/null 2>&1
        rm -f /usr/local/etc/rc.d/lychgated /usr/local/sbin/lychgated
        rm -rf "${statedir}" /usr/local/etc/lychgate
    }
    trap cleanup EXIT INT TERM

    mkdir -p /usr/local/etc/lychgate
    cat > "${inv}" <<'EOF'
[[hosts]]
name = "web"
address = "10.0.0.1"
os = "linux"
channels = ["vnc"]

[hosts.vnc]
agent_user = "lychgate"
rfb_port = 5900
local_port = 5959
target = "web"
set_password_cmd = "set {target} {password_file}"
clear_password_cmd = "clear {target}"
EOF
    ./tools/install-service.sh >/dev/null || fail "installer failed"
    sysrc lychgated_enable=YES >/dev/null
    sysrc "lychgated_inventory=${inv}" >/dev/null

    note "service lychgated start"
    service lychgated start || fail "rc start failed"
    wait_socket "${statedir}/lychgated.sock" || fail "no socket after rc start"
    service lychgated status >/dev/null || fail "rc status reports not running"
    note "service lychgated stop"
    service lychgated stop || fail "rc stop failed"
    sleep 1
    service lychgated status >/dev/null 2>&1 && fail "still running after rc stop"
else
    statedir="/var/lib/lychgate"
    inv="/etc/lychgate/inventory.toml"
    cleanup() {
        systemctl stop lychgated >/dev/null 2>&1
        systemctl disable lychgated >/dev/null 2>&1
        rm -f /etc/systemd/system/lychgated.service /usr/local/sbin/lychgated
        systemctl daemon-reload >/dev/null 2>&1
        rm -rf "${statedir}" /etc/lychgate
    }
    trap cleanup EXIT INT TERM

    mkdir -p /etc/lychgate
    cat > "${inv}" <<'EOF'
[[hosts]]
name = "web"
address = "10.0.0.1"
os = "linux"
channels = ["vnc"]

[hosts.vnc]
agent_user = "lychgate"
rfb_port = 5900
local_port = 5959
target = "web"
set_password_cmd = "set {target} {password_file}"
clear_password_cmd = "clear {target}"
EOF
    ./tools/install-service.sh >/dev/null || fail "installer failed"
    systemctl daemon-reload

    note "systemctl start lychgated"
    systemctl start lychgated || fail "systemd start failed"
    wait_socket "${statedir}/lychgated.sock" || fail "no socket after systemd start"
    systemctl is-active --quiet lychgated || fail "unit not active"
    note "systemctl stop lychgated"
    systemctl stop lychgated || fail "systemd stop failed"
    systemctl is-active --quiet lychgated && fail "still active after stop"
fi

# The service run journaled its start and stop.
grep -q '"event":"daemon-start"' "${statedir}/journal.jsonl" || fail "no daemon-start journaled"
grep -q '"event":"daemon-stop"' "${statedir}/journal.jsonl" || fail "no daemon-stop journaled"

echo
if [ "${failed}" -ne 0 ]; then
    echo "service-start: FAILED"
    exit 1
fi
echo "service-start: ok"
