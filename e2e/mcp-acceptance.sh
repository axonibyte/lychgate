#!/bin/sh
# M8b acceptance: the MCP front door and the AI-as-a-factor model, end to end
# through the real binaries. A Claude session speaks MCP to `lychgate-mcp` over
# stdio; it signs the AI factor and talks to the daemon's dedicated MCP socket;
# a human completes a "sysadmin + AI" grant out of band on the operator socket.
# Run as root on a DISPOSABLE host (a reaper guest): it touches root's
# authorized_keys, restoring it on the way out.
#
# The policy:
#   profile "ai-assisted": threshold 2 over { ai (1), sysadmin (1) }, mcp = true
#   profile "solo-human":  threshold 1 over { sysadmin (1) },         mcp = false
#
# Claims:
#   1. over MCP, open_grant on a non-mcp profile (solo-human) is REFUSED by the
#      daemon's front-door gate (and nothing opens);
#   2. over MCP, open_grant on ai-assisted contributes the AI factor (weight
#      1/2) but does NOT open — the AI alone cannot meet a 2-threshold;
#   3. a human signing the SAME challenge on the OPERATOR socket opens it (the
#      genuine sysadmin+AI gate), driving the vnc channel;
#   4. over MCP, grant_status then shows the host OPEN.
#
# What it does NOT prove: one-time-secret delivery to the AI (deferred). The vnc
# channel is just the thing the grant opens. See TESTING.md.
#
# Env: LYCHGATE_BIN_DIR (default ./target/debug).

set -u

bin="${LYCHGATE_BIN_DIR:-./target/debug}"
here="$(dirname "$0")"
work="$(mktemp -d /tmp/lychgate-m8b-XXXXXX)"
state="${work}/state"
sock="${state}/lychgated.sock"
mcp_sock="${state}/mcp.sock"
mkdir -p "${state}"

failed=0
fail() { echo "FAIL: $1" >&2; failed=1; }
note() { echo "==> $1"; }

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root on a disposable host" >&2
    exit 2
fi
for f in "${bin}/lychgated" "${bin}/lychgate" "${bin}/lychgate-mcp"; do
    [ -x "${f}" ] || { echo "missing binary ${f}" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || { echo "python3 not found: the RFB mock needs it" >&2; exit 2; }

akeys="/root/.ssh/authorized_keys"
mkdir -p /root/.ssh
touch "${akeys}"
cp "${akeys}" "${work}/authorized_keys.orig"

cleanup() {
    note "cleaning up"
    [ -n "${daemon_pid:-}" ] && kill -9 "${daemon_pid}" 2>/dev/null
    [ -n "${mock_pid:-}" ] && kill "${mock_pid}" 2>/dev/null
    pkill -f "ssh -N.*ExitOnForwardFailure" 2>/dev/null
    cp "${work}/authorized_keys.orig" "${akeys}" 2>/dev/null
    rm -rf "${work}"
}
trap cleanup EXIT INT TERM

# Keys: the agent key for the vnc tunnel, the AI principal (lychgate-mcp signs
# with it), and the human sysadmin.
ssh-keygen -q -t ed25519 -N "" -C "agent" -f "${work}/agent" </dev/null
ssh-keygen -q -t ed25519 -N "" -C "ai" -f "${work}/ai" </dev/null
ssh-keygen -q -t ed25519 -N "" -C "sysadmin" -f "${work}/sysadmin" </dev/null
cat "${work}/agent.pub" >> "${akeys}"
ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "${work}/agent" \
    root@127.0.0.1 true || { echo "cannot ssh to self; aborting" >&2; exit 2; }

ai_pub="$(cat "${work}/ai.pub")"
sysadmin_pub="$(cat "${work}/sysadmin.pub")"

free_port() {
    python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}
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
profiles = ["ai-assisted", "solo-human"]

[[approval.authenticator]]
id = "ai"
kind = "ed25519"
public-key = "${ai_pub}"
[[approval.authenticator]]
id = "sysadmin"
kind = "ed25519"
public-key = "${sysadmin_pub}"

[[approval.profile]]
id = "ai-assisted"
threshold = 2
mcp = true
factor = [
  { authenticator = "ai",       weight = 1 },
  { authenticator = "sysadmin", weight = 1 },
]

[[approval.profile]]
id = "solo-human"
threshold = 1
factor = [ { authenticator = "sysadmin", weight = 1 } ]
EOF

note "starting the RFB mock on 127.0.0.1:${rfb_port}"
python3 "${here}/rfb-mock.py" "${rfb_port}" &
mock_pid=$!

note "starting lychgated with an operator socket AND an MCP socket"
"${bin}/lychgated" --inventory "${work}/inventory.toml" --state-dir "${state}" \
    --mcp-socket "${mcp_sock}" --interval 600 --approval-window 120 \
    > "${work}/daemon.log" 2>&1 &
daemon_pid=$!
i=0
while [ ! -S "${sock}" ] || [ ! -S "${mcp_sock}" ]; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { fail "daemon never bound both sockets"; cat "${work}/daemon.log"; exit 1; }
    sleep 0.1
done

# Drive one MCP tool call: initialize, then tools/call. Prints the raw response
# lines. lychgate-mcp reads stdin to EOF, so both messages go in one pipe.
mcp_call() {
    printf '%s\n%s\n' \
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
        "$1" \
        | "${bin}/lychgate-mcp" --mcp-socket "${mcp_sock}" --principal-key "${work}/ai" 2>/dev/null
}
is_open() {
    "${bin}/lychgate" --socket "${sock}" status | grep -qE '^hv[[:space:]]+open'
}

# --- 1: a non-mcp profile is refused over MCP -------------------------------

note "over MCP, open_grant on the non-mcp profile solo-human is refused"
out="$(mcp_call '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open_grant","arguments":{"host":"hv","ttl":"15m","profile":"solo-human"}}}')"
if printf '%s' "${out}" | grep -q "not reachable via the MCP front door"; then
    note "the front-door gate refused the non-mcp profile"
else
    fail "solo-human was not refused over MCP; got: ${out}"
fi
is_open && fail "nothing should be open after a refused MCP open"

# --- 2: the AI factor is contributed but does not open a 2-threshold --------

note "over MCP, open_grant on ai-assisted contributes the AI factor"
out="$(mcp_call '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open_grant","arguments":{"host":"hv","ttl":"15m","profile":"ai-assisted"}}}')"
if printf '%s' "${out}" | grep -q "weight 1/2"; then
    note "the AI factor was accepted (weight 1/2)"
else
    fail "the AI factor was not accepted; got: ${out}"
fi
if is_open; then
    fail "the grant opened on the AI factor ALONE (threshold is 2)"
else
    note "the grant is pending — the AI alone cannot meet the threshold"
fi

# The AI surfaced the challenge for the human to sign.
challenge="$(printf '%s' "${out}" | grep -oE 'lg1\.req\.[A-Za-z0-9_-]+' | head -1)"
[ -n "${challenge}" ] || fail "open_grant did not surface a challenge for the human"

# --- 3: the human completes the gate on the OPERATOR socket -----------------

note "the human sysadmin signs the SAME challenge and approves out of band"
if printf '%s' "${challenge}" | ssh-keygen -Y sign -n lychgate-approval -f "${work}/sysadmin" 2>/dev/null \
    | "${bin}/lychgate" --socket "${sock}" approve --host hv >/dev/null 2>&1; then
    if is_open; then
        note "the grant opened only after BOTH the AI and the sysadmin (real sysadmin+AI)"
    else
        fail "both factors submitted but the grant is not open"
        cat "${work}/daemon.log"
    fi
else
    fail "the sysadmin approval was refused"
    cat "${work}/daemon.log"
fi

# --- 4: the MCP front door sees the grant open ------------------------------

note "over MCP, grant_status shows the host open"
out="$(mcp_call '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"grant_status","arguments":{"host":"hv"}}}')"
if printf '%s' "${out}" | grep -qi "open"; then
    note "MCP grant_status reports hv open"
else
    fail "MCP grant_status did not report hv open; got: ${out}"
fi

kill "${daemon_pid}" 2>/dev/null && wait "${daemon_pid}" 2>/dev/null
daemon_pid=""

echo
if [ "${failed}" -ne 0 ]; then
    echo "mcp-acceptance: FAILED"
    echo "--- daemon log ---"
    cat "${work}/daemon.log"
    exit 1
fi
echo "mcp-acceptance: ok"
