# Runbook: granting a Claude session emergency access, end to end

This is the operator's procedure for standing lychgate up and using it to grant a
Claude session break-glass access to a production host — requested by the AI over
MCP, approved by a human out of band, and reverted on a timer. It assumes the
binaries are built (`cargo build --release --workspace`); the concepts behind
each step live in [DESIGN.md](DESIGN.md), and the full inventory schema in the
[README](../README.md).

The shape of every grant: `open` records a pending request and returns a
challenge — it opens nothing. The grant opens only once a profile's weighted
threshold of approvals is met, and it reverts itself at its TTL (a dead-man on
the target does the revert even if the daemon dies). Nothing here bypasses that.

---

## 1. Install and run the daemon

Place the binaries and install the service file for your OS
(`tools/install-service.sh` installs only the service file and prints the rest):

**FreeBSD**
```sh
install -m 555 target/release/lychgated /usr/local/sbin/lychgated
install -m 555 target/release/lychgate  /usr/local/bin/lychgate
doas sh tools/install-service.sh        # writes /usr/local/etc/rc.d/lychgated
mkdir -p /usr/local/etc/lychgate        # inventory lives here
sysrc lychgated_enable=YES
```

**Linux (systemd)**
```sh
install -m 555 target/release/lychgated /usr/local/sbin/lychgated
install -m 555 target/release/lychgate  /usr/local/bin/lychgate
sudo sh tools/install-service.sh        # writes /etc/systemd/system/lychgated.service
sudo mkdir -p /etc/lychgate
```

State (the grant store, the journal, the control socket) lives in
`/var/db/lychgate` on FreeBSD and `/var/lib/lychgate` on Linux; the control
socket is `<state-dir>/lychgated.sock`, owner-only.

**Prerequisite — cron on every managed host.** The dead-man backstop rides cron
on the target: opening an ssh-borne grant is *refused* if cron is missing, since
a grant whose revert cannot fire is worse than no grant. FreeBSD ships cron in
base; on stock Ubuntu server, `apt-get install -y cron` and enable it.

Do not start the daemon yet — finish the policy in step 2 first (a daemon with no
`[approval]` policy refuses to start, by design).

---

## 2. Configure the host and an "AI-assisted" profile

The AI is a first-class approval factor: an Ed25519 key the MCP server holds,
listed like any other authenticator. Compose it with a human so neither opens
alone. Generate the AI's key first (step 3 covers the server); print its public
line with `lychgate-mcp --principal-key <keyfile> --show-public-key`.

Edit the inventory (`/usr/local/etc/lychgate/inventory.toml` on FreeBSD,
`/etc/lychgate/inventory.toml` on Linux). A minimal Claude-emergency-access setup
over the ssh channel:

```toml
[[hosts]]
name = "db-01"
address = "10.0.4.11"
os = "linux"
channels = ["ssh"]
[hosts.ssh]
agent_user = "root"
root_posture_default = "prohibit-password"
root_posture_emergency = "yes"
emergency_keys = ["ssh-ed25519 AAAA... claude-breakglass"]   # the key Claude will use
[hosts.access]
profiles = ["ai-assisted"]

[[approval.authenticator]]
id = "sysadmin"
kind = "ed25519"
public-key = "ssh-ed25519 AAAA... oncall@phone"
[[approval.authenticator]]
id = "ai"
kind = "ed25519"
public-key = "ssh-ed25519 AAAA... lychgate-mcp"              # from --show-public-key

[[approval.profile]]
id = "ai-assisted"
threshold = 2
mcp = true                                                   # reachable over the MCP front door
factor = [
  { authenticator = "sysadmin", weight = 1 },                # a human must sign
  { authenticator = "ai",       weight = 1 },                # the AI contributes over MCP
]
```

`mcp = true` is what lets this profile be opened through the MCP front door;
without it, the daemon refuses an MCP-originated open (fail-closed). The other
channels (bmc, vnc) and factor kinds (totp, password, fido2) are in the README;
the flow below is identical whichever you use.

Now start the daemon:

```sh
service lychgated start          # FreeBSD
sudo systemctl enable --now lychgated   # Linux
lychgate status                  # sanity: the daemon answers
```

Re-run these edits + a reload whenever the policy changes; revocation is an
inventory edit (drop the authenticator or the profile) plus a restart.

---

## 3. Stand up the MCP front door

`lychgate-mcp` is a low-privilege client of a **dedicated** daemon socket — a
second socket the daemon binds only when told to, whose ops are gated by the
per-profile `mcp` flag. Enable it and give the AI a key:

```sh
# The AI principal key (unencrypted OpenSSH Ed25519, mode 600). Its PUBLIC half
# is the `ai` authenticator you configured in step 2.
ssh-keygen -q -t ed25519 -N "" -C "lychgate-mcp" -f /usr/local/etc/lychgate/mcp.key
chmod 600 /usr/local/etc/lychgate/mcp.key
lychgate-mcp --mcp-socket /unused --principal-key /usr/local/etc/lychgate/mcp.key --show-public-key
```

Add the MCP socket to the daemon's flags and restart:
- **FreeBSD:** `sysrc lychgated_flags="--mcp-socket /var/db/lychgate/lychgated-mcp.sock"` then `service lychgated restart`.
- **Linux:** add `--mcp-socket /var/lib/lychgate/lychgated-mcp.sock` to `ExecStart` (a systemd drop-in), `systemctl daemon-reload && systemctl restart lychgated`.

Point the Claude session's MCP client at the server. It speaks stdio, so the
client spawns it — e.g. an entry in the client's MCP config:

```json
{
  "mcpServers": {
    "lychgate": {
      "command": "lychgate-mcp",
      "args": [
        "--mcp-socket", "/var/db/lychgate/lychgated-mcp.sock",
        "--principal-key", "/usr/local/etc/lychgate/mcp.key"
      ]
    }
  }
}
```

The process running `lychgate-mcp` must be able to open the MCP socket (it is
owner-only, like the operator socket) — the socket is the boundary; the `mcp`
flag bounds only *which profiles* it can reach.

---

## 4. Grant Claude emergency access (the end-to-end flow)

With the pieces in place, a grant is four moves — one by the AI, one by a human,
then use, then revert:

1. **Claude requests it (MCP).** The session calls the `open_grant` tool
   (`host = db-01`, `ttl = 4h`, `profile = ai-assisted`). The MCP server opens the
   request and *auto-signs the AI factor*, so the grant sits pending at weight
   1/2, awaiting the human — and the tool's reply surfaces the challenge string.

2. **A human approves out of band.** The on-call sysadmin takes that challenge
   and signs it with their own key, submitting it on the **operator** socket
   (never the MCP one):
   ```sh
   printf %s '<challenge>' | ssh-keygen -Y sign -n lychgate-approval -f ~/.ssh/id_ed25519 \
     | lychgate approve --host db-01
   ```
   That is the second factor. The weighted threshold (2) is met and the daemon
   opens the grant, driving the channel (here: flipping root's ssh posture to the
   emergency value and installing the break-glass key in a fenced block) and
   arming the dead-man for the TTL.

3. **Claude uses it.** The session calls `grant_status` / `access_handle` to see
   the grant open and how long it has left, then uses the access the channel
   exposes — for ssh, connecting as root with the break-glass key; for vnc, the
   loopback console endpoint the daemon forwards. One-time secrets (a bmc or vnc
   password) are shown once to whoever ran `approve` and are relayed to the
   session out of band — the MCP front door does not hand them over (a
   deliberate, documented limitation).

4. **It reverts itself.** At the TTL the daemon reverts every channel (restoring
   posture, stripping the fenced key) and the dead-man does the same even if the
   daemon has died. A human can end it early with `lychgate close --host db-01`;
   `lychgate renew --host db-01 --ttl 2h` extends it, but only within the final
   renewal window before expiry.

The AI cannot open anything the policy does not allow: it is one weighted factor,
reaching only `mcp = true` profiles, and a "sysadmin + AI" grant never opens
without the human's signature.

---

## 5. Schedule a drill

A revert path never observed firing is indistinguishable from one that does not
work. Mark a throwaway host as a canary and drill it on a schedule; a failed
drill exits non-zero, so cron can alert:

```toml
[[hosts]]
name = "canary"
address = "10.0.4.99"
os = "linux"
channels = ["ssh"]
drill = true                     # ONLY a drill = true host is drillable
[hosts.ssh]
agent_user = "root"
root_posture_default = "no"
root_posture_emergency = "yes"
```

```cron
*/30 * * * * lychgate drill --host canary || notify-oncall "lychgate drill FAILED"
```

`lychgate drill` opens-and-reverts the canary and reports whether the revert
fully fired. Treat a failing drill as an incident: the revert path your
break-glass grants depend on is broken *now*, before a real close needs it.

---

## 6. Optional: the TPM (a hardware factor, and secrets at rest)

A machine may or may not have a TPM 2.0 — **probe before configuring one**.
Build the TPM tooling (`cargo build --release -p lychgate --features tpm-client`
on Linux; add `-bindgen` and `LIBCLANG_PATH` on FreeBSD, with `tpm2-tss`
installed) and run:

```sh
lychgate tpm-probe --tcti device:/dev/tpm0
```

A passing probe exercises everything lychgate needs (connect, derive the
signing key, seal/unseal round trip). Then either or both of:

- **The tpm factor** — `lychgate tpm-register` prints the
  `[[approval.authenticator]] kind = "tpm"` block; at approve time
  `lychgate tpm-sign --challenge <c>` emits the `lgtpm.` token. The private key
  never leaves the chip, and nothing is persisted in the TPM (the key is
  re-derived from a fixed template).
- **Sealed secrets** — `lychgate tpm-seal --file oncall.totp > oncall.totp.sealed`,
  point the inventory's `secret-file`/`hash-file` at the sealed blob, and run
  the daemon (a `tpm-seal` feature build) with `--tpm-unseal device:/dev/tpm0`.
  The plaintext then exists only in the daemon's memory; the files at rest are
  useless off the host. Fail-closed: the flag on a build without the feature,
  or with an unreachable TPM, refuses the start — it never silently reads the
  blobs as plaintext.

## 7. Operations

- **The journal is the audit record.** `<state-dir>/journal.jsonl` records every
  transition — requests, accepted proofs, opens, reverts, expiries — and, unlike
  most refusals, a rejected approval, a refused MCP op, and a failed drill (in the
  JSONL: `"event":"approval-denied"`, `"mcp-refused"`, `"drill-failed"`). Ship it
  to your log sink and alert on those three. It never contains a token or a
  one-time secret.
- **Secrets are shown once.** A bmc/vnc one-time password appears once in the
  `approve` response and is never journaled or persisted. Capture it then, or
  reopen.
- **Fail-closed everywhere.** No cron on a target → the open is refused. No
  `[approval]` policy → the daemon refuses to start (outside `--dry-run`). A
  corrupt store or a stuck revert holds the grant in a needs-revert state that is
  retried, never silently dropped. A profile is not MCP-reachable unless it says
  `mcp = true`; a host is not drillable unless it says `drill = true`.
- **`--dry-run` is for rehearsal only.** It drives no channels and verifies no
  proof (the first approval opens the grant as bookkeeping) — never a production
  posture, and MCP opens are refused against it.
- **Restart is safe.** State is write-ahead and crash-safe; a daemon killed
  mid-operation reconciles on boot, and its lock is reclaimed at once by the next
  start (it records its holder PID). A grant open on disk has its reachability
  re-established on restart; a lapsed one is reverted.
