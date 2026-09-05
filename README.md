# lychgate

A break-glass emergency access orchestrator for SSH, iDRAC, and VNC.

A lychgate is the roofed churchyard gate where the dead are received. This one
is the gate you open when a production server is the corpse: it grants
temporary root SSH posture, BMC accounts, authorized_keys entries, and VNC
console access as a single revocable unit — and slams all of it shut on a
timer whether or not the thing that opened it is still alive.

## Why

Emergency remediation — human or AI-driven — needs access that ordinarily must
not exist: root over SSH, an enabled iDRAC account, a console. Provisioning
that by hand at 03:00 is slow; leaving it standing is worse. lychgate models
the whole bundle as a *grant* with a hard TTL: opening is deliberate and
audited, closing is idempotent, and expiry is fail-closed — a grant observed
at or past its expiry instant is expired, no daemon required to make it so.

Grant policy, by design:

- TTLs are capped at 24 hours. Break-glass access is never open-ended.
- Renewal is only accepted inside the final 2 hours before expiry, and the new
  window is anchored at the renewal instant — time cannot be stockpiled early.
- An expired grant cannot be renewed. Reopening is always an explicit act.

## Status

The control plane is real, and all four channels — `ssh`, `authorized-keys`,
`bmc`, and `vnc` — are live: opening a grant flips the host's `PermitRootLogin`
posture through a verified drop-in, installs break-glass keys inside a
lychgate-owned fence in authorized_keys, enables a break-glass iDRAC account
over Redfish with a fresh one-time password, and brings up a console: a
daemon-held SSH tunnel to the VM's RFB port plus a rotated one-time VNC password
(set through a configurable, platform-agnostic command). All are verified
against the target's actual state and reverted on close or expiry, with a
target-side dead-man backstopping the ssh channels and the tunnel dying with the
daemon it belongs to. Opening a grant is gated on a **weighted-threshold
approval authority** (EOS/Antelope model): `open --as <profile>` records a
pending request and returns a challenge, and the grant opens only once the
profile's threshold is met by weighted factors — operator signatures
(`ssh-keygen -Y sign`, an Ed25519 key in the allowed-signers set) handed back
through `lychgate approve`, nested groups, and/or an elapsed `wait`. Proofs
accumulate across calls and a wait matures on the daemon's own loop. The
daemon holds grant state durably, serves the CLI over
an owner-only unix socket, journals every transition (never a credential or
token), and re-establishes a console tunnel that outlived a restart. A `--dry-run` mode
opens grants as pure bookkeeping, touching no host — for validating an inventory
or rehearsing the lifecycle. See [TESTING.md](TESTING.md) for exactly what is
and is not proven, [docs/DESIGN.md](docs/DESIGN.md) for the architecture, and
[docs/ROADMAP.md](docs/ROADMAP.md) for the milestone plan of record.

## Components

- `lychgate` — the operator CLI. Builds for FreeBSD, Linux, and Windows.
- `lychgated` — the control-plane daemon. FreeBSD and Linux only. Holds
  grant state, drives the channels, reverts on close and expiry, retries
  stuck reverts, and journals everything.
- `lychgate-core` — the grant/TTL/inventory library both binaries share.

## Installation

### From source

Requires Rust 1.96+ and Cargo.

```sh
cargo build --release --workspace
```

Binaries land at `target/release/lychgate` and `target/release/lychgated`.

### Prebuilt binaries

Tagged releases upload binaries for FreeBSD and Linux (amd64 and aarch64) and
a Windows client to the repository's Downloads page, each with a `.sha256`
checksum sidecar.

## Usage

```sh
lychgated --inventory /usr/local/etc/lychgate/inventory.toml \
          --state-dir /var/db/lychgate
```

Validates the inventory and grant state, binds the control socket
(`<state-dir>/lychgated.sock`, owner-only), reaps expired grants on an
interval, and journals every transition to `<state-dir>/journal.jsonl`.
`--once` runs a single pass for cron; a second daemon on the same socket is
refused. `--approval-window <secs>` bounds how long a pending request waits for
its authority to be satisfied (default 300, cap 24h — long enough for a `wait`
factor); a request not satisfied in time lapses and is reaped. `--dry-run`
registers no channel drivers *and* evaluates no authority (the first proof
opens), so grants open and close as pure bookkeeping and touch no host — for
validating an inventory or rehearsing the lifecycle. Outside `--dry-run`, the
daemon refuses to start with no `[approval]` policy configured, since a grant
could then never be opened.

```sh
lychgate open  --host db-01 --as claude --ttl 4h   # prints a challenge; pending
# each operator whose factor the profile needs signs the challenge:
printf %s '<challenge>' | ssh-keygen -Y sign -n lychgate-approval -f ~/.ssh/id_ed25519
lychgate approve --host db-01          # paste a signature on stdin, then EOF
                                       # repeat per factor; the grant opens when
                                       # the profile's weighted threshold is met
lychgate status                        # shows pending progress (weight / threshold)
lychgate renew --host db-01 --ttl 2h   # accepted only within 2h of expiry
lychgate close --host db-01
```

`--as` may be omitted when the host permits exactly one profile.

The one-time secret for a channel (the BMC or VNC password) is shown once by
`approve`, where the grant actually opens — not by `open`. TTLs take the forms
`90s`, `15m`, `2h`; a unit is required, and the 24-hour
cap is enforced client-side before a connection is attempted and daemon-side
regardless. Refusals are printed in the daemon's words verbatim and exit
nonzero. `--socket` overrides the per-OS default socket path.

An inventory names each host, its address, its operating system (`freebsd` or
`linux`), and the access channels lychgate may drive for it:

```toml
[[hosts]]
name = "db-01"
address = "10.0.4.11"
os = "freebsd"
channels = ["ssh", "authorized-keys", "bmc", "vnc"]

# Required when ssh or authorized-keys channels are declared.
[hosts.ssh]
agent_user = "lychgate"              # connects via ssh(1); see become_cmd
root_posture_default = "no"          # what PermitRootLogin must be at rest
root_posture_emergency = "prohibit-password"
emergency_keys = ["ssh-ed25519 AAAA... claude-breakglass"]
become_cmd = "doas"                  # omit if the agent account is root

# Required when the bmc channel is declared.
[hosts.bmc]
endpoint = "https://10.0.4.11-idrac"
method = "redfish"                   # racadm/ipmitool reserved, not yet built
account_user = "breakglass"          # the break-glass iDRAC account
account_id = "4"                     # its AccountService slot
auth_user = "lychgate-svc"
auth_password_file = "/usr/local/etc/lychgate/db-01.bmc"   # not inline
tls = { mode = "ca-file", path = "/usr/local/etc/lychgate/idrac-ca.pem" }

# Required when the vnc channel is declared. lychgated holds an ssh -L from
# the daemon host's local_port to rfb_host:rfb_port on the hypervisor for the
# grant, and rotates a one-time VNC password via the configurable commands.
[hosts.vnc]
agent_user = "lychgate"              # ssh login on the hypervisor (host.address)
rfb_host = "127.0.0.1"               # where the VM's RFB server binds there
rfb_port = 5900
local_port = 5959                    # forwarded on the daemon host; unique per host
target = "vm-guest-01"               # VM id passed to the commands as {target}
# Agnostic: cbsd is the pilot; {password_file} is a mode-600 file lychgate
# stages (never the password on an argv). Single quotes are refused at load.
set_password_cmd = "cbsd bhyve-vnc jname={target} vncpasswordfile={password_file} apply=1"
clear_password_cmd = "cbsd bhyve-vnc jname={target} vncpassword=none apply=1"
become_cmd = "doas"                  # optional privilege prefix
```

The `[approval]` section defines the weighted-threshold authorities that gate
opening (the EOS/Antelope model): authenticators (leaf proofs), groups (nested
authorities), and profiles (the gate a host is opened under). An open under a
profile succeeds when its satisfied factors' weights sum to at least its
threshold — where a factor is an authenticator, a group, or a `wait`. It is
required outside `--dry-run`; a policy with no profile refuses the daemon's start.

```toml
# Authenticators are leaf proofs. Only ed25519 (an SSHSIG signed with
# `ssh-keygen -Y sign -n lychgate-approval`) is built today; totp/password/fido2
# parse but are refused at load until their sub-milestone. The full openssh
# public-key line (with comment) is accepted; a public key is inline, a secret
# would be a file path.
[[approval.authenticator]]
id = "oncall-key"
kind = "ed25519"
public-key = "ssh-ed25519 AAAA... oncall@phone"

# A group is itself a threshold over weighted factors.
[[approval.group]]
id = "SYSADMIN"
threshold = 1
factor = [ { authenticator = "oncall-key", weight = 1 } ]

# A profile is the gate an open is evaluated against.
[[approval.profile]]
id = "claude"
threshold = 3
factor = [
  { group = "SYSADMIN", weight = 2 },   # a grant from a sysadmin
  { wait  = "1h",        weight = 1 },   # ...plus an hour's cool-off
]
```

A host may narrow which profiles it permits, and override a profile's authority
for itself, under `[hosts.access]`; a host with no such block permits every
profile at its default authority.

```toml
[hosts.access]
profiles = ["claude", "contractor"]
# [hosts.access.override.claude] threshold = 2 / factor = [ ... ]   # optional
```

The ssh channel needs the host's `sshd_config` to
`Include /etc/ssh/sshd_config.d/*.conf` **before** any `PermitRootLogin`
line (sshd honors the first value it reads); a missing Include is caught by
the post-apply verify, not silently tolerated.

Managed hosts with an ssh-borne channel also need **cron installed and
running** (FreeBSD ships it in base; on Debian/Ubuntu, `apt install cron`).
lychgate installs a dead-man timer in root's crontab so break-glass access
reverts on schedule even if the daemon dies — a host without cron cannot
hold that guarantee, so opening a grant there is refused rather than opened
without a backstop.

## Testing

```sh
./tools/check.sh
```

runs every workstation-side phase (fmt, clippy with warnings denied, the test
suite, shell lint) and reports all failures rather than stopping at the first.
The project is a [reaper](https://github.com/calebpower/reaper) tenant:
`reaper test` runs the same battery on FreeBSD and Ubuntu guests. The testing
ethic, tier roadmap, and the claims each suite does *not* carry are recorded
in [TESTING.md](TESTING.md).

## License

BSD-2-Clause. Copyright (c) 2026 Axonibyte Innovations, LLC.
