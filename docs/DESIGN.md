# lychgate design

## The problem

Emergency remediation needs access that must not exist in steady state: root
over SSH, an enabled BMC account on the iDRAC, a VNC console. The failure mode
of provisioning it ad hoc is not that it takes too long (though it does) — it
is that ad-hoc access does not get torn down. lychgate exists to make the
teardown the default physics of the system rather than a follow-up task.

## The grant

The unit of access is a *grant*: one host, a set of channels, and a TTL.
Everything a grant opened is closed together, and the whole bundle has one
expiry. The state machine lives in `lychgate-core` and is deliberately pure:

```
Closed ──open(now, ttl)──▶ Open{opened_at, expires_at}
Open ──close()───────────▶ Closed
Open ──(time passes)─────▶ observed Expired once now >= expires_at
```

Expiry is a property of **observation**, not of a background thread:
`status(now)` reports `Expired` the instant `now >= expires_at`. Correctness
therefore never depends on a reaper loop being alive — the daemon's future
revert loop merely acts on what `status` already reports. The boundary is
closed at exactly the expiry instant: a grant observed *at* `expires_at` is
expired, not open.

Policy decisions, all enforced in core and all tested:

- **TTLs are capped at 24 hours** (`MAX_TTL_SECS`). Break-glass access is
  never open-ended; a multi-day incident reopens explicitly.
- **Renewal has a window.** `renew` is accepted only while the grant is
  observed open *and* within the final 2 hours before expiry
  (`RENEWAL_WINDOW_SECS`). The new expiry is anchored at the renewal instant,
  never at the old expiry — time cannot be stockpiled ahead of need.
- **Expired grants cannot be renewed.** Reopening is always an explicit act,
  so an operator can never accidentally resurrect access they believed dead.
- **Opening an open grant is refused**, not silently extended.
- **Closing is idempotent** and reports whether there was anything to close.
- **Clock overflow is an error**, never a saturation. An expiry that cannot be
  represented is a refusal to open, not a grant that lasts forever.

## Components

- **`lychgate-core`** — grant state machine, TTL parsing/policy, inventory
  schema and validation. Pure logic, injected time (`now: SystemTime`
  parameters), no I/O. This is the Tier-1 test surface.
- **`lychgated`** — the control-plane daemon, FreeBSD/Linux. Today (M3) it
  holds real state — a locked, atomic, versioned grant store (grants.json),
  an append-only audit journal (journal.jsonl) — serves the CLI over an
  owner-only unix socket (newline-delimited JSON, explicit protocol version,
  single-instance enforcement), and runs the write-ahead grant lifecycle
  over a `ChannelDriver` seam: open persists intent before driving, commits
  Open on success or NeedsRevert on failure; close and expiry revert through
  NeedsRevert; a crash mid-open is demoted at boot, and a daemon-held resource
  (the vnc tunnel) that outlived a restart is re-established. As of M7 all four
  channels are live: a grant flips PermitRootLogin via a verified drop-in,
  installs break-glass keys in the fence, enables a break-glass iDRAC account,
  and brings up a console tunnel with a rotated password. `--dry-run` registers
  no drivers, opening grants as pure bookkeeping.
- **`lychgate`** — the operator CLI, built for FreeBSD, Linux, and Windows
  (an operator's workstation may be anything; the daemon's host may not).
  open/renew/close/status work end to end against a local daemon; refusals
  arrive in the daemon's words verbatim. On non-unix platforms the local
  transport is an honest stub — remote transport is the M8 design question.

## Inventory

TOML, strict (`deny_unknown_fields` at every level). Each host declares a
name, an address, an OS (`freebsd` | `linux`), and the channels lychgate may
drive for it: `ssh` (PermitRootLogin posture), `authorized-keys` (fenced key
blocks), `bmc` (iDRAC/Redfish account lifecycle), `vnc` (console brokerage).
Structural rules beyond the schema — unique non-empty host names, non-empty
addresses, at least one channel per host, no duplicate channels — are
validated by hand-written code so that tests can kill mutations of them.

Per-host SSH config lives in `[hosts.ssh]` (agent account, default and
emergency `PermitRootLogin` postures, emergency keys, become prefix) — and is
required exactly when an ssh-borne channel is declared, refused as dead
config otherwise.

## Driver roadmap (1 is done; 2 onward is future)

The milestone-level plan of record, with tests and acceptance criteria per
step, is [ROADMAP.md](ROADMAP.md). The sketch below is the shape of it:

1. **ssh** — toggle `PermitRootLogin` between a per-host default and an
   emergency value via an sshd_config drop-in plus reload; manage
   authorized_keys entries inside fenced, lychgate-owned blocks so human keys
   are never touched.
2. **Dead-man revert** (done, M5) — opening a grant installs a self-contained
   script plus a marked crontab line on the target; past the deadline it
   reverts the drop-in and strips the fenced keys with no daemon
   participation, so revert survives the controller's death. The daemon's
   close removes it (doing the revert early) and journals whether it had
   already fired. Requires cron on the managed host — a grant is refused
   rather than opened without a working backstop.
3. **bmc** (done, M6) — iDRAC break-glass account enable/disable via Redfish
   `AccountService` over curl, fresh password each open (shown once, escrowed,
   never journaled); racadm/ipmitool named-but-unimplemented. No dead-man (an
   iDRAC has no shell) — expiry enforcement is the daemon's alone.
4. **vnc** (done, M7) — console reachability as a daemon-held `ssh -L` tunnel
   to the VM's RFB port, plus a one-time VNC password rotated through a
   configurable, platform-agnostic command (cbsd is the pilot). The tunnel dies
   with the daemon (a parent-death signal) and is re-established on restart;
   serialization is the per-host single-grant rule. The agent drives the
   console it exposes with [autovnc](https://github.com/calebpower/autovnc) or
   any VNC client. No dead-man — the tunnel dying with the daemon is the
   backstop, and the password's expiry is the reap loop's alone.
5. **Operator surface** — daemon transport for the CLI, audit journal,
   drill mode (scheduled open-and-revert against a canary host, because a
   revert path never observed firing is indistinguishable from one that does
   not work).
