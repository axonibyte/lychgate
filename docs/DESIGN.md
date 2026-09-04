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
- **`lychgated`** — the control-plane daemon, FreeBSD/Linux. Will own the
  inventory, execute drivers, enforce grants, and install the dead-man revert.
  Today it is honestly a config validator: it loads and validates the
  inventory, reports counts, says the control plane is unimplemented, exits.
- **`lychgate`** — the operator CLI, built for FreeBSD, Linux, and Windows
  (an operator's workstation may be anything; the daemon's host may not).
  Today its subcommands validate their inputs through core and then fail
  honestly: there is no daemon transport yet.

## Inventory

TOML, strict (`deny_unknown_fields` at every level). Each host declares a
name, an address, an OS (`freebsd` | `linux`), and the channels lychgate may
drive for it: `ssh` (PermitRootLogin posture), `authorized-keys` (fenced key
blocks), `bmc` (iDRAC/Redfish account lifecycle), `vnc` (console brokerage).
Structural rules beyond the schema — unique non-empty host names, non-empty
addresses, at least one channel per host, no duplicate channels — are
validated by hand-written code so that tests can kill mutations of them.

Per-host SSH posture defaults (`no` / `prohibit-password` / `yes`) will live
here when the ssh driver arrives; they are deliberately absent until the code
that honors them exists.

## Driver roadmap (none of this exists yet)

1. **ssh** — toggle `PermitRootLogin` between a per-host default and an
   emergency value via an sshd_config drop-in plus reload; manage
   authorized_keys entries inside fenced, lychgate-owned blocks so human keys
   are never touched.
2. **Dead-man revert** — opening a grant installs a local timer (`at`/cron) on
   the target that reverts the drop-in and strips the fenced keys at expiry,
   so revert survives the death of the controller that opened the gate. The
   daemon's close merely does it early and confirms.
3. **bmc** — iDRAC account enable/disable via Redfish `AccountService`, with
   racadm-over-SSH and ipmitool fallbacks; generated passwords go to escrow.
4. **vnc** — brokered console sessions via
   [autovnc](https://github.com/calebpower/autovnc), serialized because bhyve's
   RFB server accepts exactly one client.
5. **Operator surface** — daemon transport for the CLI, audit journal,
   drill mode (scheduled open-and-revert against a canary host, because a
   revert path never observed firing is indistinguishable from one that does
   not work).
