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
Closed  ──open(now, ttl)────────▶ Pending{requested_at, approval_deadline, ttl, nonce}
Pending ──approve(now, token)───▶ Opening ──apply──▶ Open{opened_at, expires_at}
Pending ──close()───────────────▶ Closed          (nothing was ever applied)
Pending ──(time passes)─────────▶ observed ApprovalExpired once now >= approval_deadline
Open    ──close()───────────────▶ Closed
Open    ──(time passes)─────────▶ observed Expired once now >= expires_at
```

Since M8a.1 `open` does not open: it records a **Pending** grant (the write-ahead
intent) and returns a challenge, running no drivers and issuing no secret. Only a
verified `approve` transitions Pending → Opening and runs the apply path, so the
one-time secret is issued at approve, where the grant actually opens. See
[Approval](#approval).

Expiry — and the approval window — are properties of **observation**, not of a
background thread: `status(now)` reports `Expired` the instant `now >=
expires_at`, and `ApprovalExpired` the instant `now >= approval_deadline`.
Correctness therefore never depends on a reaper loop being alive — the daemon's
revert loop merely acts on what `status` already reports. The boundary is
closed at exactly the expiry instant: a grant observed *at* `expires_at` is
expired, not open. Approval anchors the TTL at the approve instant, never at the
request — waiting for an operator does not eat into the grant's life.

Policy decisions, all enforced in core and all tested:

- **TTLs are capped at 24 hours** (`MAX_TTL_SECS`). Break-glass access is
  never open-ended; a multi-day incident reopens explicitly.
- **Renewal has a window.** `renew` is accepted only while the grant is
  observed open *and* within the final 2 hours before expiry
  (`RENEWAL_WINDOW_SECS`). The new expiry is anchored at the renewal instant,
  never at the old expiry — time cannot be stockpiled ahead of need.
- **Expired grants cannot be renewed.** Reopening is always an explicit act,
  so an operator can never accidentally resurrect access they believed dead.
- **Opening an open grant is refused**, not silently extended — and so is a
  second open while one is already pending.
- **Opening requires an operator approval** (M8a.1). A pending request that is
  not approved within a bounded window (`--approval-window`) lapses and is
  reaped, fail closed: a pending request is not access, but it must not linger.
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
  (the vnc tunnel) that outlived a restart is re-established. All four
  channels are live: a grant flips PermitRootLogin via a verified drop-in,
  installs break-glass keys in the fence, enables a break-glass iDRAC account,
  and brings up a console tunnel with a rotated password. As of M8a.1 opening is
  gated on an operator approval verified against a pluggable seam (Ed25519/SSHSIG
  first). `--dry-run` registers no drivers and accepts any approval token,
  opening grants as pure bookkeeping.
- **`lychgate`** — the operator CLI, built for FreeBSD, Linux, and Windows
  (an operator's workstation may be anything; the daemon's host may not).
  open/approve/renew/close/status work end to end against a local daemon;
  refusals arrive in the daemon's words verbatim. `approve` reads its token from
  stdin by default, keeping a secret-bearing token off the argv. On non-unix
  platforms the local transport is an honest stub — remote CLI-to-daemon
  transport remains an open M8 question, but approval itself is already
  out-of-band (the operator signs on their own device; see below).

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

## Approval

The reason the project exists is to let an agent work inside a grant that a
*human* deliberately opened. So opening is gated on an operator approval, and
the design principle is: the human authorizes, the agent works inside the grant.

The flow is **out-of-band** — the daemon grows no network listener. `open`
records the Pending grant and returns a **challenge**: a canonical,
domain-separated, length-prefixed encoding of `(nonce, host, ttl, requested_at)`,
rendered `lg1.req.<base64url>`. The operator, on whatever device they trust,
signs exactly those bytes and hands the token back through `lychgate approve`
(on stdin, off the argv). The daemon verifies the token against the pending
request's own challenge before it transitions Pending → Opening. The
length-prefixing is deliberate: daemon and signer must agree on the signed bytes
with no field-order or delimiter ambiguity.

Verification is a pure `ApprovalVerifier` seam in core. `AnyOf` composes backends
**fail-closed**: an empty approver set refuses (it never silently opens), the
first accept wins, and all-reject is a refusal that names itself. Three credential
types live behind that one seam, phased:

- **Ed25519 = SSHSIG** (M8a.1, shipped). The operator signs with
  `ssh-keygen -Y sign -n lychgate-approval -f <key>`, reusing existing SSH keys,
  ssh-agent, and hardware `ed25519-sk` tokens. The daemon parses the SSHSIG
  envelope, checks the namespace, and verifies the Ed25519 signature over the
  challenge against the configured allowed-signers set — the `[approval]`
  inventory table of `(key-id, ssh-ed25519 public-key)` pairs. No bespoke signing
  tool and no hand-rolled crypto: the `ssh-key` crate does the verify. Trust
  reduces to that allowed-signers set; revocation is an inventory edit.
- **TOTP** (M8a.2) and **FIDO2** (M8a.3) land behind the same trait.

A failed approval is journaled (`ApprovalDenied`, with a reason) — a deliberate
departure from "refusals journal nothing", because a rejected authorization is
exactly what an audit log is for. The token and the one-time secret never are.
Outside `--dry-run`, a daemon with no approver configured refuses to start: a
grant that could never be opened is a misconfiguration, not a safe default.

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
5. **Operator surface** — the approval gate (M8a.1, done; see
   [Approval](#approval)) leads; still ahead are the MCP server so a Claude
   session can request and use a grant without shell access, drill mode
   (scheduled open-and-revert against a canary host, because a revert path never
   observed firing is indistinguishable from one that does not work), and the
   remaining credential backends (TOTP, FIDO2).
