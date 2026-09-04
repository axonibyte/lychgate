# lychgate roadmap

The path from scaffold to a product that can be trusted to open production
and, more importantly, to close it again. Milestones are ordered by
dependency: every driver hangs off a daemon that can hold a grant, and every
claim of safety hangs off a revert path that has been observed firing.

Rules of the road, restated from [TESTING.md](../TESTING.md): each milestone
ships with the tests named in its section, every new assertion is
mutation-checked, and a milestone is not done while its acceptance criteria
are unmet. Version bumps land at the milestones marked with one.

Status convention: each milestone is `PLANNED`, `IN PROGRESS`, or `DONE (date)`.
Update the marker when state changes; this file is the plan of record.

---

## M1 — Grant registry and audit journal — DONE (2026-09-04)

The daemon learns to hold state. No network, no drivers.

**Deliverables**

- `GrantRegistry` in `lychgate-core`: one `Grant` per inventory host, keyed by
  host name; operations `open/close/renew/status` that delegate to the grant
  and refuse unknown hosts. Pure logic, injected time, same discipline as
  `Grant` itself.
- Persistence in `lychgated`: registry state written atomically (write-temp,
  rename) to a state directory; loaded on boot; a corrupt store is **reported,
  not silently emptied** (reaper's `a_corrupt_store_is_reported_not_silently_emptied`
  is the model). State from a newer schema version is refused, not misread.
- Append-only audit journal: one line per open/close/renew/observed-expiry,
  with timestamps, host, channels, TTL, and outcome. The journal is a record,
  never an input — replay is for humans and later tooling, not for state
  reconstruction (state has its own store).
- `lychgated` gains a real loop: load inventory + state, log status of every
  grant, act on observed expiries (today: journal them; reverting arrives with
  drivers), exit on signal. It still says plainly what it does not yet do.

**Tests** — Tier 1 extensions: registry boundary cases (unknown host, open
twice across restarts via store round-trip, expiry observed across a reload);
store tests (corrupt refused, newer-version refused, atomic replace —
`writes_replace_the_file_rather_than_editing_it_in_place`); journal tests
(append-only, well-formed lines, an entry for every transition — and the
absence of entries for refused operations asserted too).

**Acceptance** — kill `lychgated` at any point, restart it, and the registry
observes the same truth; a hand-corrupted store produces a refusal naming the
file, not an empty registry.

Also landed in M1 (scope added during planning): FreeBSD rc.d script, systemd
unit, and a DESTDIR-honoring service installer with its own test battery.
Starting the daemon under rc/systemd for real remains an M5 claim.

## M2 — Daemon transport and CLI wiring — PLANNED, bumps to v0.2.0

The CLI's honest bail messages are replaced by honest work.

**Deliverables**

- A local transport: unix domain socket, root-owned, permissions checked at
  bind. Request/response framing with explicit versioning; a request from a
  newer protocol version is refused with a message, not misparsed.
- CLI `open/close/renew/status` wired end to end. Errors from core arrive at
  the operator verbatim (the cap message, the TooEarly window message).
- `lychgate status` renders every grant with remaining time; exit codes are
  meaningful (0 all closed/open as expected, nonzero on refusal or transport
  failure).
- Windows client still builds: the transport module compiles everywhere, and
  connecting from Windows fails with "no local daemon on this platform"
  rather than a compile error or a lie. (Remote transport is out of scope
  until an authenticated design exists — see Open questions.)

**Tests** — Tier 2 arrives, per the §15 order: **seeded fuzz** over the wire
protocol decoder and both TOML parsers. Oracle: no panic, every rejection is a
well-formed error, the daemon is still alive afterwards. Seed printed on every
run, replayable via environment variable, and any seed that ever finds a
defect is promoted into the fixed set permanently. Plus contract tests for the
request/response surface as a table.

**Acceptance** — an operator can open, watch, renew inside the window, and
close a grant against a fake host entry, entirely through the real binaries,
and the journal shows every step.

## M3 — Driver trait and error-injection fakes — PLANNED

The seam every channel plugs into, proven against failure before any real
driver exists.

**Deliverables**

- A `ChannelDriver` trait: `apply(grant intent)` / `revert` / `verify`, with
  the contract stated in the trait docs: apply is atomic-or-reported (a
  half-applied channel must present as *needs revert*, never as open),
  revert is idempotent, verify reads the target's actual state.
- Grant lifecycle in the daemon composes drivers: open applies every channel
  in order and reverts the applied prefix on first failure; close/expiry
  reverts all; a revert failure is loud, journaled, and retried — never
  swallowed.
- Fake drivers with scripted failure: fail on apply, fail on revert, fail
  mid-sequence, succeed slowly. These live with the tests and never ship in
  release binaries.

**Tests** — Tier 3, browser-vs-fake's moral equivalent for a daemon:
**error-injection integration**. Every failure path in the lifecycle is
exercised deliberately — the least-exercised code is the code that runs
during an incident. Two oracles for the headline claim: after a failed open,
the registry reports needs-revert **and** the fake's own log shows the revert
call arrived. Assert the absence of driver calls for refused grants, and
assert the precondition before the success indicator.

**Acceptance** — no sequence of scripted driver failures can leave the
registry claiming a grant is cleanly open when any channel's apply failed.

## M4 — SSH driver — PLANNED, bumps to v0.3.0

The first real channel: root posture and keys, FreeBSD first.

**Deliverables**

- Inventory grows per-host SSH config *now that code honors it*: the default
  `PermitRootLogin` posture (`no` / `prohibit-password` / `yes`), the
  emergency posture, the agent account, and the authorized_keys targets.
  Schema stays strict; every new field is validated and tested.
- Posture toggle via an sshd_config drop-in owned by lychgate (never editing
  the main file), plus a reload and a **verify**: `sshd -T` must report the
  expected effective value after both apply and revert (FreeBSD `sshd` and
  OpenSSH-on-Linux both honor `-T`).
- authorized_keys managed inside fenced, lychgate-owned marker blocks; keys
  outside the fence are never touched, and a fence that has been hand-edited
  is reported, not clobbered.
- Execution over SSH from the daemon as an unprivileged agent account with
  narrowly-scoped doas/sudo rights; the required rights are documented and
  the daemon refuses clear misconfigurations loudly.

**Tests** — unit tests on drop-in rendering and fence parsing (hostile
corpus: keys containing fence-like comments, CRLF, astral-plane text in key
comments); Tier 3 fakes extended with an SSH transport that drops mid-write.
Full-stack assertions arrive in M5 where a real sshd exists.

**Acceptance** — against a disposable host: open flips posture and installs
the key, `sshd -T` and an actual connection attempt agree (two oracles),
close restores the per-host default byte-for-byte, and a hand-added key
survives the whole cycle untouched.

## M5 — Dead-man revert and the hostile full stack — PLANNED

The property that makes lychgate trustworthy, and the tier that proves it.

**Deliverables**

- Opening a grant installs a revert timer **on the target** (`at(1)`, falling
  back to a cron entry) that reverts the drop-in and strips the fenced keys
  at expiry with no participation from the daemon. Close cancels it; renew
  reschedules it. The installed script is self-contained and inspectable.
- Daemon-side expiry handling becomes real: observed expiry triggers revert
  and journals whether the dead-man had already fired (both orders are legal;
  both must converge to closed).
- Reaper `[run]` grows a full-stack battery behind a single script (no pipes;
  `#!/bin/sh` with explicit status handling like `tools/check.sh`).

**Tests** — Tier 4, **full stack, started hostile**, in reaper sessions:
- *revert-under-kill*: open a grant, `kill -9` the daemon, wait past expiry,
  prove the target closed itself. Assert the precondition (posture was open)
  before the success indicator, with time allowed to pass.
- Two oracles throughout: config-level (`sshd -T`, authorized_keys content)
  and behavior-level (connection attempts that must succeed/fail).
- Idempotence: revert twice, boot the daemon twice against the same state.
- The FreeBSD guest is mandatory here — FreeBSD is a first-class target and
  must not be the platform nothing exercises.

**Acceptance** — the revert-under-kill test exists, has been observed failing
(run once with the dead-man deliberately not installed — the oracle
self-test), and passes on both guests.

## M6 — BMC driver — PLANNED, bumps to v0.4.0

iDRAC accounts join the grant.

**Deliverables**

- Redfish `AccountService` driver: enable a designated break-glass account on
  open (fresh random password each time), disable on revert. Fallbacks:
  racadm over SSH, then ipmitool, selected per host in inventory.
- Password handoff: the generated secret goes to the operator through the CLI
  exactly once and to an escrow hook; a ddwill-backed escrow is the intended
  first implementation, behind a trait so it stays optional.
- Verify reads the account's enabled state back through the same API family.

**Tests** — unit on request construction and response parsing against
recorded Redfish/racadm fixtures (real captures, redacted); Tier 3 fakes for
mid-operation BMC failures (timeout after the password was set but before
enable — must present as needs-revert); full-stack tier extended only if a
bench iDRAC or Redfish simulator (e.g. sushy-emulator) is available in a
session — if it is not, TESTING.md must say the BMC claim is fixture-proven
only. The dead-man question for BMCs (no `at` on an iDRAC) is answered by the
daemon-side expiry path plus a documented residual risk: name what the tier
does not prove.

**Acceptance** — against one real iDRAC: open enables the account with a
fresh password, verify confirms, close disables it, and the password never
appears in the journal or logs.

## M7 — VNC driver — PLANNED

Console access joins the grant.

**Deliverables**

- autovnc integration: a grant with the `vnc` channel yields a working
  console target (host, port, password file path) for the operator or agent,
  established through autovnc's session API/CLI.
- Serialization: one console client at a time per target (bhyve's RFB server
  accepts exactly one) — the daemon queues or refuses, explicitly.
- Revert semantics: closing the grant tears down any tunnel/port-forward
  lychgate created and rotates the VNC password where the platform allows.

**Tests** — unit on target/session bookkeeping and the serialization rule
(concurrency-flavored: N simultaneous requests, assert the resource's state
read back, not response counts — this is the project's first Tier 6-style
harness); integration against a bhyve guest in a reaper session where
available.

**Acceptance** — two concurrent `open`s for the same console produce one
session and one honest refusal/queue position, never two dead connections.

## M8 — Operator surface and the long-tail tiers — PLANNED, bumps to v0.5.0

The reason the project exists: "claude go fix this," safely.

**Deliverables**

- Approval flow: opening a grant requires an operator-held credential; the
  design principle is that the human authorizes, the agent works inside the
  grant. Remote authorization (from a phone, away from the workstation) gets
  designed here — see Open questions.
- MCP server exposing `open` (returns pending until approved), `status`,
  `renew`, `close`, and access handles, so a Claude session can request and
  use a grant without shell access to the daemon host.
- Drill mode: a scheduled open-and-revert against a designated canary host,
  journaled, with a loud failure when the revert path does not fire. A revert
  path never observed firing is indistinguishable from one that does not
  work; the drill is the standing oracle self-test.
- Operational docs: runbook for granting Claude emergency access end to end.

**Tests** — the remaining tiers, in §15 order: **source-as-data** (channel
vocabulary appears in inventory schema, driver registry, CLI help, and docs —
parse the source and assert the sets agree, duplicating the mapping in the
test deliberately; exclude the checked content from the searched corpus);
**concurrency** hardened across open/close/renew races; **simulated users**
last — actors, shadow model, checker, nemesis (stale approval, act-on-expired,
double submit, abandonment), shrinker — with the invariant self-test written
*first*, fed the responses a broken daemon would send.

**Acceptance** — the §15 acceptance test for the whole exercise: revert
defects already found and fixed by hand along the way and confirm the harness
rediscovers every one. A methodology that cannot rediscover known bugs is not
yet measuring anything.

---

## Operational track (parallel to the milestones)

- **GitHub mirror**: create `github.com/axonibyte/lychgate`, add the repo SSH
  key in Bitbucket with its public half as a write deploy key on GitHub. The
  pipeline's mirror step fails until this exists.
- **First tag**: `v0.1.0` on the scaffold once the five cross-builds are
  green, proving the deploy step and the tag==version guard.
- **First reaper session**: `reaper test` — also answers whether the
  freebsd-15.1 template carries a Rust toolchain (if not, fix the template,
  not the manifest).
- **bgone upstream fix**: its pipeline keys on `main` but the default branch
  is `master`, so mirror+test+build never fire on branch pushes. Separate
  repo, separate authorization.

## Open questions (decide when their milestone starts, not before)

1. **Wire format for the transport** (M2): a small length-prefixed JSON
   protocol is the default recommendation — greppable journals and fuzzable
   decoding — unless a concrete need for anything richer appears.
2. **Remote CLI → daemon transport** (M2 deferred, M8 at latest): SSH to the
   daemon host and use the socket (recommendation: yes, and never invent a
   custom authenticated network protocol for a security tool when sshd is
   already trusted), or a TLS listener.
3. **Approval mechanism** (M8): what the operator-held credential is — a
   signed token from a phone, a hardware key tap, TOTP. Decide against the
   real workflow at the time.
4. **BMC dead-man residual risk** (M6): whether any iDRAC-side scheduled
   disable exists that is worth using, or whether daemon-plus-drill is the
   honest ceiling for the BMC channel.
5. **Escrow coupling** (M6): ddwill as a hard dependency or an optional
   backend behind the trait (recommendation: optional backend).
