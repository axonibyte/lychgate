# Testing lychgate

This project follows the testing methodology recorded at
[reaper](https://github.com/calebpower/reaper) `docs/testing-methodology.md`: a
portfolio of oracles, not a pyramid. Every tier earns its place by a defect no
cheaper tier can see, and this file records which tiers exist, which do not
yet, and — just as important — what the existing suites do **not** prove.

## Non-negotiables

These govern every change here, scaffold included:

- Never weaken a test, check, assertion, or lint to route around a defect.
- Every narrowing carries a stated reason covering exactly what it narrows,
  and is reported in the human-facing summary, not only in a comment.
- Every fix ships with a test that would have caught it, or an explicit
  statement of why the change is untestable in isolation.
- Every new assertion is mutation-checked: break the thing it covers, watch
  the test fail, restore. A test never observed failing has unmeasured value.
- A pre-existing failure must be proven pre-existing (stash and re-run).

## Tier 1 — pure unit tests: EXISTS

56 tests on `lychgate-core`, in-crate under `#[cfg(test)]`, named as full
sentences stating the claim (`a_grant_past_its_ttl_is_expired_rather_than_left_open`).
They cover the TTL policy (zero/cap/cap+1 boundaries, unit parsing, overflow
refused rather than wrapped, multibyte input refused rather than panicking),
the grant state machine (expiry at the exact instant, open/close/renew
transitions, the 2-hour renewal window at its boundary, renewal anchored at
now rather than the old expiry, clock overflow refused rather than saturated),
inventory validation (strict schema, duplicate/empty rejections), the grant
registry (fail-closed refusal of unknown hosts, reap-exactly-once), and the
snapshot layer (observation-free persistence, unknown/inverted/over-cap state
refused at load, epoch overflow refused rather than panicking).

## Daemon state and process tier: EXISTS (M1)

29 tests on `lychgated`: the locked atomic store (absent-is-empty,
corrupt-names-the-file, version-mismatch-quotes-both, tmp-then-rename with no
leftovers, stale locks aged out by rename-steal, a wedged steal ending in
Locked rather than a spin), the append-only journal (one JSON line per entry,
append across reopens, gapless per-process sequence numbers, kebab-case
channel vocabulary), and an end-to-end battery driving the real binary: a
`--once` pass reaps and journals an expired grant; SIGKILL mid-run and a
restart observe the same truth (the M1 acceptance); corrupt, newer-version,
and unknown-host stores are refusals that journal nothing; SIGTERM ends the
loop with a daemon-stop entry. The service installer has its own battery
(`tools/install-service-test.sh`), run by the gate and CI.

Mutation record: 35 at scaffold, 49 for M1, 25 for M2, and for M3 the
channel seam (12), the write-ahead machine and lifecycle (13) — ~134
checked to date, 0 surviving now. Across the project, five survivors have
appeared and each exposed a real gap rather than being waved through:
redundant guards removed (the proto version arm, the listener cap check,
the empty-needs-revert refusal that turned out to be a legitimate
transient) and missing assertions added (the renew transition payload, the
journal side of boot recovery). Several mutations hung the suite, which for
a spin or a wedged flow is the observed failure. Two behaviour decisions
were forced by tests along the way: expiry now expires-then-closes (revert
completes), and close stays idempotent.

Cross-platform record: the full battery ran green on both reaper guests
(freebsd-15.1 on pkg rust 1.96, ubuntu-26.04 in the pinned rust:1.97 image)
at M1 close and again at M2 close — the store's rename/lock semantics,
signal handling, and unix-socket transport are proven on both deployment
platforms, not assumed from the workstation.

## Tier 2 — seeded fuzz: EXISTS (M2)

`core/tests/fuzz.rs` fuzzes every externally-reachable decoder (wire
requests, TTL strings, inventory TOML) with three generators — random
bytes, token soup steered at the seams, mutated-valid — over a committed
fixed seed set. Oracle: no panic, every rejection a well-formed error.
Seeds print before use; `LYCHGATE_FUZZ_SEED` replays one,
`LYCHGATE_FUZZ_ITERS` extends the hunt (a 20k-iteration run passed at
introduction). Any seed that finds a defect is promoted into the fixed set
permanently. The harness self-tests: the fixed seeds rediscover a
resurrected real defect (the multibyte split_at panic), and a two-sidedness
check fails if the generators collapse into only-rejected inputs.

## Tier 3 — error-injection integration: EXISTS (M3)

`daemon/src/lifecycle/tests.rs` drives the write-ahead grant lifecycle
against scripted fake drivers (`lychgate-core`'s `fakes` feature — test-only,
never a release binary), with two oracles per claim: the grant state read
back from the committed store, AND the fakes' shared call log showing which
driver calls happened and, by their absence, which did not. It proves the
headline M3 property — no sequence of apply failures ever reports a cleanly
open grant (swept across the failing channel) — plus: a failed unwind lands
in needs-revert naming the stuck channels, stuck reverts are retried by
later passes until they clear rather than swallowed, an operator close and
an expiry both revert through needs-revert, boot recovery demotes a stored
`Opening` and journals it, and the empty production driver set opens and
closes end to end with nothing applied. `core/src/channel/tests.rs` proves
the orchestration primitives (apply-in-order, unwind-in-reverse,
revert-every-channel, undrivable-is-stuck) directly.

## Wire contract and operator-flow tiers: EXISTS (M2)

The request/response surface is pinned by a contract table in
`core/src/proto/tests.rs` (every op against every grant state, response
fields and journal-transition expectations per row), and the operator flow
runs end to end through both real binaries in the e2e battery:
open/status/renew-both-ways/close over the real socket, refusals verbatim
with nonzero exits, future-protocol and oversized requests refused over a
raw socket connection, the socket owner-only, a second daemon refused while
the first listens, a stale socket replaced, a missing daemon failing fast.

**What these tiers do NOT prove:**

- No access is actually opened or closed on any host. The driver seam and
  its orchestration exist and are proven against fakes, but no *real* driver
  ships (the production driver set is empty until M4), so an open grant
  changes grants.json and a journal line, not sshd, not authorized_keys, not
  a BMC, not a console. The CLI and daemon both say so.
- Authorization is the socket's file mode and nothing else: any process that
  can reach the owner-only socket can open grants. The operator-approval
  design is M8; until then, root on the daemon host is the trust boundary.
- The listener's take() allocation bound (a writer that never sends a
  newline) has no behavioral oracle — the observable is memory — and is
  stated in a comment rather than pretend-tested.
- The non-unix transport stub compiles for Windows only in CI's cross-build;
  nothing local proves it.
- Journal durability is fsync-per-line by construction, not by test; the
  residual power-loss windows (a lost line detectable as a pid/seq gap; a
  duplicated observation) are documented in the journal module, not tested.
- Concurrency is serialized by the store lock and exercised synthetically,
  not by racing clients (Tier 6 harnesses are M7+ territory).
- The service files stage correctly; whether rc(8)/systemd actually start the
  daemon from them belongs to M5's full-stack tier on the reaper guests.

The suites that will carry the stronger claims are listed below, in the order
the methodology's §15 says to build them.

## Tier roadmap — NOT YET BUILT

In adoption order (return on effort, per methodology §15):

4. **Full stack, hostile** — `lychgated` driving real hosts (reaper guests),
   started hostile; the load-bearing claim is *revert-under-kill*: open a
   grant, kill the daemon, prove the dead-man timer on the target closes
   everything anyway. Two oracles: sshd's own config report **and** an actual
   connection attempt.
5. **Source-as-data** — once there are seams that can rot (driver registry,
   channel vocabulary, CLI/daemon flag parity).
6. **Concurrency** — simultaneous open/close/renew against one host; assert
   the grant state read back, not response counts.
7. **Simulated users** — last, and the oracle self-test gets written first: an
   invariant that has never fired is indistinguishable from a passing suite.

The acceptance test for the whole exercise, when these arrive: revert known
fixed defects and confirm the harness rediscovers them.

## Running what exists

```sh
./tools/check.sh        # fmt, clippy -D warnings, tests, shell lint — runs
                        # every phase and reports all failures
cargo test --workspace  # just the tests
```

The project is a reaper tenant (`.reaper.toml`): `reaper test` runs the build
and suite on the FreeBSD and Ubuntu guests.
