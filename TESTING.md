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

Mutation record: 35 at scaffold, 49 for M1, 25 for M2, 25 for M3, 25 for
M4, and 17 for M5 (dead-man rendering 8, lifecycle + ExecDeadman wiring 9)
— ~176 checked to date, 0 surviving now. Across the project, five survivors have
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
at M1–M5 close — the store's rename/lock semantics,
signal handling, unix-socket transport, the SSH drivers, and the
crontab dead-man's revert-under-kill are proven on both deployment
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

## SSH driver tier: EXISTS (M4)

The pure string logic (posture vocabulary, drop-in, fence, sshd -T parsing)
is Tier-1 tested with a hostile corpus and fuzzed (authorized_keys content
and sshd -T output arrive from remote hosts). The drivers are proven twice:
against a scripted transport (mid-operation drops, silently lost writes,
drifted host configs, nonzero exits, the become prefix, quoting), and
against a real sshd by `e2e/ssh-acceptance.sh` on a disposable host — open
flips the effective posture (sshd -T AND a live connection with the
emergency key), close restores authorized_keys byte-for-byte and the
default posture (AND the emergency key stops working), a hand-added key
survives the whole cycle. Green on both reaper guests at M4 close. The
first live run caught the sshd SIGHUP restart window — a race the fakes
could not show — now ridden out by a bounded post-reload retry with its own
regression test.

**What the acceptance run does NOT prove:** it runs on demand, not in the
reaper [run] battery yet (that wiring is M5); and it exercises one host
driving itself over loopback — real network partitions mid-apply are the
scripted transport's territory until M5's revert-under-kill.

## Tier 4 — full stack, revert-under-kill: EXISTS (M5)

The dead-man rendering is Tier-1 tested (crontab upsert/removal, the script
baking in every revert ingredient, sh -n over both OS variants, quote
refusal) and fuzzed; ExecDeadman and the lifecycle wiring are proven against
scripted transports (install/reschedule/remove, the fail-closed open and
renew orders, removal-last-on-revert). The full stack runs on both reaper
guests via `e2e/run.sh` (the tenant [run] command): unit suites, the ssh
acceptance, service start/stop under rc(8)/systemd, and the headline —
`e2e/revert-under-kill.sh`: open a 90s grant, assert access is open and the
backstop armed, SIGKILL the daemon, and the target's own crontab dead-man
reverts posture and keys before the daemon returns to reconcile (journaling
the expire and a close with deadman_fired true, idempotent on a second
boot). Its oracle self-test is run.sh's sabotage pass: remove the installed
dead-man and the run MUST fail — a harness that passes with a dead backstop
measures nothing.

**What Tier 4 does NOT prove:** it drives one host over loopback, so a
network partition *between* the daemon and a remote target mid-apply is
still the scripted transport's territory, not the live tier's. The dead-man
depends on cron running on the managed host; the daemon refuses an open
where it is absent, but a cron daemon that is installed yet not actually
scheduling is beyond what the acceptance asserts.

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

- The ssh and authorized-keys channels really change hosts (M4); bmc and
  vnc remain bookkeeping-only until their drivers exist, and the daemon
  says so at startup.
- The dead-man timer on the target reverts access if the daemon host dies
  (M5), but it depends on cron; a host without cron is refused an open.
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
