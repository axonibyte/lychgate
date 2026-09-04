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

Mutation record: 35 mutations at scaffold time, 49 more for M1 (registry 10,
snapshot 11, store 11, journal/loop 14, installer 3) — 84 checked, 0
survived. Two mutations hung the suite (the lock spin and the zero-interval
spin); a hang is the observed failure for a spin.

Cross-platform record: the full battery ran green on both reaper guests
(freebsd-15.1 on pkg rust 1.96, ubuntu-26.04 in the pinned rust:1.97 image)
at M1 close — the store's rename/lock semantics and the signal handling are
proven on both deployment platforms, not assumed from the workstation.

**What these tiers do NOT prove:**

- No access is actually opened or closed anywhere. There are no drivers —
  "a grant expired" changes grants.json and a journal line, not sshd, not
  authorized_keys, not a BMC, not a console.
- The registry's open/close/renew are unreachable from any binary until M2's
  transport; they are Tier-1-proven only, and the journal's open/close/renew
  event kinds are deferred with them.
- Journal durability is fsync-per-line by construction, not by test; the
  residual power-loss windows (a lost line detectable as a pid/seq gap; a
  duplicated observation) are documented in the journal module, not tested.
- Single mutator only: lock behavior is exercised synthetically, not by
  concurrent daemons (real contention is Tier 6 territory, M7+).
- The service files stage correctly; whether rc(8)/systemd actually start the
  daemon from them belongs to M5's full-stack tier on the reaper guests.

The suites that will carry the stronger claims are listed below, in the order
the methodology's §15 says to build them.

## Tier roadmap — NOT YET BUILT

In adoption order (return on effort, per methodology §15):

2. **Seeded fuzz** over `Ttl::parse` and `Inventory::parse` — the oracle is
   "no panic, every rejection well-formed", the seed printed and replayable
   through the environment. Arrives with the first externally-reachable input
   surface (the daemon transport).
3. **Error-injection integration** — drivers exercised against fake SSH/BMC/
   VNC transports that fail mid-operation; a half-applied grant must present
   as needing revert, never as open. Arrives with the driver trait.
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
