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

37 tests on `lychgate-core`, in-crate under `#[cfg(test)]`, named as full
sentences stating the claim (`a_grant_past_its_ttl_is_expired_rather_than_left_open`).
They cover the TTL policy (zero/cap/cap+1 boundaries, unit parsing, overflow
refused rather than wrapped, multibyte input refused rather than panicking),
the grant state machine (expiry at the exact instant, open/close/renew
transitions, the 2-hour renewal window at its boundary, renewal anchored at
now rather than the old expiry, clock overflow refused rather than saturated),
and inventory validation (strict schema, duplicate/empty rejections).

All 35 planned mutations were applied and observed killed at scaffold time
(35 checked, 0 survived).

**What this tier does NOT prove:** that any access is actually opened or
closed anywhere. There are no drivers yet — nothing here touches sshd,
authorized_keys, a BMC, or a VNC console. The state machine being right is
necessary and nowhere near sufficient; the suites that will carry the stronger
claims are listed below, in the order the methodology's §15 says to build
them.

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
