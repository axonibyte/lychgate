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
M4, 17 for M5, 23 for M6 (bmc string logic + inventory 12, bmc driver 11),
29 for M7 (vnc config + template validation 9, the reestablish/suspend/
secret-label contract 7, the vnc driver + tunnel + dry-run 8, the lifecycle
re-establishment + serialization 5), 24 for M8a.1 (approval canonical
encoding + SSHSIG verify + AnyOf fail-closed 9, pending grant/registry
transitions 6, snapshot v3 validation + store readable-set 6, lifecycle
approve/deny + journal 3), and 22 for M8a.2 (authority engine: threshold and
wait boundaries + nested-group resolution + the config refusals 12, pending
accumulator + snapshot v4 + proto v4 6, daemon open-on-wait + the revert race 4),
14 for M8a.3 (TOTP RFC-4226 KAT + skew boundary + code/base32 parse 6, the
single-use ledger: consume/replay/reload/prune/corrupt 5, daemon dispatch +
missing-secret refusal 3), and 10 for M8a.4 (Argon2id PHC KAT + mismatch arm +
malformed/digest-less refusal 5, daemon open/wrong/reusable/missing-hash + the
password-fallback dispatch 5) — ~298 checked to date, 0 surviving now.
Across the project, five survivors have
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
at M1–M8a.4 close — the store's rename/lock semantics,
signal handling, unix-socket transport, the SSH drivers, the
crontab dead-man's revert-under-kill, the vnc tunnel's
parent-death signal (`PR_SET_PDEATHSIG` on Linux, `PROC_PDEATHSIG_CTL` on
FreeBSD): the pdeathsig proof, which has no in-process oracle, killed the
forward with the daemon on both platforms; the real SSHSIG approval path, where
`ssh-keygen -Y sign` (OpenSSH 10 on both guests) produces a token the daemon
verifies before a grant opens; the weighted authority model, where accumulation
and a real elapsed `wait` open a nested-group multi-factor gate; real RFC 6238
TOTP codes and an Ed25519-AND-TOTP two-factor open; and — new at M8a.4 — a
`lychgate hash-password` Argon2id hash the daemon verifies, and a
password-AND-Ed25519 two-factor open. All proven on both deployment
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
boot). The reconcile is driven the way production runs it — repeated passes,
not a single one — because the daemon retries a revert step left stuck by a
transient (a dropped ssh connection under load) on the next pass by design;
the test loops passes until the close lands and fails loudly if it never
does, so it proves *eventual* closure across passes, not single-pass
closure. Its oracle self-test is run.sh's sabotage pass: remove the installed
dead-man and the run MUST fail — a harness that passes with a dead backstop
measures nothing. (The sabotage run still fails: with no dead-man, the close
never records a firing across the whole pass window.)

**What Tier 4 does NOT prove:** it drives one host over loopback, so a
network partition *between* the daemon and a remote target mid-apply is
still the scripted transport's territory, not the live tier's. The dead-man
depends on cron running on the managed host; the daemon refuses an open
where it is absent, but a cron daemon that is installed yet not actually
scheduling is beyond what the acceptance asserts.

## BMC driver tier: EXISTS (M6)

The Redfish AccountService bodies, the account-GET parse (Enabled read-back,
stranger-slot refusal, empty-slot claim), and break-glass password
generation are Tier-1 tested and fuzzed (responses arrive from the iDRAC
over the network). A `Secret` type redacts through Debug/Display so a
credential cannot leak via a stray format; its one delivery path (the open
response, shown once by the CLI) and its absence from the journal are proven
by a lifecycle test with two oracles. The driver is proven over a scripted
Redfish fake (rotate+verify, escrow-before-enable, stranger-slot and HTTP
failures, read-back disagreement on apply and revert, non-200 reads), and
end to end over real HTTP by `e2e/bmc-acceptance.sh`: the real daemon and
curl transport against a self-hosted Redfish mock (enable+rotate on open,
password shown once and journal-clean, disable on close, stranger-slot
refused untouched).

**What the BMC tier does NOT prove:** a real bench iDRAC. The mock speaks
the AccountService subset lychgate uses; a real controller's quirks
(password-complexity rejections, slot-management races, vendor Redfish
deviations) are beyond CI's reach. There is no dead-man for bmc — an iDRAC
has no shell for the crontab backstop — so if the daemon dies for longer
than a bmc grant's TTL, the account stays enabled until the daemon returns;
expiry enforcement for bmc is lychgated's alone.

## VNC console tier: EXISTS (M7)

Opening the vnc channel gives a grant temporary console access: a daemon-held
`ssh -L` tunnel from the daemon host's fixed local_port to the VM's RFB port on
its hypervisor, plus a one-time VNC password rotated through a configurable,
platform-agnostic command (cbsd is the pilot). The config and command templates
are Tier-1 validated and fuzzed (single quotes refused so lychgate owns the
shell quoting; `{password_file}` required in set and forbidden in clear; unknown
placeholders named; `local_port` unique across the inventory). The driver is
proven over a scripted transport and a fake tunnel: the password is staged in a
mode-600 file and removed at once, is on no argv (scanned across the whole call
log — the in-process counterpart of the acceptance's journal grep), apply
rotates-then-tunnels and revert tunnels-down-then-clears (idempotent), verify
reads the forward's listening state, reestablish re-asserts reachability without
re-rotating, and the one-time password is handed off exactly once. The tunnel's
own lifecycle — readiness probe, teardown, self-exited-child reaping, and a
stray on the fixed port reported stuck rather than killed by port — is proven
over a fake spawner that binds a real local socket. End to end,
`e2e/vnc-acceptance.sh` runs the real binaries against real sshd and an RFB mock
(open reaches the forwarded port and rotates the password shown-once and
journal-clean; close tears both down; a second open on a held console refused),
and its pdeathsig phase proves the tunnel dies with a SIGKILLed daemon on both
guests. Boot re-establishment (a tunnel that outlived a restart is rebuilt,
reachability only; one that cannot be is demoted to needs-revert) is proven at
the lifecycle tier.

**Serialization (Tier 6):** the project's first thread-racing harness fires
sixteen simultaneous opens of one console and reads back exactly one grant and
one apply — one tunnel, one password — the losers refused as
already-open/mid-open before reaching a driver. The oracle is resource and
committed state, not response counts. The serializer is the store's file lock
plus `begin_open` refusing any non-Closed grant.

**What the VNC tier does NOT prove:** a real bhyve/cbsd. The RFB mock is a bare
TCP acceptor, not a one-client RFB server, so real RFB authentication and the
single-viewer rule are out of reach; the concurrency harness serializes
same-process threads, not cross-process racing clients beyond what the file lock
already gives, and its fake apply is instant, so it does not prove a slow real
`ssh -L` cannot interleave. The one-time password exists in plaintext in a
mode-600 file on the hypervisor for the set command's runtime (bmc avoids even
that, feeding curl on stdin), and the password's set-state is not independently
re-readable, so verify keys on the tunnel's reachability. There is no dead-man
for vnc: the tunnel dying with the daemon is the reachability backstop, and the
rotated password's expiry is the reap loop's alone — and if the parent-death
signal loses a fork/exec race on a hard crash, an orphaned forward is caught on
the next boot by the fixed-port teardown, not instantly.

## Approval tier: EXISTS (M8a.1–5)

Opening a grant requires an operator approval, and the tier proves it from the
bytes up. The challenge is a canonical, domain-separated, length-prefixed
encoding of `(nonce, host, ttl, requested_at)`; a golden vector pins the exact
bytes and a framing test shows the length prefixes defeat a delimiter collision,
so daemon and `ssh-keygen` cannot disagree about what was signed. The SSHSIG
Ed25519 verify is proven against committed `ssh-keygen -Y sign` fixtures: a good
signature resolves to its authenticator id, and the oracle self-test refuses a
signature over the wrong bytes, under the wrong namespace, for a different
request, and from a signer not configured — the four ways a verify must fail,
each asserted, not assumed.

Since M8a.2 the gate is a **weighted-threshold authority** (EOS/Antelope model),
and the engine is a pure KAT surface. The worked example — a threshold-5 profile
over a nested group, a standalone factor and a wait — is pinned as a golden
vector: both documented paths reach the threshold and open, and the near-misses
(one weight short; a subgroup one proof short contributing nothing) do not; the
threshold (`>=`) and wait-boundary (`>=`) comparisons are mutation-checked
(flipping either to `>` fails the KAT). Config is validated at load, each refusal
naming the offender: a reference cycle, a dangling authenticator/group, an
unsatisfiable threshold (threshold > Σ weights), a zero threshold or weight, and
an authenticator of an unimplemented kind. The accumulating pending lifecycle is
proven at the grant/registry tiers — proofs accumulate and a lapsed request
refuses further ones — and the daemon opens a wait-only profile on a pass once
the wait matures, with an oracle self-test that it stays pending before then.
Snapshot is v4 (profile + satisfied set, validated strictly) with v2/v3
read-compat; proto is v4; the token/challenge decoders and the model's verify
join the fuzz seed set.

Since M8a.3 **TOTP** is a second authenticator kind (RFC 6238). The crypto is
pinned by the RFC 4226 Appendix-D KAT (`code_at` matches the published 6-digit
vectors for the standard seed), with both the truncation mask and the ±skew
window mutation-checked; `matches` finds the code at its window, rejects one step
outside, and refuses a wrong or malformed code. A submitted code carries no
identity, so the daemon tries it against every configured secret and spends the
first match once against a **persisted single-use ledger** — which consumes a
code once, refuses the replay *across a reload*, prunes stale entries, and
refuses a corrupt file (fail-closed: forgetting spent codes would reopen the
replay window). At the daemon tier a real code opens a single-factor TOTP
profile, a spent code cannot reopen a fresh grant within its window, a wrong code
is refused, a digit token with no matching secret is refused cleanly (the
SSHSIG-vs-code dispatch), and a missing secret file refuses the daemon's start.

Since M8a.4 **password** is a third kind — Argon2id, the deliberately weakest,
reusable factor. A committed PHC vector verifies against its password and refuses
a wrong one (the KAT + a mutation-checked mismatch arm); a malformed or
digest-less hash is refused, not read as a silent mismatch (fail-closed). A
password names no authenticator, so it is the dispatch fallback (a token that is
neither an SSHSIG nor all-digits), verified against every configured hash in
constant time with **no ledger** — and the daemon tier asserts that reuse
opens a second grant, so "reusable" is an intended property, not an accident;
a wrong password is refused and a missing hash file refuses the daemon's start.

Since M8a.5 **FIDO2** is the fourth and last kind — the strongest, a
challenge-bound WebAuthn assertion. Committed ES256 and EdDSA assertion vectors
verify against their credential, and the oracle self-tests refuse a tampered
signature, a wrong challenge, a wrong rpIdHash, a cleared user-present flag, an
unknown credentialId, and a wrong-alg key — nine mutation-checked arms in all,
each observed failing when the check it guards is inverted. `build_assertion`
(the deterministic software authenticator) round-trips through `verify` for both
algs and its output is byte-pinned by the committed vectors, so the software
path, the CLI and the hardware client all speak bytes the KAT proves. The daemon
tier opens a fido2 profile on a valid assertion, refuses one built for a
different challenge (the challenge binding, mutation-checked by pinning the
daemon's challenge to a constant), and does not misroute a non-fido2 token.

End to end on both guests: `e2e/approval-acceptance.sh` runs the real binaries
with a real `ssh-keygen -Y sign` token (a configured key opens; a stranger and a
lapsed window are refused), and `e2e/authority-acceptance.sh` proves the weighted
model live — accumulation across multiple `approve` calls opens a nested-group
multi-factor gate, the daemon's own pass loop opens a grant on a matured `wait`
with no further proof, and a stranger is refused. That fast-interval e2e also
reproduced a latent revert race (a reap pass and an operator close both reverting
one host) that is now fixed and does not recur. `e2e/totp-acceptance.sh` proves
the TOTP factor with real RFC 6238 codes (a python3 helper computes them): a code
opens a single-factor profile, the replay is refused, a wrong code is refused,
and a **two-factor profile (Ed25519 AND TOTP) opens only after both** — the real
MFA proof end to end. `e2e/password-acceptance.sh` proves the password factor:
`lychgate hash-password` makes the hash file, the correct password opens (and
opens *again* — reusable), a wrong one is refused, and a **password-AND-Ed25519
two-factor profile** opens only after both. `e2e/fido2-acceptance.sh` proves the
FIDO2 factor with the default-build software authenticator (`lychgate
fido2-register` / `fido2-assert --software-key`): single-factor ES256 and EdDSA
assertions open, an assertion made for a different challenge and a byte-corrupted
token are refused (then the pristine one still opens, so it is the corruption the
daemon rejected), and a **fido2-AND-password two-factor profile** opens only
after both. The whole real-driver battery
(ssh/bmc/vnc/revert-under-kill/service-start) runs through the open → sign →
approve round trip via `e2e/lib.sh`, so every acceptance proof also proves the
approval gate does not get in the way of a legitimate open.

**What the approval tier does NOT prove:** the FIDO2 **hardware** client in the
default CI — there is no key on the build hosts, so the `fido2-client` feature is
not compiled or run by the gate (it is exercised by the simulated tier below and
a one-time manual ceremony on a physical key). FIDO2 attestation is not verified
and the signature counter is not tracked (both documented simplifications — we
trust the registered public key). Trust reduces to the configured public
keys, TOTP secrets and password hashes; a compromised key/secret is out of scope,
as is revocation (edit the inventory and reload). Neither a TOTP code nor a
password binds to the host/challenge — for TOTP the single-use ledger, short
window and root-only socket bound the replay; a password is reusable outright and
priced at low weight for exactly that reason. Neither is proven safe *standing
alone at a weight worth guarding* — the weighted model is the point. The out-of-band
paste path is exercised by piping the token; a phone/QR round trip is a CLI
convenience not yet built. `--dry-run` (no model, first proof opens) proves the
*lifecycle*, deliberately not the *crypto* — the real verifies are proven only by
the guest acceptances and the fixture/KAT tests.
Cross-*profile* identity binding (requiring the same operator across two factors)
is not modelled: factors are independent.

## FIDO2 hardware tier — simulated + manual (M8a.5)

The one path with no default-CI oracle: the `fido2-client` CTAP2 client driving
a key over USB-HID. There is no FIDO2 hardware on the build guests, so the
feature is not part of the gate. Its correctness reduces to the assertion format
— which the software authenticator and the verify KAT pin exactly — plus the
CTAP2 ceremony, which is exercised two ways, both manual and both using
`e2e/fido2-hardware.sh` (register → a stale-challenge assertion refused → the
genuine assertion accepted, over the real vnc channel so the daemon actually
verifies; it skips loudly with exit 2 when the feature is not built or no key is
attached):

1. **Against a physical key** — a one-time ceremony per key model. Build with
   `cargo build -p lychgate --features fido2-client` (unix; needs the system
   hidapi library) and `cargo build -p lychgated`, then run the script as root
   with a key inserted.
2. **Against a virtual authenticator (simulated)** — makes the path runnable
   with no hardware, and is how it was verified for M8a.5. On a Linux host:
   load `vhci-hcd`; build [virtual-fido](https://github.com/bulwarkid/virtual-fido)'s
   `demo`; run `yes | demo start --vault v.json --passphrase p` (it exports a
   CTAP2 device over USB/IP loopback and self-attaches via `usbip attach`, and
   `yes` auto-approves each user-presence prompt); a FIDO `/dev/hidraw*` appears.
   Then `LYCHGATE_BIN_DIR=… sh e2e/fido2-hardware.sh` runs the full ceremony
   against it. This was observed green on the Ubuntu guest: the daemon verified a
   real hardware assertion and refused a stale-challenge one. The stale test is
   itself the oracle — under `--dry-run` (no verification) it opens; under real
   verification it must refuse, and does.

This tier is deliberately not wired into `e2e/run.sh`: the default battery builds
without the feature, so the script would only ever skip there. It is run by hand,
and its green run is recorded here rather than by CI.

## MCP front-door tier: EXISTS (M8b)

The MCP front door makes the AI a factor, so it is tested from the flag up. In
core, a profile's `mcp` flag defaults false and `mcp_allowed` reflects it, the
spec→model wiring mutation-checked (skipping the insert fails the opt-in test).
In the daemon, an MCP-origin `open`/`approve` on a non-`mcp` profile is refused
and journaled `mcp-refused`, while the **operator** socket opens the same profile
fine — two oracles for one claim (the gate is origin-scoped, not global), and the
gate is mutation-checked by forcing it to always-allow. In `lychgate-mcp`, the
AI's produced token verifies through the daemon's own `verify_ed25519` against
the configured `ai` key — the signing oracle — self-tested by signing a
*different* challenge and asserting the verifier refuses it; the JSON-RPC framing
round-trips (`initialize`/`tools/list`), a notification draws no reply, a
malformed line is a clean `-32700` not a panic, and `open_grant` signs the exact
challenge `open` returned (checked by verifying the recorded Approve token).

End to end on both guests, `e2e/mcp-acceptance.sh` drives the real `lychgate-mcp`
over stdio against a daemon serving an operator socket AND a dedicated MCP socket:
over MCP a non-`mcp` profile is refused by the front-door gate; the AI factor is
contributed to an `ai-assisted` (threshold 2) grant, which does **not** open on
the AI alone; and a human signing the same challenge on the operator socket opens
it — the genuine sysadmin+AI gate — after which MCP `grant_status` reports it
open. **What it does not prove:** one-time-secret delivery to the AI (deferred);
the MCP socket, like the operator socket, is the authorization boundary (a
process that can open it is trusted) — the `mcp` flag bounds *which profiles* it
reaches, not *who* may connect.

## Drill tier: EXISTS (M8c)

Drill mode is the standing revert oracle, so its own tests are oracle-shaped. In
the daemon, a drill on a `drill = true` canary passes and leaves the canary idle
(`DrillPassed` journaled); a drill on a non-canary host is refused (mutation
-checked by forcing the canary gate open — the refusal test then fails); and **the
sabotage self-test**: a fake driver that applies but cannot revert makes the
drill report `DrillFailed`, and a follow-up drill is refused as not-idle. A drill
that passed with a broken revert would be measuring nothing, so this arm is the
point of the tier. `Op::Drill` round-trips the wire and the `drill` flag defaults
false.

End to end on both guests, `e2e/drill-acceptance.sh` drives `lychgate drill
--host canary` over the real vnc channel: a healthy drill passes (exit 0, and the
witness log shows a set then a clear — the channel really was applied and
reverted), then the canary's clear command is **sabotaged** (made to fail) and
the drill must exit non-zero with `DrillFailed` — mirroring how
`revert-under-kill --sabotage` proves that harness can still catch a dead
backstop. **What it does not prove:** a drill exercises the channel apply/revert
path, not the approval gate (it bypasses approval for the canary — approval is
the approval tier's job); and the canary is a throwaway, so the drill says
nothing about a *real* host's revert beyond that the drivers and revert logic
work against that canary's channels.

## Simulated-users tier: EXISTS (M8d)

The §15 capstone (`daemon/src/sim.rs`): seeded actors drive the real in-process
`Daemon` through adversarial sequences — opens, **real SSHSIG approvals** signed
in-process by two configured actors and one stranger, renews, closes, time
advances, and reap passes — while a pure **shadow model** predicts every
observation and a **checker** compares them after every action. The shadow
*deliberately duplicates* the policy semantics (threshold arithmetic, the closed
deadline/expiry boundaries, the renewal window, pass's wait-only opening) — the
duplication is the check. House fuzz idiom throughout: SplitMix64, committed
`FIXED_SEEDS`, the seed printed before use, `LYCHGATE_SIM_SEED` replays one seed
and `LYCHGATE_SIM_ACTIONS` scales the walk.

The **checker came first and is self-tested**: fed the observations and responses
a *broken* daemon would produce, it must complain — a grant open below threshold,
a grant outliving its expiry, wrong remaining-TTL arithmetic, a refused valid
live proof (the observable of the real approve-vs-pass bug), an accepted stale
proof. The **nemesis** moves live in the action space (a stale-challenge replay,
the stranger's signature, double submits, act-on-expired approve/renew,
abandonment past the window), plus two committed deterministic walks that
traverse all of them. On a failure the **shrinker** (ddmin over the action log,
each candidate replayed on a fresh daemon) minimizes to a locally minimal
reproducer before panicking with the seed; its reduction loop is itself
self-tested against a synthetic failing predicate.

The harness has been *observed biting*, per the §15 acceptance: three seeded
mutations were each caught and shrunk — approve opening below threshold (a
120-action walk shrank to a 2-action reproducer), the pending reap skipped, and
the renewal window dropped. The two historical *thread-interleaving* defects
(approve-vs-pass, close-vs-pass) are rediscovered by the Tier-6 threaded
harnesses, which is where they belong — this tier is sequential by construction
(that is what makes a seed replayable) and catches their *observables* through
the checker instead. **What it does not cover:** thread interleavings,
cross-process contention, factor kinds beyond ed25519 (each has its own KAT/e2e
tier), and failing drivers (the channel and drill tiers own those).

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

- All four channels really change hosts (ssh/authorized-keys M4, bmc M6, vnc
  M7); `--dry-run` opens grants as bookkeeping only, touching nothing, and the
  daemon says which mode it is in at startup.
- The dead-man timer on the target reverts access if the daemon host dies
  (M5), but it depends on cron; a host without cron is refused an open.
- Reaching the owner-only socket lets a process *request* a grant, but opening
  it requires satisfying the profile's weighted-threshold authority (M8a.1–2) —
  by M8a.2 that can be several factors and/or an elapsed wait, not one signature.
  Root on the daemon host is still the boundary for status/close and for who runs
  the daemon; the approval gate is what stands between socket access and an open
  grant.
- The listener's take() allocation bound (a writer that never sends a
  newline) has no behavioral oracle — the observable is memory — and is
  stated in a comment rather than pretend-tested.
- The non-unix transport stub compiles for Windows only in CI's cross-build;
  nothing local proves it.
- Journal durability is fsync-per-line by construction, not by test; the
  residual power-loss windows (a lost line detectable as a pid/seq gap; a
  duplicated observation) are documented in the journal module, not tested.
- Concurrency: the M7 Tier-6 harness races sixteen same-process threads for one
  console (see the VNC console tier), and the **approve-vs-pass open race** is
  hardened (M8d) — a threaded harness races two opens on one pending grant fifty
  times and asserts neither is spuriously refused and it opens exactly once, and
  `pass` is proven to defer proof-met grants to `approve` (mutation-checked both
  ways). This cured the intermittent `authority-acceptance` flake. The
  close-vs-pass revert race was hardened at M8a.2; cross-*process* racing beyond
  what the store's file lock (now PID-aware) gives is still not exercised — the
  simulated-users tier is where that lands.
- The service files stage correctly; whether rc(8)/systemd actually start the
  daemon from them belongs to M5's full-stack tier on the reaper guests.

The suites that will carry the stronger claims are listed below, in the order
the methodology's §15 says to build them.

## Tier roadmap — NOT YET BUILT

In adoption order (return on effort, per methodology §15). Tier 4 (full stack,
hostile — revert-under-kill) landed at M5 and Tier 6 (concurrency) at M7; both
have their own sections above. What remains:

5. **Source-as-data** — once there are seams that can rot (driver registry,
   channel vocabulary, CLI/daemon flag parity).
7. ~~**Simulated users**~~ — landed at M8d (its own section above), with the
   invariant self-test written first and the §15 acceptance demonstrated by
   mutation (three reverted defects, each rediscovered and shrunk).

The acceptance test for the whole exercise, when source-as-data arrives: revert
known fixed defects and confirm the harness rediscovers them.

## Running what exists

```sh
./tools/check.sh        # fmt, clippy -D warnings, tests, shell lint — runs
                        # every phase and reports all failures
cargo test --workspace  # just the tests
```

The project is a reaper tenant (`.reaper.toml`): `reaper test` runs the build
and suite on the FreeBSD and Ubuntu guests.
