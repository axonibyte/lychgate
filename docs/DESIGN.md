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
  and brings up a console tunnel with a rotated password. As of M9 opening is
  gated on a weighted-threshold approval authority (Ed25519/SSHSIG, TOTP,
  password, FIDO2 and TPM factors, with groups and waits). `--dry-run` registers no drivers and accepts any approval token,
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

The flow is **out-of-band** — the daemon grows no network listener. `open --as
<profile>` records the Pending grant and returns a **challenge**: a canonical,
domain-separated, length-prefixed encoding of `(nonce, host, ttl, requested_at)`,
rendered `lg1.req.<base64url>`. Operators, on whatever devices they trust, sign
exactly those bytes and hand the tokens back through `lychgate approve` (on
stdin, off the argv). The length-prefixing is deliberate: daemon and signer must
agree on the signed bytes with no field-order or delimiter ambiguity.

**The gate is a weighted-threshold authority** (`core/src/authority.rs`),
modelled on EOS/Antelope permissions. An authority is a `threshold` over
weighted factors; a factor is one of:

- an **authenticator** — a leaf proof identified by id (an Ed25519 SSHSIG, a
  TOTP code, a password, a FIDO2 assertion, or a TPM challenge signature — all
  five kinds implemented);
- a **group** — itself an authority, satisfied when *its* threshold is met, so
  gates nest into a DAG;
- a **wait** — satisfied once a duration has elapsed since the request.

The grant opens when the satisfied factors' weights sum to at least the
threshold. Authorities attach to named **profiles**; a host's `[hosts.access]`
lists which profiles it permits and may override a profile's authority (the
host × profile matrix). Evaluation is pure — `from_spec` validates the whole
policy at load (references resolve, groups are acyclic, every threshold is
satisfiable, and a credential that cannot be built — a bad key, an unknown
alg — is refused at load, not at 03:00), and `evaluate` sums weights against the set of verified
authenticator ids and the elapsed time. **Fail-closed throughout**: a policy with
no profile is refused, an unsatisfiable threshold is refused, and a `[approval]`
absent outside `--dry-run` refuses the daemon's start.

Approval **accumulates**: proofs arrive across one or more `approve` calls and a
wait's weight accrues over time, so a pending grant persists *which
authenticators are satisfied* (never a secret) and the reap loop opens it the
instant the weighted sum crosses the threshold — a `wait` can open a grant with
no further human action. `approve` verifies each proof against the request's own
challenge, routing by proof shape: an SSHSIG blob to `verify_ed25519` (parse the
envelope, check the namespace, match the signer to a configured key, verify over
the challenge); an all-digits code to TOTP, tried against every configured secret
(RFC 6238, ±1 step) and spent once against a persisted single-use ledger. No
bespoke signing tool and no hand-rolled crypto — `ssh-key` and RustCrypto's
`hmac`/`sha1` do the verify; trust reduces to the configured keys/secrets, and
revocation is an inventory edit.

A TOTP code, unlike an SSHSIG, does **not** bind to the host or challenge — it
proves possession of the shared secret at a moment, nothing more. The single-use
ledger stops replay (even across a restart within the window), the code is
recorded on the specific pending grant it was submitted to, the window is short,
and the socket is root-only; the weighted model prices this weakness through
weights (a code alone rarely meets a threshold worth guarding). That is *why* the
gate is weighted, not a reason TOTP is unsafe. The secret is read from a mode-600
file at startup (fail-closed on absence), never inline in the world-readable
inventory.

A **password** is weaker still — reusable, with no single-use ledger, so it
approves repeatedly until rotated. It is the low-weight factor of last resort,
meant to be paired with a bound one, never to reach a threshold alone. Its
Argon2id hash lives in a mode-600 file (`lychgate hash-password` produces it), so
a leaked file is not a trivial recovery; the daemon verifies in constant time and
routes a proof to it by elimination — an SSHSIG goes to Ed25519, an all-digits
token to TOTP, anything else is a password, so a password factor must not be
purely numeric.

A **FIDO2** assertion is the strongest factor: like an SSHSIG it **binds to the
challenge**, so it is phishing- and replay-resistant. A token prefixed
`lgfido2.` carries a WebAuthn assertion (credentialId, authenticatorData,
clientDataJSON, signature); `verify` checks the challenge inside clientDataJSON,
the relying party (authData's rpIdHash must be `SHA-256("lychgate")`, so an
assertion made for another site cannot be replayed here), the user-present flag,
and the signature — ES256 (ECDSA-P256) or EdDSA (Ed25519) over
`authenticatorData ‖ SHA-256(clientDataJSON)` — against the credential's
registered public key. That key is public and lives inline in the inventory (a
SEC1 point for ES256, the raw key for EdDSA). Two hardening layers (M9): the
daemon keeps a per-credential **signature-counter ledger** — once a device has
presented a nonzero counter, every later assertion must present a strictly
greater one, and a regression (equal, lower, or a sudden zero) is the
two-devices-one-credential clone shape, refused and journaled; and hardware
registration **verifies the packed attestation statement** and surfaces the
AAGUID, so the operator sees what device minted a credential before trusting
it (the certificate is verified, not chained to a vendor root — root-pinning is
future hardening). No challenge ledger is needed: the per-request nonce inside
the challenge is itself the anti-replay. Producing an assertion is either the
deterministic **software authenticator** (`lychgate fido2-assert
--software-key`, used by the tests and the e2e; it counts nothing and attests
nothing, said plainly) or a real hardware key over USB-HID — the **CTAP2
client** behind the `fido2-client` cargo feature, off by default so the daemon,
the guests and the Windows cross-build never pull the hidapi C dependency. Both
emit the exact bytes `verify` accepts, from one shared wire format in
`core::fido2`.

A **TPM factor** is a P-256 ECDSA key whose private half lives non-exportable
inside the machine's TPM 2.0; its proof (`lgtpm.<base64url(DER signature)>`) is
a signature over the request's challenge, verified with the registered SEC1
public key — plain ECDSA in core, which knows nothing about TPMs: the TPM-ness
is an *operational* property (the key cannot leave the chip). The key and the
sealing parent are owner-hierarchy **primaries with fixed templates**, re-derived
on demand — nothing is persisted in the TPM and there is no handle management.
The hardware ceremony (`lychgate tpm-probe / tpm-register / tpm-sign /
tpm-seal`) lives behind the `tpm-client` cargo feature (tss-esapi, the C TSS
stack; FreeBSD builds add `-bindgen`), and the daemon's `tpm-seal` feature adds
`--tpm-unseal`: configured secret files (TOTP secrets, password hashes) are
TPM-sealed blobs unsealed at startup, so the files at rest are useless off the
host. A machine may or may not have a TPM — `lychgate tpm-probe` is the
compatibility check, and everything is fail-closed: the flag without the
feature, or with an unreachable TPM, refuses the start rather than falling back
to plaintext. Sealed blobs bind to the TPM itself with no PCR policy in v1
(documented; PCR binding is future hardening).

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
5. **Operator surface** — the weighted-threshold approval gate (M8a.1–2, done;
   see [Approval](#approval)) leads; the **MCP front door** (M8b, done; see
   [MCP front door](#mcp-front-door)) lets a Claude session request and use a
   grant without shell access. **Drill mode** (M8c, done; see
   [Drill mode](#drill-mode)) is the standing revert oracle. All five
   authenticator kinds (Ed25519, TOTP, password, FIDO2, TPM) are done.

## MCP front door

`lychgate-mcp` is a separate, low-privilege binary that lets a Claude session
request and use a grant over MCP (JSON-RPC 2.0 on stdio) without shell access to
the daemon host. It is a **client** of the daemon — it holds no drivers and no
secrets — and it makes the **AI a first-class approval factor**, not merely a
requester: the server holds an Ed25519 key whose public half is an ordinary
`ed25519` authenticator in the policy, so a profile can compose the AI with
humans (`threshold 2 over { sysadmin, ai }`). When the AI opens a grant it signs
the challenge with that key, contributing its factor exactly as a human's
`ssh-keygen -Y sign` would; the daemon verifies it through the same path. The AI
alone opens only what the policy's thresholds permit.

Which grants the front door may reach is a per-profile `mcp` flag, and it is the
daemon that enforces it — via a **dedicated MCP socket**. The daemon binds a
second unix socket for `lychgate-mcp`; an op's origin is identified by which
socket it arrived on (OS-enforced, not a forgeable wire field), and an
MCP-origin `open`/`approve` is refused unless the target profile is `mcp = true`
(fail-closed, and journaled). The operator socket is never gated. The MCP server
exposes open/status/renew/close plus a non-secret `access_handle`; it does not
expose a general `approve` (the daemon returns a challenge only from `open`, so
the AI can only sign a grant it initiated), and one-time-secret delivery to the
AI is deferred (the "shown once, never persisted" invariant is not yet
revisited).

## Drill mode

A revert path never observed firing is indistinguishable from one that does not
work. `revert-under-kill` proves the revert path in CI; **drill mode** proves it
in *production*, on a schedule. `lychgate drill --host <canary>` sends `Op::Drill`
to the running daemon, which opens-and-reverts a designated canary and confirms
the revert fired — journalling `DrillPassed`/`DrillFailed` and exiting non-zero
(via the CLI) on failure, so cron schedules it and monitoring alerts.

The canary is a host flagged `drill = true` in the inventory — a designated
throwaway; a host without the flag is never drillable. The drill is a
daemon-internal self-test: it opens the canary through the exact hardened
lifecycle (`begin_pending → open_pending_now → close`) but **bypasses the
approval gate**, because it exercises the channel apply/revert path, not approval
(which the approval tier tests). The bypass is bounded to the canary flag and is
an operator/cron action — a drill is refused over the MCP front door. The verdict
needs no new oracle: `close()` already commits `Closed` only when every channel
is verifiably reverted (each driver's `verify()` confirms actual state) and
reports a stuck revert otherwise, so a drill passes exactly when the open applied
and the close fully reverted. A crash mid-drill is safe — the write-ahead
`Opening`/`NeedsRevert` states let `boot_recover` and the pass loop finish the
revert on the throwaway canary.
