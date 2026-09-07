# lychgate embedded — design of record

Status: **approved design, implementation in progress** (the E-milestones in
[ROADMAP.md](ROADMAP.md)). This document is the design of record for extending
lychgate to firmware-class devices — ESP32-class microcontrollers, classic AVR
Arduinos, Raspberry Pi-class SBCs, and FPGAs — in five features:

1. **Device as target** — a grant opens/reverts state *on* a device.
2. **Firmware-side grant verifier** — the device enforces its own TTL.
3. **Secure elements (ATECC608) where available** — hardware-held keys.
4. **IoT device as approval factor** — a device co-signs a grant.
5. **Device as access mechanism** — the device *is* the gate (PDU, relay, door).

Plus two cross-cutting requirements: **stronger security on high-end MCUs**
(ESP32 et al.), **easier signing on low-end devices** (classic AVR), and an
FPGA tier.

Everything here follows the house rules: fail-closed everywhere, secrets never
journaled, TTL enforced at the lowest layer that can hold it, and every claim
gets an oracle that has been observed failing.

Normative sections (the exact CBOR byte layout, the device line protocol, the
hardening profile and ceremonies) are added to this document by the milestones
that freeze them (E6a/E6b); until a section says **normative**, it is design
intent.

---

## 1. Device tiers

Capability, not marketing, defines the tier. A device is classed by what it can
*verify* and what it can *hold*.

| Tier | Examples | Can verify sigs? | Can hold a key? | Trusted time? |
|------|----------|------------------|-----------------|---------------|
| **L** (Linux SBC) | Raspberry Pi, BeagleBone | yes (full lychgate) | file / TPM HAT | RTC/NTP |
| **H** (high-end MCU) | ESP32/-C3/-S3, RP2040, STM32F4+ | Ed25519/P-256, ms-scale | eFuse, DS peripheral, SE | uptime only |
| **A** (low-end MCU) | ATmega328 (Uno), ATtiny | lgcap **v2** via SE (see §6) | ATECC608 add-on | uptime only |
| **F** (FPGA) | iCE40, ECP5, Artix | soft-core or RTL | fabric / PUF / SE | uptime only |

**Tier L is already done.** A Pi is a small Linux host: ssh/authorized-keys
channels, cron dead-man, drill mode, even the daemon itself all work today. The
remaining work is release targets (arm64 already ships; armv7 is milestone E1).
A TPM 2.0 HAT works with the existing `tpm` factor unchanged.

**The governing constraint for H/A/F:** no shell, no cron, no filesystem in the
lychgate sense, and no battery-backed clock you can trust. Every design below is
an answer to "where does the TTL live, and what happens on power loss?" The
answer is always the same: **a reboot closes the grant.** Power-cycling a device
must never *extend* access; on these tiers it revokes it.

---

## 2. Feature 1 — device as target

A grant against an embedded device opens some state on it (a debug UART, a
maintenance AP, OTA acceptance, a config console) and reverts it at TTL. Two
sub-designs, by how much the device cooperates.

### 2a. Dumb target: generic channel drivers (daemon-enforced TTL)

For devices we don't reflash — commercial IoT gear, existing fleets — the
daemon drives whatever management surface exists. This is the **bmc pattern**:
the daemon is the sole enforcement authority, there is no on-device dead-man,
and the docs say so plainly.

New channel drivers, all config-driven and all **exec/fd transports, no client
library dependencies** (decided; the bmc driver's curl-exec precedent):

- **`[hosts.http]`** — open/revert/verify each map to a curl-driven HTTP
  request (method, path, body, expected status/markers). Auth secrets travel
  via `--config` on curl's stdin, never argv.
- **`[hosts.mqtt]`** — open/revert publish via `mosquitto_pub`; verify
  subscribes via `mosquitto_sub -C 1 -W <secs>` and checks the retained/echoed
  state. Broker auth is anonymous or TLS client-cert only — username/password
  broker auth is refused at load with a named reason (it would put the secret
  on argv). "No verify message within budget" is *unverified* (an error),
  never a guessed state.
- **`[hosts.serial]`** — open/revert/verify write command strings to a tty
  (direct fd + termios raw; baud-set is a tolerated no-op on ptys, so the
  same driver serves real ttys and the test simulator).

Verify is the non-negotiable part: every existing channel proves actual state
after apply and after revert, and these must too. A device whose management
surface cannot *report* state can still be driven, but the inventory must say
`verify = "none"` explicitly, and the open response surfaces that as a named
narrowing (decided; a `NARROWING:` line in the CLI output).

### 2b. Cooperative target: the firmware verifier (device-enforced TTL)

For devices we control the firmware of, Feature 2 upgrades this: "open"
delivers a signed capability token and the *device* enforces expiry. Strictly
stronger than bmc — the revert survives daemon death, network partition, and
operator absence, because it lives in the same silicon as the access.

---

## 3. Feature 2 — the firmware-side grant verifier

The centerpiece: the device holds the **daemon's public key** and accepts
capability tokens the daemon signs. Two Rust crates carry it (decided):

- **`lychgate-wire`** (`wire/`): `#![no_std]` codec for the token formats —
  the wire contract between the daemon, the device simulator, firmware, the
  AVR C library, and the FPGA testbench. The committed KAT vectors in
  `wire/vectors/` are the interop contract: a vector change is a breaking
  change by definition.
- **`lychgate-embed`** (`embed/`): the reusable `#![no_std]` device engine —
  all device-side rules (token acceptance, single-grant nonce semantics, seq
  anti-replay, uptime-anchored expiry, revocation, the line protocol) behind
  three small traits (`UptimeClock`, `SeqStore`, `Gate`). **Bring your own
  firmware**: any embedded Rust project (esp-hal, RP2040, STM32) adds these
  two crates with `default-features = false`, implements the three traits,
  and is a spec-conformant lychgate device. The reference ESP32-C3 firmware
  and the e2e device simulator are both thin consumers of this engine, so
  simulator-vs-firmware drift is structurally impossible above the HAL.

### Token: `lgcap.` / `lgrvk.`

`lgcap.<b64url(payload)>.<b64url(sig)>` — payload is a deterministic
CBOR-subset encoding (decided over postcard; frozen normatively at E6a) of:

```
{ ver, device_id: bstr16, grant_nonce: bstr16,
  capability: u32 (bitmask, device-defined), ttl_secs: u32, issued_seq: u64 }
```

`lgrvk.` (revocation) carries `{ ver, device_id, grant_nonce, issued_seq }`.

- **Two signature schemes, selected by `ver`** (decided): **v1 = Ed25519**
  (tier H and up), **v2 = P-256 ECDSA with a raw r||s 64-byte signature** —
  the ATECC608's native Verify format, so a tier-A AVR verifies v2 by hashing
  on-MCU and delegating the P-256 check to its secure element (§6). The
  signed message is the ASCII token prefix concatenated with the payload
  bytes (`b"lgcap." ++ payload`) — domain separation, so a revocation
  signature can never verify as a capability, pinned by cross-type and
  cross-version reject vectors.
- `device_id` binds the token to one device; a token for one device is noise
  to another.
- `grant_nonce` is fresh per grant; the device remembers the nonce of its
  *current* grant only. Same nonce re-presented → idempotent (re-delivery is
  fine); new nonce while a grant is open → refused (per-host single-grant,
  same as the daemon's model).
- `issued_seq` is a monotonic counter from the daemon, persisted device-side
  (flash record, or an SE monotonic counter). A token with `seq <= stored` is
  refused — **the anti-replay**: a captured token is dead once superseded.
- **No absolute timestamps anywhere.** The device has no trusted wall clock.

### Time model (the crux)

TTL anchors at *token acceptance* on the device's **uptime clock**. Expiry =
accept_uptime + ttl_secs. Consequences, all deliberate:

- **Reboot loses the anchor → the grant closes.** The device boots into the
  reverted state unconditionally, before any protocol handling; grant state
  is held in RAM only (the seq counter persists — it is anti-replay, not
  grant state). This is the embedded dead-man: the default state *is*
  reverted, and only live RAM holds it open.
- Renewal = the daemon issues a fresh token (new seq, same nonce, new ttl);
  the device re-anchors. The daemon still applies the 24h-cap/final-window
  policy — the device verifies and anchors; **policy stays server-side**. The
  device bounds `ttl_secs` (refuses > 24h) as defense in depth; the wire
  format deliberately *parses* a larger value (a pinned vector proves it), so
  every port agrees policy lives in the consumer.
- Clock skew is bounded by crystal tolerance (~±50 ppm ≈ ±4 s/day) — noise
  against break-glass TTLs.

### Close and revert

`close` delivers a signed `lgrvk.` revocation; the device reverts immediately
and bumps seq. Delivery is best-effort (the device may be unreachable); the
TTL is the guarantee, early close is the courtesy — exactly the
daemon/dead-man split of the ssh channel, with the roles swapped.

### Transport and daemon integration

The token is transport-agnostic bytes (< 256 B; `MAX_TOKEN_LEN` is exported).
A `device` channel (`[hosts.device]`) names one of the §2a transports to carry
a line protocol (TOK/RVK/STAT — frozen normatively at E6a); the channel driver
delivers tokens and reads back the device's state report; the *device*
enforces. State reports are transport-echoed in v1 (signed device state
reports are named future work — the narrowing is documented). The daemon's
signing key lives in the inventory's `[signing]` table and loads through the
same startup path as other secrets, so TPM-sealing it comes free.

---

## 4. Feature 4 — IoT device as an approval factor

**The `tpm` kind already speaks secure-element.** `lgtpm.` verification is
deliberately *plain P-256 ECDSA over the challenge* — no TPM structures in the
verify path. An **ATECC608** signs P-256 with a non-exportable key. An
**ESP32's DS peripheral** signs with an eFuse-wrapped key. Both mint valid
`lgtpm.` tokens **with zero changes to core or the daemon.** The work is
tooling and ceremony, not engine:

- Registration and challenge signing go through the device's serial protocol
  (`SE-PUBKEY?`, `SE-SIGN <challenge>`), with `tools/se-register.sh` printing
  the ready-to-paste `[[approval.authenticator]] kind = "tpm"` block. The
  trust boundary is which key signed, never which wire carried it (the MCP
  lesson) — the engine already only trusts the signature.
- **Kind naming (decided): document, don't fork.** `kind = "tpm"` means "a
  non-exportable P-256 signer"; TPM 2.0, ATECC608, and the ESP32 DS
  peripheral are instances. A `p256` alias is deferred until someone actually
  asks.
- **User presence**: a bare auto-signing device is a *possession* factor and
  weight should reflect that. An optional firmware button-press gate on
  `SE-SIGN` (press within N seconds) upgrades it toward a presence factor.
  The inventory cannot see the difference; the runbook must state which the
  device implements — name what a factor does not prove.

Use cases: "the rack's own gateway must co-sign entry to the rack", "opening
the lab door requires sysadmin + the lab's fixture box", geofencing-by-silicon
(the factor only exists inside the building).

---

## 5. Feature 3 + "more secure high-end MCUs" — the hardening profile

For tier H devices acting as verifier, factor, or gate, a documented
**hardening profile** (finalized at E6b, ceremonies included), in ascending
strength:

1. **Key storage.** Never a key in plain flash. In order of preference:
   ATECC608/SE050 secure element (generate *in situ*, export the public half
   only) → ESP32 DS peripheral (HMAC-eFuse-wrapped key, CPU never sees
   plaintext) → encrypted NVS as the floor.
2. **Secure boot** (ESP32 Secure Boot v2 or equivalents): the device only
   runs signed firmware, so the verifier and the daemon pubkey it embeds
   can't be swapped by flash access.
3. **Flash encryption**: captured flash reveals no configuration or (floor
   case) key material.
4. **Anti-rollback**: eFuse-versioned firmware; the SE monotonic counter
   backs `issued_seq` so token replay survives even a full flash restore.
5. **Provisioning ceremony** (runbook-style, E6b): generate the device key in
   the SE at enrollment, verify the full sign/verify round trip, and burn
   eFuses / lock zones **last** — they are one-way, so the ceremony orders
   them after everything is verified working, with a checkpoint before each
   burn.

The daemon-side complement: the inventory records the hardening class per
device authenticator (`hardening = "se" | "efuse" | "flash"`) and surfaces it,
so an operator weighting a device factor sees what actually holds its key.

---

## 6. "Easier signing for low-end devices" — the tier-A (classic AVR) strategy

An ATmega328 has 2 KB RAM / 32 KB flash and no hardware crypto: Ed25519/P-256
in software is seconds-per-op and most of the flash. **Correction to the
original sketch** (which claimed the SE could verify lgcap's Ed25519): the
ATECC608 verifies **P-256 only** — that is precisely why lgcap **v2** exists
(decided). The sanctioned paths:

**Path 1 (preferred): delegate to an ATECC608 over I²C.** The crypto happens
in the $1 chip; the AVR does I²C framing (~2 KB of code, milliseconds). An Uno
with a CryptoAuth breakout is a full-strength P-256 approval factor (§4) *and*
a full lgcap **v2** verifier: the AVR computes SHA-256 of the signed message
(fits comfortably) and the SE's Verify command checks the raw r||s signature.
Deliverable: the `avr/lychgate-se` C library (I²C framing + grant logic +
token decode, sharing the same committed KAT vectors as the Rust crates) plus
the wiring/provisioning appendix.

**Path 2 (fallback, no add-on hardware): the symmetric `hmac` authenticator
kind.** `lghmac.<b64url(HMAC-SHA256(secret, challenge))>` — SHA-256 costs
~kilobytes and ~ms on AVR. A real engine kind, honest about what it is:
symmetric (the daemon holds the same secret in a secret-file, sealable by
`--tpm-unseal`; compromise of that file forges the factor — documented, and
priced at low weight composed with an asymmetric human factor, the password
kind's positioning). Challenge-bound, so no ledger. Ed25519 (lgcap v1) on AVR
stays rejected: seconds of blocking compute, flash-dominating code, plaintext
key in unprotected flash — every property worse than paths 1–2.

---

## 7. Feature 5 — device as access mechanism

The inversion: the device isn't what you break into, it's what does the
breaking-in. The grant's channel drives an actuator:

- **Smart PDU / relay**: open = energize the console server / KVM outlet;
  revert = de-energize. Verify reads back relay state *and*, where a sensor
  exists, the actual load — "switch commanded" vs "load powered" are two
  oracles, take both (`current_sense = true` promises the second; a state
  report missing it is then an error).
- **Door / cabinet controller**: open = unlock for TTL; verify = the lock's
  position sensor, not the command echo.
- **Hardware interlock**: open = close the relay that physically enables a
  programming header / JTAG line on some *other* device.

Design points:

- Built on the cooperative-target verifier, not the dumb drivers: an actuator
  whose fail-state matters must enforce its own TTL and boot into the safe
  state.
- **Fail-state is per-device policy and lives in inventory** (decided
  vocabulary: `fail_state = "energized" | "de-energized"` — explicit words,
  not a site-relative "safe"): a server-power relay should fail *energized*
  (don't hard-down a machine because lychgate lost power); a door must fail
  *locked*. The one place "fail-closed" needs a per-site definition, made as
  an explicit, named choice — and checked: the device reports its configured
  fail-state, and drift from the inventory's declaration is a loud error.
- **Drill mode is the killer feature.** A relay that has stopped actuating is
  precisely the silent revert-path failure drills exist to catch. `drill =
  true` on a canary outlet with current-sense verify gives a standing
  hardware oracle: cron proves the physical revert fires, weekly, forever.

---

## 8. FPGAs

Three roles, mirroring the device roles, plus one property no MCU can offer.

**8a. FPGA as target.** "Open" gates reconfiguration/debug: enable the JTAG
or configuration port for TTL, or hot-load a debug bitstream. Mechanically
this is Feature 2 with the verifier in either a management CPU next to the
fabric (then it's tier H again), or the fabric itself:

**8b. Verifier in fabric.** *Soft core (decided):* picorv32 (pure Verilog, no
Scala toolchain, ~1–2k LUT + BRAM) running the same `lychgate-wire` verifier
`no_std` binary — same code, same KATs. Pure-RTL Ed25519/ECDSA verify is
rejected by default: a large, hard-to-audit core with a bespoke KAT story.
Key storage: bitstream encryption + eFuse keys on modern parts; PUF keys are
research-grade future work. Bitstream authentication plays the secure-boot
role.

**8c. FPGA as access mechanism — the unique property.** In fabric, the TTL
countdown and the gate are *the same hardware*: a counter clocked from the
board oscillator whose enable line (`gate_en = |counter`) is combinational on
the counter with no state of its own. No software — not even the soft core —
can hold the gate open past expiry, because there is no instruction stream
between the counter and the enable; the core can only *load* the counter
(after verifying a token) and *clear* it. A revert guarantee stated in gates,
small enough to review exhaustively and to **formally verify** (SymbiYosys:
safety `!(gate_en && counter == 0)` by k-induction, plus a cover observing
the drop — and a committed broken variant proving the formal harness itself
fails when it should: the oracle self-test, in gates).

**8d. FPGA as factor** falls out of 8b: the soft core + an SE on a PMOD signs
challenges like any tier-H device.

---

## 9. Testing story (per the house ethic)

Every tier needs an oracle that has been observed failing; hardware being
awkward to CI is a design input, not an excuse.

- **Shared KATs as the interop contract.** `wire/vectors/*.kat` (CAVP-style
  flat text — trivially parsed from Rust, C, and a Python testbench
  generator) are consumed by the wire/embed crate tests, the AVR C test
  binary, and the FPGA simulation harness. A port that passes the vectors
  speaks the protocol.
- **The e2e battery runs a host device simulator** (decided over QEMU):
  `lychgate-devsim`, a workspace binary running the *real* `lychgate-embed`
  engine and `lychgate-wire` verify over a PTY, with a control FIFO for
  nemesis moves (reboot, replay, corrupt-replay, stick-relay) and a
  greppable state file — the redfish-mock pattern, deterministic on both
  guests, with `--time-scale` so TTL-expiry oracles run in seconds.
- **Reboot-closes-the-grant is a first-class test**: open, reboot the sim,
  assert the device state reverted *and* the daemon observes the loss (two
  oracles), like the tunnel Lost path.
- **Replay/rollback tests**: an old token after a newer seq → refused; the
  oracle self-tested by breaking the seq check and watching the test catch
  it.
- **HIL (hardware-in-the-loop) manual tier**: the owner's real ESP32 +
  ATECC608 (+ relay board later), exercised by `e2e/embedded-hardware.sh` —
  the fido2-hardware.sh pattern: not in the default battery, named in the
  source-as-data manual vocabulary, documented in TESTING with *what the sim
  tier does not prove*: crystal drift, brown-out behavior, flash wear, real
  I²C, real GPIO timing.
- **FPGA**: the counter/gate RTL gets an iverilog testbench + the formal
  cover; the soft-core tier gets a verilator harness fed by the same KAT
  vectors. Fabric-on-real-hardware is manual-tier (an iCE40 board is $40).

---

## 10. Milestones (tracked in ROADMAP.md)

| # | Deliverable |
|---|-------------|
| E0 | this document into the repo |
| E1 | armv7 release target (arm64 already ships) |
| E2 | generic channel drivers: http, mqtt, serial + verify-or-named-narrowing |
| E3 | `lychgate-wire`: lgcap/lgrvk v1+v2 codec + KAT vectors |
| E4 | device channel + `lychgate-embed` engine + devsim e2e + ESP32-C3 reference firmware + HIL |
| E5 | SE tooling: ATECC608 layer, se-register, p256der |
| E6 | normative wire/protocol spec (E6a) + hardening profile & ceremonies (E6b) |
| E7 | `lghmac.` kind + the AVR C library |
| E8 | actuator channel + fail_state policy + hardware drill |
| E9 | FPGA: gate RTL + formal (M1), picorv32 soft core (M2), iCE40 build (M3) |

## 11. NORMATIVE: the wire contract (E6a)

This section is normative. The committed vectors in `wire/vectors/*.kat`
are the machine-checkable form of it; a change to either is a breaking
protocol change. `lychgate-wire` implements everything here for both ends.

### 11.1 Token grammar

```
lgcap.<base64url-nopad(payload)>.<base64url-nopad(signature)>
lgrvk.<base64url-nopad(payload)>.<base64url-nopad(signature)>
```

The signature covers the ASCII prefix concatenated with the raw payload
bytes (`b"lgcap." ++ payload`) — domain separation, so a revocation
signature can never verify as a capability. Signatures are 64 bytes in both
schemes. Tokens never exceed `MAX_TOKEN_LEN` (192 bytes).

### 11.2 Payload encoding

RFC 8949 deterministic CBOR, restricted to: definite lengths only,
minimal-width unsigned integers, byte strings, and one top-level map with
unsigned-integer keys in strictly ascending order. Every deviation —
non-minimal integers, out-of-order/duplicate/unknown keys, indefinite
lengths, wrong byte-string lengths, trailing bytes — is refused with a
named reason. Each payload has exactly one valid encoding.

Capability (map of 6): `0: ver (uint)`, `1: device_id (bstr, exactly 16)`,
`2: grant_nonce (bstr, exactly 16)`, `3: capability (uint ≤ u32)`,
`4: ttl_secs (uint ≤ u32)`, `5: issued_seq (uint ≤ u64)`.
Revocation (map of 4): `0: ver`, `1: device_id`, `2: grant_nonce`,
`3: issued_seq`.

`ver = 1`: Ed25519 (RFC 8032). `ver = 2`: ECDSA P-256 over SHA-256 of the
signed message, signature as raw `r || s` (the ATECC608's native Verify
format). Any other ver is refused. A `ttl_secs` above `MAX_TTL_SECS`
(86400) **parses** — the wire format is policy-free; the device refuses it
and the daemon never issues it (`ttl_bound.kat` pins this so every port
agrees where policy lives).

### 11.3 The device line protocol

Newline-delimited ASCII; one command, one reply. Both directions are
implemented once in `lychgate_wire::line` (daemon renders commands/parses
replies; the engine parses commands/renders replies). Unknown commands,
replies, and STATE trailers are refused — a newer dialect must never be
half-understood.

```
daemon -> device                 device -> daemon
TOK <lgcap-token>                ACK <nonce-hex32> <remaining_secs> | NAK <reason>
RVK <lgrvk-token>                ACK closed                         | NAK <reason>
STAT                             STATE open <nonce-hex32> <remaining_secs> seq=<n> [trailers]
                                 STATE closed seq=<n> [trailers]
SE-PUBKEY?                       PUBKEY <hex>                       | NAK <reason>
SE-SIGN <challenge>              SIG <lgtpm-token>                  | NAK <reason>
```

Trailers: `load=on|off`, `fail=energized|de-energized`,
`reason=revert|expiry|boot`. `seq=` is mandatory in every STATE. Pinned
examples (also the wire test suite's KAT):

```
TOK lgcap.AA.BB
ACK a0a1a2a3a4a5a6a7a8a9aaabacadaeaf 900
STATE open a0a1a2a3a4a5a6a7a8a9aaabacadaeaf 887 seq=42 load=on fail=energized
STATE closed seq=7 reason=boot
```

NAK reason words the engine emits: `bad-token` (signature/structure),
`wrong-alg` (ver/key mismatch), `wrong-device`, `replay` (seq did not
advance), `busy` (a different grant is open), `ttl` (over the cap),
`store-failed` (the seq mark could not be made durable — fail closed),
`wrong-grant` (a fresh revocation naming a grant not held), `bad-command`,
`unsupported`.

### 11.4 Engine semantics (what a conformant device does)

- Boot drives the gate closed before any protocol handling; grant state is
  RAM-only. **A reboot closes the grant.**
- The TTL anchors at token acceptance on the device's monotonic uptime
  clock; expiry is a property of observation and drops the gate.
- `issued_seq` must strictly advance past the durable mark, which is
  persisted BEFORE the grant takes effect. Redelivery of the exact current
  token (same nonce, seq equal to the mark) is re-acknowledged WITHOUT
  re-anchoring; a same-nonce higher-seq token is a renewal and re-anchors;
  a new nonce while open is `busy`.
- A stale revocation is dead by seq ordering; a fresh one naming a grant
  the device does not hold is `wrong-grant`.

### 11.5 Bring your own firmware

Any embedded Rust project is four steps from being a conformant device:

1. depend on `lychgate-wire` and `lychgate-embed`, both with
   `default-features = false`;
2. implement `UptimeClock` (a monotonic ms counter), `SeqStore` (a durable
   u64 — flash, NVS, an SE monotonic counter; `store` must be
   write-through), and `Gate` (the GPIO/relay/port-enable access flows
   through);
3. construct `DeviceEngine::new(device_id, TrustRoot::..., clock, seq,
   gate)` at boot;
4. feed inbound lines to `handle_line` and call `tick()` from the main
   loop.

The engine owns every rule in §11.4; the e2e simulator (`devsim/`) and the
reference ESP32-C3 firmware are both thin wrappers over it, and the
committed KAT vectors are the cross-language contract for non-Rust ports.

## 12. Decisions (resolved)

1. **Token payload encoding** — deterministic CBOR subset (portability of the
   C/FPGA ports and language-neutral vectors beat postcard's size edge).
2. **Signature schemes** — v1 Ed25519 *and* v2 P-256 (raw r||s) from day one,
   selected by the payload's `ver`; v2 exists so tier-A devices verify via
   the ATECC608 (owner decision).
3. **Kind naming** — keep `kind = "tpm"`, documented as "non-exportable P-256
   signer"; no `p256` alias until demanded.
4. **Device state reporting** — transport-echoed in v1; signed state reports
   are named future work (the narrowing is documented where it applies).
5. **MQTT broker trust** — signatures are the boundary (the MCP lesson); TLS
   client-cert is defense in depth; password broker auth is refused at load
   (argv leak).
6. **Fail-state vocabulary** — explicit `"energized" | "de-energized"`, per
   device, drift-checked against the device's own report.
7. **e2e device testing** — host device simulator running the real engine;
   QEMU/Renode rejected as a heavy, unpackaged dependency.
8. **hmac kind** — built (E7a), positioned honestly at low weight.
