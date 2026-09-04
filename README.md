# lychgate

A break-glass emergency access orchestrator for SSH, iDRAC, and VNC.

A lychgate is the roofed churchyard gate where the dead are received. This one
is the gate you open when a production server is the corpse: it grants
temporary root SSH posture, BMC accounts, authorized_keys entries, and VNC
console access as a single revocable unit — and slams all of it shut on a
timer whether or not the thing that opened it is still alive.

## Why

Emergency remediation — human or AI-driven — needs access that ordinarily must
not exist: root over SSH, an enabled iDRAC account, a console. Provisioning
that by hand at 03:00 is slow; leaving it standing is worse. lychgate models
the whole bundle as a *grant* with a hard TTL: opening is deliberate and
audited, closing is idempotent, and expiry is fail-closed — a grant observed
at or past its expiry instant is expired, no daemon required to make it so.

Grant policy, by design:

- TTLs are capped at 24 hours. Break-glass access is never open-ended.
- Renewal is only accepted inside the final 2 hours before expiry, and the new
  window is anchored at the renewal instant — time cannot be stockpiled early.
- An expired grant cannot be renewed. Reopening is always an explicit act.

## Status

This is a scaffold. The grant state machine, TTL policy, and inventory schema
are real and tested; no driver exists yet, so nothing opens or closes access
on an actual host. See [TESTING.md](TESTING.md) for exactly what is and is not
proven, [docs/DESIGN.md](docs/DESIGN.md) for the architecture, and
[docs/ROADMAP.md](docs/ROADMAP.md) for the milestone plan of record.

## Components

- `lychgate` — the operator CLI. Builds for FreeBSD, Linux, and Windows.
- `lychgated` — the control-plane daemon. FreeBSD and Linux only. Today it
  validates an inventory file and exits; it says so when it runs.
- `lychgate-core` — the grant/TTL/inventory library both binaries share.

## Installation

### From source

Requires Rust 1.97+ and Cargo.

```sh
cargo build --release --workspace
```

Binaries land at `target/release/lychgate` and `target/release/lychgated`.

### Prebuilt binaries

Tagged releases upload binaries for FreeBSD and Linux (amd64 and aarch64) and
a Windows client to the repository's Downloads page, each with a `.sha256`
checksum sidecar.

## Usage

```sh
lychgated --inventory /usr/local/etc/lychgate/inventory.toml
```

Validates the inventory and reports host and channel counts. The control plane
is not yet implemented; the daemon says so and exits.

```sh
lychgate open --host db-01 --ttl 4h
lychgate close --host db-01
lychgate status
```

TTLs take the forms `90s`, `15m`, `2h`; a unit is required. `open` enforces the
24-hour cap before anything else happens. All three subcommands currently fail
with an honest error: there is no daemon transport yet.

An inventory names each host, its address, its operating system (`freebsd` or
`linux`), and the access channels lychgate may drive for it:

```toml
[[hosts]]
name = "db-01"
address = "10.0.4.11"
os = "freebsd"
channels = ["ssh", "authorized-keys", "bmc"]
```

## Testing

```sh
./tools/check.sh
```

runs every workstation-side phase (fmt, clippy with warnings denied, the test
suite, shell lint) and reports all failures rather than stopping at the first.
The project is a [reaper](https://github.com/calebpower/reaper) tenant:
`reaper test` runs the same battery on FreeBSD and Ubuntu guests. The testing
ethic, tier roadmap, and the claims each suite does *not* carry are recorded
in [TESTING.md](TESTING.md).

## License

BSD-2-Clause. Copyright (c) 2026 Axonibyte Innovations, LLC.
