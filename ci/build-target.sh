#!/usr/bin/env bash
# ci/build-target.sh  build lychgate release binaries for one target triple.
# Usage: bash ci/build-target.sh <target-triple>
# All per-target knowledge (linkers, toolchains, std availability, which
# crates ship there) lives here; bitbucket-pipelines.yml just dispatches.
set -euo pipefail

TARGET="${1:?usage: build-target.sh <target-triple>}"
export CARGO_HOME="${CARGO_HOME:-$BITBUCKET_CLONE_DIR/.cargo_cache}"

# Pinned: -Z build-std against a floating nightly breaks spontaneously and
# makes tag builds unreproducible. Bump deliberately, together with the image
# pin in bitbucket-pipelines.yml and rust-version in Cargo.toml.
NIGHTLY="nightly-2026-08-01"

apt_install() {
    apt-get update
    apt-get install -y --no-install-recommends "$@"
}

# Zig ships FreeBSD libc headers, letting cargo-zigbuild cross-link FreeBSD
# binaries from Linux with no docker and no sysroot images.
install_zigbuild() {
    apt_install python3-pip
    pip3 install --break-system-packages cargo-zigbuild
}

build() { # build [extra cargo args...]  tries offline first, falls back to online
    cargo build --target "$TARGET" --release --locked "$@" --offline ||
    cargo build --target "$TARGET" --release --locked "$@"
}

# The daemon drives sshd, authorized_keys and BMCs on unix hosts; on Windows
# only the operator client ships.
BINS=(lychgate lychgated)

case "$TARGET" in
    x86_64-unknown-linux-gnu)
        build --workspace
        ;;

    aarch64-unknown-linux-gnu)
        # libc6-dev-arm64-cross is only a Recommends of the gcc package, so
        # with --no-install-recommends it must be named explicitly — without
        # it the cross-gcc has no target libc headers/CRT.
        apt_install gcc-aarch64-linux-gnu libc6-dev-arm64-cross
        rustup target add "$TARGET"
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
        build --workspace
        ;;

    x86_64-unknown-freebsd)
        # Tier 2: prebuilt std exists; stable toolchain + zig linker.
        install_zigbuild
        rustup target add "$TARGET"
        cargo zigbuild --target "$TARGET" --release --locked --workspace
        ;;

    aarch64-unknown-freebsd)
        # Tier 3: no prebuilt std, so compile it with nightly -Z build-std.
        install_zigbuild
        rustup toolchain install "$NIGHTLY" --profile minimal --component rust-src
        cargo "+$NIGHTLY" zigbuild --target "$TARGET" --release --locked --workspace -Z build-std=std,panic_abort
        ;;

    x86_64-pc-windows-gnu)
        apt_install mingw-w64
        rustup target add "$TARGET"
        BINS=(lychgate)
        build -p lychgate
        ;;

    *)
        echo "unknown target: $TARGET" >&2
        exit 1
        ;;
esac

# --- package ---------------------------------------------------------------
VERSION=$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^version *= *"\([^"]*\)".*/\1/p;}' Cargo.toml)
test -n "$VERSION"
mkdir -p dist
for bin in "${BINS[@]}"; do
    if [[ "$TARGET" == *windows* ]]; then
        cp "target/$TARGET/release/${bin}.exe" "dist/${bin}-v${VERSION}-${TARGET}.exe"
    else
        cp "target/$TARGET/release/${bin}" "dist/${bin}-v${VERSION}-${TARGET}"
    fi
done
