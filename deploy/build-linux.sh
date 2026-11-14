#!/bin/sh
# Produces dist/mail_sloth, a Linux x86_64 binary for the server.
#
# Three ways, tried in order:
#   1. docker         compiles natively in a Debian 12 container and cross-links
#                     for x86_64 with Debian's cross gcc, so it is fast on an
#                     Apple Silicon Mac too (no emulation) and links against the
#                     server's glibc 2.36
#   2. cargo zigbuild cross-compiles from this machine (brew install zig; cargo install cargo-zigbuild)
#   3. gh             downloads the binary the GitHub release workflow built for the latest tag
set -eu
cd "$(dirname "$0")/.."
mkdir -p dist
# Docker Desktop puts its CLI here and not always on PATH.
PATH="$PATH:$HOME/.docker/bin"

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "== building in docker"
    docker run --rm \
        -v "$PWD":/src \
        -v mail_sloth_cargo_registry:/usr/local/cargo/registry \
        -v mail_sloth_target:/src/target \
        -w /src \
        -e CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
        -e CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
        -e AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar \
        rust:1-slim-bookworm \
        sh -c 'apt-get update -qq >/dev/null \
            && apt-get install -y -qq pkg-config gcc-x86-64-linux-gnu libc6-dev-amd64-cross >/dev/null \
            && rustup target add x86_64-unknown-linux-gnu >/dev/null \
            && cargo build --release --locked --target x86_64-unknown-linux-gnu \
            && install -m 755 target/x86_64-unknown-linux-gnu/release/mail_sloth /src/dist/mail_sloth'
elif cargo zigbuild --version >/dev/null 2>&1; then
    echo "== cross-compiling with cargo zigbuild"
    rustup target add x86_64-unknown-linux-gnu >/dev/null
    # glibc 2.36 is Debian 12's.
    cargo zigbuild --release --locked --target x86_64-unknown-linux-gnu.2.36
    install -m 755 target/x86_64-unknown-linux-gnu/release/mail_sloth dist/mail_sloth
elif command -v gh >/dev/null 2>&1; then
    TAG="${MAIL_SLOTH_TAG:-$(gh release list --limit 1 --json tagName --jq '.[0].tagName')}"
    echo "== downloading release $TAG from GitHub (push a v* tag to make one)"
    gh release download "$TAG" --pattern mail_sloth --output dist/mail_sloth --clobber
    chmod 755 dist/mail_sloth
else
    echo "no way to build a Linux binary: install docker, or cargo-zigbuild, or the gh CLI" >&2
    exit 1
fi
file dist/mail_sloth 2>/dev/null || true
ls -la dist/mail_sloth
