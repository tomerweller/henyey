#!/bin/sh
# Install Rust for quickstart compatibility.
#
# The stellar/quickstart Dockerfile runs ./install-rust.sh in a bare
# ubuntu:24.04 container that has no Rust toolchain. This script installs
# Rust via the official rustup installer so that `cargo` is available for
# the subsequent `make` step.
#
# The Dockerfile sets ENV PATH "/root/.cargo/bin:$PATH" after this script
# runs, making cargo available to later RUN commands.

# Skip if rustup (and therefore cargo) is already available.
rustup --version >/dev/null 2>&1 && exit 0

set -eu
set -x

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain stable
