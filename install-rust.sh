#!/bin/sh
# No-op shim for quickstart compatibility.
# The stellar/quickstart Dockerfile runs ./install-rust.sh unconditionally.
# Henyey's build environment already has Rust installed, so this script is a no-op.
exit 0
