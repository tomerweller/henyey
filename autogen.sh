#!/bin/sh
# No-op shim for quickstart compatibility.
# The stellar/quickstart Dockerfile runs ./autogen.sh unconditionally.
# Henyey uses Cargo and does not need autotools, so this script is a no-op.
exit 0
