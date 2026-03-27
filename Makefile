# Makefile for quickstart compatibility.
#
# The stellar/quickstart Dockerfile expects a repo that builds via
# `make -j $(nproc)` and installs via `make install`. This Makefile
# wraps Cargo so henyey can be used as a drop-in `core` dependency
# in quickstart images.

PREFIX ?= /usr/local

.PHONY: all install clean quickstart-build quickstart-local quickstart-logs quickstart-stop

all:
	cargo build --release -p henyey

install: all
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 target/release/henyey $(DESTDIR)$(PREFIX)/bin/stellar-core

clean:
	cargo clean

# ── Local quickstart testing ─────────────────────────────────────────────────

quickstart-build: all
	docker build -f Dockerfile.quickstart-local -t henyey-quickstart:local .

quickstart-local:
	./scripts/quickstart-local.sh

quickstart-logs:
	docker logs -f henyey-quickstart

quickstart-stop:
	docker stop henyey-quickstart && docker rm henyey-quickstart
