PREFIX ?= /usr/local
DESTDIR ?=

.PHONY: all install

all:
	cargo build --release -p henyey

install: all
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 target/release/henyey $(DESTDIR)$(PREFIX)/bin/henyey
