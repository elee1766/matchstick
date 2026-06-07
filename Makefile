PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
SYSCONFDIR ?= /etc
SHAREDIR   ?= $(PREFIX)/share/matchstick
DESTDIR    ?=

NIM        ?= nim
NIMFLAGS   ?= -d:release

BIN        = matchstick
SRC        = src/matchstick.nim

.PHONY: all build install uninstall clean test

all: build

build:
	nimble build -d:release

install: build
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	install -d $(DESTDIR)$(SYSCONFDIR)/matchstick
	install -d $(DESTDIR)$(SHAREDIR)/examples
	install -m 644 contrib/examples/*.lua $(DESTDIR)$(SHAREDIR)/examples/
	install -d $(DESTDIR)$(SHAREDIR)/luals
	install -m 644 contrib/luals/matchstick.lua $(DESTDIR)$(SHAREDIR)/luals/

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)
	rm -rf $(DESTDIR)$(SHAREDIR)

clean:
	rm -f $(BIN)
	rm -rf nimcache/
	rm -f tests/test_*[!.nim]
	rm -f tests/integration/test_*[!.nim]

test: build
	nimble test
