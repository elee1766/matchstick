PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
SYSCONFDIR ?= /etc
SHAREDIR   ?= $(PREFIX)/share/matchstick
DESTDIR    ?=

BIN        = matchstick

.PHONY: all build install uninstall clean test

all: build

# Always run nimble — it handles its own incremental compilation.
# The $(BIN) file target below is only for install's dependency check.
build:
	nimble build -d:release -y

# install depends on the binary file existing, not on build.
# This means `make` as user, then `sudo make install` won't rebuild as root.
install: $(BIN)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	install -m 755 msctl $(DESTDIR)$(BINDIR)/msctl
	install -d $(DESTDIR)$(SYSCONFDIR)/matchstick
	test -f $(DESTDIR)$(SYSCONFDIR)/matchstick/firewall.lua.example || \
		install -m 644 contrib/firewall.lua.example $(DESTDIR)$(SYSCONFDIR)/matchstick/firewall.lua.example
	install -d $(DESTDIR)$(SHAREDIR)/examples
	install -m 644 contrib/examples/*.lua $(DESTDIR)$(SHAREDIR)/examples/
	install -d $(DESTDIR)$(SHAREDIR)/luals
	install -m 644 contrib/luals/matchstick.lua $(DESTDIR)$(SHAREDIR)/luals/

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)
	rm -f $(DESTDIR)$(BINDIR)/msctl
	rm -rf $(DESTDIR)$(SHAREDIR)

clean:
	rm -f $(BIN)
	rm -rf nimcache/
	rm -f tests/test_*[!.nim]
	rm -f tests/integration/test_*[!.nim]

test: build
	nimble test
