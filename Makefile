# BackMaster - host intrusion prevention for Arch Linux
# Plain GNU make: no cmake/meson required.

PREFIX      ?= /usr/local
SYSCONFDIR  ?= /etc
UNITDIR     ?= /usr/lib/systemd

CXX         ?= g++
CXXSTD      := -std=c++23
WARN        := -Wall -Wextra -Wno-unused-parameter -Wshadow
OPT         ?= -O2 -g
HARDEN      := -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
LDHARDEN    := -pie -Wl,-z,relro,-z,now

CXXFLAGS    += $(CXXSTD) $(WARN) $(OPT) $(HARDEN) -Iinclude -pthread
LDFLAGS     += $(LDHARDEN) -pthread

GTK_CFLAGS  := $(shell pkg-config --cflags gtk4)
GTK_LIBS    := $(shell pkg-config --libs gtk4)

BUILD       := build
BIN         := $(BUILD)/bin

COMMON_SRC  := $(wildcard src/common/*.cpp)
DAEMON_SRC  := $(wildcard src/daemon/*.cpp)
AGENT_SRC   := $(wildcard src/agent/*.cpp)
CTL_SRC     := $(wildcard src/ctl/*.cpp)

COMMON_OBJ  := $(COMMON_SRC:%.cpp=$(BUILD)/%.o)
DAEMON_OBJ  := $(DAEMON_SRC:%.cpp=$(BUILD)/%.o)
AGENT_OBJ   := $(AGENT_SRC:%.cpp=$(BUILD)/%.gtk.o)
CTL_OBJ     := $(CTL_SRC:%.cpp=$(BUILD)/%.o)

TARGETS     := $(BIN)/backmasterd $(BIN)/backmaster-agent $(BIN)/backmasterctl

.PHONY: all clean install uninstall
all: $(TARGETS)

$(BIN)/backmasterd: $(DAEMON_OBJ) $(COMMON_OBJ)
	@mkdir -p $(@D)
	$(CXX) $^ -o $@ $(LDFLAGS)

$(BIN)/backmasterctl: $(CTL_OBJ) $(COMMON_OBJ)
	@mkdir -p $(@D)
	$(CXX) $^ -o $@ $(LDFLAGS)

$(BIN)/backmaster-agent: $(AGENT_OBJ) $(COMMON_OBJ)
	@mkdir -p $(@D)
	$(CXX) $^ -o $@ $(LDFLAGS) $(GTK_LIBS)

$(BUILD)/%.gtk.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(GTK_CFLAGS) -MMD -MP -c $< -o $@

$(BUILD)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)

clean:
	rm -rf $(BUILD)

# Config and blocklists are never overwritten: an upgrade must not discard the
# user's exclusions.
install: all
	install -Dm755 $(BIN)/backmasterd       $(DESTDIR)$(PREFIX)/bin/backmasterd
	install -Dm755 $(BIN)/backmasterctl     $(DESTDIR)$(PREFIX)/bin/backmasterctl
	install -Dm755 $(BIN)/backmaster-agent  $(DESTDIR)$(PREFIX)/bin/backmaster-agent
	install -Dm755 tools/update-blocklists.sh $(DESTDIR)$(PREFIX)/bin/backmaster-update-blocklists
	install -dm755 $(DESTDIR)$(SYSCONFDIR)/backmaster/blocklists
	@if [ -f $(DESTDIR)$(SYSCONFDIR)/backmaster/backmaster.conf ]; then \
	    echo "  keeping existing backmaster.conf (new version at backmaster.conf.new)"; \
	    install -Dm644 data/backmaster.conf $(DESTDIR)$(SYSCONFDIR)/backmaster/backmaster.conf.new; \
	else \
	    install -Dm644 data/backmaster.conf $(DESTDIR)$(SYSCONFDIR)/backmaster/backmaster.conf; \
	fi
	@for f in data/blocklists/*.txt; do \
	    b=$$(basename $$f); \
	    if [ -f $(DESTDIR)$(SYSCONFDIR)/backmaster/blocklists/$$b ]; then \
	        echo "  keeping existing blocklists/$$b"; \
	    else \
	        install -Dm644 $$f $(DESTDIR)$(SYSCONFDIR)/backmaster/blocklists/$$b; \
	    fi; \
	done
	install -Dm644 systemd/backmasterd.service $(DESTDIR)$(UNITDIR)/system/backmasterd.service
	install -Dm644 systemd/backmaster-agent.service $(DESTDIR)$(UNITDIR)/user/backmaster-agent.service
	install -Dm644 data/backmaster-agent.desktop $(DESTDIR)$(PREFIX)/share/applications/backmaster-agent.desktop
	install -Dm644 README.md $(DESTDIR)$(PREFIX)/share/doc/backmaster/README.md
	@echo
	@echo "Installed. Next:"
	@echo "  sudo systemctl daemon-reload && sudo systemctl enable --now backmasterd"
	@echo "  systemctl --user enable --now backmaster-agent"

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/backmasterd $(DESTDIR)$(PREFIX)/bin/backmasterctl \
	      $(DESTDIR)$(PREFIX)/bin/backmaster-agent \
	      $(DESTDIR)$(PREFIX)/bin/backmaster-update-blocklists \
	      $(DESTDIR)$(UNITDIR)/system/backmasterd.service \
	      $(DESTDIR)$(UNITDIR)/user/backmaster-agent.service \
	      $(DESTDIR)$(PREFIX)/share/applications/backmaster-agent.desktop
	@echo "Left in place: $(SYSCONFDIR)/backmaster and /var/lib/backmaster"
