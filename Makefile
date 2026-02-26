BINARY    := macos-dns-proxy
PLIST_SRC := com.local.macos-dns-proxy.plist
PLIST_DST := /Library/LaunchDaemons/com.local.macos-dns-proxy.plist
INSTALL_BIN := /usr/local/bin/$(BINARY)
LOG_FILE  := /var/log/macos-dns-proxy.log

.PHONY: build test clean install uninstall status logs

build:
	cargo build --release
	cp target/release/$(BINARY) ./$(BINARY)

test:
	cargo test

clean:
	cargo clean
	rm -f $(BINARY)

install: build
ifndef LISTEN
	@printf "Listen address (e.g., 192.168.99.1:53): "; \
	read LISTEN_ADDR; \
	if [ -z "$$LISTEN_ADDR" ]; then \
		echo "error: listen address is required"; \
		exit 1; \
	fi; \
	sed "s|LISTEN_ADDR|$$LISTEN_ADDR|g" $(PLIST_SRC) > /tmp/$(PLIST_SRC)
else
	@sed "s|LISTEN_ADDR|$(LISTEN)|g" $(PLIST_SRC) > /tmp/$(PLIST_SRC)
endif
	sudo cp $(BINARY) $(INSTALL_BIN)
	sudo chmod 755 $(INSTALL_BIN)
	sudo cp /tmp/$(PLIST_SRC) $(PLIST_DST)
	sudo chmod 644 $(PLIST_DST)
	sudo launchctl bootout system/com.local.macos-dns-proxy 2>/dev/null || true
	sudo launchctl bootstrap system $(PLIST_DST)
	@rm -f /tmp/$(PLIST_SRC)
	@echo ""
	@echo "$(BINARY) installed and running."
	@echo "  Binary:  $(INSTALL_BIN)"
	@echo "  Plist:   $(PLIST_DST)"
	@echo "  Log:     $(LOG_FILE)"
	@echo ""
	@echo "Verify with: sudo launchctl list | grep macos-dns-proxy"

uninstall:
	sudo launchctl bootout system/com.local.macos-dns-proxy 2>/dev/null || true
	sudo rm -f $(INSTALL_BIN)
	sudo rm -f $(PLIST_DST)
	@echo "$(BINARY) uninstalled."

status:
	@sudo launchctl list | grep macos-dns-proxy || echo "Service not found (not installed or not loaded)"

logs:
	@tail -f $(LOG_FILE)
