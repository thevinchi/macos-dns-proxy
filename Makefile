BINARY    := macos-dns-proxy
PLIST_SRC := com.local.macos-dns-proxy.plist
PLIST_DST := /Library/LaunchDaemons/com.local.macos-dns-proxy.plist
INSTALL_BIN := /usr/local/bin/$(BINARY)
LOG_FILE  := /var/log/macos-dns-proxy.log
BUILD_DIR := /tmp/$(BINARY)-build

.PHONY: build test test-cargo lint coverage clean install uninstall status logs

build:
	cargo build --release
	cp target/release/$(BINARY) ./$(BINARY)

test:
	@command -v cargo-nextest >/dev/null 2>&1 || { echo "Installing cargo-nextest..."; cargo install cargo-nextest --locked; }
	cargo nextest run

lint:
	cargo fmt --check
	cargo clippy -- -D warnings

coverage:
	cargo llvm-cov nextest --html --output-dir coverage
	@echo "Coverage report: coverage/html/index.html"

clean:
	cargo clean
	rm -f $(BINARY)
	rm -rf coverage

install:
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
	CARGO_TARGET_DIR=$(BUILD_DIR) cargo build --release
	sudo cp $(BUILD_DIR)/release/$(BINARY) $(INSTALL_BIN)
	sudo chmod 755 $(INSTALL_BIN)
	sudo cp /tmp/$(PLIST_SRC) $(PLIST_DST)
	sudo chmod 644 $(PLIST_DST)
	sudo launchctl bootout system/com.local.macos-dns-proxy 2>/dev/null || true
	sudo launchctl bootstrap system $(PLIST_DST)
	@rm -f /tmp/$(PLIST_SRC)
	@rm -rf $(BUILD_DIR)
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
