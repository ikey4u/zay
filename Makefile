.PHONY: fmt build pkg macos.build-linux-x64 macos.build-for-window-x64 macos.build-for-macos-arm64 setup

CARGO_HOME_DIR = /tmp/cargo-tmp
REMAP = --remap-path-prefix=$(CARGO_HOME_DIR)=~ --remap-path-prefix=$(CURDIR)=.

DIST_DIR = dist
TARGET_MACOS_ARM64 = aarch64-apple-darwin
TARGET_LINUX_X64 = x86_64-unknown-linux-gnu
TARGET_WINDOWS_X64 = x86_64-pc-windows-gnu
BIN_MACOS_ARM64 = target/$(TARGET_MACOS_ARM64)/release/zay
BIN_LINUX_X64 = target/$(TARGET_LINUX_X64)/release/zay
BIN_WINDOWS_X64 = target/$(TARGET_WINDOWS_X64)/release/zay.exe
ZIP_MACOS_ARM64 = zay-macos-arm64.zip
ZIP_LINUX_X64 = zay-macos-linux-x64.zip
ZIP_WINDOWS_X64 = zay-windows-x64.zip

-include Makefile.local

setup:
	mkdir -p $(CARGO_HOME_DIR)
	ln -sf $(CARGO_HOME_DIR) $(HOME)/.cargo
	rustup target add x86_64-unknown-linux-gnu x86_64-pc-windows-gnu aarch64-apple-darwin

fmt:
	cargo +nightly fmt

build: setup
	CARGO_HOME=$(CARGO_HOME_DIR) RUSTFLAGS="$(REMAP)" cargo build --release

macos.build-linux-x64: setup
	CARGO_HOME=$(CARGO_HOME_DIR) RUSTFLAGS="$(REMAP)" cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.17

macos.build-for-window-x64: setup
	CARGO_HOME=$(CARGO_HOME_DIR) RUSTFLAGS="$(REMAP)" cargo zigbuild --release --target x86_64-pc-windows-gnu

macos.build-for-macos-arm64: setup
	CARGO_HOME=$(CARGO_HOME_DIR) RUSTFLAGS="$(REMAP)" cargo zigbuild --release --target aarch64-apple-darwin

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

# $(1) zip name under dist/, $(2) path to binary
define zip_binary
	rm -f $(DIST_DIR)/$(1)
	cd $(dir $(2)) && zip -j $(CURDIR)/$(DIST_DIR)/$(1) $(notdir $(2))
endef

pkg: macos.build-for-macos-arm64 macos.build-linux-x64 macos.build-for-window-x64 | $(DIST_DIR)
	$(call zip_binary,$(ZIP_MACOS_ARM64),$(BIN_MACOS_ARM64))
	$(call zip_binary,$(ZIP_LINUX_X64),$(BIN_LINUX_X64))
	$(call zip_binary,$(ZIP_WINDOWS_X64),$(BIN_WINDOWS_X64))
	@echo "packaged: $(DIST_DIR)/$(ZIP_MACOS_ARM64) $(DIST_DIR)/$(ZIP_LINUX_X64) $(DIST_DIR)/$(ZIP_WINDOWS_X64)"
