.PHONY: fmt build pkg cross-build macos.build-for-linux-x64 macos.build-for-windows-x64 macos.build-for-window-x64 macos.build-for-macos-arm64 setup setup-zig check-zig check-mingw

CARGO_HOME_DIR = /tmp/cargo-tmp
REMAP = --remap-path-prefix=$(CARGO_HOME_DIR)=~ --remap-path-prefix=$(CURDIR)=.
CARGO = CARGO_HOME=$(CARGO_HOME_DIR) RUSTFLAGS="$(REMAP)"
MINGW_DLLTOOL ?= x86_64-w64-mingw32-dlltool
MINGW_CC ?= x86_64-w64-mingw32-gcc
MINGW_AR ?= x86_64-w64-mingw32-ar
WINDOWS_CARGO = CARGO_HOME=$(CARGO_HOME_DIR) \
	CC_x86_64_pc_windows_gnu=$(MINGW_CC) \
	AR_x86_64_pc_windows_gnu=$(MINGW_AR) \
	RUSTFLAGS="$(REMAP) -C dlltool=$(MINGW_DLLTOOL)"

VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

DIST_DIR = dist
TARGET_MACOS_ARM64 = aarch64-apple-darwin
# zig/cargo-zigbuild glibc 2.17 ABI (CentOS 7+, old distros)
ZIG_LINUX_TARGET = x86_64-unknown-linux-gnu.2.17
# Artifact directory (no glibc suffix in path)
TARGET_LINUX_X64 = x86_64-unknown-linux-gnu
TARGET_WINDOWS_X64 = x86_64-pc-windows-gnu
BIN_MACOS_ARM64 = target/$(TARGET_MACOS_ARM64)/release/zay
BIN_LINUX_X64 = target/$(TARGET_LINUX_X64)/release/zay
BIN_WINDOWS_X64 = target/$(TARGET_WINDOWS_X64)/release/zay.exe
ZIP_MACOS_ARM64 = zay-macos-arm64-v$(VERSION).zip
ZIP_LINUX_X64 = zay-linux-x64-v$(VERSION).zip
ZIP_WINDOWS_X64 = zay-windows-x64-v$(VERSION).zip

-include Makefile.local

check-zig:
	@command -v zig >/dev/null || (echo "Install zig: https://ziglang.org/" >&2; exit 1)
	@command -v cargo-zigbuild >/dev/null || (echo "Install cargo-zigbuild: cargo install cargo-zigbuild" >&2; exit 1)

check-mingw:
	@command -v $(MINGW_DLLTOOL) >/dev/null || ( \
		echo "Missing $(MINGW_DLLTOOL), required for the Windows GNU target." >&2; \
		echo "Install it with: brew install mingw-w64" >&2; \
		echo "Or override MINGW_DLLTOOL=/path/to/dlltool." >&2; \
		exit 1; \
	)
	@command -v $(MINGW_CC) >/dev/null || ( \
		echo "Missing $(MINGW_CC), required for Windows C dependencies." >&2; \
		echo "Install it with: brew install mingw-w64" >&2; \
		echo "Or override MINGW_CC=/path/to/gcc." >&2; \
		exit 1; \
	)
	@command -v $(MINGW_AR) >/dev/null || ( \
		echo "Missing $(MINGW_AR), required for Windows C dependencies." >&2; \
		echo "Install it with: brew install mingw-w64" >&2; \
		echo "Or override MINGW_AR=/path/to/ar." >&2; \
		exit 1; \
	)

setup:
	mkdir -p $(CARGO_HOME_DIR)
	rustup target add x86_64-unknown-linux-gnu x86_64-pc-windows-gnu aarch64-apple-darwin
	@if $(CARGO) cargo fetch -q; then :; else \
		echo "repairing broken registry in $(CARGO_HOME_DIR)" >&2; \
		rm -rf $(CARGO_HOME_DIR)/registry; \
		$(CARGO) cargo fetch -q; \
	fi

setup-zig: setup check-zig

fmt:
	cargo +nightly fmt
	pnpm --dir webui exec biome format --write .

build: setup
	$(CARGO) cargo build --release

macos.build-for-linux-x64: setup-zig
	$(CARGO) cargo zigbuild --release --target $(ZIG_LINUX_TARGET)
	@test -f $(BIN_LINUX_X64) || (echo "missing $(BIN_LINUX_X64) (zig target $(ZIG_LINUX_TARGET))" >&2; exit 1)

macos.build-for-windows-x64: setup-zig check-mingw
	$(WINDOWS_CARGO) cargo zigbuild --release --target $(TARGET_WINDOWS_X64)
	@test -f $(BIN_WINDOWS_X64)

# Back-compat alias (typo in older docs/Makefile.local)
macos.build-for-window-x64: macos.build-for-windows-x64

macos.build-for-macos-arm64: setup
	$(CARGO) cargo build --release --target $(TARGET_MACOS_ARM64)
	@test -f $(BIN_MACOS_ARM64)

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

# $(1) zip name under dist/, $(2) path to binary
define zip_binary
	@test -f $(2) || (echo "missing binary: $(2)" >&2; exit 1)
	rm -f $(DIST_DIR)/$(1)
	cd $(dir $(2)) && zip -j $(CURDIR)/$(DIST_DIR)/$(1) $(notdir $(2))
endef

define zip_windows_binary
	@test -f $(2) || (echo "missing binary: $(2)" >&2; exit 1)
	rm -f $(DIST_DIR)/$(1)
	tmpdir=$$(mktemp -d); \
	cp $(2) "$$tmpdir/"; \
	packet_dll=$$(find target/$(TARGET_WINDOWS_X64)/release/build -type f -path '*/windows-runtime/Packet.dll' 2>/dev/null | head -1); \
	runtime_dir=$${packet_dll%/Packet.dll}; \
	if [ -z "$$packet_dll" ] || [ ! -f "$$runtime_dir/wintun.dll" ] || [ ! -f "$$runtime_dir/WinDivert64.sys" ]; then \
		echo "missing generated Windows runtime under target/$(TARGET_WINDOWS_X64)/release/build/*/out/windows-runtime" >&2; \
		rm -rf "$$tmpdir"; \
		exit 1; \
	fi; \
	for file in Packet.dll wintun.dll WinDivert64.sys; do \
		cp "$$runtime_dir/$$file" "$$tmpdir/"; \
	done; \
	cd "$$tmpdir" && zip -j "$(CURDIR)/$(DIST_DIR)/$(1)" *; \
	rm -rf "$$tmpdir"
endef

cross-build: pkg

# Sequential cross-builds (avoid parallel cargo/zig races); Linux uses glibc 2.17 via zig.
# Requires on macOS: zig, cargo-zigbuild (`cargo install cargo-zigbuild`), mingw-w64 (`brew install mingw-w64`).
pkg: check-zig check-mingw | $(DIST_DIR)
	$(MAKE) macos.build-for-macos-arm64
	$(MAKE) macos.build-for-linux-x64
	$(MAKE) macos.build-for-windows-x64
	$(call zip_binary,$(ZIP_MACOS_ARM64),$(BIN_MACOS_ARM64))
	$(call zip_binary,$(ZIP_LINUX_X64),$(BIN_LINUX_X64))
	$(call zip_windows_binary,$(ZIP_WINDOWS_X64),$(BIN_WINDOWS_X64))
	@echo "packaged (v$(VERSION)): $(DIST_DIR)/$(ZIP_MACOS_ARM64) $(DIST_DIR)/$(ZIP_LINUX_X64) $(DIST_DIR)/$(ZIP_WINDOWS_X64)"
