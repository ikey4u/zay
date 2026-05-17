.PHONY: fmt build macos.build-linux-x64 setup

CARGO_HOME_DIR = /tmp/cargo-tmp
REMAP = --remap-path-prefix=$(CARGO_HOME_DIR)=~ --remap-path-prefix=$(CURDIR)=.

-include Makefile.local

setup:
	mkdir -p $(CARGO_HOME_DIR)
	ln -sf $(CARGO_HOME_DIR) $(HOME)/.cargo

fmt:
	cargo +nightly fmt

build: setup
	CARGO_HOME=$(CARGO_HOME_DIR) RUSTFLAGS="$(REMAP)" cargo build --release

macos.build-linux-x64: setup
	CARGO_HOME=$(CARGO_HOME_DIR) RUSTFLAGS="$(REMAP)" cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.17
