.PHONY: fmt build macos.build-linux-x64

fmt:
	cargo +nightly fmt

build:
	cargo +nightly build --release

macos.build-linux-x64:
	cargo +nightly zigbuild --release --target x86_64-unknown-linux-gnu.2.17
