#!/usr/bin/env bash
# Compile on the host; Docker only packages and runs these Linux executables.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
case "${DEVPANE_TARGET_ARCH:?launcher must provide the Docker engine architecture}" in
  aarch64|arm64) arch=arm64; target=aarch64-unknown-linux-gnu ;;
  x86_64|amd64) arch=amd64; target=x86_64-unknown-linux-gnu ;;
  *) echo "unsupported lab architecture: $DEVPANE_TARGET_ARCH" >&2; exit 1 ;;
esac
cd "$root"
rustup target add "$target"
export CARGO_TARGET_DIR="$root/devpane/.build/linux-target"
export CARGO_ZIGBUILD_CACHE_DIR="$root/devpane/.build/zig-cache"
export CARGO_BUILD_JOBS="${DEVPANE_BUILD_JOBS:-2}"
# Keep incremental host builds small; packaged binaries do not need debug symbols.
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_DEV_STRIP=symbols
export PROTOC="$(command -v protoc)"
export PROTOC_INCLUDE="$(dirname "$PROTOC")/../include"
test -f "$PROTOC_INCLUDE/google/protobuf/duration.proto"
echo "compiling Linux $arch binaries on $(uname -s) host"
cargo zigbuild --locked --target "$target.2.28" -p zay --bin zay
cargo zigbuild --locked --target "$target.2.28" --manifest-path devpane/be/Cargo.toml
output="$root/devpane/.build/linux/$arch"
mkdir -p "$output"
# Copy only after both builds succeed; partial builds never replace running services.
cp "$CARGO_TARGET_DIR/$target/debug/zay" "$output/zay"
cp "$CARGO_TARGET_DIR/$target/debug/devpane-be" "$output/devpane-be"
