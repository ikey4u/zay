#!/usr/bin/env bash
# Build libzay_ios.a for iOS device (+ optional simulator) and generate the C header.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRATE="$ROOT/Rust/zay-ios"
OUT="$ROOT/Vendor"
HEADER_OUT="$ROOT/Shared"
MIN_IOS="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"

mkdir -p "$OUT" "$HEADER_OUT"

export IPHONEOS_DEPLOYMENT_TARGET="$MIN_IOS"
# Only target-specific flags — do NOT set global CFLAGS (breaks host build-deps / ring).
export CFLAGS_aarch64_apple_ios="-miphoneos-version-min=${MIN_IOS}"
unset CFLAGS || true
unset CFLAGS_aarch64_apple_darwin || true

rustup target add aarch64-apple-ios >/dev/null

echo "==> cargo build zay-ios (ios device / aarch64-apple-ios)"
cargo build --manifest-path "$CRATE/Cargo.toml" --release --target aarch64-apple-ios

DEVICE_LIB="$CRATE/target/aarch64-apple-ios/release/libzay_ios.a"
cp "$DEVICE_LIB" "$OUT/libzay_ios-ios.a"
cp "$DEVICE_LIB" "$OUT/libzay_ios.a"

if [[ "${BUILD_IOS_SIM:-0}" == "1" ]]; then
  rustup target add aarch64-apple-ios-sim >/dev/null
  echo "==> cargo build zay-ios (ios simulator)"
  cargo build --manifest-path "$CRATE/Cargo.toml" --release --target aarch64-apple-ios-sim
  cp "$CRATE/target/aarch64-apple-ios-sim/release/libzay_ios.a" "$OUT/libzay_ios-sim.a"
fi

if command -v cbindgen >/dev/null; then
  echo "==> cbindgen"
  cbindgen --config "$CRATE/cbindgen.toml" --crate zay-ios --output "$HEADER_OUT/zay_ios.h" "$CRATE"
else
  echo "==> cbindgen not installed; keeping Shared/zay_ios.h"
fi

echo "OK: $OUT/libzay_ios.a ($(du -h "$OUT/libzay_ios.a" | awk '{print $1}'))"
echo "OK: $HEADER_OUT/zay_ios.h"
