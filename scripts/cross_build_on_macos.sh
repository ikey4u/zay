#!/usr/bin/env bash
# Cross-build zay on macOS for macOS / Linux / Windows without embedding host paths.
#
# Technique:
#   1. CARGO_HOME=/tmp/cargo-tmp  — crates/git checkouts never live under $HOME/.cargo
#   2. CARGO_TARGET_DIR=/tmp/zay-target — build outs off the repo tree
#   3. RUSTFLAGS --remap-path-prefix — scrub HOME/RUSTUP/CARGO/ROOT/TARGET
#      (overlapping prefixes: last match wins; list broad → specific)
#   4. strip after link — drop leftover symbols
#   5. strings scan — fail if personal / project-layout paths remain
#
# Usage (from repo root):
#   ./scripts/cross_build_on_macos.sh
#   mise run macos:build:all
#
# Env overrides:
#   CARGO_HOME_DIR, CARGO_TARGET_DIR, RUSTUP_HOME, DIST_DIR, MINGW_{CC,AR,DLLTOOL}
#   SKIP_PACKAGE=1  — build+strip+verify only, skip dist/*.zip
#   SKIP_VERIFY=1   — skip strings privacy check

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: this script must run on macOS (host=$(uname -s))" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CARGO_HOME_DIR="${CARGO_HOME_DIR:-/tmp/cargo-tmp}"
# Keep OUT_DIR / build script paths off the repo tree so panic locations
# cannot leak folder names like Dev/zay even if remap order regresses.
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/zay-target}"
RUSTUP_HOME="${RUSTUP_HOME:-${HOME}/.rustup}"
DIST_DIR="${DIST_DIR:-dist}"

TARGET_MACOS_ARM64="${TARGET_MACOS_ARM64:-aarch64-apple-darwin}"
ZIG_LINUX_TARGET="${ZIG_LINUX_TARGET:-x86_64-unknown-linux-gnu.2.17}"
TARGET_LINUX_X64="${TARGET_LINUX_X64:-x86_64-unknown-linux-gnu}"
TARGET_WINDOWS_X64="${TARGET_WINDOWS_X64:-x86_64-pc-windows-gnu}"

MINGW_DLLTOOL="${MINGW_DLLTOOL:-x86_64-w64-mingw32-dlltool}"
MINGW_CC="${MINGW_CC:-x86_64-w64-mingw32-gcc}"
MINGW_AR="${MINGW_AR:-x86_64-w64-mingw32-ar}"

BIN_MACOS="${CARGO_TARGET_DIR}/${TARGET_MACOS_ARM64}/release/zay"
BIN_LINUX="${CARGO_TARGET_DIR}/${TARGET_LINUX_X64}/release/zay"
BIN_WINDOWS="${CARGO_TARGET_DIR}/${TARGET_WINDOWS_X64}/release/zay.exe"

# ---------------------------------------------------------------------------
# Path scrubbing
# ---------------------------------------------------------------------------

build_remap_flags() {
  local flags=()
  # Overlapping remaps: rustc applies the *last* matching prefix (not longest).
  # Broad → specific order so repo/target/rustup win over $HOME.
  flags+=("--remap-path-prefix=${HOME}=/home")
  if [[ -n "${RUSTUP_HOME}" && -d "${RUSTUP_HOME}" ]]; then
    flags+=("--remap-path-prefix=${RUSTUP_HOME}=/rustup")
  fi
  flags+=("--remap-path-prefix=${CARGO_HOME_DIR}=/cargo")
  flags+=("--remap-path-prefix=${ROOT}=/src")
  flags+=("--remap-path-prefix=${CARGO_TARGET_DIR}=/target")
  # Strip at link time so we do not depend on zig objcopy (unimplemented for ELF).
  flags+=("-C" "strip=symbols")
  # Join with spaces for RUSTFLAGS.
  local out=""
  local f
  for f in "${flags[@]}"; do
    out+="${out:+ }${f}"
  done
  printf '%s' "$out"
}

export_build_env() {
  local extra="${1:-}"
  mkdir -p "$CARGO_HOME_DIR" "$CARGO_TARGET_DIR"
  export CARGO_HOME="$CARGO_HOME_DIR"
  export CARGO_TARGET_DIR
  local remap
  remap="$(build_remap_flags)"
  if [[ -n "$extra" ]]; then
    export RUSTFLAGS="${remap} ${extra}"
  else
    export RUSTFLAGS="${remap}"
  fi
  echo "CARGO_HOME=$CARGO_HOME" >&2
  echo "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" >&2
  echo "RUSTFLAGS=$RUSTFLAGS" >&2
}

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: missing required command: $1" >&2
    echo "  hint: $2" >&2
    exit 1
  }
}

check_prereqs() {
  need_cmd rustup "https://rustup.rs/"
  need_cmd cargo "rustup default stable"
  need_cmd zig "https://ziglang.org/  (or brew install zig)"
  need_cmd cargo-zigbuild "cargo install cargo-zigbuild"
  need_cmd strip "Xcode CLT /usr/bin/strip"
  need_cmd strings "Xcode CLT"
  need_cmd zip "built-in on macOS"
  need_cmd "$MINGW_DLLTOOL" "brew install mingw-w64  (or set MINGW_DLLTOOL)"
  need_cmd "$MINGW_CC" "brew install mingw-w64  (or set MINGW_CC)"
  need_cmd "$MINGW_AR" "brew install mingw-w64  (or set MINGW_AR)"

  rustup target add \
    "$TARGET_MACOS_ARM64" \
    "$TARGET_LINUX_X64" \
    "$TARGET_WINDOWS_X64" >/dev/null
}

fetch_deps() {
  export_build_env
  if ! cargo fetch -q; then
    echo "repairing broken registry in $CARGO_HOME_DIR" >&2
    rm -rf "$CARGO_HOME_DIR/registry"
    cargo fetch -q
  fi
}

# ---------------------------------------------------------------------------
# Builds
# ---------------------------------------------------------------------------

build_macos_arm64() {
  echo "==> macOS arm64 ($TARGET_MACOS_ARM64)" >&2
  export_build_env
  cargo build --release --target "$TARGET_MACOS_ARM64"
  test -f "$BIN_MACOS"
}

build_linux_x64() {
  echo "==> Linux x64 (zig $ZIG_LINUX_TARGET → $TARGET_LINUX_X64)" >&2
  export_build_env
  cargo zigbuild --release --target "$ZIG_LINUX_TARGET"
  test -f "$BIN_LINUX" || {
    echo "error: missing $BIN_LINUX (zig target was $ZIG_LINUX_TARGET)" >&2
    exit 1
  }
}

build_windows_x64() {
  echo "==> Windows x64 ($TARGET_WINDOWS_X64)" >&2
  # dlltool path stays out of remap targets; do not put brew paths into panic strings
  # beyond what rustc records for -C dlltool (usually not $HOME).
  export_build_env "-C dlltool=${MINGW_DLLTOOL}"
  export "CC_x86_64_pc_windows_gnu=$MINGW_CC"
  export "AR_x86_64_pc_windows_gnu=$MINGW_AR"
  cargo zigbuild --release --target "$TARGET_WINDOWS_X64"
  test -f "$BIN_WINDOWS"
}

# ---------------------------------------------------------------------------
# Strip
# ---------------------------------------------------------------------------

find_rust_objcopy() {
  local sysroot
  sysroot="$(rustc --print sysroot 2>/dev/null)" || return 0
  find "${sysroot}/lib/rustlib" -name rust-objcopy -type f 2>/dev/null | head -1
}

strip_macos() {
  local bin="$1"
  # -x: remove local symbols; keep essential dylib linkage info.
  if ! strip -x "$bin" 2>/dev/null; then
    echo "warn: macOS strip failed for $bin (already stripped?)" >&2
  fi
}

strip_linux() {
  local bin="$1"
  local objcopy
  objcopy="$(find_rust_objcopy)"
  if [[ -n "$objcopy" ]]; then
    "$objcopy" --strip-all "$bin"
    return
  fi
  if command -v llvm-strip >/dev/null 2>&1; then
    llvm-strip --strip-all "$bin"
    return
  fi
  # Do not use `zig objcopy --strip-all`: current zig prints "unimplemented"
  # and may leave a broken/empty output.
  echo "warn: no rust-objcopy/llvm-strip; relying on -C strip=symbols for $bin" >&2
}

strip_windows() {
  local bin="$1"
  if command -v x86_64-w64-mingw32-strip >/dev/null 2>&1; then
    x86_64-w64-mingw32-strip "$bin" || {
      echo "warn: mingw strip failed for $bin" >&2
    }
    return
  fi
  local objcopy
  objcopy="$(find_rust_objcopy)"
  if [[ -n "$objcopy" ]]; then
    "$objcopy" --strip-all "$bin" || {
      echo "warn: rust-objcopy strip failed for $bin" >&2
    }
    return
  fi
  echo "warn: no Windows strip tool; relying on -C strip=symbols for $bin" >&2
}

strip_all() {
  echo "==> strip" >&2
  strip_macos "$BIN_MACOS"
  strip_linux "$BIN_LINUX"
  strip_windows "$BIN_WINDOWS"
}

# ---------------------------------------------------------------------------
# Privacy check
# ---------------------------------------------------------------------------

verify_no_personal_paths() {
  local bin="$1"
  local label="$2"
  local repo_name parent_name
  repo_name="$(basename "$ROOT")"
  parent_name="$(basename "$(dirname "$ROOT")")"
  echo "==> verify paths: $label" >&2

  local hits
  hits="$(
    strings "$bin" | rg -n \
      -e "${HOME}" \
      -e '/Users/[^/]+/\.cargo' \
      -e '/Users/[^/]+/\.rustup' \
      -e '/Users/[^/]+/Dev/' \
      -e '/Users/[^/]+/Library/' \
      -e "/home/${parent_name}/" \
      -e "/home/.*/${repo_name}/" \
      -e "${CARGO_HOME_DIR}" \
      -e "${CARGO_TARGET_DIR}" \
      || true
  )"
  # Remapped prefixes /cargo /src /home /rustup /target are OK.
  # System frameworks under /System/Library are OK and not matched above.

  if [[ -n "$hits" ]]; then
    echo "error: personal path(s) still embedded in $bin:" >&2
    echo "$hits" | head -40 >&2
    exit 1
  fi
  echo "    OK: $bin" >&2
}

verify_all() {
  verify_no_personal_paths "$BIN_MACOS" "macos-arm64"
  verify_no_personal_paths "$BIN_LINUX" "linux-x64"
  verify_no_personal_paths "$BIN_WINDOWS" "windows-x64"
}

# ---------------------------------------------------------------------------
# Package
# ---------------------------------------------------------------------------

pkg_version() {
  sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1
}

find_windows_runtime_dir() {
  local packet
  packet="$(
    find "${CARGO_TARGET_DIR}/${TARGET_WINDOWS_X64}/release/build" -type f \
      -path '*/windows-runtime/Packet.dll' 2>/dev/null | head -1
  )"
  if [[ -z "$packet" ]]; then
    echo ""
    return
  fi
  printf '%s' "${packet%/Packet.dll}"
}

package_all() {
  local version zip_macos zip_linux zip_windows
  version="$(pkg_version)"
  zip_macos="zay-macos-arm64-v${version}.zip"
  zip_linux="zay-linux-x64-v${version}.zip"
  zip_windows="zay-windows-x64-v${version}.zip"

  mkdir -p "$DIST_DIR"

  echo "==> package → $DIST_DIR" >&2
  rm -f "${DIST_DIR}/${zip_macos}" "${DIST_DIR}/${zip_linux}" "${DIST_DIR}/${zip_windows}"

  (
    cd "$(dirname "$BIN_MACOS")"
    zip -j "${ROOT}/${DIST_DIR}/${zip_macos}" "$(basename "$BIN_MACOS")"
  )
  (
    cd "$(dirname "$BIN_LINUX")"
    zip -j "${ROOT}/${DIST_DIR}/${zip_linux}" "$(basename "$BIN_LINUX")"
  )

  local runtime tmpdir
  runtime="$(find_windows_runtime_dir)"
  if [[ -z "$runtime" || ! -f "${runtime}/wintun.dll" || ! -f "${runtime}/WinDivert64.sys" ]]; then
    echo "error: missing Windows runtime under ${CARGO_TARGET_DIR}/${TARGET_WINDOWS_X64}/release/build/*/out/windows-runtime" >&2
    exit 1
  fi
  tmpdir="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmpdir'" RETURN
  cp "$BIN_WINDOWS" "$tmpdir/"
  cp "${runtime}/Packet.dll" "${runtime}/wintun.dll" "${runtime}/WinDivert64.sys" "$tmpdir/"
  (
    cd "$tmpdir"
    zip -j "${ROOT}/${DIST_DIR}/${zip_windows}" ./*
  )

  echo "packaged (v${version}):" >&2
  echo "  ${DIST_DIR}/${zip_macos}" >&2
  echo "  ${DIST_DIR}/${zip_linux}" >&2
  echo "  ${DIST_DIR}/${zip_windows}" >&2
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  echo "cross_build_on_macos: ROOT=$ROOT" >&2
  check_prereqs
  fetch_deps

  # Sequential: avoid parallel cargo/zig races on shared CARGO_HOME.
  build_macos_arm64
  build_linux_x64
  build_windows_x64

  strip_all

  if [[ "${SKIP_VERIFY:-0}" != "1" ]]; then
    need_cmd rg "brew install ripgrep"
    verify_all
  else
    echo "warn: SKIP_VERIFY=1 — skipping path scan" >&2
  fi

  if [[ "${SKIP_PACKAGE:-0}" != "1" ]]; then
    package_all
  else
    echo "warn: SKIP_PACKAGE=1 — binaries left under ${CARGO_TARGET_DIR}/*/release/" >&2
  fi

  echo "done." >&2
}

main "$@"
