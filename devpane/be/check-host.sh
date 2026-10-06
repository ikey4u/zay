#!/usr/bin/env bash
# Validate the requested guest before installing tools or changing lab state.
set -euo pipefail
lab="${1:?expected linux or macos}"
host="$(uname -s)"
arch="$(uname -m)"
case "$lab:$host:$arch" in
  linux:Linux:x86_64|linux:Linux:aarch64|linux:Linux:arm64) ;;
  linux:Darwin:arm64|linux:Darwin:x86_64|macos:Darwin:arm64)
    version="$(sw_vers -productVersion)"
    if (( ${version%%.*} < 13 )); then
      echo "The $lab lab requires macOS 13 or newer on this host (found $version)." >&2
      exit 1
    fi
    ;;
  macos:*)
    echo "The macOS lab requires an Apple Silicon Mac running macOS 13 or newer; this host is $host/$arch. Use mise devpane:linux for the Linux lab." >&2
    exit 1
    ;;
  linux:*)
    echo "The Linux lab supports Linux and macOS hosts on ARM64 or x86-64; this host is $host/$arch." >&2
    exit 1
    ;;
  *) echo "Unknown lab: $lab (expected linux or macos)" >&2; exit 2 ;;
esac
