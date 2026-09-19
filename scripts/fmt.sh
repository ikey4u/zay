#!/usr/bin/env bash

set -euo pipefail

zay_script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
zay_workspace_root="$(cd -- "${zay_script_dir}/.." && pwd -P)"

cd "${zay_workspace_root}"

zay_packages=(
    --package zay
    --package singbox
    --package zay-ios
)

case "${1:-}" in
    "")
        exec cargo +nightly fmt \
            --manifest-path "${zay_workspace_root}/Cargo.toml" \
            "${zay_packages[@]}"
        ;;
    --check)
        exec cargo +nightly fmt \
            --manifest-path "${zay_workspace_root}/Cargo.toml" \
            "${zay_packages[@]}" \
            --check
        ;;
    *)
        printf 'usage: %s [--check]\n' "$0" >&2
        exit 2
        ;;
esac
