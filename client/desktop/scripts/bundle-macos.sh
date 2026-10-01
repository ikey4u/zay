#!/usr/bin/env bash
set -euo pipefail

desktop_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
if [[ "$(uname -s)" != Darwin ]]; then
    echo 'Zay Desktop currently supports macOS only.' >&2
    exit 1
fi
profile=release
args=(--manifest-path "$desktop_dir/Cargo.toml" --locked --target-dir "$desktop_dir/target")
case "${1:-}" in
    '') args+=(--release) ;;
    --debug) profile=debug ;;
    *) echo "Usage: $0 [--debug]" >&2; exit 2 ;;
esac
cargo build "${args[@]}"
app="$desktop_dir/dist/Zay Desktop.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$desktop_dir/target/$profile/zay-desktop" "$app/Contents/MacOS/zay-desktop"
cp "$desktop_dir/Info.plist" "$app/Contents/Info.plist"
# Local builds use ad-hoc signing. Distribution needs Developer ID + notarization.
codesign --force --sign "${ZAY_SIGN_IDENTITY:--}" "$app"
codesign --verify --strict "$app"
printf 'Built %s\nLaunch with: open "%s"\n' "$app" "$app"
