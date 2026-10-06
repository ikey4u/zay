#!/usr/bin/env bash
set -euo pipefail

desktop_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
if [[ "$(uname -s)" != Darwin ]]; then
    echo 'Zay Desktop currently supports macOS only.' >&2
    exit 1
fi
profile=release
args=(--manifest-path "$desktop_dir/Cargo.toml" --locked --bins --target-dir "$desktop_dir/target")
case "${1:-}" in
    '') args+=(--release) ;;
    --debug) profile=debug ;;
    *) echo "Usage: $0 [--debug]" >&2; exit 2 ;;
esac
mkdir -p "$desktop_dir/dist"
staging="$(mktemp -d "$desktop_dir/dist/.bundle.XXXXXX")"
trap 'rm -rf "$staging"' EXIT
identity="${APPLE_SIGN_IDENTITY:--}"
export ZAY_MACOS_TEAM_ID=""
if [[ "$identity" != - ]]; then
    # Sign a disposable executable to read the identity's actual Team ID. The
    # probe is never executed, and no certificate or keychain entry is created.
    cp /usr/bin/true "$staging/signing-probe"
    codesign --force --sign "$identity" "$staging/signing-probe"
    ZAY_MACOS_TEAM_ID="$(codesign -dv --verbose=4 "$staging/signing-probe" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
    if [[ ! "$ZAY_MACOS_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]]; then
        echo 'An Apple signing identity with a valid Team ID is required for the privileged helper.' >&2
        exit 1
    fi
fi
export ZAY_DESKTOP_PLIST_DIR="$staging"
cargo build "${args[@]}"
app="$staging/Zay Desktop.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Library/LaunchServices" "$app/Contents/Resources"
cp "$desktop_dir/target/$profile/zay-desktop" "$app/Contents/MacOS/zay-desktop"
cp "$desktop_dir/target/$profile/zay-desktop-helper" "$app/Contents/Library/LaunchServices/dev.zay.desktop.helper"
cp "$staging/Info.plist" "$app/Contents/Info.plist"
iconset="$staging/Zay.iconset"
mkdir -p "$iconset"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$desktop_dir/assets/app-icon.png" --out "$iconset/icon_${size}x${size}.png" >/dev/null
    double=$((size * 2))
    sips -z "$double" "$double" "$desktop_dir/assets/app-icon.png" --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/Zay.icns"
# The helper and containing app have reciprocal, same-team requirements.
# Ad-hoc bundles deliberately cannot install a root helper.
sign_args=(--force --sign "$identity")
if [[ "$identity" != - ]]; then
    sign_args+=(--options runtime)
    if [[ "$profile" == release ]]; then
        sign_args+=(--timestamp)
    else
        # Local development needs a valid identity, not a distribution timestamp.
        sign_args+=(--timestamp=none)
    fi
fi
codesign "${sign_args[@]}" --identifier dev.zay.desktop.helper "$app/Contents/Library/LaunchServices/dev.zay.desktop.helper"
codesign "${sign_args[@]}" "$app"
codesign --verify --strict "$app/Contents/Library/LaunchServices/dev.zay.desktop.helper"
codesign --verify --strict "$app"
# Replace only generated distribution output after build and signing succeed.
destination="$desktop_dir/dist/Zay Desktop.app"
if [[ -e "$destination" ]]; then mv "$destination" "$staging/previous.app"; fi
mv "$app" "$destination"
printf 'Built %s\nLaunch with: open "%s"\n' "$destination" "$destination"
