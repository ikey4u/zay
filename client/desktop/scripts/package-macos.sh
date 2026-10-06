#!/usr/bin/env bash
set -euo pipefail

desktop_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
if [[ "$(uname -s)" != Darwin ]]; then
    echo 'Zay Desktop currently supports macOS only.' >&2
    exit 1
fi

bash "$desktop_dir/scripts/bundle-macos.sh"
app="$desktop_dir/dist/Zay Desktop.app"
version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist")"
package="$desktop_dir/dist/zay-desktop-macos-$(uname -m)-v${version}.zip"

# Preserve the complete signed app bundle, including macOS resource metadata.
# Stage the archive so a failed packaging run does not replace a good artifact.
staging="$(mktemp -d "$desktop_dir/dist/.package.XXXXXX")"
trap 'rm -rf "$staging"' EXIT
ditto -c -k --sequesterRsrc --keepParent "$app" "$staging/package.zip"
mv -f "$staging/package.zip" "$package"
printf 'Packaged %s\n' "$package"
