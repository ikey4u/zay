#!/usr/bin/env bash
# Wrap libzay_ios.a into ZayCore.framework (dynamic) so its EH personality
# does not collide with Libbox's C++ personality inside the Packet Tunnel dylib.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/Vendor"
LIB="$OUT/libzay_ios.a"
FW="$OUT/ZayCore.framework"
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
MIN="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"

if [[ ! -f "$LIB" ]]; then
  echo "missing $LIB — run Scripts/build-rust.sh first" >&2
  exit 1
fi

rm -rf "$FW"
mkdir -p "$FW/Headers" "$FW/Modules"

echo "==> linking ZayCore.framework/ZayCore"
xcrun --sdk iphoneos clang++ -dynamiclib \
  -target "arm64-apple-ios${MIN}" \
  -isysroot "$SDK" \
  -miphoneos-version-min="$MIN" \
  -Wl,-force_load,"$LIB" \
  -framework Security \
  -framework SystemConfiguration \
  -framework Network \
  -framework CoreFoundation \
  -install_name "@rpath/ZayCore.framework/ZayCore" \
  -compatibility_version 1 \
  -current_version 1 \
  -o "$FW/ZayCore"

cp "$ROOT/Shared/zay_ios.h" "$FW/Headers/zay_ios.h"
cat > "$FW/Headers/ZayCore.h" <<'EOF'
#import <ZayCore/zay_ios.h>
EOF

cat > "$FW/Modules/module.modulemap" <<'EOF'
framework module ZayCore {
  umbrella header "ZayCore.h"
  export *
  module * { export * }
}
EOF

cat > "$FW/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleExecutable</key><string>ZayCore</string>
  <key>CFBundleIdentifier</key><string>dev.zay.ios.ZayCore</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>ZayCore</string>
  <key>CFBundlePackageType</key><string>FMWK</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>MinimumOSVersion</key><string>${MIN}</string>
</dict>
</plist>
EOF

echo "OK: $FW"
