#!/usr/bin/env bash
# Build Libbox.xcframework from vendor/sing-box via gomobile.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SB="$ROOT/../../vendor/sing-box"
OUT="$ROOT/Vendor"

mkdir -p "$OUT"

# shellcheck disable=SC1091
if ! command -v go >/dev/null && [[ -f "$(dirname "$0")/env-go.sh" ]]; then
  source "$(dirname "$0")/env-go.sh"
fi

if ! command -v go >/dev/null; then
  echo "Go is required. Install with: brew install go" >&2
  echo "Or extract https://go.dev/dl/ and source Scripts/env-go.sh" >&2
  exit 1
fi

export PATH="$(go env GOPATH)/bin:${PATH}"

echo "==> installing gomobile/gobind"
go install -v github.com/sagernet/gomobile/cmd/gomobile@v0.1.13
go install -v github.com/sagernet/gomobile/cmd/gobind@v0.1.13
gomobile init || true

echo "==> building Libbox.xcframework"
cd "$SB"

# Device arm64 is enough for real-device Packet Tunnel testing.
PLATFORMS="${LIBBOX_PLATFORMS:-ios/arm64}"
go run ./cmd/internal/build_libbox -target apple -platform "${PLATFORMS}"

FOUND=""
for cand in \
  "${SB}/Libbox.xcframework" \
  "${SB}/../sing-box-for-apple/Libbox.xcframework" \
  "${SB}/build/Libbox.xcframework"
do
  if [[ -d "${cand}" ]]; then
    FOUND="${cand}"
    break
  fi
done

if [[ -z "${FOUND}" ]]; then
  echo "Libbox.xcframework not found after build" >&2
  find "${SB}" -maxdepth 3 -name 'Libbox.xcframework' 2>/dev/null || true
  exit 1
fi

rm -rf "${OUT}/Libbox.xcframework"
cp -R "${FOUND}" "${OUT}/Libbox.xcframework"

# iOS expects shallow frameworks (Info.plist at framework root). gomobile/Apple
# builds sometimes emit macOS-style Versions/A/Resources/Info.plist layouts.
flatten_ios_framework() {
  local FW="$1"
  [[ -d "${FW}/Versions" ]] || return 0
  local NAME TMP VER
  NAME="$(basename "${FW}" .framework)"
  TMP="$(mktemp -d)"
  VER="${FW}/Versions/Current"
  [[ -d "${VER}" ]] || VER="${FW}/Versions/A"
  [[ -d "${VER}/Headers" ]] && cp -R "${VER}/Headers" "${TMP}/Headers"
  [[ -d "${VER}/Modules" ]] && cp -R "${VER}/Modules" "${TMP}/Modules"
  [[ -f "${VER}/${NAME}" ]] && cp "${VER}/${NAME}" "${TMP}/${NAME}"
  if [[ -f "${VER}/Resources/Info.plist" ]]; then
    cp "${VER}/Resources/Info.plist" "${TMP}/Info.plist"
  fi
  if [[ ! -f "${TMP}/Info.plist" ]]; then
    cat > "${TMP}/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>${NAME}</string>
	<key>CFBundleIdentifier</key>
	<string>dev.zay.ios.${NAME}</string>
	<key>CFBundleName</key>
	<string>${NAME}</string>
	<key>CFBundlePackageType</key>
	<string>FMWK</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>MinimumOSVersion</key>
	<string>16.0</string>
</dict>
</plist>
EOF
  else
    /usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "${TMP}/Info.plist" >/dev/null 2>&1 \
      || /usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string dev.zay.ios.${NAME}" "${TMP}/Info.plist"
    /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier dev.zay.ios.${NAME}" "${TMP}/Info.plist" 2>/dev/null || true
    /usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "${TMP}/Info.plist" >/dev/null 2>&1 \
      || /usr/libexec/PlistBuddy -c "Add :CFBundleExecutable string ${NAME}" "${TMP}/Info.plist"
    /usr/libexec/PlistBuddy -c "Print :CFBundlePackageType" "${TMP}/Info.plist" >/dev/null 2>&1 \
      || /usr/libexec/PlistBuddy -c "Add :CFBundlePackageType string FMWK" "${TMP}/Info.plist"
  fi
  rm -rf "${FW}"
  mkdir -p "${FW}"
  cp -R "${TMP}"/* "${FW}/"
  rm -rf "${TMP}"
  echo "flattened shallow framework: ${FW}"
}

while IFS= read -r -d '' fw; do
  flatten_ios_framework "${fw}"
done < <(find "${OUT}/Libbox.xcframework" -name '*.framework' -type d -print0)

echo "OK: ${OUT}/Libbox.xcframework"
