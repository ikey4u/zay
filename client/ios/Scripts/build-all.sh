#!/usr/bin/env bash
# Full native dependency build for Zay iOS.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Prefer a local Go install if present.
# shellcheck disable=SC1091
[[ -f Scripts/env-go.sh ]] && source Scripts/env-go.sh || true

./Scripts/build-rust.sh
./Scripts/build-zaycore-framework.sh
./Scripts/build-libbox.sh
./Scripts/generate-project.sh

echo
echo "All artifacts ready. Open Zay.xcodeproj, set your Team, run on a device."
