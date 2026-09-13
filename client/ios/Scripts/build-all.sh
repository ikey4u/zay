#!/usr/bin/env bash
# Full native dependency build for Zay iOS.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

./Scripts/build-rust.sh
./Scripts/build-zaycore-framework.sh
./Scripts/generate-project.sh

echo
echo "All artifacts ready. Open Zay.xcodeproj, set your Team, run on a device."
