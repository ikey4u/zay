#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
command -v xcodegen >/dev/null || { echo "Install xcodegen: brew install xcodegen" >&2; exit 1; }

if [[ ! -f project.local.yml ]]; then
  echo "note: project.local.yml missing — DEVELOPMENT_TEAM will not be set." >&2
  echo "      cp project.local.yml.example project.local.yml  # then fill YOUR_TEAM_ID" >&2
elif ! grep -qE 'DEVELOPMENT_TEAM:[[:space:]]*["'\'']?[A-Z0-9]{10}' project.local.yml; then
  echo "note: set DEVELOPMENT_TEAM in project.local.yml to keep signing across xcodegen runs." >&2
fi

xcodegen generate
echo "OK: $ROOT/Zay.xcodeproj"
