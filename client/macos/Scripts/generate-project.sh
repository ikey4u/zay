#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
project_dir="$(dirname "$script_dir")"
cd "$project_dir"

created_local=0
if [[ ! -f project.local.yml ]]; then
  created_local=1
  printf '{}\n' > project.local.yml
fi
cleanup() {
  if [[ "$created_local" == 1 ]]; then
    rm -f project.local.yml
  fi
}
trap cleanup EXIT

xcodegen generate
