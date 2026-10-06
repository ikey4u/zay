#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
lab="${1:-auto}"
if [[ "$lab" == auto ]]; then
  case "$(uname -s)" in
    Darwin) lab=macos ;;
    Linux) lab=linux ;;
    *) echo "Devpane supports only Linux and macOS hosts." >&2; exit 1 ;;
  esac
fi
bash "$root/devpane/be/check-host.sh" "$lab"
case "$lab" in
  linux) exec bash "$root/devpane/be/manage.sh" up ;;
  macos)
    bash "$root/devpane/be/macos-pane.sh" stop
    mise -C "$root" run devpane:linux
    mise -C "$root" exec tart@2.40.1 rust@stable protoc@36.2 node@24.19.0 cmake@4.4.3 -- \
      bash "$root/devpane/be/macos-vm.sh"
    exec mise -C "$root" run devpane:macos-serve
    ;;
esac
