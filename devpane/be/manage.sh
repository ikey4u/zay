#!/usr/bin/env bash
# Start, stop, or reset the isolated devpane lab.
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
devpane="${root}/devpane"
action="${1:-up}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing $1" >&2
    exit 1
  fi
}

# Install and activate the macOS tools for every entry point, including direct
# invocations of this script. Linux uses its existing Docker Engine.
case "${action}" in
  up|down|reset|logs|status|test) ;;
  *)
    echo "usage: $0 {up|down|reset|logs|status|test}" >&2
    exit 2
    ;;
esac
if [[ "$(uname -s)" == Darwin && "${DEVPANE_MACOS_READY:-}" != 1 ]]; then
  need mise
  exec mise -C "${root}" run devpane:macos -- "${action}"
fi

if [[ "$action" != up && -f "${devpane}/.build/host.env" ]]; then source "${devpane}/.build/host.env"; fi
# Compose also interpolates variables during teardown.
if [[ "$action" != up ]]; then export DEVPANE_HOST_ADDR="${DEVPANE_HOST_ADDR:-127.0.0.1}"; fi

compose() {
  docker compose -f "${devpane}/compose.yaml" --project-directory "${devpane}" "$@"
}

# Linux keeps the existing mirror/DNS workaround. Colima on macOS uses
# the normal build network inside its Linux VM.
if [[ -z "${DEVPANE_BUILD_NETWORK:-}" ]]; then
  case "$(uname -s)" in
    Linux) export DEVPANE_BUILD_NETWORK=host ;;
    *) export DEVPANE_BUILD_NETWORK=default ;;
  esac
fi

case "${action}" in
  up)
    need docker
    docker info >/dev/null
    if [[ "$(uname -s)" == Darwin ]]; then
      export DEVPANE_HOST_ADDR="$(colima --profile zay-devpane ssh -- getent ahostsv4 host.lima.internal | awk 'NR==1 {print $1}')"
      export DEVPANE_HOST_BIND=127.0.0.1
    else
      export DEVPANE_HOST_ADDR="${DEVPANE_HOST_ADDR:-$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')}"
      export DEVPANE_HOST_BIND="${DEVPANE_HOST_BIND:-$DEVPANE_HOST_ADDR}"
    fi
    [[ "$DEVPANE_HOST_ADDR" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid host gateway address" >&2; exit 1; }
    [[ "$DEVPANE_HOST_BIND" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid host bind address" >&2; exit 1; }
    mkdir -p "${devpane}/.build"
    printf 'export DEVPANE_HOST_ADDR=%s\nexport DEVPANE_HOST_BIND=%s\n' "$DEVPANE_HOST_ADDR" "$DEVPANE_HOST_BIND" > "${devpane}/.build/host.env"
    mise -C "$root" run devpane:host-build
    echo "building Linux lab images (first build may take several minutes)"
    compose build
    bash "${devpane}/be/host-proxy.sh" stop
    # Recreate the old edge first to release its former host port 18090.
    compose up -d be sink relay mesh-peer mesh-echo
    bash "${devpane}/be/host-proxy.sh" start
    compose up -d zay
    cat <<'EOF'

devpane is up. Host routing is unchanged; TUN and EasyTier stay in the zay container.

  WebUI  http://127.0.0.1:18787/

Open the WebUI, then use the Lab sidebar. No access token is required.
The fake subscription and proxy run natively on the host (:18090/sub and :13128).
Run mise devpane:test for TUN and Mesh data-path and failure/recovery tests.

  devpane/be/manage.sh logs
  devpane/be/manage.sh down
  devpane/be/manage.sh reset
EOF
    ;;
  down)
    need docker
    trap 'bash "${devpane}/be/host-proxy.sh" stop' EXIT
    compose down
    ;;
  reset)
    need docker
    trap 'bash "${devpane}/be/host-proxy.sh" stop' EXIT
    compose down -v
    ;;
  logs)
    need docker
    compose logs -f --tail 80
    ;;
  status)
    need docker
    compose ps
    bash "${devpane}/be/host-proxy.sh" status
    ;;
  test)
    need docker
    python3 "${devpane}/be/test_network.py"
    ;;
  *)
    echo "usage: $0 {up|down|reset|logs|status|test}" >&2
    exit 2
    ;;
esac
