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
  up|down|reset|logs|status) ;;
  *)
    echo "usage: $0 {up|down|reset|logs|status}" >&2
    exit 2
    ;;
esac
if [[ "$(uname -s)" == Darwin && "${DEVPANE_MACOS_READY:-}" != 1 ]]; then
  need mise
  exec mise -C "${root}" run devpane:macos -- "${action}"
fi

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
    echo "building Linux lab images (first build may take several minutes)"
    compose up -d --build
    cat <<'EOF'

devpane is up. Host routing is unchanged; TUN and EasyTier stay in the zay container.

  WebUI  http://127.0.0.1:18787/

Open the WebUI, then use the Lab sidebar. No access token is required.
The lab subscription is http://172.30.126.10:8090/sub inside the docker network
(from the host: http://127.0.0.1:18090/sub).

  devpane/be/manage.sh logs
  devpane/be/manage.sh down
  devpane/be/manage.sh reset
EOF
    ;;
  down)
    need docker
    compose down
    ;;
  reset)
    need docker
    compose down -v
    ;;
  logs)
    need docker
    compose logs -f --tail 80
    ;;
  status)
    need docker
    compose ps
    ;;
  *)
    echo "usage: $0 {up|down|reset|logs|status}" >&2
    exit 2
    ;;
esac
