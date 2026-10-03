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

compose() {
  docker compose -f "${devpane}/compose.yaml" --project-directory "${devpane}" "$@"
}

# Linux keeps the existing mirror/DNS workaround. Docker Desktop uses its
# normal build network and does not require host-networking support.
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
  Token  devpane-local-token

Open the WebUI, paste the token, then use the Lab sidebar.
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
