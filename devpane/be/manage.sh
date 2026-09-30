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

build_be() {
  need cargo
  echo "building devpane-be"
  (cd "${devpane}/be" && cargo build --release)
  mkdir -p "${devpane}/be/.build"
  cp -f "${devpane}/be/target/release/devpane-be" "${devpane}/be/.build/devpane-be"
  chmod 755 "${devpane}/be/.build/devpane-be"
  if command -v strip >/dev/null 2>&1; then
    strip --strip-unneeded "${devpane}/be/.build/devpane-be" || true
  fi
}

build_zay() {
  need cargo
  echo "building zay (debug; the WebUI is embedded by the build)"
  (cd "${root}" && cargo build)
  mkdir -p "${devpane}/.build"
  cp -f "${root}/target/debug/zay" "${devpane}/.build/zay"
  chmod 755 "${devpane}/.build/zay"
  if command -v strip >/dev/null 2>&1; then
    strip --strip-unneeded "${devpane}/.build/zay" || true
  fi
}

case "${action}" in
  up)
    need docker
    build_be
    build_zay
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
