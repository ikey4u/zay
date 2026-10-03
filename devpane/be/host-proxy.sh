#!/usr/bin/env bash
# Native host process: never started inside a container or the Colima VM.
set -euo pipefail
devpane="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
native="${devpane}/.build/host-target/release/devpane-be"
pidfile="${devpane}/.build/host-proxy.pid"
logfile="${devpane}/.build/host-proxy.log"
if [[ -f "${devpane}/.build/host.env" ]]; then
  source "${devpane}/.build/host.env"
fi
export DEVPANE_ROLE=host
export DEVPANE_IPV4_ONLY=1
export DEVPANE_BIND="${DEVPANE_HOST_BIND:-127.0.0.1}"
export DEVPANE_ADVERTISE_HOST="${DEVPANE_HOST_ADDR:-127.0.0.1}"
export DEVPANE_CONTROL_PORT=18090 DEVPANE_PROXY_PORT=13128
running() {
  [[ -f "$pidfile" ]] || return 1
  read -r pid < "$pidfile"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  local command
  command="$(ps -p "$pid" -o command= 2>/dev/null)" || return 1
  [[ "$command" == *"$native"* ]]
}
case "${1:-start}" in
  start)
    if running; then exit 0; fi
    mkdir -p "${devpane}/.build"
    nohup "$native" > "$logfile" 2>&1 < /dev/null &
    echo "$!" > "$pidfile"
    for attempt in {1..40}; do
      running || { cat "$logfile" >&2; exit 1; }
      if "$native" --healthcheck >/dev/null 2>&1; then
        echo "host subscription: http://${DEVPANE_BIND}:18090/sub (proxy :13128)"
        exit 0
      fi
      running || { cat "$logfile" >&2; exit 1; }
      sleep 0.25
    done
    if running; then kill "$pid"; fi
    rm -f "$pidfile"
    echo "host proxy did not become ready; see $logfile" >&2
    exit 1
    ;;
  stop)
    if running; then
      kill "$pid"
      for attempt in {1..40}; do
        running || break
        sleep 0.25
      done
      if running; then echo "host proxy did not stop (PID $pid)" >&2; exit 1; fi
    fi
    rm -f "$pidfile"
    ;;
  status)
    if running; then echo "host proxy running (PID $pid)"; else echo "host proxy stopped"; exit 1; fi
    ;;
  *) echo "usage: $0 {start|stop|status}" >&2; exit 2 ;;
esac
