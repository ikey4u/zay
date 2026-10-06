#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
state="$root/devpane/.build/macos"
mkdir -p "$state"
pidfile="$state/devpane.pid"
running() {
  [[ -f "$pidfile" ]] || return 1
  pid="$(cat "$pidfile")"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  ps -p "$pid" -o command= | grep -q 'test_macos.py --serve'
}
case "${1:-start}" in
 start)
  if running; then echo 'macOS devpane: http://127.0.0.1:18788/'; exit 0; fi
  nohup bash "$root/devpane/be/manage.sh" serve-macos > "$state/devpane.log" 2>&1 < /dev/null &
  pid=$!
  for attempt in {1..120}; do
   if grep -q 'macOS devpane ready:' "$state/devpane.log"; then
    echo 'macOS devpane: http://127.0.0.1:18788/'; exit 0
   fi
   kill -0 "$pid" 2>/dev/null || { cat "$state/devpane.log"; exit 1; }
   sleep 2
  done
  echo "Startup still running; see $state/devpane.log"; exit 1
  ;;
 stop)
  if running; then
   kill -TERM "$pid"
   for attempt in {1..60}; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
   done
   if kill -0 "$pid" 2>/dev/null; then echo "Cleanup still running; see $state/devpane.log"; exit 1; fi
  fi
  rm -f "$pidfile"
  ;;
 status)
  if running; then echo 'macOS devpane: http://127.0.0.1:18788/'; else echo 'macOS devpane stopped'; fi
  echo "Log: $state/devpane.log"
  ;;
 *) exit 2 ;;
esac
