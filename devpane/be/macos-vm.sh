#!/usr/bin/env bash
# A native macOS guest, separate from the Colima Linux lab.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
[[ "$(uname -s)/$(uname -m)" == Darwin/arm64 ]] || {
  echo "The macOS VM lab requires an Apple Silicon Mac." >&2; exit 1;
}
export TART_HOME="$root/devpane/.build/macos-vm"
name=zay-devpane-macos
state="$root/devpane/.build/macos"
mkdir -p "$state"
case "${1:-up}" in
  up)
    # All compilation happens on the host. The guest receives only artifacts.
    cd "$root"
    export PROTOC="$(command -v protoc)"
    export PROTOC_INCLUDE="$(dirname "$PROTOC")/../include"
    cargo build --locked -p zay --bin zay
    cp "${CARGO_TARGET_DIR:-$root/target}/debug/zay" "$state/zay"
    if ! tart get "$name" >/dev/null 2>&1; then
      tart clone --concurrency "${DEVPANE_VM_DOWNLOAD_CONCURRENCY:-16}" \
        "${DEVPANE_MACOS_IMAGE:-ghcr.io/cirruslabs/macos-tahoe-base:latest}" "$name"
    fi
    if ! tart ip "$name" >/dev/null 2>&1; then
      tart set "$name" --cpu 4 --memory 6144
      nohup tart run --no-graphics --no-audio --no-clipboard "$name" > "$state/vm.log" 2>&1 < /dev/null &
      echo "$!" > "$state/vm.pid"
    fi
    tart ip --wait 180 "$name" > "$state/ip"
    if [[ ! -f "$state/id_ed25519" ]]; then
      ssh-keygen -q -t ed25519 -N '' -C zay-macos-lab -f "$state/id_ed25519"
    fi
    ip="$(cat "$state/ip")"
    ssh_opts=(-o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new
      -o "UserKnownHostsFile=$state/known_hosts" -i "$state/id_ed25519")
    ready=false
    for attempt in {1..60}; do
      if nc -z -w 2 "$ip" 22; then ready=true; break; fi
      sleep 2
    done
    "$ready" || { echo "Guest SSH did not become ready; see $state/vm.log" >&2; exit 1; }
    if ! ssh "${ssh_opts[@]}" -o BatchMode=yes "admin@$ip" true 2>/dev/null; then
      # Cirrus base images document admin/admin as their initial credentials.
      # Install a dedicated lab key; never read or copy the developer's SSH keys.
      export ZAY_VM_IP="$ip" ZAY_VM_STATE="$state"
      /usr/bin/expect <<'EXPECT'
set timeout 60
set state $env(ZAY_VM_STATE)
set keyfile [open "$state/id_ed25519.pub" r]
set key [string trim [read $keyfile]]
close $keyfile
spawn ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$state/known_hosts" admin@$env(ZAY_VM_IP) "umask 077; mkdir -p ~/.ssh; printf '%s\\n' '$key' >> ~/.ssh/authorized_keys"
expect {
    -nocase "password:" { send "admin\r"; exp_continue }
    eof { catch wait result; exit [lindex $result 3] }
    timeout { exit 1 }
}
EXPECT
    fi
    ssh "${ssh_opts[@]}" -o BatchMode=yes "admin@$ip" 'mkdir -p ~/zay-lab; sw_vers; uname -m; sudo -n true'
    scp "${ssh_opts[@]}" "$state/zay" "admin@$ip:zay-lab/zay"
    ssh "${ssh_opts[@]}" "admin@$ip" 'chmod +x ~/zay-lab/zay; ~/zay-lab/zay --version'
    echo "macOS guest: $(cat "$state/ip")"
    echo "Native host-built executable: $state/zay"
    ;;
  status) tart get "$name"; tart ip "$name" ;;
  stop) tart stop "$name" ;;
  *) echo "usage: $0 {up|status|stop}" >&2; exit 2 ;;
esac
