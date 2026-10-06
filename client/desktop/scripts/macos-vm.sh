#!/usr/bin/env bash
# Build on the host, run only inside a dedicated macOS guest. No host elevation,
# proxy, TUN, Mesh, DNS changes, bridged networking, or signing-key transfer.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
desktop="$root/client/desktop"
state="$root/devpane/.build/desktop-macos"
export TART_HOME="$root/devpane/.build/macos-vm"
export TART_NO_AUTO_PRUNE=1
name=zay-desktop-macos
base="${DEVPANE_MACOS_IMAGE:-ghcr.nju.edu.cn/cirruslabs/macos-tahoe-base:latest}"
action="${1:-up}"
bash "$root/devpane/be/check-host.sh" macos
mkdir -p "$state"
ssh_options=(-o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=accept-new
    -o "UserKnownHostsFile=$state/known_hosts" -i "$state/id_ed25519")
guest() { ssh "${ssh_options[@]}" "admin@$ip" "$@"; }
guest_ready() {
    ip="$(tart ip "$name")"
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
        echo 'The desktop VM has no IPv4 address yet.' >&2; return 1;
    }
    # The marker belongs to this dedicated guest. Every privileged maintenance
    # action is sent through SSH after this check, never executed on the host.
    guest 'test "$(uname -s)" = Darwin && test "$(cat /etc/zay-desktop-vm)" = zay-desktop-macos'
}
case "$action" in
    up)
        if [[ -z "${APPLE_SIGN_IDENTITY:-}" || "$APPLE_SIGN_IDENTITY" == - ]]; then
            echo 'Set APPLE_SIGN_IDENTITY to an existing Apple signing identity before testing the privileged helper in the VM.' >&2
            exit 1
        fi
        bash "$desktop/scripts/bundle-macos.sh" --debug
        vm_dns="${ZAY_DESKTOP_VM_DNS:-inherited}"
        case "$vm_dns" in inherited|alidns) ;; *) echo "Unknown ZAY_DESKTOP_VM_DNS: $vm_dns" >&2; exit 2 ;; esac
        if [[ "$vm_dns" == alidns ]]; then
            # Opt-in guest DNS sends queries to dns.alidns.com over HTTPS.
            cargo build --manifest-path "$root/devpane/be/Cargo.toml" --locked --release --target-dir "$state/dns-target"
        fi
        if ! tart get "$name" >/dev/null 2>&1; then
            echo 'Creating a dedicated desktop VM from the macOS base image…'
            tart clone --concurrency "${DEVPANE_VM_DOWNLOAD_CONCURRENCY:-4}" "$base" "$name"
        fi
        if ! tart ip "$name" >/dev/null 2>&1; then
            tart set "$name" --cpu 4 --memory 6144
            # Default Tart networking is NAT. There is intentionally no
            # --net-bridged, shared host directory, or host clipboard here.
            nohup tart run --no-graphics --no-audio --no-clipboard "$name" > "$state/vm.log" 2>&1 < /dev/null &
            echo "$!" > "$state/vm.pid"
        fi
        tart ip --wait 180 "$name" > "$state/ip"
        ip="$(cat "$state/ip")"
        if [[ ! -f "$state/id_ed25519" ]]; then
            ssh-keygen -q -t ed25519 -N '' -C zay-desktop-vm -f "$state/id_ed25519"
        fi
        ready=false
        for attempt in {1..60}; do
            if nc -z -w 2 "$ip" 22; then ready=true; break; fi
            sleep 2
        done
        "$ready" || { echo "Guest SSH is unavailable; see $state/vm.log" >&2; exit 1; }
        if ! guest true 2>/dev/null; then
            # Only the image's documented admin/admin lab credentials are used.
            # Host SSH keys, signing certificates, and profiles are never copied.
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
        guest 'set -eu; test "$(uname -s)/$(uname -m)" = Darwin/arm64; printf "%s\n" zay-desktop-macos | sudo -n tee /etc/zay-desktop-vm >/dev/null; mkdir -p ~/zay-desktop-vm'
        guest_ready
        if [[ "$vm_dns" == alidns ]]; then
        scp "${ssh_options[@]}" "$state/dns-target/release/devpane-be" "admin@$ip:zay-desktop-vm/zay-vm-dns.new"
        guest 'set -eu; test "$(cat /etc/zay-desktop-vm)" = zay-desktop-macos; cd ~/zay-desktop-vm; if test -f dns.pid; then pid=$(cat dns.pid); if test "$(ps -p "$pid" -o comm=)" = /usr/local/libexec/zay-vm-dns; then sudo -n kill "$pid"; fi; fi; sudo -n install -d /usr/local/libexec; sudo -n install -m 755 zay-vm-dns.new /usr/local/libexec/zay-vm-dns; sudo -n sh -c '\''cd /Users/admin/zay-desktop-vm; DEVPANE_ROLE=dns DEVPANE_BIND=127.0.0.1 DEVPANE_CONTROL_PORT=18092 DEVPANE_DOH=1 DEVPANE_IPV4_ONLY=1 nohup /usr/local/libexec/zay-vm-dns > dns.log 2>&1 < /dev/null & echo $! > dns.pid'\''; sudo -n networksetup -setdnsservers Ethernet 127.0.0.1; sudo -n dscacheutil -flushcache; sudo -n killall -HUP mDNSResponder'
        fi
        ditto -c -k --sequesterRsrc --keepParent "$desktop/dist/Zay Desktop.app" "$state/desktop.zip"
        scp "${ssh_options[@]}" "$state/desktop.zip" "admin@$ip:zay-desktop-vm/desktop.zip"
        # Deploy into the guest's Applications directory so Launch Services can
        # associate the background helper with Zay. Quit only this app first.
        guest '/usr/bin/osascript -e '\''tell application id "dev.zay.desktop" to quit'\'' >/dev/null 2>&1 || true'
        guest 'test "$(cat /etc/zay-desktop-vm)" = zay-desktop-macos && sudo -n ditto -x -k ~/zay-desktop-vm/desktop.zip /Applications && codesign --verify --strict "/Applications/Zay Desktop.app" && codesign --verify --strict "/Applications/Zay Desktop.app/Contents/Library/LaunchServices/dev.zay.desktop.helper"'
        guest 'open "/Applications/Zay Desktop.app"'
        echo "Zay Desktop is running in the dedicated macOS VM ($name)."
        echo 'Guest login and authorization password: admin (disposable lab account).'
        echo 'Host networking is unchanged. Use mise dev:desktop:logs for guest diagnostics.'
        open "vnc://admin@$ip"
        ;;
    open)
        guest_ready
        guest 'open "/Applications/Zay Desktop.app"'
        open "vnc://admin@$ip"
        ;;
    logs)
        guest_ready
        guest '/bin/launchctl print system/dev.zay.desktop.helper' > "$state/helper-status.log" 2>&1 || true
        guest 'sudo -n /usr/bin/log show --last 15m --style compact --predicate '\''process == "zay-desktop" OR process == "dev.zay.desktop.helper"'\'' --info' > "$state/helper.log" 2>&1
        echo "Guest diagnostics: $state/helper.log and $state/helper-status.log"
        tail -40 "$state/helper.log"
        ;;
    status) tart get "$name"; tart ip "$name" ;;
    stop) tart stop "$name" ;;
    *) echo "usage: $0 {up|open|logs|status|stop}" >&2; exit 2 ;;
esac
