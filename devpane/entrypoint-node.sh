#!/bin/sh
set -eu
data="${ZAY_DATA_DIR:-/var/lib/zay}"
mkdir -p "$data"
if [ ! -f "$data/zay.toml" ]; then
    sed "s/@DEVPANE_HOST@/${DEVPANE_HOST_ADDR:?}/g" /etc/zay/zay.toml > "$data/zay.toml"
fi
# Migrate only the old fixture subscription, preserving all other lab settings.
if grep -q 'http://172.30.126.10:8090/sub' "$data/zay.toml"; then
    cp "$data/zay.toml" "$data/zay.toml.before-host-proxy"
    sed "s|http://172.30.126.10:8090/sub|http://${DEVPANE_HOST_ADDR:?}:18090/sub|g" "$data/zay.toml" > "$data/zay.toml.next"
    mv "$data/zay.toml.next" "$data/zay.toml"
fi
# Preserve custom mixins when upgrading existing seeded lab configs.
if ! grep -Eq '^[[:space:]]*mixin[[:space:]]*=' "$data/zay.toml"; then
    cp "$data/zay.toml" "$data/zay.toml.before-lab-dns"
    awk 'FNR == NR { if (/^mixin =/) dns = $0; next } { print; if ($0 == "[proxy]") print dns }' /etc/zay/zay.toml "$data/zay.toml" > "$data/zay.toml.next"
    mv "$data/zay.toml.next" "$data/zay.toml"
fi
# Upgrade only the exact previous seed mixin; retain user-authored mixins.
legacy_dns=$(cat <<'EOF'
mixin = '{"dns":{"servers":[{"type":"udp","tag":"dns-direct","server":"172.30.126.10"},{"type":"udp","tag":"dns-direct-alt","server":"172.30.126.10"},{"type":"fakeip","tag":"fake-ip","inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"}]}}'
EOF
)
if [ "$(sed -n '/^mixin = /p' "$data/zay.toml")" = "$legacy_dns" ]; then
    cp "$data/zay.toml" "$data/zay.toml.before-lab-proxy-dns"
    awk 'FNR == NR { if (/^mixin =/) dns = $0; next } /^mixin =/ { print dns; next } { print }' /etc/zay/zay.toml "$data/zay.toml" > "$data/zay.toml.next"
    mv "$data/zay.toml.next" "$data/zay.toml"
fi
exec zay webui \
    --listen 0.0.0.0:8787 \
    --devpane-no-auth \
    --data-dir "$data" \
    --config "$data/zay.toml"
