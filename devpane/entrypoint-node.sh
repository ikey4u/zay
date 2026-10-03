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
exec zay webui \
    --listen 0.0.0.0:8787 \
    --devpane-no-auth \
    --data-dir "$data" \
    --config "$data/zay.toml"
