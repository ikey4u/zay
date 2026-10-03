#!/bin/sh
set -eu
data="${ZAY_DATA_DIR:-/var/lib/zay}"
mkdir -p "$data"
if [ ! -f "$data/zay.toml" ]; then
    cp /etc/zay/zay.toml "$data/zay.toml"
fi
exec zay webui \
    --listen 0.0.0.0:8787 \
    --devpane-no-auth \
    --data-dir "$data" \
    --config "$data/zay.toml"
