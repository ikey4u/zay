#!/bin/sh
set -eu
exec zay x run proxy \
    --no-tun \
    --mesh relay \
    --mesh-auth "${DEVPANE_MESH_AUTH:?DEVPANE_MESH_AUTH is required}" \
    --mesh-ip "${DEVPANE_MESH_IP:-10.126.126.1/24}"
