#!/usr/bin/env bash
# Invoked by manage.sh inside the mise-managed tool environment.
set -euo pipefail

devpane="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
action="${1:-up}"
profile="zay-devpane"

# Keep plugin links and Docker client state local to the lab. In particular,
# do not overwrite ~/.docker/config.json or change the user's active context.
export DOCKER_CONFIG="${devpane}/.build/docker"
mkdir -p "${DOCKER_CONFIG}/cli-plugins"
ln -sfn "$(command -v docker-cli-plugin-docker-compose)" "${DOCKER_CONFIG}/cli-plugins/docker-compose"
ln -sfn "$(command -v docker-cli-plugin-docker-buildx)" "${DOCKER_CONFIG}/cli-plugins/docker-buildx"
unset DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH
export COLIMA_HOME="${COLIMA_HOME:-${HOME}/.colima}"
export DOCKER_HOST="unix://${COLIMA_HOME}/${profile}/docker.sock"

# Only `up` starts a VM. Inspection and teardown must not start one by accident.
if [[ "${action}" == up ]] && ! colima --profile "${profile}" status >/dev/null 2>&1; then
  echo "starting the devpane Colima VM"
  colima --profile "${profile}" start --runtime docker --vm-type vz --activate=false \
    --cpus "${DEVPANE_VM_CPUS:-4}" \
    --memory "${DEVPANE_VM_MEMORY:-8}" \
    --disk "${DEVPANE_VM_DISK:-60}"
fi

docker compose version >/dev/null
docker buildx version >/dev/null
export DEVPANE_MACOS_READY=1
exec bash "${devpane}/be/manage.sh" "${action}"
