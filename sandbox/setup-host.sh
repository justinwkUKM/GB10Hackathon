#!/usr/bin/env bash
# One-time host setup (DGX Spark, arm64; also works on x86_64):
#   1. install gVisor's runsc and register it with Docker
#   2. create the internal models network and attach the vLLM container to it
#
#   sudo is used for installing binaries and restarting Docker.
#   VLLM_CONTAINER=<name> sandbox/setup-host.sh   # also attaches vLLM
set -euo pipefail
MODELS_NETWORK="${MODELS_NETWORK:-dgx_models}"

if ! command -v runsc >/dev/null; then
  arch="$(uname -m)"   # aarch64 on the Spark
  url="https://storage.googleapis.com/gvisor/releases/release/latest/$arch"
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  echo "installing runsc ($arch)"
  for f in runsc containerd-shim-runsc-v1; do
    curl -fsSL -o "$tmp/$f" "$url/$f"
    curl -fsSL -o "$tmp/$f.sha512" "$url/$f.sha512"
  done
  (cd "$tmp" && sha512sum -c runsc.sha512 -c containerd-shim-runsc-v1.sha512)
  chmod a+rx "$tmp/runsc" "$tmp/containerd-shim-runsc-v1"
  sudo mv "$tmp/runsc" "$tmp/containerd-shim-runsc-v1" /usr/local/bin/
fi

if ! docker info --format '{{json .Runtimes}}' | grep -q '"runsc"'; then
  echo "registering runsc with Docker and restarting it"
  sudo /usr/local/bin/runsc install
  sudo systemctl restart docker
fi

if ! docker network inspect "$MODELS_NETWORK" >/dev/null 2>&1; then
  docker network create --internal "$MODELS_NETWORK" >/dev/null
  echo "created internal network $MODELS_NETWORK"
fi

if [[ -n "${VLLM_CONTAINER:-}" ]]; then
  docker network connect --alias vllm "$MODELS_NETWORK" "$VLLM_CONTAINER" 2>/dev/null \
    && echo "attached $VLLM_CONTAINER to $MODELS_NETWORK as 'vllm'" \
    || echo "$VLLM_CONTAINER already attached to $MODELS_NETWORK (or not running)"
else
  echo "attach vLLM with: docker network connect --alias vllm $MODELS_NETWORK <vllm-container>"
fi

echo "checking gVisor:"
docker run --rm --runtime=runsc alpine dmesg | head -3
