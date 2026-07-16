#!/usr/bin/env bash
# Build the KubeSentinel image and load it into the kind cluster.
#
# No registry involved. `kind load` pushes the image straight into the node's
# containerd, which is why the deployment uses imagePullPolicy: Never.
# (The EKS-based workshop apps push to a per-namespace registry instead — this
# project targets a local kind cluster, so it skips that entirely.)
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER_NAME="kubesentinel"
IMAGE="kubesentinel:latest"

echo "==> Building ${IMAGE}"
docker build -f "${REPO_DIR}/Containerfile" -t "${IMAGE}" "${REPO_DIR}"

echo "==> Image size"
docker images "${IMAGE}" --format '    {{.Size}}'

echo "==> Loading ${IMAGE} into kind cluster '${CLUSTER_NAME}'"
kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"

echo "==> Done. Deploy with: bash k8s/deploy.sh"
