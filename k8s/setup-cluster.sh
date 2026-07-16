#!/usr/bin/env bash
# Create the KubeSentinel kind cluster and seed the demo namespaces.
#
# The preflight checks below are not defensive padding. Both of them are failures
# we actually hit building this on a current Linux box, and both produce error
# messages that tell you nothing about the real cause:
#
#   1. kind < 0.32 cannot create a cluster on Docker 27+. It fails with
#      "could not find a log line that matches Reached target Multi-User System".
#   2. fs.inotify.max_user_instances defaults to 128. A running kind cluster eats
#      most of them, so the SECOND cluster's API server never bootstraps and you
#      get "context deadline exceeded" from kubeadm.
#
# If you are in a Codespace or on a fresh laptop, you will hit at least one of these.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER_NAME="kubesentinel"
MIN_KIND_VERSION="0.32.0"
TRIVY_VERSION="0.72.0"

echo "==> Preflight"

# --- kind present and new enough ---
if ! command -v kind >/dev/null 2>&1; then
  echo "ERROR: kind is not installed."
  echo "    Install: https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
  exit 1
fi

KIND_VERSION="$(kind --version | awk '{print $3}')"
if [ "$(printf '%s\n%s\n' "$MIN_KIND_VERSION" "$KIND_VERSION" | sort -V | head -1)" != "$MIN_KIND_VERSION" ]; then
  echo "ERROR: kind $KIND_VERSION is too old — need >= $MIN_KIND_VERSION."
  echo "    kind < 0.32 cannot create clusters on Docker 27+. It fails with a"
  echo "    misleading 'Reached target Multi-User System' error."
  echo "    Upgrade: curl -Lo /usr/local/bin/kind https://kind.sigs.k8s.io/dl/v${MIN_KIND_VERSION}/kind-linux-amd64 && chmod +x /usr/local/bin/kind"
  exit 1
fi
echo "    kind $KIND_VERSION"

# --- docker up ---
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker is not running or not reachable."
  exit 1
fi
echo "    docker $(docker info --format '{{.ServerVersion}}')"

# --- trivy on the host ---
# The deployed app carries its own trivy in the image, so this is not needed to
# DEPLOY. It is needed to run the app locally (`uvicorn app:app`) and to do Part 2
# of the lab, which compares raw scanner output against the agent's ranking.
if command -v trivy >/dev/null 2>&1; then
  echo "    trivy $(trivy --version 2>/dev/null | head -1 | awk '{print $2}')"
else
  echo "    trivy NOT installed (optional)"
  echo "        The deployed app is unaffected - it has trivy in its image."
  echo "        You need it on the host only for local dev and lab Part 2:"
  echo "          curl -sSL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz | sudo tar xz -C /usr/local/bin trivy"
fi

# --- inotify headroom ---
WANT_INSTANCES=512
WANT_WATCHES=524288
HAVE_INSTANCES="$(sysctl -n fs.inotify.max_user_instances)"
if [ "$HAVE_INSTANCES" -lt "$WANT_INSTANCES" ]; then
  echo "    inotify instances = $HAVE_INSTANCES (too low; kind needs headroom)"
  if sudo -n true 2>/dev/null; then
    sudo sysctl -w fs.inotify.max_user_instances=$WANT_INSTANCES >/dev/null
    sudo sysctl -w fs.inotify.max_user_watches=$WANT_WATCHES >/dev/null
    echo "    raised to $WANT_INSTANCES / $WANT_WATCHES (runtime only — reverts on reboot)"
  else
    echo ""
    echo "ERROR: need sudo to raise the inotify limit, and passwordless sudo is unavailable."
    echo "    Run this yourself, then re-run this script:"
    echo "      sudo sysctl -w fs.inotify.max_user_instances=$WANT_INSTANCES"
    echo "      sudo sysctl -w fs.inotify.max_user_watches=$WANT_WATCHES"
    echo ""
    echo "    Without this, the cluster's API server will fail to start and kubeadm"
    echo "    will report a misleading 'context deadline exceeded'."
    exit 1
  fi
else
  echo "    inotify instances = $HAVE_INSTANCES (ok)"
fi

# --- Cluster ---
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  echo "==> Cluster '$CLUSTER_NAME' already exists — reusing it"
else
  echo "==> Creating kind cluster '$CLUSTER_NAME'"
  kind create cluster --config "${REPO_DIR}/k8s/kind-cluster.yaml" --wait 150s
fi

kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null
echo "==> Context set to kind-${CLUSTER_NAME}"
kubectl get nodes

echo "==> Seeding demo namespaces"
bash "${REPO_DIR}/k8s/seed-demo.sh"

echo ""
echo "==> Cluster ready."
echo "    Next: bash k8s/build-and-load.sh && bash k8s/deploy.sh"
