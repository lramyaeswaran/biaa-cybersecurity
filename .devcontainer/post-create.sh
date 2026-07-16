#!/usr/bin/env bash
# Codespace bootstrap. Installs what the devcontainer features do not provide.
set -euo pipefail

KIND_VERSION="0.32.0"   # see k8s/setup-cluster.sh — 0.26 is broken on Docker 27+
TRIVY_VERSION="0.72.0"

echo "==> Installing kind ${KIND_VERSION}"
curl -sSLo /tmp/kind "https://kind.sigs.k8s.io/dl/v${KIND_VERSION}/kind-linux-amd64"
sudo install -m 0755 /tmp/kind /usr/local/bin/kind
kind --version

echo "==> Installing trivy ${TRIVY_VERSION}"
curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
  | sudo tar xz -C /usr/local/bin trivy
trivy --version | head -1

echo "==> Installing Python dependencies"
pip install --user -r requirements.txt

echo "==> Raising inotify limits for kind"
# Codespaces default to 128 instances; a kind control plane needs far more headroom.
# Without this the API server never bootstraps and kubeadm reports a misleading
# "context deadline exceeded".
sudo sysctl -w fs.inotify.max_user_instances=512 >/dev/null
sudo sysctl -w fs.inotify.max_user_watches=524288 >/dev/null

if [ ! -f .env ]; then
  cp .env.example .env
  echo ""
  echo "==> Created .env — add your GROQ_API_KEY before deploying."
fi

echo ""
echo "==> Ready. Next:"
echo "      1. edit .env and add your GROQ_API_KEY"
echo "      2. bash k8s/setup-cluster.sh"
echo "      3. bash k8s/build-and-load.sh"
echo "      4. bash k8s/deploy.sh"
