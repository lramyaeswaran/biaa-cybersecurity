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
# Console scripts land in ~/.local/bin, which is not reliably on PATH. Use the module
# form everywhere (python -m uvicorn / python -m pytest) rather than depending on it.
python -c "import uvicorn, fastapi, langgraph, kubernetes" \
  && echo "    dependencies importable"

echo "==> Trying to raise inotify limits for kind"
# `sysctl -w fs.inotify.*` is PERMISSION DENIED inside a container even as root —
# the sysctl belongs to the host, and a Codespace is a container. So this is
# best-effort and MUST NOT abort: with `set -e`, a bare `sudo sysctl -w` here would
# fail the whole postCreate and leave you with a broken Codespace.
if sudo sysctl -w fs.inotify.max_user_instances=512 >/dev/null 2>&1; then
  sudo sysctl -w fs.inotify.max_user_watches=524288 >/dev/null 2>&1 || true
  echo "    raised"
else
  echo "    not permitted here (normal in a Codespace — the sysctl is the host's)."
  echo "    Current: $(sysctl -n fs.inotify.max_user_instances 2>/dev/null || echo '?') instances."
  echo "    One kind cluster usually fits. k8s/setup-cluster.sh will tell you if not."
fi

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
