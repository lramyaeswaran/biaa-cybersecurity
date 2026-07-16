#!/usr/bin/env bash
# Deploy KubeSentinel to the kind cluster. Reads .env for the API key.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONTEXT="$(kubectl config current-context)"

if [ "$CONTEXT" != "kind-kubesentinel" ]; then
  echo "ERROR: current context is '${CONTEXT}', expected 'kind-kubesentinel'."
  echo "    Run: kubectl config use-context kind-kubesentinel"
  exit 1
fi

# --- Config from .env ---
if [ ! -f "${REPO_DIR}/.env" ]; then
  echo "ERROR: no .env file. Copy the example and add your key:"
  echo "    cp .env.example .env"
  exit 1
fi

set -a
# shellcheck disable=SC1091
source "${REPO_DIR}/.env"
set +a

LLM_PROVIDER="${LLM_PROVIDER:-groq}"

case "$LLM_PROVIDER" in
  groq)
    : "${GROQ_API_KEY:?ERROR: LLM_PROVIDER=groq but GROQ_API_KEY is not set in .env}"
    if [ "$GROQ_API_KEY" = "your-groq-api-key-here" ]; then
      echo "ERROR: GROQ_API_KEY is still the placeholder. Get one at https://console.groq.com"
      exit 1
    fi
    ;;
  ollama-cloud)
    : "${OLLAMA_API_KEY:?ERROR: LLM_PROVIDER=ollama-cloud but OLLAMA_API_KEY is not set in .env}"
    ;;
  ollama-local)
    echo "==> WARNING: LLM_PROVIDER=ollama-local"
    echo "    The pod cannot reach your laptop's localhost:11434 from inside the cluster."
    echo "    Use ollama-local for 'python app.py' on the host, not for the in-cluster deploy."
    ;;
esac
echo "==> Provider: ${LLM_PROVIDER}"

# --- Secret (built imperatively so keys never live in a committed manifest) ---
echo "==> Creating secret kubesentinel-secret"
kubectl create namespace kubesentinel --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create secret generic kubesentinel-secret \
  --namespace kubesentinel \
  --from-literal=LLM_PROVIDER="${LLM_PROVIDER}" \
  --from-literal=GROQ_API_KEY="${GROQ_API_KEY:-}" \
  --from-literal=OLLAMA_API_KEY="${OLLAMA_API_KEY:-}" \
  --dry-run=client -o yaml | kubectl apply -f -

# --- Manifests ---
echo "==> Applying RBAC (read-only)"
kubectl apply -f "${REPO_DIR}/k8s/rbac.yaml"

echo "==> Applying Deployment + Service"
kubectl apply -f "${REPO_DIR}/k8s/deployment.yaml"
kubectl apply -f "${REPO_DIR}/k8s/service.yaml"

echo "==> Restarting to pick up a freshly loaded image"
kubectl rollout restart deployment/kubesentinel -n kubesentinel >/dev/null

echo "==> Waiting for rollout"
if ! kubectl rollout status deployment/kubesentinel -n kubesentinel --timeout=150s; then
  echo ""
  echo "ERROR: rollout failed. Recent events:"
  kubectl get events -n kubesentinel --sort-by=.lastTimestamp | tail -10
  echo ""
  echo "Pod logs:"
  kubectl logs -n kubesentinel -l app=kubesentinel --tail=30 || true
  exit 1
fi

echo ""
echo "==> KubeSentinel deployed."
echo "    Local:     http://localhost:8080"
echo "    Codespace: check the PORTS tab for the forwarded 8080 URL (private by default)"
echo ""
echo "    Verify RBAC is genuinely read-only:"
echo "      kubectl auth can-i delete pods --as=system:serviceaccount:kubesentinel:kubesentinel -A"
