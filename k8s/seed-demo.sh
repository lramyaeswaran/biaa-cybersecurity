#!/usr/bin/env bash
# Seed the two demo namespaces KubeSentinel reasons about.
#
# vuln-demo is DELIBERATELY INSECURE: privileged container, host filesystem mount,
# a ServiceAccount bound to cluster-admin, fake cloud credentials, NodePort, no
# NetworkPolicy. It exists so the agent has something real to find.
#
# Only ever apply this to a local kind cluster. The guard below enforces that.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONTEXT="$(kubectl config current-context)"

# --- Refuse to seed deliberately-vulnerable workloads into a real cluster ---
case "$CONTEXT" in
  kind-kubesentinel) ;;
  *)
    echo "ERROR: refusing to seed vulnerable workloads into context '${CONTEXT}'."
    echo "    demo/vuln-demo.yaml creates a privileged pod with a cluster-admin token."
    echo "    It is only ever safe on the local kind cluster."
    echo "    Run: kubectl config use-context kind-kubesentinel"
    exit 1
    ;;
esac

echo "==> Applying demo/vuln-demo.yaml   (deliberately insecure)"
kubectl apply -f "${REPO_DIR}/demo/vuln-demo.yaml"

echo "==> Applying demo/safe-demo.yaml   (hardened contrast)"
kubectl apply -f "${REPO_DIR}/demo/safe-demo.yaml"

echo "==> Waiting for demo pods"
kubectl wait --for=condition=ready pod -l app=payments-api -n vuln-demo --timeout=90s || true
kubectl wait --for=condition=ready pod -l app=reports-api -n safe-demo --timeout=90s || true

echo "==> Demo namespaces seeded"
kubectl get pods -n vuln-demo -n vuln-demo 2>/dev/null || kubectl get pods -n vuln-demo
kubectl get pods -n safe-demo
