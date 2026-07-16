#!/usr/bin/env bash
# Delete the KubeSentinel kind cluster.
#
# Only ever touches the cluster named 'kubesentinel'. Other kind clusters on this
# machine are left alone.
set -euo pipefail

CLUSTER_NAME="kubesentinel"

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  echo "==> No cluster named '${CLUSTER_NAME}' — nothing to do."
  exit 0
fi

echo "==> Deleting kind cluster '${CLUSTER_NAME}'"
kind delete cluster --name "$CLUSTER_NAME"

echo "==> Done. Other kind clusters were not touched:"
kind get clusters 2>/dev/null | sed 's/^/    /' || echo "    (none)"
