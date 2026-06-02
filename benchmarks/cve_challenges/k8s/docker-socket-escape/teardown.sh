#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-17-docker-sock"

echo "[*] Tearing down K8S-17 Docker Socket Escape..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already deleted"

# Clean up flag directory
rm -rf /home/kianabin/cve-flags/k8s-17 2>/dev/null || true

echo "[+] K8S-17 torn down"
