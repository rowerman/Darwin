#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-16-cri-socket"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Tearing down K8S-16 CRI Socket Escape..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already deleted"

# Clean up flag directory
rm -rf /home/kianabin/cve-flags/k8s-16 2>/dev/null || true

echo "[+] K8S-16 torn down"
