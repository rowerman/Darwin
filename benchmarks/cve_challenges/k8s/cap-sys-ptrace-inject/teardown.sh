#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-19-ptrace"

echo "[*] Tearing down K8S-19 CAP_SYS_PTRACE..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already deleted"

# Clean up flag directory
rm -rf /home/kianabin/cve-flags/k8s-19 2>/dev/null || true

echo "[+] K8S-19 torn down"
