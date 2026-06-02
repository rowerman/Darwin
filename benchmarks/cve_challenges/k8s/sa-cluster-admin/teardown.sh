#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-18-sa-admin"

echo "[*] Tearing down K8S-18 SA Cluster-Admin..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already deleted"

echo "[+] K8S-18 torn down"
