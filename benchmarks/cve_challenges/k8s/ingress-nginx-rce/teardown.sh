#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-20-ingress-rce"
FLAG_DIR="/home/kianabin/cve-flags/k8s-20"

echo "[K8S-20] Tearing down..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf "$FLAG_DIR"
echo "[+] K8S-20 teardown complete"