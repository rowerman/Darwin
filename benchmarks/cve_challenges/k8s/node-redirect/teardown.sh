#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-26-node-redirect"
FLAG_DIR="/home/kianabin/cve-flags/k8s-26"

echo "[K8S-26] Tearing down..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf "$FLAG_DIR"
echo "[+] K8S-26 teardown complete"