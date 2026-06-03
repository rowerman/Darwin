#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-22-externalip"
FLAG_DIR="/home/kianabin/cve-flags/k8s-22"

echo "[K8S-22] Tearing down..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf "$FLAG_DIR"
echo "[+] K8S-22 teardown complete"