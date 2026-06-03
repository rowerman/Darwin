#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-25-webhook-inject"
FLAG_DIR="/home/kianabin/cve-flags/k8s-25"

echo "[K8S-25] Tearing down..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf "$FLAG_DIR"
echo "[+] K8S-25 teardown complete"