#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-24-localhost-bypass"
FLAG_DIR="/home/kianabin/cve-flags/k8s-24"

echo "[K8S-24] Tearing down..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf "$FLAG_DIR"
echo "[+] K8S-24 teardown complete"