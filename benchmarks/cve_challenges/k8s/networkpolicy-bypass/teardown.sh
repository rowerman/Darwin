#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-27-netpol-bypass"
FLAG_DIR="/home/kianabin/cve-flags/k8s-27"

echo "[K8S-27] Tearing down..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf "$FLAG_DIR"
echo "[+] K8S-27 teardown complete"