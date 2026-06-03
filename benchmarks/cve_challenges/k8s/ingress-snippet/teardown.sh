#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-21-ingress-snippet"
FLAG_DIR="/home/kianabin/cve-flags/k8s-21"

echo "[K8S-21] Tearing down..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf "$FLAG_DIR"
echo "[+] K8S-21 teardown complete"