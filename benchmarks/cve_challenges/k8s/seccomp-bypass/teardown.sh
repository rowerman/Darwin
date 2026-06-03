#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-23-seccomp-bypass"
FLAG_DIR="/home/kianabin/cve-flags/k8s-23"

echo "[K8S-23] Tearing down..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf "$FLAG_DIR"
echo "[+] K8S-23 teardown complete"