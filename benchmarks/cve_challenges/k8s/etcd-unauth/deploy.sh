#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-08-etcd"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

# Store flag as a Kubernetes Secret
FLAG="${CVE_FLAG:-flag{k8s-08-default}}"
kubectl create secret generic etcd-flag --from-literal=flag="$FLAG" -n kube-system

echo "[+] K8S-08 ready"
echo "[+] etcd exposed at localhost:2379 (no auth)"
echo "[+] Attack: etcdctl --endpoints=http://localhost:2379 get /registry/secrets/kube-system/etcd-flag"
