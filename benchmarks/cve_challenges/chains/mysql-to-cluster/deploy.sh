#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[Chain 7] MySQL UDF to K8s Cluster Admin — 4 steps, DB→Linux→K8s"

# Step 1: MySQL UDF web app (Docker)
echo "=== Step 1: WEB-08 MySQL UDF ==="
docker compose -f "$ROOT/docker/web/mysql-udf/docker-compose.yml" up -d --build 2>&1 | tail -3
echo "  [+] Web app at localhost:3002, MySQL at localhost:3306"

# Step 2: Linux PrivEsc (Vagrant)
echo "=== Step 2: LNX-01 nftables kernel exploit ==="
if command -v vagrant &>/dev/null; then
  (cd "$ROOT/docker/linux/nftables-cve-2024-1086" && vagrant up) &
  echo "  [+] LNX-01 VM starting (192.168.57.101)"
else
  echo "  [!] Vagrant not installed — manual start: cd $ROOT/docker/linux/nftables-cve-2024-1086 && vagrant up"
fi

# Steps 3-4: K8s (KIND)
echo "=== Steps 3-4: K8s RBAC + etcd ==="
CLUSTER_NAME="cve-chain7-k8s"
kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraPortMappings:
      - containerPort: 2379
        hostPort: 11379
KINDCFG

kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

kubectl create sa chain7-sa -n default
kubectl apply -f - << 'RBAC'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: chain7-secrets-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: chain7-binding
subjects:
  - kind: ServiceAccount
    name: chain7-sa
    namespace: default
roleRef:
  kind: ClusterRole
  name: chain7-secrets-reader
  apiGroup: rbac.authorization.k8s.io
RBAC

kubectl create secret generic chain7-rbac-flag --from-literal=flag="flag{chain7-step3-rbac}" -n kube-system
kubectl create secret generic chain7-final-flag --from-literal=flag="flag{chain7-step4-etcd-final}" -n kube-system

echo ""
echo "[Chain 7] Ready — 4 steps across DB→Linux→K8s"
