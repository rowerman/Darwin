#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
echo "[Chain 3] WordPress to K8s — 7 steps, 4 domains (longest chain)"

# Step 1: WordPress (Docker)
echo "=== Step 1: WEB-03 WordPress ==="
CVE_FLAG="flag{chain3-step1-wp}" docker compose -f "$ROOT/docker/web/wordpress-simple-file-list/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] WordPress at http://localhost:8080"

# Step 2: MySQL DB (Docker)
echo "=== Step 2: DB-02 MySQL ==="
docker compose -f "$ROOT/docker/db/mysql-udf-direct/docker-compose.yml" up -d 2>&1 | tail -2
echo "  [+] MySQL at localhost:3306 (root:password123)"
docker exec mysql-udf-direct-mysql-1 bash -c 'echo "flag{chain3-step2-mysql}" > /flag.txt' 2>/dev/null || \
  echo "  [!] MySQL container may need a moment to initialize"

# Step 3: Linux PrivEsc (Vagrant)
echo "=== Step 3: LNX-02 nftables pipapo ==="
if command -v vagrant &>/dev/null; then
  (cd "$ROOT/docker/linux/nftables-cve-2024-26809" && vagrant up) &
  echo "  [+] Vagrant VM at 192.168.57.102"
else
  echo "  [!] Vagrant not installed — config at docker/linux/nftables-cve-2024-26809/Vagrantfile"
fi

# Step 4-5: K8s (KIND)
echo "=== Steps 4-5: K8S RBAC + Container Escape ==="
CLUSTER_NAME="cve-chain3-k8s"
kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraMounts:
      - hostPath: /home/kianabin/cve-flags/chain3-flags
        containerPath: /chain-flags
KINDCFG

kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

# RBAC flag
kubectl create secret generic chain3-rbac-flag \
  --from-literal=flag="flag{chain3-step4-rbac}" -n kube-system

kubectl create serviceaccount chain3-sa -n default
kubectl apply -f - << 'YAML'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: chain3-secrets-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: chain3-binding
subjects:
  - kind: ServiceAccount
    name: chain3-sa
    namespace: default
roleRef:
  kind: ClusterRole
  name: chain3-secrets-reader
  apiGroup: rbac.authorization.k8s.io
YAML

# Final escape flag on host
mkdir -p /home/kianabin/cve-flags/chain3-flags
echo "flag{chain3-step5-escape-final}" > /home/kianabin/cve-flags/chain3-flags/flag.txt

echo ""
echo "[Chain 3] Ready — 7 steps across 4 domains"
echo "  Step 1: WEB-03 → RCE → flag{chain3-step1-wp}"
echo "  Step 2: MySQL root → UDF → flag{chain3-step2-mysql}"
echo "  Step 3: LNX-02 priv esc → root → flag{chain3-step3-privesc}"
echo "  Step 4: K8s RBAC → read secrets → flag{chain3-step4-rbac}"
echo "  Step 5: Container escape → /chain-flags/flag.txt → FINAL"
