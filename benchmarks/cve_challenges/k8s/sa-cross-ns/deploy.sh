#!/bin/bash
# K8S-13: SA Token Cross-Namespace Lateral Movement
set -euo pipefail
CLUSTER_NAME="cve-k8s-13-sa-cross"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FLAG="${CVE_FLAG:-flag{k8s-13-default}}"

kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"
docker pull alpine:latest 2>/dev/null
kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

# Create two namespaces
kubectl create ns ns-alpha --dry-run=client -o yaml | kubectl apply -f -
kubectl create ns ns-beta --dry-run=client -o yaml | kubectl apply -f -

# Flag in ns-beta (target namespace)
kubectl create secret generic flag-secret -n ns-beta --from-literal=flag="$FLAG"

# SA in ns-beta that can read secrets (the attacker discovers this token)
kubectl create sa target-reader -n ns-beta
kubectl create clusterrole secret-reader --verb=get --verb=list --resource=secrets
kubectl create clusterrolebinding beta-reader \
  --clusterrole=secret-reader --serviceaccount=ns-beta:target-reader

# Simulate compromised pod in ns-alpha with ns-beta SA token mounted
TOKEN=$(kubectl create token target-reader -n ns-beta)
kubectl create secret generic leaked-token -n ns-alpha --from-literal=token="$TOKEN"

# Attacker pod in ns-alpha (starts with no permissions)
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: ns-alpha
spec:
  containers:
    - name: shell
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      env:
        - name: LEAKED_TOKEN
          valueFrom:
            secretKeyRef:
              name: leaked-token
              key: token
YAML

echo "[+] K8S-13 ready"
echo "[+] Attack: discover leaked SA token in ns-alpha → use to read flag-secret in ns-beta"
