#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-06-rbac"

kind create cluster --name "$CLUSTER_NAME" \
  --config "$(dirname "$0")/kind-config.yaml" 2>&1

echo "[+] KIND cluster $CLUSTER_NAME created"

# Flag in kube-system as a secret
FLAG="${CVE_FLAG:-flag{k8s-06-default}}"
kubectl create secret generic flag-secret \
  --namespace=kube-system \
  --from-literal=flag="$FLAG" 2>/dev/null || \
kubectl create secret generic flag-secret \
  --namespace=kube-system \
  --from-literal=flag="$FLAG" --dry-run=client -o yaml | kubectl apply -f -

# Create attacker ServiceAccount
kubectl create serviceaccount attacker-sa --namespace=default 2>/dev/null || true

# Create overly-permissive RBAC (read all secrets in all namespaces)
kubectl apply -f - << 'YAML'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secrets-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: attacker-secrets-binding
subjects:
  - kind: ServiceAccount
    name: attacker-sa
    namespace: default
roleRef:
  kind: ClusterRole
  name: secrets-reader
  apiGroup: rbac.authorization.k8s.io
YAML

# Create attacker pod with kubectl
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: default
spec:
  serviceAccountName: attacker-sa
  containers:
    - name: kubectl
      image: bitnami/kubectl:1.27
      command: ["sleep", "3600"]
YAML

echo "[+] Waiting for attacker-pod to be ready..."
kubectl wait --for=condition=Ready pod/attacker-pod --timeout=120s 2>/dev/null || true

echo "[+] K8S-06 ready"
echo "[+] To exploit: kubectl exec -it attacker-pod -- /bin/bash"
echo "[+] Then: kubectl get secret flag-secret -n kube-system -o jsonpath='{.data.flag}' | base64 -d"
echo "[+] Flag: $FLAG"
