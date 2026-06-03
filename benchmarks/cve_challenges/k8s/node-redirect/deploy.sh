#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-k8s-26-node-redirect"

FLAG="${CVE_FLAG:-flag{k8s-26-default}}"
FLAG_DIR="/home/kianabin/cve-flags/k8s-26"
mkdir -p "$FLAG_DIR"
echo "$FLAG" > "$FLAG_DIR/flag.txt"

echo "[K8S-26] CVE-2020-8559 Compromised Node API Server Redirect"
echo "[*] Creating KIND cluster..."
kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

echo "[*] Waiting for cluster stabilization..."
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true

echo "[*] Pre-loading container images into KIND..."
for img in alpine:latest nginx:1.24-alpine; do
  kind load docker-image $img --name "$CLUSTER_NAME" 2>/dev/null || true
done
sleep 10

echo "[*] Setting up victim pod with flag..."
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: secure-ns
---
# Victim pod containing the flag
apiVersion: v1
kind: Pod
metadata:
  name: victim-pod
  namespace: secure-ns
spec:
  containers:
    - name: app
      image: nginx:1.24-alpine
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c"]
      args:
        - |
          echo 'FLAG_PLACEHOLDER' > /flag.txt
          nginx -g 'daemon off;'
      ports:
        - containerPort: 80
---
# Compromised node simulation - attacker pod with node-like access
apiVersion: v1
kind: ServiceAccount
metadata:
  name: node-operator
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: node-operator
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "patch", "update"]
  - apiGroups: [""]
    resources: ["nodes/proxy"]
    verbs: ["get", "create"]
  - apiGroups: [""]
    resources: ["pods/exec", "pods/attach"]
    verbs: ["create", "get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: node-operator
subjects:
  - kind: ServiceAccount
    name: node-operator
    namespace: default
roleRef:
  kind: ClusterRole
  name: node-operator
  apiGroup: rbac.authorization.k8s.io
---
# Attacker pod simulating a compromised node
apiVersion: v1
kind: Pod
metadata:
  name: compromised-node
  namespace: default
spec:
  serviceAccountName: node-operator
  hostNetwork: true
  containers:
    - name: attacker
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        privileged: false
        runAsUser: 0
YAML

echo "[*] Injecting flag into victim pod..."
kubectl wait --for=condition=Ready pod/victim-pod -n secure-ns --timeout=60s 2>/dev/null || true
kubectl wait --for=condition=Ready pod/compromised-node --timeout=60s 2>/dev/null || true
sleep 5

kubectl exec -n secure-ns victim-pod -- sh -c "echo '$FLAG' > /flag.txt" 2>/dev/null || true

NODE_NAME=$(kubectl get node -o jsonpath='{.items[0].metadata.name}')
echo ""
echo "[+] K8S-26 Node API Redirect Ready"
echo "    Cluster: $CLUSTER_NAME"
echo "    Victim pod: victim-pod in secure-ns namespace"
echo "    Node name: $NODE_NAME"
echo "    Flag in victim pod: /flag.txt"
echo "    Flag: $FLAG"
echo ""
echo "    Exploitation steps:"
echo "    1. The attacker pod has node-like RBAC (nodes/proxy, pods/exec)"
echo "    2. CVE-2020-8559: API server follows redirects on upgrade requests"
echo "    3. From the compromised-node pod, use the node proxy endpoint:"
echo "       TOKEN=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
echo "       curl -k -H \"Authorization: Bearer \$TOKEN\" \\"
echo "         https://kubernetes.default.svc/api/v1/nodes/${NODE_NAME}/proxy/pods"
echo "    4. Exploit the redirect to exec into victim-pod:"
echo "       kubectl exec -n secure-ns victim-pod -- cat /flag.txt"
echo ""
echo "    Note: This scenario simulates a compromised node that can redirect"
echo "    API server requests to access other pods."