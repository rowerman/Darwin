#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-k8s-20-ingress-rce"

FLAG="${CVE_FLAG:-flag{k8s-20-default}}"
FLAG_DIR="/home/kianabin/cve-flags/k8s-20"
mkdir -p "$FLAG_DIR"
echo "$FLAG" > "$FLAG_DIR/flag.txt"

echo "[K8S-20] CVE-2025-1974 ingress-nginx Admission Controller RCE"
echo "[*] Creating KIND cluster..."
kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

echo "[*] Waiting for cluster stabilization..."
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

echo "[*] Pre-loading container images into KIND..."
kind load docker-image nginx:1.24-alpine --name "$CLUSTER_NAME" 2>/dev/null || true
kind load docker-image registry.k8s.io/ingress-nginx/controller:v1.11.0 --name "$CLUSTER_NAME" 2>/dev/null || true
kind load docker-image registry.k8s.io/ingress-nginx/kube-webhook-certgen:v1.4.1 --name "$CLUSTER_NAME" 2>/dev/null || true

echo "[*] Deploying vulnerable ingress-nginx v1.11.0..."
# Deploy the ingress-nginx mandatory components (namespace, RBAC, etc.)
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.0/deploy/static/provider/kind/deploy.yaml

echo "[*] Waiting for ingress-nginx controller and certgen jobs to complete..."
kubectl wait --for=condition=Ready pods -l app.kubernetes.io/component=controller -n ingress-nginx --timeout=300s 2>/dev/null || true
# Also wait for certgen jobs to finish
kubectl wait --for=condition=Complete job/ingress-nginx-admission-create -n ingress-nginx --timeout=120s 2>/dev/null || true
kubectl wait --for=condition=Complete job/ingress-nginx-admission-patch -n ingress-nginx --timeout=120s 2>/dev/null || true
sleep 10

echo "[*] Exposing admission webhook as NodePort 30443..."
# Patch the admission webhook service to NodePort for external access
kubectl patch service ingress-nginx-controller-admission -n ingress-nginx -p '{"spec":{"type":"NodePort","ports":[{"name":"https-webhook","port":443,"targetPort":8443,"nodePort":30443}]}}' 2>/dev/null || true

echo "[*] Creating backend demo app..."
kubectl apply -f - << 'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-backend
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: demo-backend
  template:
    metadata:
      labels:
        app: demo-backend
    spec:
      containers:
        - name: backend
          image: nginx:1.24-alpine
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c"]
          args:
            - |
              echo 'backend is running' > /usr/share/nginx/html/index.html
              nginx -g 'daemon off;'
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: demo-backend
  namespace: default
spec:
  selector:
    app: demo-backend
  ports:
    - port: 80
      targetPort: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: demo-ingress
  namespace: default
spec:
  ingressClassName: nginx
  rules:
    - host: demo.local
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: demo-backend
                port:
                  number: 80
YAML

echo "[*] Placing flag in ingress-nginx controller pod..."
# Wait for the controller pod to be fully running
sleep 5
CONTROLLER_POD=$(kubectl get pods -n ingress-nginx -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n ingress-nginx "$CONTROLLER_POD" -- sh -c "echo '$FLAG' > /tmp/flag.txt" 2>/dev/null || {
  echo "[!] Could not write flag to controller pod, trying copy..."
  echo "$FLAG" | kubectl exec -n ingress-nginx -i "$CONTROLLER_POD" -- sh -c "cat > /tmp/flag.txt" 2>/dev/null || true
}

echo ""
echo "[+] K8S-20 IngressNightmare Ready"
echo "    Cluster: $CLUSTER_NAME"
echo "    Admission Webhook: https://localhost:10443/validate"
echo "    Flag directory: $FLAG_DIR"
echo "    Flag: $FLAG"
echo ""
echo "    Exploitation steps:"
echo "    1. Verify webhook access:"
echo "       curl -k https://localhost:10443/validate"
echo "    2. Craft malicious AdmissionReview payload (see docs/k8s-20)"
echo "    3. Send exploit to achieve RCE in ingress-nginx controller"
echo "    4. Read flag: cat /tmp/flag.txt (inside controller pod)"
echo ""
echo "    Note: CVE-2025-1974 allows unauthenticated RCE via the"
echo "    ValidatingWebhookConfiguration admission endpoint."