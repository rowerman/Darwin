#!/bin/bash
# K8S-15: Mutable Image Tag Supply Chain Attack
set -euo pipefail
CLUSTER_NAME="cve-k8s-15-image-tag"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FLAG="${CVE_FLAG:-flag{k8s-15-default}}"

# Start local registry
docker compose -f "$SCRIPT_DIR/registry-compose.yml" up -d 2>/dev/null || true

kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

# Deploy with mutable tag + Always pull
kubectl apply -f - << 'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable-app
  template:
    metadata:
      labels:
        app: vulnerable-app
    spec:
      containers:
        - name: app
          image: nginx:1.24-alpine
          imagePullPolicy: Always
          env:
            - name: FLAG
              value: "${CVE_FLAG}"
YAML

kubectl create configmap app-config --from-literal=flag="$FLAG"

echo "[+] K8S-15 ready"
echo "[+] Attack: push malicious image with same tag → trigger redeploy → read configmap → get flag"
echo "[+] Flag: $FLAG (in configmap app-config)"
