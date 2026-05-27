#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-09-registry"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Start insecure private registry
docker rm -f k8s-registry 2>/dev/null || true
docker run -d --name k8s-registry --network host \
  -e REGISTRY_HTTP_TLS_ENABLED=false \
  registry:2.8.3

sleep 3

# Push a tagged nginx to the private registry
docker tag nginx:1.24-alpine localhost:5000/backdoored-nginx:latest
docker push localhost:5000/backdoored-nginx:latest 2>/dev/null || true

# Create KIND cluster
kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

# Deploy a pod using the private registry image
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: registry-target
  namespace: default
spec:
  containers:
    - name: app
      image: localhost:5000/backdoored-nginx:latest
      ports:
        - containerPort: 80
YAML

echo "[+] K8S-09 ready"
echo "[+] Private registry at localhost:5000 (no TLS)"
echo "[+] Attack: push malicious image → modify Deployment → lateral movement"
