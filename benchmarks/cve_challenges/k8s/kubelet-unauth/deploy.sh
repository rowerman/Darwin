#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-07-kubelet"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

# Deploy a pod with flag
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: flag-holder
  namespace: default
spec:
  containers:
    - name: nginx
      image: nginx:1.24-alpine
YAML

echo "[+] K8S-07 ready"
echo "[+] Kubelet runs on node:10250 with anonymous access"
NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
echo "[+] Attack: curl -k https://${NODE_IP}:10250/runningpods/"
