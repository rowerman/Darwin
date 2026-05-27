#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-10-helm"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

# Create Tiller ServiceAccount and ClusterRoleBinding
kubectl create serviceaccount tiller -n kube-system
kubectl create clusterrolebinding tiller-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=kube-system:tiller

# Install Helm v2 Tiller (in-cluster)
kubectl apply -f - << 'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tiller-deploy
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: tiller
  template:
    metadata:
      labels:
        app: tiller
    spec:
      serviceAccountName: tiller
      containers:
        - name: tiller
          image: ghcr.io/helm/tiller:v2.17.0
          ports:
            - containerPort: 44134
          command: ["/tiller"]
          env:
            - name: TILLER_NAMESPACE
              value: kube-system
---
apiVersion: v1
kind: Service
metadata:
  name: tiller-deploy
  namespace: kube-system
spec:
  selector:
    app: tiller
  ports:
    - port: 44134
      targetPort: 44134
YAML

FLAG="${CVE_FLAG:-flag{k8s-10-default}}"
kubectl create secret generic helm-flag --from-literal=flag="$FLAG" -n kube-system

echo "[+] K8S-10 ready"
echo "[+] Tiller at tiller-deploy.kube-system:44134 (no auth)"
echo "[+] Attack: helm --host tiller-deploy.kube-system:44134 ls --all"
