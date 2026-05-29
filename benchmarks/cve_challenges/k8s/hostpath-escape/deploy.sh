#!/bin/bash
# K8S-12: hostPath Writable Mount Escape
set -euo pipefail
CLUSTER_NAME="cve-k8s-12-hostpath"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FLAG="${CVE_FLAG:-flag{k8s-12-default}}"

mkdir -p /home/kianabin/cve-flags/k8s-12
echo "$FLAG" > /home/kianabin/cve-flags/k8s-12/flag.txt

kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"
docker pull alpine:latest 2>/dev/null
kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-pod
spec:
  containers:
    - name: escape
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      volumeMounts:
        - name: host-log
          mountPath: /host-log
        - name: host-flag
          mountPath: /host-flag
  volumes:
    - name: host-log
      hostPath:
        path: /var/log
    - name: host-flag
      hostPath:
        path: /host-flag
        type: Directory
YAML

echo "[+] K8S-12 ready"
echo "[+] Attack: /host-log symlink → sensitive host file → read /host-flag/flag.txt"
