#!/bin/bash
# K8S-14: CAP_SYS_ADMIN cgroup Escape
set -euo pipefail
CLUSTER_NAME="cve-k8s-14-capsys"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FLAG="${CVE_FLAG:-flag{k8s-14-default}}"

mkdir -p /home/kianabin/cve-flags/k8s-14
echo "$FLAG" > /home/kianabin/cve-flags/k8s-14/flag.txt

kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"
docker pull alpine:latest 2>/dev/null
kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: capsys-pod
spec:
  containers:
    - name: escape
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        capabilities:
          add: ["SYS_ADMIN"]
      volumeMounts:
        - name: host-flag
          mountPath: /host-flag
        - name: cgroup
          mountPath: /sys/fs/cgroup
  volumes:
    - name: host-flag
      hostPath:
        path: /host-flag
        type: Directory
    - name: cgroup
      hostPath:
        path: /sys/fs/cgroup
YAML

echo "[+] K8S-14 ready"
echo "[+] Attack: mount cgroup → write release_agent → trigger escape → cat /host-flag/flag.txt"
