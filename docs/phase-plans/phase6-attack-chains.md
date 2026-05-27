# Phase 6: 攻击链编排 (2天)

> **Phase 1+2 修正**: 攻击链中每个 Docker 节点必须包含 flag 文件。预构建镜像需 Dockerfile 包装添加 flag。链 deploy.sh 需在启动时注入各节点中间 flag。
> **Phase 4 修正**: K8s 节点在链 deploy.sh 中必须加 `kubectl wait` 等待集群就绪。`kind load docker-image` 必须在 `kind create cluster` 之后、`kubectl apply` 之前执行。runC 逃逸场景 (K8S-01/02/03) 在 KIND 容器嵌套环境中受限于宿主机内核，链中使用这些场景需标注 bare metal 要求。

## 目标

完成 3 条 MVP 攻击链的环境互联配置，使多个场景在一个 Docker network / 混合网络中协作。

---

## 前置检查

```bash
# 确认 Phase 1-4 已完成至少 15 个独立场景
ls benchmarks/cve_challenges/scripts/scenarios.yaml
grep -c "id:" benchmarks/cve_challenges/scripts/scenarios.yaml 2>/dev/null || python3 -c "
import yaml
d=yaml.safe_load(open('benchmarks/cve_challenges/scripts/scenarios.yaml'))
print(f'Scenarios registered: {len(d[\"scenarios\"])}')
"
```

---

## 攻击链网络拓扑设计

### Chain 1: "Web to Domain Admin" (AD-Chain-1)

```
  INTERNET (攻击者)
    │
    ├─> WEB-03 (WordPress) [docker, 10.0.1.10]
    │     └─> RCE → 反弹 Shell
    │          │
    │          ├─> LNX-01 (nftables 提权) [docker, 10.0.1.20]
    │          │     └─> root → 内网扫描
    │          │          │
    │          │          ├─> AD-01 (Kerberoasting) [GOAD, 192.168.56.10]
    │          │          │     └─> svc_sql TGS → 破解
    │          │          │          │
    │          │          ├─> AD-05 (Pass-the-Hash) [GOAD, 192.168.56.11]
    │          │          │     └─> 横向移动
    │          │          │          │
    │          │          └─> AD-09 (DCSync) [GOAD, 192.168.56.10]
    │          │                └─> Domain Admin → FINAL FLAG
    │
    共 6 步, 3 个领域
```

### Chain 2: "Container Escape to Cluster Admin" (K8s-Chain-1)

```
  K8S-06 (RBAC 滥用) [KIND, localhost]
    └─> secrets-reader ClusterRole → 读取 ServiceAccount token
         │
         ├─> K8S-01 (runC 逃逸) [KIND, localhost]
         │     └─> WORKDIR=/proc/self/fd/7 → 宿主机文件系统
         │          │
         └─> K8S-08 (etcd 未授权) [KIND, localhost:2379]
               └─> etcd 读取 Secret → 集群完全控制 → FINAL FLAG

  共 4 步, 纯 K8s
```

### Chain 3: "WordPress to K8s" (Cross-Chain-2)

```
  WEB-03 (WordPress) [docker, 10.0.2.10]
    └─> RCE → wp-config.php 凭据
         │
         ├─> DB-02 (MySQL UDF) [docker, 10.0.2.20]
         │     └─> MySQL root 密码 → UDF 命令执行
         │          │
         ├─> LNX-02 (nftables pipapo) [vagrant, 192.168.57.102]
         │     └─> root → .kube/config 发现
         │          │
         ├─> K8S-06 (RBAC 滥用) [KIND, localhost]
         │     └─> list secrets → 高权限 SA token
         │          │
         └─> K8S-01 (runC 逃逸) [KIND, localhost]
               └─> 宿主机 → FINAL FLAG

  共 7 步, 4 个领域 — 最长攻击链
```

---

## Day 1: Chain 1 + Chain 2

### Chain 1 配置: `chains/web-to-da/`

```bash
mkdir -p benchmarks/cve_challenges/chains/web-to-da
```

**docker-compose.chain.yml** (仅启动 Docker 部分，GOAD 手动启动):
```yaml
# chains/web-to-da/docker-compose.chain.yml
services:
  web:
    extends:
      file: ../../docker/web/wordpress-simple-file-list/docker-compose.yml
      service: wordpress
    networks:
      chain-net:
        ipv4_address: 10.0.1.10

  linux:
    extends:
      file: ../../docker/linux/../... (Vagrant, 不由 compose 管理)
    # Linux VM 使用 Vagrant 独立启动

networks:
  chain-net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.1.0/24
```

**deploy.sh**:
```bash
#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[Chain 1] Web to Domain Admin"
echo "=== Step 1: Start WEB-03 ==="
docker compose -f "${SCRIPT_DIR}/docker-compose.chain.yml" up -d

echo "=== Step 2: Ensure LNX-01 is running ==="
cd "${SCRIPT_DIR}/../../docker/linux/nftables-cve-2024-1086"
vagrant up

echo "=== Step 3: Ensure GOAD AD environment is running ==="
cd ~/GOAD
vagrant up

echo "=== Chain 1 ready ==="
echo "Attack sequence: WEB-03 → LNX-01 → AD-01 → AD-05 → AD-09"
echo "Intermediate flags at each step"
```

**deploy.sh** 在启动时注入中间节点 flag:
```bash
# 每个中间节点有独立 flag
# WEB-03 flag → /flag.txt (web layer)
# LNX-01 flag → /root/flag_lnx01.txt
# AD-01 flag → AD user svc_sql description
# AD-05 flag → C:\Users\Public\flag_pth.txt on member server
# AD-09 flag → FINAL: Domain Admin NTLM hash or flag on DC
```

---

### Chain 2 配置: `chains/container-to-admin/`

全部在 K8s 生命周期内，部署简单：

```bash
mkdir -p benchmarks/cve_challenges/chains/container-to-admin

cat > benchmarks/cve_challenges/chains/container-to-admin/deploy.sh << 'SCRIPT'
#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-chain-k8s-admin"

# 1. 创建 KIND 集群（同时配置 etcd 端口暴露 + RBAC 宽松 + 旧 runC）
kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraPortMappings:
      - containerPort: 2379
        hostPort: 2379
KINDCONFIG

# 2. 部署 RBAC 滥用 (K8S-06)
kubectl apply -f - << 'RBAC'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secrets-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: attacker-binding
subjects:
  - kind: ServiceAccount
    name: attacker-sa
    namespace: default
roleRef:
  kind: ClusterRole
  name: secrets-reader
  apiGroup: rbac.authorization.k8s.io
RBAC

# 3. 部署 attacker pod
kubectl create serviceaccount attacker-sa

# 4. 注入中间 flag
STAGE1_FLAG="flag{chain2-stage1-rbac}"
STAGE2_FLAG="flag{chain2-stage2-escape}"
STAGE3_FLAG="flag{chain2-stage3-etcd-final}"

kubectl create secret generic stage1-flag --from-literal=flag="$STAGE1_FLAG" -n kube-system
mkdir -p /tmp/chain-flags
echo "$STAGE2_FLAG" > /tmp/chain-flags/stage2.txt
echo "$STAGE3_FLAG" > /tmp/chain-flags/stage3.txt

kubectl apply -f - << 'POD'
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
spec:
  serviceAccountName: attacker-sa
  containers:
    - name: kubectl
      image: bitnami/kubectl:1.27
      command: ["sleep", "infinity"]
POD

echo "[Chain 2] Container to Admin ready"
echo "Stage 1: kubectl get secret stage1-flag -n kube-system"
echo "Stage 2: Container escape → /tmp/chain-flags/stage2.txt (on host)"
echo "Stage 3: etcdctl get /registry/secrets/... → stage3 flag"
SCRIPT
```

---

## Day 2: Chain 3 + 链部署脚本模板

### Chain 3 配置: `chains/wordpress-to-k8s/`

这是最复杂的链（7 步 4 领域），需要 Docker Compose + Vagrant + KIND 协同：

```bash
mkdir -p benchmarks/cve_challenges/chains/wordpress-to-k8s
```

**deploy.sh**:
```bash
#!/bin/bash
set -euo pipefail

echo "[Chain 3] WordPress to K8s (7 steps, 4 domains)"

# Node 1: WordPress (Docker)
echo "=== Node 1: WordPress WEB-03 ==="
docker compose -f ../../docker/web/wordpress-simple-file-list/docker-compose.yml up -d
WEB03_FLAG="flag{chain3-node1-wp}"
# ... 注入 flag

# Node 2: MySQL DB (Docker)
echo "=== Node 2: MySQL DB-02 ==="
docker compose -f ../../docker/db/mysql-udf-direct/docker-compose.yml up -d
DB02_FLAG="flag{chain3-node2-mysql}"

# Node 3: Linux PrivEsc (Vagrant)
echo "=== Node 3: Linux LNX-02 ==="
cd ../../docker/linux/nftables-cve-2024-26809
LNX02_FLAG="flag{chain3-node3-privesc}" vagrant up
cd -

# Node 4: K8s RBAC + Escape (KIND)
echo "=== Nodes 4-5: K8S-06 + K8S-01 ==="
kind create cluster --name cve-chain3-k8s
kubectl create secret generic wp-secrets --from-literal=password='reused_k8s_pass_12345' -n kube-system
FINAL_FLAG="flag{chain3-final-k8s-escape}"
echo "$FINAL_FLAG" > /tmp/chain3-final-flag.txt

echo "[Chain 3] Ready. Total 7 steps."
```

---

### 通用攻击链脚本模板

为简化后续 Phase 2 扩展中 11 条额外链的部署，创建通用模板：

```bash
# chains/_template/deploy.sh
#!/bin/bash
# 通用攻击链部署模板
set -euo pipefail

CHAIN_NAME="${1:-$(basename "$(dirname "$0")")}"
CHAIN_CONFIG="${CHAIN_NAME}.yaml"

python3 -c "
import yaml, subprocess, os

with open('$CHAIN_CONFIG') as f:
    config = yaml.safe_load(f)

for node in config['nodes']:
    scenario_id = node['scenario']
    print(f'[Chain] Starting {scenario_id}')
    subprocess.run(['../../scripts/start-scenario.sh', scenario_id], check=True)
"
```

**chain 配置文件格式** (如 `web-to-da.yaml`):
```yaml
name: "Web to Domain Admin"
chain_id: AD-Chain-1
steps: 6
nodes:
  - scenario: web-03
    flag: "flag{chain1-step1-wp}"
    next_hint: "Enumerate the internal network on this host"
  - scenario: lnx-01
    flag: "flag{chain1-step2-privesc}"
    next_hint: "Scan for AD domain controllers in 192.168.56.0/24"
  - scenario: ad-01
    flag: "flag{chain1-step3-kerberoast}"
    next_hint: "Use the cracked credentials to move laterally"
  - scenario: ad-05
    flag: "flag{chain1-step4-pth}"
    next_hint: "With higher privileges, extract domain hashes"
  - scenario: ad-09
    flag: "flag{chain1-step5-final}"
    next_hint: null
```

---

## 验证清单

```bash
cd /home/kianabin/Darwin/benchmarks/cve_challenges/chains

echo "=== Chain 1: Web to Domain Admin ==="
cd web-to-da && bash deploy.sh
# 手动按链路径攻击:
# step 1: curl WEB-03 → RCE
# step 2: SSH to LNX-01 → priv esc
# step 3: impacket-GetUserSPNs from LNX-01 → Kerberoast
# step 4: impacket-psexec → PTH
# step 5: impacket-secretsdump → DCSync → FINAL flag
# 验证每一步的中间 flag
cd .. && bash teardown.sh web-to-da

echo "=== Chain 2: Container to Admin ==="
cd container-to-admin && bash deploy.sh
# stage 1: kubectl get secret stage1-flag -n kube-system
# stage 2: pod exec → runC escape → cat /flags/stage2.txt
# stage 3: etcdctl get → FINAL flag
cd .. && bash teardown.sh container-to-admin

echo "=== Chain 3: WordPress to K8s ==="
cd wordpress-to-k8s && bash deploy.sh
# 按 7 步路径逐一验证
cd .. && bash teardown.sh wordpress-to-k8s
```

---

## Phase 6 交付物

| # | 文件 | 说明 |
|---|------|------|
| 1 | `chains/web-to-da/{deploy.sh,docker-compose.chain.yml,web-to-da.yaml}` | Chain 1 |
| 2 | `chains/container-to-admin/{deploy.sh,container-to-admin.yaml}` | Chain 2 |
| 3 | `chains/wordpress-to-k8s/{deploy.sh,wordpress-to-k8s.yaml}` | Chain 3 |
| 4 | `chains/_template/deploy.sh` | 通用链部署模板 |
| 5 | `chains/_template/chain.yaml.schema` | 链配置 Schema |
