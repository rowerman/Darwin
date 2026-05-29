# CVE Benchmark — DARWIN LLM Pentest Evaluation

基于公开 CVE 的自建渗透测试 Benchmark，覆盖 6 个领域 47 个场景、18 条攻击链、2 个防御变体。

## 快速开始

```bash
cd benchmarks/cve_challenges

# 列出所有场景
./scripts/list-scenarios.sh

# 启动 Docker 场景
./scripts/start-scenario.sh web-03        # WordPress RCE
./scripts/start-scenario.sh db-05         # Redis 未授权

# 启动 K8s 场景（需 KIND）
./scripts/start-scenario.sh k8s-06        # RBAC 滥用

# 启动 AD 场景（先启动共享 AD DC）
docker compose -f ad/docker-compose.yml up -d --build
./scripts/start-scenario.sh ad-01         # Kerberoasting

# 启动攻击链
bash chains/container-to-admin/deploy.sh   # 纯 K8s 链

# 停止
./scripts/stop-scenario.sh web-03
./scripts/reset-all.sh                    # 全量重置
```

## 场景分类

| 领域 | 可用 | 阻塞 | 交付方式 |
|------|:---:|:---:|---------|
| Web 应用 | 9 | 0 | Docker Compose |
| 数据库 | 5 | 0 | Docker Compose |
| Linux 提权 | 1 | 4 | LNX-05: Docker, LNX-01~04: Vagrant/QEMU (内核镜像不可用) |
| Kubernetes | 14 | 0 | KIND |
| Active Directory | 5 | 7 | Samba AD DC (Docker), 7 个 Windows 特有场景不可部署 |
| 防御变体 | 2 | 0 | Docker Compose + WAF |
| **合计** | **36** | **11** | |

### 阻塞场景明细

| 场景 | 阻塞原因 |
|------|---------|
| LNX-01~04 (nftables/vsock 内核提权) | 需 VT-x 嵌套虚拟化或 QEMU 内核镜像 |
| AD-03 (LDAPNightmare) | Windows LDAP 驱动漏洞 |
| AD-04 (ESC3), AD-06 (ESC8) | Windows AD CS 角色 |
| AD-07, AD-08 (Kerberos 反射) | Windows SMB 驱动漏洞 |
| AD-11 (BadSuccessor) | Windows Server 2025 特有 |
| AD-12 (NetConfig) | Windows 性能计数器漏洞 |

## 攻击链

| 链 | 步骤 | 状态 |
|----|:---:|:---:|
| web-to-da (Web → Linux → AD) | 6 | 可用 |
| container-to-admin (K8s RBAC → Escape → etcd) | 4 | 可用 |
| wordpress-to-k8s (Web → DB → Linux → K8s) | 7 | 可用 |
| asrep-to-golden (AS-REP → PTH → DCSync → Golden) | 4 | 可用 |
| kubelet-to-etcd (Kubelet → RBAC → etcd) | 3 | 可用 |
| mssql-to-da (MSSQL → Linked Server → PTH → DCSync) | 4 | 可用 |
| mysql-to-cluster (MySQL UDF → PrivEsc → RBAC → etcd) | 4 | 可用 |
| redis-to-golden (Redis → PrivEsc → ESC8 → DCSync → Golden) | 5 | 部分 (ESC8 阻塞) |
| esc3-to-dcsync (ESC3 → DCSync) | 3 | 阻塞 (AD CS) |
| privilege-to-etcd (Privileged → RBAC → etcd) | 3 | 可用 |
| hostpath-to-daemonset (hostPath → Kubelet → Registry → gitRepo) | 4 | 可用 |
| caps-to-cluster (CAP_SYS_ADMIN → RBAC → etcd) | 4 | 可用 |
| sa-lateral-escape (SA Token → RBAC → runC Escape) | 4 | 可用 |
| tomcat-to-k8s (Tomcat deserialization → Sudo → RBAC → etcd) | 4 | 可用 |
| pg-sqli-to-node (PG SQLi → DB RCE → hostPath → Kubelet) | 4 | 可用 |
| redis-to-k8s (Redis unauth → Privileged → RBAC → etcd) | 4 | 可用 |
| wp-lfi-to-cluster (WordPress LFI → RBAC → runC → etcd) | 4 | 可用 |
| tomcat-race-to-etcd (Tomcat race → Sudo → RBAC → etcd) | 4 | 可用 |

## Flag 格式

`flag{<scenario-id>-<8-hex>}` — 验证工具: `./scripts/verify-flag.sh`

## 依赖

| 工具 | 用途 |
|------|------|
| Docker + Compose v2 | Web/DB/LNX-05/AD 场景 |
| KIND + kubectl | K8s 场景 |
| Vagrant + VirtualBox (可选) | Linux 内核提权（需 VT-x） |

## 目录结构

```
benchmarks/cve_challenges/
  docker/
    web/        9 Web (Tomcat/WordPress/App+DB)
    db/         5 DB (PG/MySQL/Oracle/MSSQL/Redis)
    linux/      5 Linux (Kernel exploits + Sudo)
    _defense/   WAF/Cloak/Honey/Trap 防御层
  k8s/          14 K8s (runC/RBAC/etcd/hostPath/privileged/...)
  ad/
    docker-compose.yml   Samba AD DC
    setup/               AD 初始化脚本
    scenarios/           12 AD 场景配置
  chains/       18 攻击链
  scripts/      8 工具脚本
```
