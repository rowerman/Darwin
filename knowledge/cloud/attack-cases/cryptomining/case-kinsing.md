# 攻击案例: Kinsing 云原生挖矿攻击

Project: Kinsing Cryptojacking Campaign
Date: 2020-01-01
Severity: High

**攻击者**: Kinsing（以恶意软件家族/行动代称）
**时间**: 2020-2024（持续活跃并迭代）
**目标**: 容器化工作负载、Kubernetes 集群、云主机与对外暴露的应用/数据库
**攻击类型**: 加密货币挖矿、后门投递、隐蔽持久化

## 案例概述

Kinsing 是长期活跃的云原生挖矿威胁之一。公开遥测显示，Kinsing 在 Kubernetes 环境中常见的初始访问路径包括：利用存在漏洞的镜像/应用实现远程代码执行，以及利用暴露且配置不当的 PostgreSQL 容器（如“trust authentication” 配置）获取未授权访问并执行投递脚本。

公开研究进一步指出，Kinsing 在云主机/服务器环境中也会通过“不常被排查的路径”进行隐蔽持久化（例如伪装为 man page 缓存文件），并内嵌 XMRig 进行挖矿。

**关键事实**:
- 初始访问常见手法: “漏洞镜像/应用 RCE”与“暴露 PostgreSQL 容器配置不当”
- 影响: 资源劫持（挖矿导致成本上升与性能下降）

## 攻击链分析

### 1. 初始访问 (Initial Access)

**技术**: 利用漏洞镜像/应用与数据库配置错误
**MITRE ATT&CK**: T1190 - Exploit Public-Facing Application

公开遥测显示，Kinsing 常通过两类方式进入 Kubernetes 环境：利用容器镜像内应用漏洞实现 RCE；或攻击暴露且配置不当的 PostgreSQL 容器（例如过于宽泛的信任认证配置）以获得未授权访问并最终执行恶意载荷。

**具体手法**:
- PostgreSQL 容器启用 “trust authentication” 且允许来自过宽 IP 范围的连接
- 利用存在漏洞的镜像/应用触发 RCE 后拉取脚本执行（常见为 `curl|bash` / `wget|bash`）

### 2. 执行 (Execution)

**技术**: 通过脚本投递运行矿工与控制组件
**MITRE ATT&CK**: T1609 - Container Administration Command

公开报告中给出了典型投递命令结构，攻击者常以 `/bin/bash -c` 包裹下载与执行逻辑，通过外部地址拉取脚本后直接执行。

### 3. 持久化 (Persistence)

**技术**: 伪装落地路径以降低被发现概率
**MITRE ATT&CK**: T1036 - Masquerading

公开研究描述了 Kinsing 通过伪装为系统文件/缓存文件来隐藏自身，尤其将恶意文件放置在 man page 缓存目录等不常被排查的位置，以提高驻留时间。

### 4. 权限提升 (Privilege Escalation)

**技术**: 依赖受害工作负载权限扩大影响面（环境相关）
**MITRE ATT&CK**: T1611 - Escape to Host

公开材料中更强调其初始访问与投递方式；在实际事件中，是否发生容器逃逸/主机权限提升取决于受害者容器权限、挂载与节点配置。

### 5. 凭证访问 (Credential Access)

**技术**: 访问敏感配置与凭证文件（环境相关）
**MITRE ATT&CK**: T1552.007 - Unsecured Credentials: Container API

在 Kubernetes 场景中，一旦获得容器内执行权限，攻击者可尝试访问工作负载中暴露的凭证与配置（具体取决于部署与权限）。

### 6. 横向移动 (Lateral Movement)

**技术**: 利用集群内网络与配置错误扩展感染面
**MITRE ATT&CK**: T1613 - Container and Resource Discovery

Kinsing 在云原生环境中的传播常依赖继续寻找可被利用的工作负载与入口（例如更多暴露的数据库/管理接口），并通过脚本化手段扩大感染范围。

### 7. 影响 (Impact)

**技术**: 资源劫持（挖矿）
**MITRE ATT&CK**: T1496 - Resource Hijacking

公开报告指出其内嵌 XMRig 进行挖矿，导致资源消耗与云成本上升。

## TTP 映射

| MITRE ATT&CK ID | 技术名称 | 描述 |
|-----------------|---------|------|
| T1190 | Exploit Public-Facing Application | 利用漏洞镜像/应用或暴露服务获取初始执行 |
| T1609 | Container Administration Command | 通过脚本化命令拉取并执行载荷 |
| T1036 | Masquerading | 伪装为系统缓存/手册页文件以隐藏 |
| T1613 | Container and Resource Discovery | 在集群内发现更多目标与资源 |
| T1496 | Resource Hijacking | 部署 XMRig 等矿工进行挖矿 |

## 威胁指标 (IoC)

**可疑落地路径（伪装为 man page / 系统缓存）**:
- `/var/cache/man/cs/cat1/`
- `/var/cache/man/cs/cat3/`
- `/var/cache/man/zh_TW/cat8/`
- `/var/lib/gssproxy/rcache/`

**文件哈希** (SHA256):
- XMRig `063f80c2c5accaecd8c9e6b6815ae80e372477f9df1113dafc72a2a0703aaa68`

## 检测方法

### 网络层检测

```bash
# 识别高风险：对外暴露的 PostgreSQL 容器（示例：5432）
ss -lntp | grep -E ":5432"
```

### 容器层检测

```bash
# 发现典型的脚本化下载执行痕迹（示例）
grep -R --line-number -E "(curl|wget).*(\\|\\s*bash)" /var/log 2>/dev/null | head
```

### 主机层检测

```bash
# 检查可疑 man cache 目录中的异常可执行文件/最近修改
find /var/cache/man -type f -mtime -30 -ls 2>/dev/null | head
```

## 防护建议

### 预防措施

1. **修复镜像与应用漏洞**：对镜像做持续漏洞扫描与及时升级，避免运行已知可 RCE 的组件版本。
2. **数据库最小暴露**：避免将 PostgreSQL 等数据库容器直接暴露到公网；收紧访问控制，避免不安全的 “trust authentication” 配置。
3. **运行时威胁检测**：对异常 `curl|bash`、矿工进程、高 CPU 占用、异常出站流量进行告警联动。

## 参考资料

- [Microsoft Defender for Cloud: Initial access techniques in Kubernetes environments used by Kinsing malware](https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/initial-access-techniques-in-kubernetes-environments-used-by/ba-p/3697975)
- [Tenable: Kinsing Malware Hides Itself as a Manual Page and Targets Cloud Servers](https://www.tenable.com/blog/kinsing-malware-hides-itself-as-a-manual-page-and-targets-cloud-servers)

## 时间线

| 日期 | 事件 |
|------|------|
| 2023-01 | 公开报告披露 Kubernetes 环境中 Kinsing 的两类常见初始访问路径 |
| 2024-05 | 公开报告披露其在云服务器上的新隐蔽落地与 IoC（伪装为 man page） |
