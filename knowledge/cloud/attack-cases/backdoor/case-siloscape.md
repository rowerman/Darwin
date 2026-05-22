# 攻击案例: Siloscape Windows 容器恶意软件（后门 Kubernetes 集群）

Project: Siloscape Windows Container Malware Campaign
Date: 2021-03-01
Severity: High

**攻击者**: 未公开（通过 Siloscape 行动代称）
**时间**: 2021（披露时已持续超过一年）
**目标**: Windows Server 容器（Server isolation）、Kubernetes 集群与节点
**攻击类型**: 容器逃逸、集群后门、恶意容器投放

## 案例概述

Unit 42 在 2021 年披露 Siloscape：这是已知首个专门针对 Windows 容器的恶意软件，其主要目标是从 Windows Server 容器逃逸至宿主节点，并在配置不当的 Kubernetes 集群中建立后门以投放恶意容器。报告指出 Siloscape 使用 Tor 代理与 `.onion` 域名连接 C2，并通过 IRC 协议在 Tor 上通信；研究人员还在其 C2 上识别到 23 个活跃受害者，并发现该活动已持续超过一年。

**关键事实**:
- 首次披露: 2021 年 6 月公开报告
- 主要目标: Windows Server 容器逃逸并控制 Kubernetes 集群
- C2 通信: IRC over Tor，使用 `.onion` 域名

## 攻击链分析

### 1. 初始访问 (Initial Access)

**技术**: 利用常见云应用漏洞获取容器内 RCE
**MITRE ATT&CK**: T1190 - Exploit Public-Facing Application

公开报告指出，攻击者会针对常见云应用（web server、web page、database）利用已知漏洞（“1-days”）以获得在 Windows 容器内的执行能力。

### 2. 执行 (Execution)

**技术**: 执行恶意二进制并建立 C2 通信
**MITRE ATT&CK**: T1204.003 - Malicious Image

攻击者在容器内执行 Siloscape（文中示例命名为 `CloudMalware.exe`），并通过命令行参数传入 C2 信息（而非硬编码在二进制中）。随后，Siloscape 会准备 Tor 组件并通过 Tor 建立到 C2 的通信通道。

### 3. 持久化 (Persistence)

**技术**: 集群后门（通过创建恶意工作负载维持控制）
**MITRE ATT&CK**: T1098 - Account Manipulation

Siloscape 的目标不是单一容器，而是通过对集群的控制来投放新的恶意容器/部署，即使某个容器被删除，攻击者仍可在集群内创建新的工作负载以维持控制面。

### 4. 权限提升 (Privilege Escalation)

**技术**: Windows 容器逃逸（server silo / 符号链接）
**MITRE ATT&CK**: T1611 - Escape to Host

公开报告描述了 Siloscape 的关键步骤：通过模仿 `CExecSvc.exe` 获取 `SeTcbPrivilege` 权限，并创建全局符号链接，将容器的 `X:` 盘映射到宿主机的 `C:` 盘，从而访问宿主文件系统并进一步搜索 Kubernetes 工具与配置。

### 5. 凭证访问 (Credential Access)

**技术**: 搜索 Kubernetes 配置与工具以接管集群
**MITRE ATT&CK**: T1552.007 - Unsecured Credentials: Container API

在逃逸后，Siloscape 会在宿主机上搜索 `kubectl.exe` 与 Kubernetes 配置文件，以评估是否具备创建新部署的权限并推进集群接管。

### 6. 横向移动 (Lateral Movement)

**技术**: 通过节点权限在集群内创建/扩展恶意工作负载
**MITRE ATT&CK**: T1610 - Deploy Container

Siloscape 会检查被攻陷节点是否具备创建新 Kubernetes 部署的权限；若权限足够，则可在集群内投放恶意容器实现横向扩展与后门维持。

### 7. 影响 (Impact)

**技术**: 资源劫持与潜在数据泄露/供应链风险
**MITRE ATT&CK**: T1496 - Resource Hijacking

公开报告指出，控制集群后可用于多种目的：投放挖矿容器、潜在数据窃取、甚至软件供应链攻击等。

## TTP 映射

| MITRE ATT&CK ID | 技术名称 | 描述 |
|-----------------|---------|------|
| T1190 | Exploit Public-Facing Application | 利用云应用漏洞获得容器内执行 |
| T1611 | Escape to Host | Windows 容器逃逸到宿主机 |
| T1552.007 | Unsecured Credentials: Container API | 搜索 kubectl/配置文件与凭证 |
| T1610 | Deploy Container | 在集群内创建恶意部署/容器 |
| T1496 | Resource Hijacking | 投放挖矿或资源滥用工作负载 |

## 威胁指标 (IoC)

**进程/文件名**:
- `CloudMalware.exe`（公开报告中的命名示例）
- 通过 Tor 建立 C2（`.onion`）并使用 IRC 协议通信

**行为特征**:
- 创建全局符号链接，将容器盘符映射到宿主盘符（`X:` → `C:`）
- 搜索宿主机的 `kubectl.exe` 与 Kubernetes 配置文件

## 检测方法

### Windows/容器运行时检测

```powershell
# 示例：在 Windows 节点上排查可疑二进制与异常落地（需结合实际路径与审计策略）
Get-ChildItem -Recurse -ErrorAction SilentlyContinue C:\ | Select-String -Pattern "CloudMalware.exe" -List
```

### Kubernetes 层检测

```bash
# 检查近期新增的可疑 Deployment/Pod（结合镜像来源与命名规则）
kubectl get deploy -A --sort-by=.metadata.creationTimestamp
kubectl get pods -A --sort-by=.metadata.creationTimestamp

# 审计节点权限是否过大（例如节点凭证可直接创建新部署）
kubectl auth can-i create deployments --as system:node:<node-name> -A
```

## 防护建议

### 预防措施

1. **Windows 容器隔离策略**：对需要安全边界的工作负载采用 Hyper-V 容器隔离，并遵循 Windows Server 容器安全边界的建议。
2. **Kubernetes 权限收敛**：确保节点权限不足以直接创建新的部署；使用 RBAC 与授权模块限制节点/组件权限。
3. **漏洞治理与运行时检测**：及时修补面向互联网的云应用漏洞，监控异常进程、Tor/IRC over Tor 通信与异常工作负载创建。

## 参考资料

- [Unit 42: Siloscape: First Known Malware Targeting Windows Containers to Compromise Cloud Environments](https://unit42.paloaltonetworks.com/siloscape/)

## 时间线

| 日期 | 事件 |
|------|------|
| 2021-03 | 研究团队发现并命名 Siloscape（披露为首个 Windows 容器恶意软件） |
| 2021-06 | 公开发布技术报告与防护建议 |
