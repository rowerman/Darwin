# CIS Benchmark: 5.2.13 Minimize the admission of containers which use HostPorts

**编号**: 5.2.13
**级别**: Level 1
**描述**: 一般情况下，禁止允许需要使用 ** 主机端口（HostPorts）** 的容器准入。
主机端口会将容器直接接入宿主机的网络，这种方式可能绕过网络策略等管控措施。
集群中应至少配置一项准入控制策略，禁止需要使用主机端口的容器准入。
若确实需要运行必须使用主机端口的容器，则需为此单独定义一套策略，同时应仔细核查，确保仅为有限的服务账户和用户授予该策略的使用权限。

**影响**: 除非遵循特定策略运行，否则禁止创建在容器（container）、初始化容器（initContainer）或临时容器（ephemeralContainer） 段中配置了 hostPort 的 Pod。

**审计方法**: 列出集群内每个命名空间当前生效的策略，确保每项策略均禁止包含 hostPort 配置段的容器准入。

**修复方法**: 为集群内所有承载用户工作负载的命名空间添加策略，限制使用 hostPort 配置段的容器准入。

**参考**: 1. https://kubernetes.io/docs/concepts/security/pod-security-standards/

**元数据**:
- category: "pod_security"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.2"
- level: "1"
