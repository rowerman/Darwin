# CIS Benchmark: 5.2.11 Minimize the admission of Windows HostProcess Containers

**编号**: 5.2.11
**级别**: Level 1
**描述**: 一般情况下，禁止运行将 hostProcess 标志设为 true 的 Windows 容器。
启用 hostProcess 标志的 Windows 容器能够与底层的 Windows 集群节点进行交互。根据 Kubernetes 官方文档的说明，这一配置会赋予容器对 Windows 节点的特权访问权限。
若 Kubernetes 集群中存在 Windows 容器的使用场景，则应至少配置一项准入控制策略，禁止 hostProcess 类型的 Windows 容器准入。
若确实需要运行启用 hostProcess 的 Windows 容器，则需为此单独定义一套策略，同时应仔细核查，确保仅为有限的服务账户和用户授予该策略的使用权限。

**影响**: 除非遵循特定策略运行，否则禁止创建将 securityContext.windowsOptions.hostProcess 配置为 true 的 Pod。

**审计方法**: 列出集群内每个命名空间当前生效的策略，确保每项策略均禁止 hostProcess 容器准入。

**修复方法**: 为集群内所有承载用户工作负载的命名空间添加策略，限制 hostProcess 容器的准入。

**参考**: 1. https://kubernetes.io/docs/tasks/configure-pod-container/create-hostprocess-pod/
2. https://kubernetes.io/docs/concepts/security/pod-security-standards/

**元数据**:
- category: "pod_security"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.2"
- level: "1"
