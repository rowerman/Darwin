# CIS Benchmark: 5.2.5 Minimize the admission of containers wishing to share the

**编号**: 5.2.5
**级别**: Level 1
**描述**: 一般情况下，禁止运行将 hostNetwork 标志设置为 true 的容器。在宿主机网络命名空间中运行的容器，可访问本地回环设备，还能获取其他 Pod 的入网和出网流量。
集群中应至少配置一项准入控制策略，明确禁止容器共享宿主机的网络命名空间。
若确实需要运行需要访问宿主机网络命名空间的容器，则需为此单独定义一套策略，同时应仔细核查，确保仅为有限的服务账户和用户授予使用该策略的权限。

**影响**: 除非遵循特定策略运行，否则禁止创建配置了 spec.hostNetwork: true 的 Pod。

**审计方法**: 列出集群内每个命名空间当前生效的策略，确保每项策略均禁止共享宿主机网络命名空间的容器准入。

**修复方法**: 为集群内所有承载用户工作负载的命名空间添加策略，限制共享宿主机网络命名空间的容器准入。

**参考**: 1. https://kubernetes.io/docs/concepts/security/pod-security-standards/

**元数据**:
- category: "pod_security"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.2"
- level: "1"
