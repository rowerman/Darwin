# CIS Benchmark: 5.2.12 Minimize the admission of HostPath volumes

**编号**: 5.2.12
**级别**: Level 1
**描述**: 一般情况下，禁止允许挂载 hostPath 卷的容器准入。
若容器的配置中挂载了 hostPath 卷，该容器将能够访问底层集群节点的文件系统。使用 hostPath 卷可能会让容器获取到节点文件系统中的特权区域访问权限。
集群中应至少配置一项准入控制策略，禁止容器挂载 hostPath 卷。
若确实需要运行必须挂载 hostPath 卷的容器，则需为此单独定义一套策略，同时应仔细核查，确保仅为有限的服务账户和用户授予该策略的使用权限。

**影响**: 除非遵循特定策略运行，否则禁止创建挂载 hostPath 卷的 Pod。

**审计方法**: 列出集群内每个命名空间当前生效的策略，确保每项策略均禁止挂载 hostPath 卷的容器准入。

**修复方法**: 为集群内所有承载用户工作负载的命名空间添加策略，限制挂载 hostPath 卷的容器准入。

**参考**: 1. https://kubernetes.io/docs/concepts/security/pod-security-standards/

**元数据**:
- category: "pod_security"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.2"
- level: "1"
