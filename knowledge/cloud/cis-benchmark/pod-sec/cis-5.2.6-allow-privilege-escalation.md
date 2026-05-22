# CIS Benchmark: 5.2.6 Minimize the admission of containers with

**编号**: 5.2.6
**级别**: Level 1
**描述**: 一般情况下，禁止运行将 allowPrivilegeEscalation 标志设置为 true 的容器。允许该配置可能导致容器内的进程获得超出其初始权限范围的更多权限。
需要注意的是，这些权限仍会受容器整体沙箱环境的限制，且该配置与特权容器的使用并无关联。将 allowPrivilegeEscalation 标志设为 true 的容器，其内部进程的权限可能会高于父进程。
集群中应至少配置一项准入控制策略，明确禁止容器开启权限提升功能。该配置项的存在（且默认值为 true）是为了支持 setuid 二进制程序的运行。
若确实需要运行使用 setuid 二进制程序或需要开启权限提升的容器，则需为此单独定义一套策略，同时应仔细核查，确保仅为有限的服务账户和用户授予使用该策略的权限。

**影响**: 除非遵循特定策略运行，否则禁止创建配置了 spec.allowPrivilegeEscalation: true 的 Pod。

**审计方法**: 列出集群内每个命名空间当前生效的策略，确保每项策略均禁止允许权限提升的容器准入。

**修复方法**: 为集群内所有承载用户工作负载的命名空间添加策略，限制将 .spec.allowPrivilegeEscalation 配置为 true 的容器准入。

**参考**: 1. https://kubernetes.io/docs/concepts/security/pod-security-standards/

**元数据**:
- category: "pod_security"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.2"
- level: "1"
