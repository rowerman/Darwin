# CIS Benchmark: 5.2.10 Minimize the admission of containers with capabilities assigned

**编号**: 5.2.10
**级别**: Level 2
**描述**: 一般情况下，禁止容器赋予任何内核权限。
容器会携带容器运行时分配的默认权限集运行。内核权限是 Linux 系统中通常授予 root 用户的权限子集。在许多场景下，运行于容器内的应用程序并不需要任何内核权限即可正常工作，因此，基于最小权限原则，应最大限度减少容器权限的授予。

**影响**: 禁止创建包含需要内核权限才能运行的容器的 Pod。

**审计方法**: 列出集群内每个命名空间当前生效的策略，确保至少有一项策略要求所有容器移除全部内核权限。

**修复方法**: 审查集群上运行的应用程序对内核权限的使用情况。如果某个命名空间内的应用程序运行时无需任何 Linux 内核权限，则可考虑添加一项策略，禁止未移除全部内核权限的容器准入。

**参考**: 1. https://kubernetes.io/docs/concepts/security/pod-security-standards/
2. https://www.nccgroup.trust/uk/our-research/abusing-privileged-and-unprivilegedlinux-containers/

**元数据**:
- category: "pod_security"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.2"
- level: "2"
