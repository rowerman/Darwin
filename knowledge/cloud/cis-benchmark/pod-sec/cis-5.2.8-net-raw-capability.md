# CIS Benchmark: 5.2.8 Minimize the admission of containers with the NET_RAW capability

**编号**: 5.2.8
**级别**: Level 1
**描述**: 一般情况下，禁止运行包含高风险 NET_RAW 权限的容器。
容器会携带容器运行时分配的默认权限集运行，该权限集可能默认包含部分高风险权限。若以 Docker 作为容器运行时，NET_RAW 权限会处于启用状态，此权限可能被恶意容器滥用。
理想情况下，所有容器都应移除该权限。
集群中应至少配置一项准入控制策略，明确禁止包含 NET_RAW 权限的容器准入。
若确实需要运行包含该权限的容器，则需为此单独定义一套策略，同时应仔细核查，确保仅为有限的服务账户和用户授予使用该策略的权限。

**影响**: 禁止创建包含启用了 NET_RAW 权限的容器的 Pod。

**审计方法**: 列出集群内每个命名空间当前生效的策略，确保至少有一项策略禁止包含 NET_RAW 权限的容器准入。

**修复方法**: 为集群内所有承载用户工作负载的命名空间添加策略，限制包含 NET_RAW 权限的容器准入。

**参考**: 1. https://kubernetes.io/docs/concepts/security/pod-security-standards/
2. https://www.nccgroup.trust/uk/our-research/abusing-privileged-and-unprivilegedlinux-containers/

**元数据**:
- category: "pod_security"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.2"
- level: "1"
