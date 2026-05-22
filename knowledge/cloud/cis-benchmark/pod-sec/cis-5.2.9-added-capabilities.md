# CIS Benchmark: 5.2.9 Minimize the admission of containers with added capabilities

**编号**: 5.2.9
**级别**: Level 1
**描述**: 一般情况下，禁止为容器分配默认权限集之外的权限。
容器会携带容器运行时分配的默认权限集运行。若为容器添加该权限集之外的权限，可能会增加容器遭遇逃逸攻击的风险。
集群中应至少配置一项策略，阻止携带默认权限集以外权限的容器启动。
若确实需要运行带有额外权限的容器，则需为此单独定义一套策略，同时应仔细核查，确保仅为有限的服务账户和用户授予使用该策略的权限。

**影响**: 禁止创建包含需要默认权限集之外权限的容器的 Pod。

**审计方法**: 列出集群内每个命名空间当前生效的策略，确保存在相关策略以限制 allowedCapabilities 的值只能被设置为空数组。

**修复方法**: 确保集群策略中不出现 allowedCapabilities 配置项，除非其值被设为空数组。

**参考**: 1. https://kubernetes.io/docs/concepts/security/pod-security-standards/
2. https://www.nccgroup.trust/uk/our-research/abusing-privileged-and-unprivilegedlinux-containers/

**元数据**:
- category: "pod_security"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.2"
- level: "1"
