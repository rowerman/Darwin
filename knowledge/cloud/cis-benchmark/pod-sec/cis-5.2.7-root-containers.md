# CIS Benchmark: 5.2.7 Minimize the admission of root containers

**编号**: 5.2.7
**级别**: Level 2
**描述**: 一般情况下，禁止以 root 用户身份运行容器。
容器可以以任意 Linux 用户身份运行。即便容器运行时的安全功能会对其加以限制，以 root 用户身份运行的容器，发生容器逃逸的风险依然会更高。
理想状态下，所有容器都应使用一个已明确指定的非 UID 0 用户来运行。
集群中应至少配置一项准入控制策略，明确禁止以 root 用户身份运行的容器准入。
若确实需要运行 root 容器，则需为此单独定义一套策略，同时应仔细核查，确保仅为有限的服务账户和用户授予使用该策略的权限。

**影响**: 禁止创建包含以 root 用户身份运行的容器的 Pod。

**审计方法**: 列出集群内每个命名空间当前生效的策略，确保每项策略均通过设置 MustRunAsNonRoot（必须以非 root 用户运行）或 MustRunAs（必须以指定用户运行，且用户 ID 范围不包含 0）来限制 root 容器的使用。

**修复方法**: 为集群内的每个命名空间创建一项策略，确保已配置 MustRunAsNonRoot（强制以非 root 用户运行）或 MustRunAs（强制以指定用户运行，且用户 ID 范围不包含 0）。

**参考**: 1. https://kubernetes.io/docs/concepts/security/pod-security-standards/

**元数据**:
- category: "pod_security"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.2"
- level: "2"
