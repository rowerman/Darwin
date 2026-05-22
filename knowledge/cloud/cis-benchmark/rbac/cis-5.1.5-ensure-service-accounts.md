# CIS Benchmark: 5.1.5 Ensure that default service accounts are not actively used

**编号**: 5.1.5
**级别**: Level 1
**描述**: 为确保授予应用程序的权限更易于审计和核查，不应使用默认服务账户。
Kubernetes 会提供一个默认服务账户，当 Pod 未被分配特定服务账户时，集群工作负载将使用该默认账户。
当 Pod 需要访问 Kubernetes API 时，应为该 Pod 创建一个专用服务账户，并为这个专用账户分配相应权限。
默认服务账户的配置应当满足两个要求：不提供服务账户令牌，且不配置任何显式的权限分配。

**影响**: 所有需要访问 Kubernetes API 的工作负载，都必须创建一个专用的服务账户。

**审计方法**: 针对集群中的每个命名空间，检查分配给默认服务账户的权限，确保除默认配置外，该账户未绑定任何角色或集群角色。
此外，需确保每个默认服务账户均已配置 automountServiceAccountToken: false 参数。

**修复方法**: 当 Kubernetes 工作负载需要以特定权限访问 Kubernetes API 服务器时，均需创建专用服务账户。
修改每个默认服务账户的配置，使其包含该参数。
```yaml
automountServiceAccountToken: false
```

**参考**: 1. https://kubernetes.io/docs/tasks/configure-pod-container/configure-serviceaccount/

**元数据**:
- category: "rbac"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.1"
- level: "1"
