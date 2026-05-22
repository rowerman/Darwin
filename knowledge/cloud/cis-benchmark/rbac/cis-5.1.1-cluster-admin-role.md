# CIS Benchmark: 5.1.1 Ensure that the cluster-admin role is only used where required

**编号**: 5.1.1
**级别**: Level 1
**描述**: RBAC 角色 cluster-admin 拥有对环境的广泛权限，仅应在必要的场景和时机下使用。Kubernetes 在启用 RBAC 时会提供一组默认角色。其中部分角色（如 cluster-admin）具备的广泛权限，只应在确有必要的情况下授予。cluster-admin 这类角色允许超级用户权限，可对任意资源执行任意操作。当该角色通过 ** 集群角色绑定（ClusterRoleBinding）配置时，将获得对集群内所有命名空间及所有资源的完全控制权；当通过角色绑定（RoleBinding）** 配置时，则可获得对该角色绑定所属命名空间内所有资源（包括命名空间本身）的完全控制权。

**影响**: 在从环境中移除任何集群角色绑定（ClusterRoleBinding）前，务必谨慎操作，以确保这些绑定并非集群运行所必需的组件。需要特别注意的是，不得修改名称以 system: 为前缀的集群角色绑定，因为此类绑定是系统组件正常运行的必要条件。

**审计方法**:需查看所有关联了 cluster-admin 角色的集群角色绑定（ClusterRoleBinding）的输出信息，以此获取拥有该角色访问权限的主体（principal）清单；执行此操作时务必仔细核对。
```bash
kubectl get clusterrolebindings -o=customcolumns=NAME:.metadata.name,ROLE:.roleRef.name,SUBJECT:.subjects[*].name
```
对列出的每一个主体（principal）逐一进行核查，确认其确实需要 cluster-admin 权限。

**修复方法**:找出所有绑定到 cluster-admin 角色的集群角色绑定（ClusterRoleBinding）。检查这些绑定是否仍在使用、是否确实需要该角色权限，或是否可改用权限范围更小的角色。若条件允许，应先为用户绑定权限更低的角色，再移除其对应的 cluster-admin 集群角色绑定。
```yaml
kubectl delete clusterrolebinding [name]
```

**参考**: 1. https://kubernetes.io/docs/admin/authorization/rbac/#user-facing-roles

**元数据**:
- category: "rbac"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.1"
- level: "1"
