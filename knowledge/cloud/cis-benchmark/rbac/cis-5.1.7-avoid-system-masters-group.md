# CIS Benchmark: 5.1.7 Avoid use of system

**编号**: 5.1.7
**级别**: masters group:Level 1
**描述**: 除非存在绝对必要的场景（例如，在基于角色的访问控制（RBAC）完全生效前，用于配置初始访问权限），否则不应使用 system:masters 这个特殊组，为任何用户或服务账户授予权限。
system:masters 组拥有对 Kubernetes API 的无限制访问权限，这一权限被硬编码在 API 服务器的源代码中。只要已认证用户属于该组，即便删除了所有关联此组的角色绑定和集群角色绑定，也无法限制其访问权限。
若将该组与客户端证书认证方式结合使用，可能会导致集群中出现权限无法撤销的集群管理员级别凭据。

**影响**: 一旦集群中的 RBAC 系统投入运行，就不再需要专门依赖 system:masters 组；如果确实需要无限制的访问权限，只需为相关主体配置指向 cluster-admin 集群角色的常规绑定即可。

**审计方法**: 检查所有拥有集群访问权限的凭据清单，确保未使用 system:masters 这个用户组。

**修复方法**: 将 system:masters 组从集群的所有用户中移除。

**参考**: 1. https://github.com/kubernetes/kubernetes/blob/master/pkg/registry/rbac/escalatio
n_check.go#L38

**元数据**:
- category: "rbac"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.1"
- level: "1"
