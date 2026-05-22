# CIS Benchmark: 5.1.13 Minimize access to the service account token creation

**编号**: 5.1.13
**级别**: Level 1
**描述**: 拥有集群级别的服务账户令牌创建权限的用户，能够在集群内生成长期有效的高权限凭据。即便该用户的账户权限已被撤销，此类操作仍可能被利用来实现权限提升，以及对集群的持续性访问。
因此，服务账户令牌的创建权限应当受到严格限制。

**影响**: 

**审计方法**: 检查那些拥有在 Kubernetes API 中创建服务账户（ServiceAccount）对象令牌子资源权限的用户。

**修复方法**: 在条件允许的情况下，移除对服务账户（ServiceAccount）对象令牌子资源的访问权限。

**参考**: 1. https://kubernetes.io/docs/concepts/security/rbac-good-practices/#token-request

**元数据**:
- category: "rbac"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.1"
- level: "1"
