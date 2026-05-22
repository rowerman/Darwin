# CIS Benchmark: 5.1.2 Minimize access to secrets

**编号**: 5.1.2
**级别**: Level 1
**描述**: Kubernetes API 会存储密钥，这些密钥可能是用于 Kubernetes API 的服务账户令牌，也可能是集群中工作负载所使用的凭据。为降低权限提升风险，应将对这些密钥的访问权限限制在尽可能小的用户群体范围内。
若攻击者获得了对 Kubernetes 集群内存储密钥的不当访问权限，就可能进一步获取对 Kubernetes 集群，或是对那些凭据以密钥形式存储的外部资源的访问权限。

**影响**: 需要注意的是，不要移除系统组件对密钥的访问权限 —— 这些组件的运行依赖该权限。

**审计方法**: 检查那些对 Kubernetes API 中的密钥对象拥有 get、list 或 watch 访问权限的用户。

**修复方法**: 在可行的情况下，移除对集群中密钥对象的 get、list 和 watch 访问权限。

**参考**: 

**元数据**:
- category: "rbac"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.1"
- level: "1"
