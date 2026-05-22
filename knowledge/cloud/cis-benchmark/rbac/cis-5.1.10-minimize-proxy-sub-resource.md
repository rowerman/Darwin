# CIS Benchmark: 5.1.10 Minimize access to the proxy sub-resource of nodes

**编号**: 5.1.10
**级别**: Level 1
**描述**: 拥有节点（Node）对象代理子资源（Proxy sub-resource）访问权限的用户，会被自动授予kubelet API 的使用权限，这可能会为权限提升行为提供可乘之机，或是绕过审计日志等集群安全管控措施。
kubelet 本身提供了一套 API，其中包含在节点上运行的任意容器内执行命令的权限。对这套 API 的访问权限，是通过主 Kubernetes API 中针对节点对象的权限配置来管控的。而代理子资源则明确允许用户以宽泛的权限范围访问 kubelet API。
直接访问 kubelet API 会绕过审计日志（kubelet API 的访问操作不会被记录到审计日志中）和准入控制等安全管控措施。
节点对象代理子资源的使用权限会增加权限提升的风险，因此在条件允许的情况下，应对该权限加以限制。

**影响**: 

**审计方法**: 检查那些拥有 Kubernetes API 中节点（Node）对象代理子资源访问权限的用户。

**修复方法**: 在条件允许的情况下，移除对节点对象代理子资源的访问权限。

**参考**: 1. https://kubernetes.io/docs/concepts/security/rbac-good-practices/#access-toproxy-subresource-of-nodes
2. https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authnauthz/#kubelet-authorization

**元数据**:
- category: "rbac"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.1"
- level: "1"
