# CIS Benchmark: 5.1.11 Minimize access to the approval sub-resource of

**编号**: 5.1.11
**级别**: Level 1
**描述**: 拥有更新证书签名请求（CertificateSigningRequest）对象审批子资源权限的用户，能够为 Kubernetes API 审批新的客户端证书，这实际上相当于允许他们创建新的高权限用户账户。
根据集群内配置的用户权限情况，此类操作甚至可能导致权限被提升至完整的集群管理员级别。
因此，更新证书签名请求的权限应当受到严格限制。

**影响**: 

**审计方法**: 检查那些拥有更新 Kubernetes API 中证书签名请求（CertificateSigningRequest）对象审批子资源权限的用户。

**修复方法**: 在条件允许的情况下，移除对证书签名请求（CertificateSigningRequest）对象审批子资源的访问权限。

**参考**: 1. https://kubernetes.io/docs/concepts/security/rbac-good-practices/#csrs-andcertificate-issuing

**元数据**:
- category: "rbac"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.1"
- level: "1"
