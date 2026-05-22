# CIS Benchmark: 5.1.9 Minimize access to create persistent volumes

**编号**: 5.1.9
**级别**: Level 1
**描述**: 在集群中创建持久卷的权限，可能会通过创建 hostPath 类型卷的方式，为权限提升行为提供可乘之机。由于持久卷不受 Pod 安全准入控制的管控，因此即便集群已配置严格的 Pod 安全准入策略，拥有持久卷创建权限的用户，仍有可能访问到底层宿主机中的敏感文件。
在集群中创建持久卷的权限会增加权限提升的风险，因此在可行的情况下，应对该权限加以限制。

**影响**: 

**审计方法**: 检查那些对 Kubernetes API 中的持久卷（PersistentVolume）对象拥有创建权限的用户。

**修复方法**: 在条件允许的情况下，移除对集群中持久卷（PersistentVolume）对象的创建权限。

**参考**: 1. https://kubernetes.io/docs/concepts/security/rbac-good-practices/#persistentvolume-creation

**元数据**:
- category: "rbac"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.1"
- level: "1"
