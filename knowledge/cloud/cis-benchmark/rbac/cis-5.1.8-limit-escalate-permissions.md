# CIS Benchmark: 5.1.8 Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster

**编号**: 5.1.8
**级别**: Level 1
**描述**: 除非确属必需，否则不应为集群角色（ClusterRole）和角色（Role）授予模拟（impersonate）、绑定（bind）或权限提升（escalate）权限。这三类权限中的任意一项，都可能使相关主体获得超出集群管理员明确授予范围的更高权限。
其中，模拟权限允许主体模拟其他用户身份，获取该用户对应的集群访问权限；绑定权限允许主体为集群角色或角色添加绑定关系，借此提升自身在集群中的实际操作权限；权限提升权限允许主体修改其所绑定的集群角色，从而将自身权限提升至该角色对应的级别。
上述三类权限均存在被滥用的风险，可能导致权限被提升至 集群管理员（cluster-admin） 级别。

**影响**: 在某些情况下，集群服务的运行确实需要用到这些权限，因此在从系统服务账户中移除这些权限前，需格外谨慎。

**审计方法**: 检查那些拥有包含模拟、绑定或权限提升权限的集群角色或角色访问权限的用户。

**修复方法**: 在可行的情况下，从相关主体中移除模拟、绑定及权限提升权限。

**参考**: 1. https://www.impidio.com/blog/kubernetes-rbac-security-pitfalls
2. https://raesene.github.io/blog/2020/12/12/Escalating_Away/
3. https://raesene.github.io/blog/2021/01/16/Getting-Into-A-Bind-with-Kubernetes/

**元数据**:
- category: "rbac"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.1"
- level: "1"
