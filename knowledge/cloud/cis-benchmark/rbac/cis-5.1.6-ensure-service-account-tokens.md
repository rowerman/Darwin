# CIS Benchmark: 5.1.6 Ensure that Service Account Tokens are only mounted where necessary

**编号**: 5.1.6
**级别**: Level 1
**描述**: 除非 Pod 内运行的工作负载明确需要与 API 服务器通信，否则不应在 Pod 中挂载服务账户令牌。
在 Pod 内挂载服务账户令牌，可能会为权限提升攻击提供可乘之机 —— 攻击者一旦攻陷集群中的某个 Pod，便可利用该令牌进一步发起攻击。避免挂载此类令牌，能够直接消除这一攻击途径。

**影响**: 未挂载服务账户令牌的 Pod 无法与 API 服务器通信，但资源对未认证主体开放的情况除外。

**审计方法**: 检查集群中的 Pod 和服务账户对象，确保已配置以下选项，除非相关资源明确需要此项访问权限。
```bash
automountServiceAccountToken: false
```

**修复方法**: 修改那些无需挂载服务账户令牌的 Pod 与服务账户的定义，禁用令牌挂载功能。

**参考**: 1. https://kubernetes.io/docs/tasks/configure-pod-container/configure-serviceaccount/

**元数据**:
- category: "rbac"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.1"
- level: "1"
