# CIS Benchmark: 5.1.12 Minimize access to webhook configuration objects

**编号**: 5.1.12
**级别**: Level 1
**描述**: 拥有创建 / 修改 / 删除验证型 Webhook 配置（ValidatingWebhookConfiguration）或变异型 Webhook 配置（MutatingWebhookConfiguration）权限的用户，能够管控对应的 Webhook 组件。这些 Webhook 可以读取所有被准入到集群中的对象；而对于变异型 Webhook 而言，还可以对被准入的对象进行修改操作。此类权限可能会被利用来实现权限提升，或是对集群的正常运行造成干扰。
因此，管理 Webhook 配置的权限应当受到严格限制。

**影响**: 

**审计方法**: 检查那些拥有 Kubernetes API 中验证型 Webhook 配置（ValidatingWebhookConfiguration）或变异型 Webhook 配置（MutatingWebhookConfiguration）对象访问权限的用户。

**修复方法**: 在条件允许的情况下，移除对验证型 Webhook 配置（ValidatingWebhookConfiguration）或变异型 Webhook 配置（MutatingWebhookConfiguration）对象的访问权限。

**参考**: 1. https://kubernetes.io/docs/concepts/security/rbac-good-practices/#controladmission-webhooks

**元数据**:
- category: "rbac"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.1"
- level: "1"
