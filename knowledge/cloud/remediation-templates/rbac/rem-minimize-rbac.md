# 修复方案: RBAC 最小权限配置

**风险类型**: RBAC Over-Permission
**严重性**: HIGH
**场景**: ServiceAccount 被授予过多权限（如 cluster-admin 或过于宽泛的 Role），可能被滥用

## 风险描述

RBAC（Role-Based Access Control）权限过大是 Kubernetes 集群中常见的安全问题。攻击者获取 ServiceAccount Token 后，可利用过高权限执行敏感操作。

**安全影响**:
- 权限提升：通过 impersonate 等权限提升为 cluster-admin
- 横向移动：访问其他命名空间的资源
- 数据泄露：读取 Secrets、ConfigMaps 等敏感数据
- 集群破坏：删除关键资源或修改安全策略

## 修复步骤

### 方法 1: 创建最小权限 Role（推荐）

**配置示例**:
```yaml
# 最小权限 Role - 仅允许读取 Pod
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: production
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]  # 仅读取操作

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-pod-reader
  namespace: production
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: production
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

### 方法 2: 避免使用 cluster-admin

**错误示例（禁止）**:
```yaml
# ❌ 不要这样做
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dangerous-binding
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: production
roleRef:
  kind: ClusterRole
  name: cluster-admin  # 危险：完全集群权限
  apiGroup: rbac.authorization.k8s.io
```

**正确示例**:
```yaml
# ✅ 仅授予必需权限
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list"]
  resourceNames: ["myapp"]  # 限制到特定资源
```

## 验证方法

```bash
# 检查是否有 ServiceAccount 绑定到 cluster-admin
kubectl get clusterrolebindings -o json | jq -r '
  .items[] |
  select(.roleRef.name == "cluster-admin") |
  .metadata.name
'

# 审计过大权限（通配符）
kubectl get roles,clusterroles -A -o json | jq -r '
  .items[] |
  select(.rules[].verbs[] == "*" or .rules[].resources[] == "*") |
  "\(.metadata.namespace // "cluster")/\(.metadata.name)"
'

# 检查 ServiceAccount 的实际权限
kubectl auth can-i --list --as=system:serviceaccount:production:app-sa
```

## 最佳实践

1. 最小权限原则：仅授予应用运行所需的最小权限
2. 避免通配符：不使用 `*` 作为 verbs、resources 或 apiGroups
3. 使用 resourceNames：限制权限到特定资源实例
4. 定期审计：使用 kubectl 或第三方工具（rbac-lookup）审计权限
5. 分离职责：不同功能使用不同 ServiceAccount

## 参考资料

- [Kubernetes RBAC Best Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [CIS Kubernetes Benchmark 5.1](https://www.cisecurity.org/benchmark/kubernetes)

**元数据**:
- category: "remediation"
- risk_type: "rbac_over_permission"
- severity: "HIGH"
- topic: "rbac"
