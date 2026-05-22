# 修复方案: 避免 RBAC 通配符权限

**风险类型**: Wildcard Permissions
**严重性**: HIGH
**场景**: RBAC 规则使用通配符（`*`）授予过于宽泛的权限

## 风险描述

在 RBAC 规则中使用通配符（`*`）会授予对所有资源或所有操作的权限，极易被滥用。常见的通配符滥用包括：
- `verbs: ["*"]`: 允许所有操作（get、create、delete 等）
- `resources: ["*"]`: 允许访问所有资源类型
- `apiGroups: ["*"]`: 允许访问所有 API 组

**安全影响**:
- 权限过大：攻击者可执行任意操作
- 难以审计：无法清晰了解实际权限范围
- 违反最小权限原则

## 修复步骤

### 方法 1: 显式列举权限（推荐）

**错误示例（使用通配符）**:
```yaml
# ❌ 不要这样做
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: bad-role
rules:
- apiGroups: ["*"]        # 危险：所有 API 组
  resources: ["*"]        # 危险：所有资源
  verbs: ["*"]            # 危险：所有操作
```

**正确示例（显式列举）**:
```yaml
# ✅ 显式列举所需权限
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: good-role
  namespace: production
rules:
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list"]
```

### 方法 2: 限制到特定资源实例

**配置示例**:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: restricted-role
  namespace: production
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "update", "patch"]
  resourceNames: ["myapp", "frontend"]  # 仅允许访问特定 Deployment
```

## 验证方法

```bash
# 查找使用通配符的 Role/ClusterRole
kubectl get roles,clusterroles -A -o json | jq -r '
  .items[] |
  select(
    .rules[].verbs[] == "*" or
    .rules[].resources[] == "*" or
    .rules[].apiGroups[] == "*"
  ) |
  "\(.kind)/\(.metadata.namespace // "cluster")/\(.metadata.name)"
'

# 详细审计某个 Role
kubectl describe role <role-name> -n <namespace>
```

## 最佳实践

1. 避免所有通配符：不使用 `*` 作为 verbs、resources 或 apiGroups
2. 显式列举：清晰列出所有需要的权限
3. 使用 resourceNames：进一步限制到特定资源实例
4. 代码审查：在 PR 中审查 RBAC 配置，拒绝通配符
5. 自动化检测：使用 OPA/Kyverno 策略拦截通配符权限

## 参考资料

- [Kubernetes RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [CIS Kubernetes Benchmark 5.1.3](https://www.cisecurity.org/benchmark/kubernetes)

**元数据**:
- category: "remediation"
- risk_type: "wildcard_permissions"
- severity: "HIGH"
- topic: "rbac"
