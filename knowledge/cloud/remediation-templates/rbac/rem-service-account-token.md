# 修复方案: ServiceAccount Token 自动挂载控制

**风险类型**: ServiceAccount Token Auto-Mount
**严重性**: MEDIUM
**场景**: ServiceAccount Token 自动挂载到所有 Pod，即使 Pod 不需要访问 Kubernetes API

## 风险描述

默认情况下，Kubernetes 会自动将 ServiceAccount Token 挂载到每个 Pod 的 `/var/run/secrets/kubernetes.io/serviceaccount/token` 路径。如果应用不需要访问 API Server，这个 Token 会增加攻击面。

**安全影响**:
- Token 泄露：攻击者获取 Token 后可访问 Kubernetes API
- 权限滥用：即使应用不使用 API，Token 仍可被利用
- 横向移动：通过 Token 访问其他资源

## 修复步骤

### 方法 1: 在 Pod 级别禁用自动挂载（推荐）

**配置示例**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      automountServiceAccountToken: false  # 禁用自动挂载
      containers:
      - name: app
        image: myapp:1.0
```

### 方法 2: 在 ServiceAccount 级别禁用

**配置示例**:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: production
automountServiceAccountToken: false  # 默认禁用

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      serviceAccountName: app-sa
      # 如果需要，可在 Pod 级别覆盖为 true
      containers:
      - name: app
        image: myapp:1.0
```

## 验证方法

```bash
# 检查是否有自动挂载 Token 的 Pod
kubectl get pods -n production -o json | jq -r '
  .items[] |
  select(.spec.automountServiceAccountToken != false) |
  .metadata.name
'

# 验证容器内是否存在 Token
kubectl exec -it <pod-name> -- ls /var/run/secrets/kubernetes.io/serviceaccount/
# 如果禁用成功，应返回：No such file or directory
```

## 最佳实践

1. 默认禁用：对于不需要访问 API 的应用，禁用自动挂载
2. 显式启用：仅在确实需要时，在 Pod 级别显式设置为 true
3. 最小权限：如果需要 Token，确保 ServiceAccount 权限最小化
4. 使用 Projected Volumes：Kubernetes 1.20+ 使用短期 Token（自动轮换）

## 参考资料

- [Kubernetes Service Accounts](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [CIS Kubernetes Benchmark 5.1.6](https://www.cisecurity.org/benchmark/kubernetes)

**元数据**:
- category: "remediation"
- risk_type: "serviceaccount_token_auto_mount"
- severity: "MEDIUM"
- topic: "rbac"
