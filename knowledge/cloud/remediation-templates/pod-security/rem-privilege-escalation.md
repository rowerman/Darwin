# 修复方案: 限制容器权限提升

**风险类型**: Privilege Escalation
**严重性**: HIGH
**场景**: 容器允许权限提升（`allowPrivilegeEscalation: true`），进程可通过 setuid/setgid 获取更高权限

## 风险描述

当 `allowPrivilegeEscalation` 设置为 true 时，容器内的进程可以获得比父进程更多的权限。这允许攻击者利用 setuid 二进制文件（如 sudo、su）提升权限。

**安全影响**:
- 权限提升：非 root 进程可提升为 root
- 绕过安全策略：即使配置了 runAsNonRoot，仍可能被绕过
- 利用 setuid 漏洞：系统中的 setuid 程序成为攻击面

## 修复步骤

### 方法 1: 显式禁止权限提升（推荐）

**配置示例**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:1.0
        securityContext:
          allowPrivilegeEscalation: false  # 禁止权限提升
          runAsNonRoot: true               # 强制非 root 运行
          runAsUser: 1000
```

### 方法 2: 使用 Pod Security Standards

**Restricted 策略自动设置**:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
```

Restricted 策略要求 `allowPrivilegeEscalation: false` 必须显式设置。

## 验证方法

```bash
# 检查是否允许权限提升
kubectl get pods -n production -o json | jq -r '
  .items[] |
  select(
    .spec.containers[].securityContext.allowPrivilegeEscalation == true or
    (.spec.containers[].securityContext.allowPrivilegeEscalation | not)
  ) |
  .metadata.name
'

# 审计所有未设置 allowPrivilegeEscalation 的容器
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{end}'
```

## 最佳实践

1. 显式设置：始终显式设置 `allowPrivilegeEscalation: false`
2. 结合 runAsNonRoot：同时配置 `runAsNonRoot: true` 提供深度防御
3. 移除 setuid 程序：在容器镜像构建时移除不必要的 setuid 二进制文件
4. 使用 Distroless 镜像：减少攻击面

## 参考资料

- [Kubernetes Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [CIS Kubernetes Benchmark 5.2.6](https://www.cisecurity.org/benchmark/kubernetes)

**元数据**:
- category: "remediation"
- risk_type: "privilege_escalation"
- severity: "HIGH"
- topic: "pod_security"
