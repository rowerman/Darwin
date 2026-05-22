# 修复方案: 移除危险 Capabilities

**风险类型**: Dangerous Capabilities
**严重性**: HIGH
**场景**: 容器被授予危险的 Linux Capabilities（如 CAP_SYS_ADMIN），可能导致提权或逃逸

## 风险描述

Linux Capabilities 将 root 权限细分为多个独立的能力单元。某些 Capabilities（如 CAP_SYS_ADMIN、CAP_SYS_PTRACE、CAP_NET_ADMIN）可被滥用以逃逸容器或执行特权操作。

**安全影响**:
- 容器逃逸：CAP_SYS_ADMIN 允许挂载文件系统、修改内核模块
- 进程注入：CAP_SYS_PTRACE 允许调试和注入其他进程
- 网络劫持：CAP_NET_RAW 允许嗅探网络流量

## 修复步骤

### 方法 1: Drop ALL + 仅添加必需 Capabilities（推荐）

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
          capabilities:
            drop:
            - ALL
            # 仅在必要时添加最小 Capabilities
            add:
            - NET_BIND_SERVICE  # 允许绑定 <1024 端口
```

### 方法 2: 使用 Pod Security Standards 自动限制

**Restricted 策略自动禁止的 Capabilities**:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
```

Restricted 策略自动禁止添加除以下以外的任何 Capabilities：
- NET_BIND_SERVICE

## 验证方法

```bash
# 检查容器的 Capabilities
kubectl get pods -n production -o json | jq -r '
  .items[] | select(
    .spec.containers[].securityContext.capabilities.add[]? |
    contains("SYS_ADMIN") or contains("SYS_PTRACE") or contains("NET_RAW")
  ) | .metadata.name
'

# 审计所有添加了 Capabilities 的容器
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {.spec.containers[*].securityContext.capabilities.add}{"\n"}{end}'
```

## 最佳实践

1. 默认 Drop ALL：始终从 `drop: [ALL]` 开始，仅添加必需的 Capabilities
2. 避免危险 Capabilities：禁止 SYS_ADMIN、SYS_PTRACE、NET_RAW、SYS_MODULE
3. 文档化需求：如果必须添加 Capabilities，在代码注释中说明原因
4. 定期审计：使用自动化工具扫描危险 Capabilities

## 参考资料

- [Linux Capabilities Manual](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Kubernetes Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [CIS Kubernetes Benchmark 5.2.9](https://www.cisecurity.org/benchmark/kubernetes)

**元数据**:
- category: "remediation"
- risk_type: "dangerous_capabilities"
- severity: "HIGH"
- topic: "pod_security"
