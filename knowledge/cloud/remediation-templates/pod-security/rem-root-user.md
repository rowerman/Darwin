# 修复方案: 配置非 Root 用户运行

**风险类型**: Root User
**严重性**: MEDIUM
**场景**: 容器以 root 用户（UID 0）运行，增加容器逃逸和提权的风险

## 风险描述

默认情况下，许多容器以 root 用户运行。虽然容器提供了一定的隔离，但 root 用户仍具有更高的权限，容易被利用进行逃逸或横向移动。

**安全影响**:
- 提权风险：如果存在容器逃逸漏洞，攻击者直接获得 root 权限
- 文件系统修改：root 用户可修改容器内任意文件
- 增加攻击面：root 权限使更多系统调用和操作成为可能

## 修复步骤

### 方法 1: 在 SecurityContext 中指定用户（推荐）

**配置示例**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true  # 强制非 root 运行
        runAsUser: 1000     # 指定 UID
        runAsGroup: 3000    # 指定 GID
        fsGroup: 2000       # 文件系统组
      containers:
      - name: app
        image: myapp:1.0
```

### 方法 2: 在 Dockerfile 中指定用户

**Dockerfile 示例**:
```dockerfile
FROM nginx:1.21

# 创建非 root 用户
RUN useradd -u 1000 -U -s /bin/false appuser

# 切换到非 root 用户
USER 1000

CMD ["nginx", "-g", "daemon off;"]
```

## 验证方法

```bash
# 检查以 root 运行的容器
kubectl get pods -n production -o json | jq -r '
  .items[] |
  select(
    .spec.securityContext.runAsUser == 0 or
    (.spec.securityContext.runAsNonRoot | not)
  ) |
  .metadata.name
'

# 验证容器内的实际用户
kubectl exec -it <pod-name> -- id
# 预期输出：uid=1000(appuser) gid=3000 groups=2000
```

## 最佳实践

1. 显式指定 UID：避免使用用户名，直接使用数字 UID（如 1000）
2. 使用 runAsNonRoot: true：提供额外的安全检查
3. 设置 fsGroup：确保挂载的卷文件权限正确
4. 镜像构建时配置：在 Dockerfile 中 USER 指令设置默认用户

## 参考资料

- [Kubernetes Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [CIS Kubernetes Benchmark 5.2.7](https://www.cisecurity.org/benchmark/kubernetes)

**元数据**:
- category: "remediation"
- risk_type: "root_user"
- severity: "MEDIUM"
- topic: "pod_security"
