# 修复方案: 移除 Docker Socket 挂载

**风险类型**: Docker Socket Mount
**严重性**: CRITICAL
**场景**: 容器挂载 Docker Socket（`/var/run/docker.sock`），可完全控制宿主机 Docker Daemon

## 风险描述

将 Docker Socket 挂载到容器是最危险的配置之一。攻击者获取容器访问权限后，可以：
- 创建特权容器并逃逸到宿主机
- 列出和访问宿主机上的所有容器
- 读取其他容器的环境变量和密钥
- 停止或删除关键容器

**安全影响**:
- 容器逃逸：通过 Docker Socket 创建特权容器逃逸
- 完全宿主机控制：等同于 root 权限访问宿主机
- 横向移动：访问宿主机上的所有容器
- 数据泄露：读取其他容器的敏感数据

## 修复步骤

### 方法 1: 移除 Docker Socket 挂载（推荐）

**错误配置**:
```yaml
# ❌ 不要这样做
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
        volumeMounts:
        - name: docker-socket
          mountPath: /var/run/docker.sock  # 危险：挂载 Docker Socket
      volumes:
      - name: docker-socket
        hostPath:
          path: /var/run/docker.sock
```

**正确配置**:
```yaml
# ✅ 移除 Docker Socket 挂载
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
        # 不挂载任何 Docker Socket
```

### 方法 2: 使用 Kubernetes API 替代 Docker API

如果需要管理容器，使用 Kubernetes API 而不是 Docker API：

**配置示例**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: controller
spec:
  template:
    spec:
      serviceAccountName: controller-sa  # 授予有限的 K8s API 权限
      containers:
      - name: controller
        image: my-controller:1.0
        env:
        - name: KUBERNETES_SERVICE_HOST
          value: kubernetes.default.svc
```

**RBAC 配置**:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: controller-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]  # 仅读取权限
```

### 方法 3: 使用 Admission Webhook 拦截

**Kyverno 策略示例**:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-docker-socket
spec:
  validationFailureAction: enforce
  rules:
  - name: check-docker-socket
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Mounting /var/run/docker.sock is forbidden"
      pattern:
        spec:
          =(volumes):
          - =(hostPath):
              path: "!/var/run/docker.sock"
```

## 验证方法

```bash
# 检查挂载 Docker Socket 的 Pod
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(
    .spec.volumes[]?.hostPath?.path == "/var/run/docker.sock"
  ) |
  "\(.metadata.namespace)/\(.metadata.name)"
'

# 验证容器内是否能访问 Docker
kubectl exec -it <pod-name> -- docker ps
# 预期：command not found 或连接失败
```

## 最佳实践

1. 完全禁止：在生产环境禁止挂载 Docker Socket
2. 使用 Kubernetes API：通过 K8s API 管理 Pod，而不是 Docker API
3. Admission Control：使用 OPA/Kyverno 策略自动拦截
4. 审计监控：定期审计挂载配置，确保没有遗漏
5. 容器运行时隔离：使用 containerd、CRI-O 等运行时，避免直接暴露 Docker Socket

## 参考资料

- [CIS Docker Benchmark 5.31](https://www.cisecurity.org/benchmark/docker)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)

**元数据**:
- category: "remediation"
- risk_type: "docker_socket_mount"
- severity: "CRITICAL"
- topic: "storage"
