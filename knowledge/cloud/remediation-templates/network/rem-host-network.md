# 修复方案: 禁止 HostNetwork 访问

**风险类型**: Host Network Access
**严重性**: HIGH
**场景**: 容器使用宿主机网络（`hostNetwork: true`），绕过 NetworkPolicy，增加攻击面

## 风险描述

当容器设置 `hostNetwork: true` 时，容器将直接使用宿主机的网络命名空间，而不是隔离的容器网络。这会导致：
- 绕过 NetworkPolicy 隔离
- 可监听宿主机上的所有端口
- 可嗅探宿主机网络流量
- 容器内进程可访问宿主机网络服务

**安全影响**:
- 网络隔离失效：NetworkPolicy 不再生效
- 端口冲突：容器可绑定宿主机端口，影响其他服务
- 流量嗅探：使用 tcpdump 等工具捕获宿主机流量
- 横向移动：直接访问宿主机上的其他服务

## 修复步骤

### 方法 1: 移除 hostNetwork 配置（推荐）

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
      hostNetwork: true  # 危险：使用宿主机网络
      containers:
      - name: app
        image: myapp:1.0
```

**正确配置**:
```yaml
# ✅ 使用容器网络
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      # hostNetwork: false  # 默认为 false，无需显式设置
      containers:
      - name: app
        image: myapp:1.0
        ports:
        - containerPort: 8080  # 容器端口
```

### 方法 2: 使用 Service 暴露端口（替代 hostPort）

如果需要暴露服务，使用 Service 而不是 hostNetwork 或 hostPort：

**配置示例**:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: app-service
spec:
  type: LoadBalancer  # 或 NodePort
  selector:
    app: myapp
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
```

### 方法 3: 使用 Pod Security Standards 限制

**配置示例**:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
```

Restricted 策略自动禁止 `hostNetwork: true`。

## 验证方法

```bash
# 检查使用 hostNetwork 的 Pod
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostNetwork == true) |
  "\(.metadata.namespace)/\(.metadata.name)"
'

# 验证容器网络命名空间
kubectl exec -it <pod-name> -- ip link show
# 应看到容器网络接口（如 eth0），而不是宿主机网络接口
```

## 最佳实践

1. 默认禁止：不使用 hostNetwork，除非绝对必要（如 CNI 插件）
2. 使用 Service：通过 Service 暴露端口，而不是 hostNetwork
3. 策略限制：使用 Pod Security Standards 或 Admission Webhook 拦截
4. 审计监控：定期审计使用 hostNetwork 的 Pod，确认合理性

## 参考资料

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CIS Kubernetes Benchmark 5.2.5](https://www.cisecurity.org/benchmark/kubernetes)

**元数据**:
- category: "remediation"
- risk_type: "host_network_access"
- severity: "HIGH"
- topic: "network"
