# 修复方案: NetworkPolicy 隔离配置

**风险类型**: Network Policy Missing
**严重性**: MEDIUM
**场景**: 命名空间缺少 NetworkPolicy，所有 Pod 之间可以自由通信，缺乏网络隔离

## 风险描述

默认情况下，Kubernetes 集群中所有 Pod 可以相互通信。攻击者入侵一个 Pod 后，可以轻易横向移动到其他 Pod、访问数据库或敏感服务。

**安全影响**:
- 横向移动：攻击者可访问同命名空间或其他命名空间的 Pod
- 数据泄露：未授权访问数据库、缓存等服务
- 攻击扩散：蠕虫式攻击可快速传播

## 修复步骤

### 方法 1: 默认拒绝 + 白名单策略（推荐）

**步骤 1: 创建默认拒绝策略**:
```yaml
# 拒绝所有入站和出站流量
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}  # 应用到命名空间的所有 Pod
  policyTypes:
  - Ingress
  - Egress
```

**步骤 2: 创建白名单策略**:
```yaml
# 仅允许前端访问后端
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

### 方法 2: 允许特定命名空间访问

**配置示例**:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-monitoring
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring  # 仅允许 monitoring 命名空间访问
    ports:
    - protocol: TCP
      port: 9090
```

### 方法 3: 允许出站到特定服务（DNS、外部 API）

**配置示例**:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-and-external
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53  # DNS
  - to:
    - podSelector: {}
    ports:
    - protocol: TCP
      port: 443  # HTTPS 出站
```

## 验证方法

```bash
# 检查命名空间是否有 NetworkPolicy
kubectl get networkpolicy -n production

# 测试网络连接（从 Pod A 访问 Pod B）
kubectl exec -it pod-a -- curl http://pod-b-service:8080

# 验证默认拒绝策略生效
kubectl exec -it pod-a -- curl http://unauthorized-service:8080
# 预期：超时或连接被拒绝
```

## 最佳实践

1. 默认拒绝策略：在所有命名空间配置 default-deny-all
2. 最小化网络访问：仅允许必需的通信路径
3. 分离命名空间：使用 namespaceSelector 隔离不同环境
4. 测试策略：在测试环境验证策略不会影响正常功能
5. 文档化网络拓扑：绘制服务依赖图，辅助策略设计

## 参考资料

- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Network Policy Recipes](https://github.com/ahmetb/kubernetes-network-policy-recipes)

**元数据**:
- category: "remediation"
- risk_type: "network_policy_missing"
- severity: "MEDIUM"
- topic: "network"
