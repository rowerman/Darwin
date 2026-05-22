# 修复方案: 配置 EmptyDir 大小限制

**风险类型**: EmptyDir Size Limit
**严重性**: LOW
**场景**: EmptyDir 卷未设置大小限制，可能导致磁盘耗尽和拒绝服务

## 风险描述

EmptyDir 是 Kubernetes 提供的临时存储卷，与 Pod 生命周期绑定。如果不设置大小限制，恶意或有缺陷的应用可能：
- 无限制写入数据，耗尽节点磁盘空间
- 导致节点上的其他 Pod 无法正常运行
- 触发节点驱逐（Eviction）机制

**安全影响**:
- 拒绝服务：磁盘耗尽导致节点不可用
- 影响其他 Pod：同节点的其他 Pod 受到影响
- 资源滥用：恶意应用占用过多存储

## 修复步骤

### 方法 1: 设置 sizeLimit（推荐）

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
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /var/cache
      volumes:
      - name: tmp
        emptyDir:
          sizeLimit: 1Gi  # 限制 /tmp 最大 1GB
      - name: cache
        emptyDir:
          sizeLimit: 500Mi  # 限制缓存最大 500MB
```

### 方法 2: 使用内存介质（临时高速存储）

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
        volumeMounts:
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: tmp
        emptyDir:
          medium: Memory  # 使用内存作为介质
          sizeLimit: 256Mi  # 必须设置大小限制
```

**注意**: 使用 `medium: Memory` 时，容量会计入容器的内存限制。

## 验证方法

```bash
# 检查未设置 sizeLimit 的 emptyDir
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(
    .spec.volumes[]? |
    select(.emptyDir) |
    .emptyDir.sizeLimit == null
  ) |
  "\(.metadata.namespace)/\(.metadata.name)"
'

# 监控 emptyDir 使用情况
kubectl exec -it <pod-name> -- df -h /tmp
```

## 最佳实践

1. 始终设置 sizeLimit：根据应用需求设置合理的大小限制
2. 保守估计：初始设置较小值，根据监控数据调整
3. 监控使用量：使用 Prometheus 监控 emptyDir 使用率
4. 使用 PVC：对于需要持久化或大容量存储的场景，使用 PVC
5. 资源配额：结合 ResourceQuota 限制命名空间的总存储

## 参考资料

- [Kubernetes EmptyDir Volumes](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir)
- [Resource Management](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)

**元数据**:
- category: "remediation"
- risk_type: "emptydir_size_limit"
- severity: "LOW"
- topic: "storage"
