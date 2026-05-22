# 修复方案: 配置 PersistentVolume 安全上下文

**风险类型**: PVC Security Context
**严重性**: MEDIUM
**场景**: PersistentVolume 未正确配置文件系统权限，导致权限过大或数据泄露

## 风险描述

PersistentVolume（PV）和 PersistentVolumeClaim（PVC）提供持久化存储。如果未正确配置安全上下文：
- 文件权限过于宽松（如 777）
- 多个 Pod 可能意外共享数据
- 非 root 容器无法访问卷

**安全影响**:
- 数据泄露：其他用户或进程可读取敏感数据
- 数据篡改：未授权的写入权限导致数据被修改
- 权限错误：非 root 容器无法访问卷

## 修复步骤

### 方法 1: 设置 fsGroup 和 fsGroupChangePolicy（推荐）

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
        fsGroup: 2000  # 设置文件系统组 ID
        fsGroupChangePolicy: OnRootMismatch  # 仅在权限不匹配时修改
      containers:
      - name: app
        image: myapp:1.0
        securityContext:
          runAsUser: 1000
          runAsGroup: 3000
        volumeMounts:
        - name: data
          mountPath: /data
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: app-data
```

### 方法 2: 使用 accessModes 限制访问

**配置示例**:
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: app-data
spec:
  accessModes:
  - ReadWriteOnce  # 仅允许单个节点读写
  resources:
    requests:
      storage: 10Gi
  storageClassName: encrypted-storage  # 使用加密存储类
```

**accessModes 说明**:
- `ReadWriteOnce` (RWO): 单节点读写（推荐）
- `ReadOnlyMany` (ROX): 多节点只读
- `ReadWriteMany` (RWX): 多节点读写（谨慎使用）

### 方法 3: 使用 StorageClass 加密

**配置示例**:
```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: encrypted-storage
provisioner: kubernetes.io/aws-ebs
parameters:
  type: gp3
  encrypted: "true"  # 启用加密
  kmsKeyId: arn:aws:kms:us-east-1:123456789:key/xxx
```

## 验证方法

```bash
# 检查 PVC 的 accessModes
kubectl get pvc -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {.spec.accessModes}{"\n"}{end}'

# 验证文件系统权限
kubectl exec -it <pod-name> -- ls -ld /data
# 预期输出：drwxrwsr-x 2 1000 2000 4096 Jan 1 00:00 /data

# 检查文件所有者和组
kubectl exec -it <pod-name> -- stat /data
```

## 最佳实践

1. 设置 fsGroup：确保非 root 容器能正确访问卷
2. 使用 ReadWriteOnce：避免多节点共享写入
3. 启用加密：使用加密 StorageClass 保护静态数据
4. 最小权限：避免 777 等过于宽松的权限
5. 定期备份：重要数据定期备份到外部存储

## 参考资料

- [Kubernetes Persistent Volumes](https://kubernetes.io/docs/concepts/storage/persistent-volumes/)
- [Configure a Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

**元数据**:
- category: "remediation"
- risk_type: "pvc_security_context"
- severity: "MEDIUM"
- topic: "storage"
