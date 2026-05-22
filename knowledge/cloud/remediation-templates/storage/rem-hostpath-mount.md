# 修复方案: 限制 HostPath 挂载

**风险类型**: HostPath Mount
**严重性**: HIGH
**场景**: 容器挂载宿主机敏感目录（如 `/etc`、`/root`、`/var/log`），可读写宿主机文件

## 风险描述

HostPath 卷允许容器挂载宿主机的文件系统路径。攻击者可以利用 HostPath 挂载：
- 读取宿主机敏感文件（SSH 密钥、证书、配置）
- 修改宿主机配置文件
- 通过 `/etc/crontab` 植入后门
- 覆盖系统二进制文件

**安全影响**:
- 数据泄露：读取 `/etc/shadow`、SSH 密钥等
- 容器逃逸：修改 `/etc/passwd`、`/etc/sudoers` 等
- 持久化：写入 cron 任务或 systemd 服务
- 宿主机破坏：删除关键文件

## 修复步骤

### 方法 1: 使用其他卷类型替代（推荐）

**使用 emptyDir（临时存储）**:
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
        emptyDir: {}  # 使用 emptyDir 替代 hostPath
```

**使用 PersistentVolumeClaim（持久存储）**:
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: app-data
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi

---
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
        - name: data
          mountPath: /data
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: app-data
```

### 方法 2: 限制 HostPath 路径和权限

如果必须使用 HostPath，限制到非敏感路径并设置为只读：

**配置示例**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: log-collector
spec:
  template:
    spec:
      containers:
      - name: collector
        image: log-collector:1.0
        volumeMounts:
        - name: logs
          mountPath: /host-logs
          readOnly: true  # 只读挂载
      volumes:
      - name: logs
        hostPath:
          path: /var/log/pods  # 限制到特定路径
          type: Directory
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

Restricted 策略禁止 HostPath 卷。

## 验证方法

```bash
# 检查使用 HostPath 的 Pod
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.volumes[]?.hostPath) |
  "\(.metadata.namespace)/\(.metadata.name): \(.spec.volumes[] | select(.hostPath) | .hostPath.path)"
'

# 检查挂载敏感目录的 Pod
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(
    .spec.volumes[]?.hostPath?.path |
    test("^(/etc|/root|/var/run|/sys|/proc)")
  ) |
  "\(.metadata.namespace)/\(.metadata.name)"
'
```

## 最佳实践

1. 避免 HostPath：优先使用 emptyDir、PVC 或 ConfigMap
2. 限制路径：如果必须使用，限制到非敏感路径（如 `/var/log/pods`）
3. 只读挂载：设置 `readOnly: true`
4. 使用 type 字段：指定 `type: Directory` 或 `type: File` 进行验证
5. Admission Control：使用策略引擎拦截危险 HostPath

## 参考资料

- [Kubernetes Volumes](https://kubernetes.io/docs/concepts/storage/volumes/)
- [CIS Kubernetes Benchmark 5.2.12](https://www.cisecurity.org/benchmark/kubernetes)

**元数据**:
- category: "remediation"
- risk_type: "hostpath_mount"
- severity: "HIGH"
- topic: "storage"
