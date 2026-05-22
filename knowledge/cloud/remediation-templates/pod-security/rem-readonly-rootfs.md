# 修复方案: 配置只读根文件系统

**风险类型**: Writable RootFS
**严重性**: MEDIUM
**场景**: 容器根文件系统可写，攻击者可植入恶意文件、修改配置或下载工具

## 风险描述

默认情况下，容器的根文件系统是可写的。攻击者入侵容器后可以：
- 下载和执行恶意工具
- 修改应用配置文件
- 植入后门和持久化机制
- 覆盖系统二进制文件

**安全影响**:
- 恶意软件植入：攻击者可下载挖矿、后门等工具
- 配置篡改：修改应用配置导致数据泄露
- 取证困难：攻击者可清除日志和痕迹

## 修复步骤

### 方法 1: 设置只读根文件系统 + emptyDir（推荐）

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
          readOnlyRootFilesystem: true  # 只读根文件系统
        volumeMounts:
        - name: tmp
          mountPath: /tmp              # 临时文件目录
        - name: cache
          mountPath: /var/cache/app    # 缓存目录
      volumes:
      - name: tmp
        emptyDir: {}
      - name: cache
        emptyDir: {}
```

### 方法 2: Nginx 示例（需要额外挂载点）

**Nginx 配置示例**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  template:
    spec:
      containers:
      - name: nginx
        image: nginx:1.21
        securityContext:
          readOnlyRootFilesystem: true
        volumeMounts:
        - name: nginx-cache
          mountPath: /var/cache/nginx
        - name: nginx-run
          mountPath: /var/run
      volumes:
      - name: nginx-cache
        emptyDir: {}
      - name: nginx-run
        emptyDir: {}
```

## 验证方法

```bash
# 检查未设置只读根文件系统的容器
kubectl get pods -n production -o json | jq -r '
  .items[] |
  select(
    .spec.containers[].securityContext.readOnlyRootFilesystem != true
  ) |
  .metadata.name
'

# 验证容器内文件系统是否只读
kubectl exec -it <pod-name> -- touch /test
# 预期输出：touch: cannot touch '/test': Read-only file system
```

## 最佳实践

1. 识别可写目录需求：分析应用需要写入的目录（/tmp、/var/log 等）
2. 使用 emptyDir：为必须可写的目录挂载 emptyDir 卷
3. 限制 emptyDir 大小：设置 `sizeLimit` 防止磁盘耗尽
4. 日志外部化：使用 sidecar 或日志收集器，避免在容器内写日志

## 参考资料

- [Kubernetes Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [CIS Kubernetes Benchmark 5.2.6](https://www.cisecurity.org/benchmark/kubernetes)

**元数据**:
- category: "remediation"
- risk_type: "writable_rootfs"
- severity: "MEDIUM"
- topic: "pod_security"
