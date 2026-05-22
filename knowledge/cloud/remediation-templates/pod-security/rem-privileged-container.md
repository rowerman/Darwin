# 修复方案: 禁止特权容器

**风险类型**: Privileged Container
**严重性**: CRITICAL
**场景**: 容器以特权模式运行（`privileged: true`），拥有宿主机的所有权限，存在逃逸风险

## 风险描述

特权容器（Privileged Container）拥有对宿主机所有 Linux Capabilities 和设备的访问权限。攻击者可以利用特权容器逃逸到宿主机，访问所有容器和敏感数据，修改内核参数，安装后门。

**安全影响**:
- 容器逃逸风险：攻击者可以轻易突破容器隔离
- 横向移动：获取宿主机权限后可访问所有容器
- 数据泄露：访问宿主机上的敏感文件和密钥

## 修复步骤

### 方法 1: Pod Security Standards - Restricted 策略（推荐）

**适用场景**: Kubernetes 1.23+，使用原生 Pod Security Admission 控制

**配置示例**:
```yaml
# 为命名空间配置 Restricted 策略
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### 方法 2: 修复已存在的特权容器

**修复 Deployment 配置**:
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
          privileged: false              # 显式设置为 false
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true
```

## 验证方法

**验证 Pod Security Standards 是否生效**:
```bash
# 检查命名空间策略
kubectl get namespace production -o yaml | grep pod-security

# 尝试创建特权容器（应被拒绝）
kubectl run test --image=nginx --privileged -n production

# 检查现有 Pod 是否有特权容器
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {.spec.containers[*].securityContext.privileged}{"\n"}{end}' | grep -v "false"
```

## 最佳实践

1. 默认拒绝策略：在所有应用命名空间配置 Restricted 策略
2. 白名单例外：对于确实需要特权的组件（如 CNI），创建单独的命名空间
3. CI/CD 集成：在部署流水线中集成 kubesec 扫描，拦截特权容器配置
4. 定期审计：使用 kube-bench 定期审计集群

## 参考资料

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CIS Kubernetes Benchmark 5.2.2](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)

**元数据**:
- category: "remediation"
- risk_type: "privileged_container"
- severity: "CRITICAL"
- topic: "pod_security"
