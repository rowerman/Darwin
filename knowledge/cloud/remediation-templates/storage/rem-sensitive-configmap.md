# 修复方案: 敏感信息使用 Secret 而非 ConfigMap

**风险类型**: Sensitive ConfigMap
**严重性**: MEDIUM
**场景**: 敏感信息（密码、API Key、证书）存储在 ConfigMap 中，明文可读

## 风险描述

ConfigMap 是为非敏感配置数据设计的，存储为明文。如果将敏感信息存储在 ConfigMap 中：
- 任何有权限读取 ConfigMap 的用户都能看到敏感数据
- ConfigMap 备份和日志可能泄露密钥
- RBAC 权限管理不够精细

**安全影响**:
- 数据泄露：密码、API Key 等明文暴露
- 权限滥用：攻击者获取凭证后访问外部系统
- 合规违规：违反数据保护法规

## 修复步骤

### 方法 1: 使用 Secret 存储敏感信息（推荐）

**错误配置（使用 ConfigMap）**:
```yaml
# ❌ 不要这样做
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  database-password: "MySecretPassword123"  # 明文密码
  api-key: "sk-1234567890abcdef"
```

**正确配置（使用 Secret）**:
```yaml
# ✅ 使用 Secret
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
stringData:
  database-password: "MySecretPassword123"
  api-key: "sk-1234567890abcdef"
```

**在 Pod 中使用 Secret**:
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
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: database-password
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: api-key
```

### 方法 2: 使用外部密钥管理系统

**集成 HashiCorp Vault**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "myapp"
        vault.hashicorp.com/agent-inject-secret-db: "secret/data/database"
    spec:
      serviceAccountName: app-sa
      containers:
      - name: app
        image: myapp:1.0
```

**集成 AWS Secrets Manager（使用 External Secrets Operator）**:
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secretsmanager
    kind: SecretStore
  target:
    name: app-secrets
    creationPolicy: Owner
  data:
  - secretKey: database-password
    remoteRef:
      key: prod/database/password
```

## 验证方法

```bash
# 检查 ConfigMap 中可能的敏感信息（关键词搜索）
kubectl get configmaps -A -o json | jq -r '
  .items[] |
  select(
    .data | to_entries[] |
    .key | test("password|secret|key|token|credential"; "i")
  ) |
  "\(.metadata.namespace)/\(.metadata.name)"
'

# 审计 ConfigMap 内容
kubectl get configmap <configmap-name> -o yaml
```

## 最佳实践

1. 分类存储：敏感数据使用 Secret，非敏感配置使用 ConfigMap
2. 加密静态数据：启用 Kubernetes Secret 加密（Encryption at Rest）
3. RBAC 限制：限制对 Secret 的访问权限
4. 外部密钥管理：使用 Vault、AWS Secrets Manager 等专业工具
5. 定期轮换：定期更新密钥和凭证
6. 避免环境变量：优先使用 Volume 挂载 Secret（避免环境变量泄露）

## 参考资料

- [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
- [Secrets Management Good Practices](https://kubernetes.io/docs/concepts/security/secrets-good-practices/)

**元数据**:
- category: "remediation"
- risk_type: "sensitive_configmap"
- severity: "MEDIUM"
- topic: "storage"
