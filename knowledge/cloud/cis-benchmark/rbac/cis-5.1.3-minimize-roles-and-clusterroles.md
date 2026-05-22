# CIS Benchmark: 5.1.3 Minimize wildcard use in Roles and ClusterRoles

**编号**: 5.1.3
**级别**: Level 1
**描述**: Kubernetes 角色（Role）和集群角色（ClusterRole）基于对象集合以及可对这些对象执行的操作，来提供资源访问权限。可以将这两者的对象或操作设置为通配符 *，以匹配所有项目。
从安全角度来看，使用通配符并非最优选择，因为当新的资源（无论是以自定义资源定义（CRD）的形式，还是随该产品后续版本）被添加到 Kubernetes API 时，这可能会导致授予非预期的访问权限。
最小权限原则建议，只为用户提供其角色所需的访问权限，仅此而已。而授予通配符权限，则很可能会为 Kubernetes API 赋予过度的权限。

**影响**: [TODO: 从 PDF 复制影响说明]

**审计方法**: 获取集群中各命名空间下定义的角色，并检查其中是否存在通配符。
```bash
kubectl get roles --all-namespaces -o yaml
```
获取集群中定义的集群角色，并检查其中是否存在通配符。
```bash
kubectl get clusterroles -o yaml
```

**修复方法**: 在可行的情况下，将集群角色（ClusterRole）和角色（Role）中所有使用通配符的配置，替换为具体的对象或操作。

**参考**: 

**元数据**:
- category: "rbac"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.1"
- level: "1"
