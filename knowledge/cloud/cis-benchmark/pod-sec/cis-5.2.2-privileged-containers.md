# CIS Benchmark: 5.2.2 Minimize the admission of privileged containers

**编号**: 5.2.2
**级别**: Level 1
**描述**: 一般情况下，禁止运行将 securityContext.privileged 标志设置为 true 的容器。
特权容器拥有对所有 Linux 内核能力及设备的访问权限。以完全特权模式运行的容器，几乎可以执行宿主机能完成的所有操作。该标志的存在是为了支持部分特殊使用场景，例如操控网络协议栈、访问硬件设备等。
集群中应至少配置一项准入控制策略，明确禁止特权容器的运行。
若确实需要运行特权容器，则需为此单独定义一套策略，同时应仔细核查，确保仅为有限的服务账户和用户授予使用该策略的权限。

**影响**: 禁止创建以下容器配置的 Pod：
spec.containers[].securityContext.privileged: true;
spec.initContainers[].securityContext.privileged: true;
spec.ephemeralContainers[].securityContext.privileged: true

**审计方法**: 运行以下命令：
```bash
get pods -A -o=jsonpath=$'{range .items[*]}{@.metadata.name}:
{@..securityContext}\n{end}'
```
该工具会生成集群内所有特权使用情况的清单（若存在特权使用行为，可参考下方示例）。还可通过进一步的过滤检索操作，实现各类具体违规行为的自动化检测。
calico-kube-controllers-57b57c56f-jtmk4: {} << 无特权权限calico-nodec4xv4: {} {"privileged":true} {"privileged":true} {"privileged":true} {"privileged":true} << 违反规则 5.2.2dashboard-metrics-scraper-7bc864c59-2m2xw:{"seccompProfile":{"type":"RuntimeDefault"}}{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"runAsGroup":2001,"runAsUser":1001}

**修复方法**: 为集群内所有承载用户工作负载的命名空间添加策略，以限制特权容器的准入。

**参考**: 1. https://kubernetes.io/docs/concepts/security/pod-security-standards/

**元数据**:
- category: "pod_security"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.2"
- level: "1"
