# CIS Benchmark: 5.2.1 Ensure that the cluster has at least one active policy control

**编号**: 5.2.1
**级别**: Level 1
**描述**: 每个 Kubernetes 集群都应至少部署一套策略管控机制，以落实本节提出的其他各项要求。该机制可以是内置的 Pod 安全准入控制器，也可以是第三方策略管控系统。
若未启用有效的策略管控机制，则无法限制那些能够访问集群底层节点的容器的使用 —— 比如特权容器的运行，或是 hostPath 卷挂载的操作。

**影响**: 在已部署策略管控系统的情况下，存在集群运行所需的工作负载被阻止运行的风险。因此在实施准入控制策略时，需格外谨慎，以避免出现此类情况。

**审计方法**: 运行以下命令：
```bash
get pods -A -o=jsonpath=$'{range .items[*]}{@.metadata.name}:
{@..securityContext}\n{end}'
```
该工具会生成集群内所有特权使用情况的清单（若存在特权使用行为，请参考下方示例）。还可以通过进一步的过滤操作，实现各类违规行为的自动化检测。

calico-kube-controllers-57b57c56f-jtmk4: {} << 无特权权限
calico-nodec4xv4: {} {"privileged":true} {"privileged":true} {"privileged":true} {"privileged":true} << 违反规则 5.2.2dashboard-metrics-scraper-7bc864c59-2m2xw:{"seccompProfile":{"type":"RuntimeDefault"}}{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"runAsGroup":2001,"runAsUser":1001}

**修复方法**: 确保所有承载用户工作负载的命名空间，均已部署 Pod 安全准入控制器或第三方策略管控系统。

**参考**: 1. https://kubernetes.io/docs/concepts/security/pod-security-admission

**元数据**:
- category: "pod_security"
- source: "CIS"
- version: "1.8.0"
- date: "2023-10-01"
- section: "5.2"
- level: "1"
