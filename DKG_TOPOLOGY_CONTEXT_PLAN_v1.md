# DARWIN 拓扑上下文下一轮计划

本轮基础闭环已完成：

- DKG 关系按 `(from, to, type)` 幂等 upsert；历史重复边可折叠；变更 journal 和 scope 可持久化。
- 基础扫描后使用规则分类器区分 `WEB_DB`、`PRIVATE_CLOUD`、`PUBLIC_CLOUD`、`HYBRID`、`UNKNOWN`。
- 云/K8s discovery 只在分类命中后执行，K8s 只读命令通过 gateway tool port。
- Host/Service/Endpoint 基础关系、K8s Service selector → Pod 关系已接入。
- `DKG.topology_context()` 提供全局摘要、局部图、增量变化和 coverage；belief/research/replan 可消费云上下文。
- 攻击路径支持稳定 `path_id`、confidence、status、evidence 和 checkpoint 持久化。

## 下一轮优先级

1. **RelationAnalyzer**
   - 新增确定性 `TopologyAnalysisResult`。
   - 分析 K8s selector、labels、Ingress、EndpointSlice、RBAC、NetworkPolicy。
   - 分析 IAM trust/permission policy、网络可达性、服务调用和资源依赖。
   - 只让 observed/inferred 关系生成高优先级任务。

2. **完整 K8s 资源采集**
   - Deployment、StatefulSet、DaemonSet、EndpointSlice、Ingress、NetworkPolicy。
   - Role、ClusterRole、RoleBinding、ClusterRoleBinding、Secret、ConfigMap。
   - 采集结果必须经过 discovery gateway，并使用现有 canonical 关系名。

3. **AWS 资源采集**
   - Account、VPC、Subnet、RouteTable、SecurityGroup、ENI、EC2、EKS、LoadBalancer、RDS、S3。
   - IAMPolicy 与 Role/Resource 关系。
   - 完成 AWS + Kubernetes hybrid 关系合并和资源去重。

4. **攻击路径 replan 完善**
   - 将稳定 `path_id` 映射到任务依赖。
   - 根据 Evaluator 结果更新路径 confidence/status。
   - 只重算受影响路径，不重算无关路径。

5. **测试与验收**
   - K8s/AWS/Hybrid fixture 和 CLI stubs。
   - 验证普通 Web/DB 不触发云采集。
   - 验证 topology diff、coverage、路径状态和 checkpoint 作用域。

## 保持不变的约束

- 外部命令必须经 MCPGateway/Executor；mapper 不得直接创建子进程。
- 原始 DKG 不截断，`max_nodes/max_edges` 只限制 LLM 视图。
- 不引入同义关系双写；新关系必须先进入语义注册表。
- Azure/GCP 本轮仍只保留 provider-neutral 分类和扩展接口。
