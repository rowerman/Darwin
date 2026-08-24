# `darwin/topology_analysis.py`

## 模块定位

对已写入 DKG 的 Kubernetes 资源执行确定性关系分析，不调用 LLM，也不直接执行外部命令。

## 关键入口

- `RelationAnalyzer.analyze(dkg, environment=None)`：根据 Service selector、Pod ownerReferences、EndpointSlice、Ingress、RBAC Binding、NetworkPolicy、IAM policy/trust 和 AWS 网络资源事实幂等写入关系。
- `TopologyAnalysisResult`：返回 revision、关系变更数、coverage、受影响攻击路径和 warnings。

## 约束

- 所有关系必须使用 `dkg.py` 中登记的 canonical edge type。
- `observed`/`inferred` 关系可供 Planner 使用；弱推断不能直接提升任务优先级。
- 分析器只消费已有 DKG 节点，采集失败通过 coverage/warnings 表示，不阻断普通 Web/DB 流程。
- AWS 与 K8s 通过 EKS cluster 名称/ARN crosswalk 建立关联；ARN、K8s UID 和规范化 resource ID 优先于名称匹配。
