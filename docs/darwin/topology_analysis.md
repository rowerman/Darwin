# `darwin/topology_analysis.py`

## 模块定位

对已写入 DKG 的 Kubernetes 资源执行确定性关系分析，不调用 LLM，也不直接执行外部命令。

## 关键入口

- `RelationAnalyzer.analyze(dkg, environment=None)`：根据 Service selector/ports、Pod ownerReferences、EndpointSlice、Ingress、RBAC Binding 与 rules、NetworkPolicy、ConfigMap 服务引用、IAM policy/trust 和 AWS 网络资源事实幂等写入关系。
- `TopologyAnalysisResult`：返回 revision、关系变更数、coverage、受影响攻击路径和 warnings。

## 约束

- 所有关系必须使用 `dkg.py` 中登记的 canonical edge type。
- `observed`/`inferred` 关系可供 Planner 使用；弱推断不能直接提升任务优先级。
- 分析器只消费已有 DKG 节点，采集失败通过 coverage/warnings 表示，不阻断普通 Web/DB 流程。
- AWS 与 K8s 通过 EKS cluster 名称/ARN crosswalk 建立关联；ARN、K8s UID 和规范化 resource ID 优先于名称匹配。
- 服务暴露关系（`service_exposes_endpoint`/`endpoint_backed_by_service`）与 AWS 暴露关系（`resource_exposed_via`）会自动创建缺失的 Endpoint 节点，来源标记为 `relation_analyzer`。
- 服务调用（`service_calls_service`）仅依据 ConfigMap 非敏感 data 中的显式 `http://svc` 或 `svc:port` 引用推断；RBAC 权限以 `role_grants_permission → K8sNamespace` 聚合呈现。
