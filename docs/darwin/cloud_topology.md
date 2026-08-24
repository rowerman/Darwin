# `darwin/cloud_topology.py`

## 模块定位

把云环境、Kubernetes 拓扑、RBAC、Pod 安全和 IAM 信任关系映射到 DKG；K8s 资源采集完成后由确定性关系分析器补齐控制器、服务和策略关系。

## 所在链路

云侦察与分析阶段，位于工具输出和攻击路径推理之间。

## 关键入口

- `CloudTopologyMapper`：维护拓扑映射，接受注入的 discovery tool port。
- `discover_cloud_topology()`：异步发现并写入拓扑。
- `CloudTopology`、`K8sRBACBinding`、`PodSecurityProfile`：拓扑结果模型。
- `CloudTopology` 还承载 Service、Deployment/StatefulSet/DaemonSet、EndpointSlice、Ingress、NetworkPolicy、RBAC 资源及 Secret/ConfigMap 元数据。

## 输入/输出概览

输入为 `DKG` 和经网关取得的云/K8s 工具观察结果；输出为 `CloudTopology`，并以幂等关系更新图。Orchestrator 只在环境分类命中云/K8s 后调用它。

## 相关模块

`dkg.py`、`topology_analysis.py`、`cloud_attack_path.py`、`dpm.py`、`tools/recon_server.py`。

## 阅读建议

先理解结果模型，再看 `CloudTopologyMapper` 的写图逻辑和发现入口。

## 维护提示

拓扑字段或关系变化时同步检查攻击路径和防御探测的消费者。
