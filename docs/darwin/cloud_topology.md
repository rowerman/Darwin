# `darwin/cloud_topology.py`

## 模块定位

把云环境、Kubernetes 拓扑、AWS 资源、RBAC、Pod 安全和 IAM 信任关系映射到 DKG；资源采集完成后由确定性关系分析器补齐控制器、服务、策略和网络关系。

## 所在链路

云侦察与分析阶段，位于工具输出和攻击路径推理之间。

## 关键入口

- `CloudTopologyMapper`：维护拓扑映射，接受注入的 discovery tool port。
- `discover_cloud_topology()`：异步发现并写入拓扑。
- `write_k8s_service_nodes()`：K8s Service 的唯一写入点。一个 Service 节点 =
  一个监听端口（`port/protocol/service_name/version/banner` + `k8s_namespace`/
  `k8s_service_type`/`cluster_ip`/`k8s_selector`/`name`），id 为
  `svc-k8s-<ns>-<name>-<port>`；cluster discovery 与本 mapper 都调用它，
  重复发现是幂等更新，同一 Service 不会以两种形状出现在世界模型里。
- `CloudTopology`、`K8sRBACBinding`、`PodSecurityProfile`：拓扑结果模型。
- `CloudTopology` 还承载 Service、Deployment/StatefulSet/DaemonSet、EndpointSlice、Ingress、NetworkPolicy、RBAC 资源及 Secret/ConfigMap 元数据。
- IMDS 发现会写入完整 `Credential`、`IAMRole`、metadata Host/Service/Endpoint 及 `credential_for_role` 关系；完整凭据仅用于执行器读取，摘要和 prompt-facing 拓扑视图自动脱敏。
- 对已有云 dashboard URL fetcher 证据，mapper 会建立 Docker benchmark 的 IMDS 假设拓扑和 Web→IMDS 可达/调用关系，后续真实响应通过幂等 upsert 合并。
- `cloud_discovery_aws` 只允许通过 gateway 执行读取型 STS/EC2/EKS/ELB/RDS/S3/IAM action；AWS 资源使用 ARN 或规范化复合 ID。
- ConfigMap 采集保存非敏感 `data`（单值截断 200 字符、排除 secret 类 key）；IAMPolicy 额外按 `DefaultVersionId` 拉取 `get-policy-version` 文档。
- RouteTable 与 Subnet 的 association 写为 `route_table_routes_to`；EKS `name`/`ClusterName` 均登记为 crosswalk 查找键。
- **Host 唯一主机模型**：K8s 节点与 AWS EC2 实例统一写入 `Host` 节点（`provider=k8s/aws`，属性保留 cluster/internal_ip/InstanceId/SubnetId/Groups 等）；ENI 折叠为 Host 的 `network_interfaces` 属性，不再单独建节点。`EC2`/`K8sNode`/`ENI` 仅为旧 checkpoint 的 legacy 类型，新环境不再产生。
- **Pod 安全画像**：`securityContext.capabilities.add` 里的裸能力名（K8s 写成
  `NET_RAW`）与 libcap 写法（`CAP_NET_RAW`）归一后参与 `escape_vectors` /
  `risk_score`；high-risk 入选条件是「分数 > 0.3 或存在任一 escape vector」，
  因此只带 NET_RAW 的 pod（二层 MITM 原语）也会进入 `cloud-topology-high-risk`
  Analysis 节点。`K8sPod` 节点同时写入 `privileged` 与 `capabilities`，
  供 planner 世界状态读取；容器镜像以 `images` 列表写入，使"节点上已有哪个
  镜像"成为可规划事实（特权 pod 路线必须使用节点上已存在的镜像）。

## 输入/输出概览

输入为 `DKG` 和经网关取得的云/K8s 工具观察结果；输出为 `CloudTopology`，并以幂等关系更新图。Orchestrator 只在环境分类命中云/K8s 后调用它。

## 相关模块

`dkg.py`、`topology_analysis.py`、`cloud_attack_path.py`、`dpm.py`、`tools/recon_server.py`。

## 阅读建议

先理解结果模型，再看 `CloudTopologyMapper` 的写图逻辑和发现入口。

## 维护提示

拓扑字段或关系变化时同步检查攻击路径和防御探测的消费者。
