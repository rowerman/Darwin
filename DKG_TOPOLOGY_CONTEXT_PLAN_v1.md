AWS/Hybrid 拓扑闭环与局部 Replan

## Summary

在现有 K8s 拓扑和 `RelationAnalyzer` 基础上，补齐 AWS 只读资源采集、AWS/K8s Hybrid 去重、IAM/网络关系分析，以及基于资源影响范围的局部攻击路径重算。普通 Web/DB 流程保持不变，Azure/GCP 仍只保留分类接口。

当前基线：上一轮全量测试 `584 passed`，现有 AWS 仅支持 IMDS/IAM Role，攻击路径状态尚未保存资源索引。

## Key Changes

### P1 — AWS 只读采集契约

- 在 `darwin/tools/recon_server.py` 增加独立的 `cloud_discovery_aws` gateway 工具，不复用可执行变更操作的 `aws_cli`。
- 接口固定为 `service/action/resource/region/endpoint_url`，只允许以下读取操作：
  - STS：`get-caller-identity`
  - EC2：VPC、Subnet、RouteTable、SecurityGroup、ENI、Instance
  - EKS：`list-clusters`、`describe-cluster`
  - ELBv2：`describe-load-balancers`
  - RDS：`describe-db-instances`
  - S3：`list-buckets`、`get-bucket-location`、`get-bucket-policy-status`
  - IAM：Role、Policy、Role policy/trust 查询
- 对未列入 allowlist 的 action 返回失败，不执行 shell 拼接的任意命令。
- `CloudTopologyMapper` 新增 AWS 资源采集与 coverage/warnings；AWS discovery 失败只标记 `incomplete`，不阻断主流程。
- 资源 ID 优先使用 ARN，其次使用 `provider/account/region/type/id` 规范化生成；Secret/credential 内容不写入拓扑。

### P2 — AWS DKG 建模与 Hybrid 合并

- 将 AWS 资源写入已有节点类型：`CloudAccount`、`VPC`、`Subnet`、`RouteTable`、`SecurityGroup`、`ENI`、`EC2`、`EKS`、`LoadBalancer`、`RDS`、`S3`、`IAMRole`、`IAMPolicy`。
- 新增并登记必要的 canonical 关系：
  - Account → resource
  - Subnet → VPC
  - ENI/EC2 → Subnet
  - RouteTable → Subnet
  - SecurityGroup → resource
  - IAMRole → IAMPolicy
  - IAMPolicy → resource
  - resource → Endpoint/Service
  - resource → resource dependency
- `RelationAnalyzer` 扩展：
  - 解析 IAM trust policy，生成 `role_can_assume`；
  - 解析 permission policy 的 action/resource/effect；
  - 依据 SecurityGroup/RouteTable/ENI 推导网络可达关系；
  - 从 EKS ARN、账号、区域和集群名建立 EKS ↔ K8sCluster crosswalk。
- Hybrid 去重规则：ARN、K8s UID、EKS cluster ARN 是主键；名称仅用于匹配候选，不覆盖已确认的唯一 ID；合并时保留 aliases 和 provenance。

### P3 — 稳定路径索引与局部 Replan

- 扩展 `AttackPath` 和 DKG 持久化状态，保存：
  - `path_id`
  - `node_ids`
  - `edge_keys`
  - `confidence`
  - `status`
  - `updated_revision`
- `compute_attack_paths()` 增加可选类别/影响范围参数；按资源类型选择需要重算的路径族：
  - IAM/Account/Policy：权限提升、跨账号；
  - Pod/SA/NetworkPolicy：容器逃逸、横向移动；
  - AWS 网络资源：横向移动和资源依赖。
- 新增局部路径更新入口，保留未受影响路径缓存，只替换受影响 `path_id`。
- Task 使用结构化 `requires_attack_path` 依赖引用稳定 `path_id`；路径变为 `stale/rejected` 时，依赖任务进入 `needs_replan` 或 `blocked`。
- Evaluator 反馈继续更新 confidence/status；单任务失败只触发局部 replan，拓扑作用域变化或路径索引缺失时才升级为全局 replan。

### P4 — 端到端验收与文档

- 同步 `tools_manifest.json`、`docs/darwin/cloud_topology.md`、`docs/darwin/topology_analysis.md` 和 `DKG_TOPOLOGY_CONTEXT_PLAN_v1.md`。
- 待办清单记录 AWS 资源覆盖、Hybrid 去重、局部路径重算和已知限制。

## Test Plan

- 单元测试：
  - AWS action allowlist 拒绝写操作；
  - 各 AWS 资源 JSON 解析与稳定 ID；
  - IAM trust/permission 关系；
  - SecurityGroup/RouteTable/ENI 网络关系；
  - EKS/K8s crosswalk 去重；
  - 路径索引持久化和受影响路径筛选；
  - rejected/stale 路径使依赖任务不可执行。
- Integration 测试：
  - Web/DB 场景不调用 K8s/AWS discovery；
  - AWS fixture 经过 `Orchestrator → gateway → mapper → analyzer`；
  - Hybrid fixture 不重复创建资源；
  - 新关系进入 topology diff、belief context 和 replan prompt。
- 验收命令：
  - `python -m pytest -q`
  - `python -m pytest -m integration -v`
  - `python -m pytest -m acceptance -v`
  - `python -m darwin.tools.manifest --out tools_manifest.json --check`
  - `python -m tools.audit_coverage`
  - `git diff --check`

## Assumptions

- 只支持 AWS public cloud 与 AWS+Kubernetes hybrid；Azure/GCP 不扩展资源采集。
- 所有 AWS 测试使用本地 JSON fixture、CLI stub 或本地 simulator，不访问真实云环境。
- 采集默认只保存资源元数据、策略结构和 key 名称，不保存完整 Secret/credential 值。
- 资源关系必须先登记到 DKG canonical registry；不允许通过同义 edge type 绕过注册。
- 局部重算优先保证路径状态正确；若某类 finder 无法安全裁剪，必须显式升级为该路径族重算，而不是静默复用旧结果。

## 实施状态（2026-08-24）

### 本轮已完成

- `cloud_discovery_aws` 只读 gateway：STS/EC2/EKS/ELBv2/RDS/S3/IAM allowlist，argv 无 shell 执行，非 localhost endpoint 拒绝，未登记 action 返回失败。
- `CloudTopologyMapper` AWS 资源采集与 DKG 写入：CloudAccount/VPC/Subnet/RouteTable/SecurityGroup/ENI/EC2/EKS/LoadBalancer/RDS/S3/IAMRole/IAMPolicy；Secret/credential 值不进入拓扑。
- 新 canonical 关系已登记：`account_contains_resource`、`resource_in_subnet`、`route_table_routes_to`、`security_group_attaches`、`policy_grants_resource`、`eks_links_k8s_cluster`、`resource_reaches_resource`。
- `RelationAnalyzer` IAM trust/permission 与 SG/子网网络关系；EKS ↔ K8sCluster crosswalk；ARN/规范 ID 主键去重。
- 攻击路径 `node_ids/edge_keys` 索引、`compute_attack_paths(categories=...)`、`attack_path_summary(affected_node_ids=...)` 局部重算。
- `TaskGraph.REQUIRES_ATTACK_PATH` 依赖；Scheduler 接收 world snapshot；Runtime 兼容二参数 Scheduler；Planner 自动附加 path 依赖。
- 新增单元测试 `tests/test_aws_hybrid.py`（6 个）与 integration 测试 `tests/integration/test_cloud_topology_gating.py`（3 个，覆盖 Web/DB 不触发云采集、AWS 分类资源映射与关系、无端口不执行子进程）。
- `tools_manifest.json` 已同步（134 个工具）；相关 docs 已更新。
- 关系补全：`service_exposes_endpoint`/`endpoint_backed_by_service`、ConfigMap 驱动的 `service_calls_service`、`host_reaches_host`、`resource_exposed_via`、`resource_depends_on`、`role_grants_permission`、RouteTable 网络关系已实现并登记。
- IAMPolicy 版本文档解析已接入；`policy_document` 优先于 `policy_detail`。
- `priority_hints` 已接入 Planner（仅提升、弱推断不提升）；局部 replan 将 stale/rejected 路径的 blocked 任务迁移为 `needs_replan`；exploit 任务注入目标相关拓扑子图。
- 新增 Hybrid integration（K8s + AWS 同时采集、EKS crosswalk 去重）。

### 后续待完成任务

1. **AWS 采集深化**：补 policy version 文档解析、RouteTable 细粒度目标、LoadBalancer/RDS 后端关系，以及 AWS simulator 分页和部分权限失败 fixture。
2. **局部 replan 深化**：补充路径索引缺失时升级为路径族/全局重算的运行时指标，并将 `needs_replan` 任务的实际分支替换纳入 replan 测试。
3. **RelationAnalyzer 深化**：补充 DNS/URL/环境变量来源的服务调用推断与 AWS simulator 分页/部分权限失败 fixture。
4. **提交当前改动**：本轮文件改动仍未提交；提交前确认全量回归、manifest、coverage 和 `git diff --check` 全部通过。
