# DARWIN 条件化云/K8s 拓扑建模执行计划

## Summary

将 DKG 从“节点和部分云关系的存储器”扩展为条件化的云/K8s 拓扑建模管线：

```text
基础 scan
  -> 环境分类
  -> 仅在检测到 public cloud / private cloud(K8s) 时执行云资源采集
  -> 关系归一化与分析
  -> research / analyze / plan / exploit / replan 复用拓扑
```

普通 Web/DB 场景保持现有流程，不启动云/K8s 深度采集和关系分析。

本计划重点解决：

- 原始 DKG 中重复边和重复写入；
- Host、Service、Endpoint、Pod、IAM 之间关系缺失；
- 云/K8s 资源发现与普通目标扫描未分流；
- 原始图与 LLM 上下文视图边界不清导致的认知偏差；
- 云关系只在 analyze 阶段体现，未统一贯穿 research 和后续阶段。

## Key Changes

### 1. 增加环境分类与条件化执行

新增只读、规则驱动的环境检测，不使用 LLM 判断是否进入云模式。

建议增加：

```python
class EnvironmentKind(str, Enum):
    UNKNOWN = "unknown"
    WEB_DB = "web_db"
    PRIVATE_CLOUD = "private_cloud"
    PUBLIC_CLOUD = "public_cloud"
    HYBRID = "hybrid"


@dataclass
class ScanClassification:
    kind: EnvironmentKind
    provider: str = ""
    signals: list[str] = field(default_factory=list)
    confidence: float = 0.0
    cloud_enabled: bool = False
```

检测信号包括：

- 目标扫描发现的 K8s API、6443/10250 等 K8s 特征；
- AWS IMDS、AWS API、云厂商服务指纹；
- Azure/GCP metadata endpoint；
- S3、EKS、AKS、GKE、云 IAM 等明确服务特征；
- 已发现的云凭证或云专用工具结果。

`kubectl cluster-info`、云 metadata 等只读命令只能作为基础扫描之后的轻量确认探针，不能在基础扫描之前无条件执行完整资源采集。benchmark 会把对外暴露端口约束在固定范围（例如 `10000-11000`），因此目标扫描不会误把宿主机上无关的本地 K8s 服务当成目标环境。

执行策略：

- `WEB_DB`：保持现有 bootstrap、deep recon、research、analyze、plan、exploit 流程，不执行完整云采集。
- `PRIVATE_CLOUD`：执行 K8s 资源采集和 K8s 关系分析。
- `PUBLIC_CLOUD`：执行对应 provider 的云资产采集和 IAM/网络关系分析。
- `HYBRID`：同时执行 K8s 和公有云采集。
- `UNKNOWN`：只执行基础扫描，不主动扩大范围。

环境分类结果写入 DKG 的运行作用域元数据，供后续阶段判断是否注入云上下文。

### 2. 将 bootstrap 拆成“基础扫描”和“条件化云发现”

调整现有 bootstrap 流程：

```text
基础 nmap / HTTP / 服务指纹
  -> ScanClassifier
  -> 轻量 K8s/cloud 确认探针（仅在出现相关扫描信号时）
  -> CloudDiscoveryCoordinator（仅 cloud_enabled=True）
  -> RelationAnalyzer
  -> deep recon / research / analyze
```

现有 K8s discovery 不再作为所有场景的无条件深度流程。基础扫描完成后，只有出现目标环境相关信号时才运行一次短时、只读的 K8s/cloud 可用性探针；确认成功后才执行完整的：

- nodes；
- pods；
- namespaces；
- services；
- service accounts；
- RBAC；
- network policies；
- workload；

只在判定为 private cloud 或 hybrid 后执行。

云发现失败必须是非致命错误：

- 记录 discovery failure；
- 保留已有基础扫描结果；
- 将 coverage 标记为 incomplete；
- 继续进入普通 research/analyze/plan 流程。

### 3. 解决原始 DKG 的重复边问题

保留 `MultiDiGraph` 兼容性，但将关系写入改为幂等 upsert。

推荐接口：

```python
def upsert_edge(
    self,
    from_id: str,
    to_id: str,
    edge_type: str,
    *,
    properties: dict | None = None,
    confidence: float | None = None,
    source: str = "",
    evidence: str = "",
) -> bool:
    ...
```

关系唯一键：

```text
(from_id, to_id, edge_type)
```

写入规则：

- 相同唯一键的边只保留一条；
- 重复写入不新增 MultiDiGraph 平行边；
- `first_seen` 保留首次时间；
- `last_seen` 更新为最近观测时间；
- provenance source 合并去重；
- evidence 合并去重并限制数量；
- confidence 按明确规则合并，默认保留较高可信度；
- 只有语义发生变化时才递增 DKG revision。

兼容处理：

- `load()` 时折叠历史 checkpoint 中的重复边；
- `topology_snapshot()` 不再依赖展示层去重作为主要修复手段；
- 保持 `query_edges()`、旧 checkpoint 和现有调用方兼容；
- 为旧边补齐缺省 provenance 和时间字段。

### 4. 补齐云/K8s 资源关系

保留现有关系类型，并增加最低必要的关系类型：

```text
host_has_service
host_has_endpoint
service_targets_pod
service_exposes_endpoint
endpoint_backed_by_service
pod_runs_on_node
pod_uses_service_account
service_account_bound_to_role
role_has_policy
policy_grants_resource
credential_for_host
credential_for_role
session_on_host
host_reaches_host
service_calls_service
resource_contains
resource_exposed_via
resource_depends_on
network_policy_allows
network_policy_denies
```

关系写入要求：

- Host/Service/Endpoint 在基础扫描阶段立即建立；
- K8s Service selector 解析为 Service → Pod；
- Pod 与 Node、Namespace、ServiceAccount 建立关系；
- Ingress/LB 与后端 Service 建立关系；
- IAM Role 与 Policy、Resource 建立关系；
- Session、Credential 与 Host/Role 建立关系；
- 关系必须带 `source`、`evidence`、`confidence`；
- 观察到的关系和推断关系使用不同的关系置信度和状态。

关系状态建议使用简短枚举：

```text
observed
inferred
hypothesized
stale
```

Prompt 中只展示非 `observed` 关系的状态标签，不展示冗长 provenance，避免无效 token 增长。

### 5. 增加 Cloud/K8s Relation Analyzer

新增确定性关系分析器，不让 LLM 直接创造基础关系事实。

接口建议：

```python
@dataclass
class TopologyAnalysisResult:
    before_revision: int
    after_revision: int
    added_relations: int
    updated_relations: int
    attack_paths: list
    coverage: dict
    warnings: list[str]


class RelationAnalyzer:
    async def analyze(
        self,
        dkg: DKG,
        environment: ScanClassification,
    ) -> TopologyAnalysisResult:
        ...
```

分析来源：

- K8s selector、labels、Ingress、EndpointSlice；
- RBAC Role/ClusterRole verbs 和 resources；
- IAM trust policy 和 permission policy；
- Security Group、NSG、NetworkPolicy；
- DNS、URL、环境变量、配置文件；
- 已有 Session、Credential、Service、Endpoint；
- 必要时执行受限网络可达性探测。

分析输出：

- 服务调用关系；
- Host 间网络可达性；
- 资源从属关系；
- 当前 foothold 的可达资源；
- 权限提升和横向移动路径；
- coverage 和未知区域。

规则优先级：

1. 直接观测；
2. 配置或控制面明确推断；
3. 仅作为候选的弱推断。

只有前两类关系可以自动生成高优先级任务；弱推断只能作为低置信度候选交给 Planner。

### 6. 扩展公有云与私有云采集边界

第一版明确支持：

- AWS public cloud；
- Kubernetes private cloud；
- AWS + Kubernetes hybrid。

AWS 第一版覆盖：

```text
Account
VPC
Subnet
RouteTable
SecurityGroup
ENI
EC2
EKS
LoadBalancer
RDS
S3
IAMRole
IAMPolicy
```

K8s 第一版覆盖：

```text
Cluster
Node
Namespace
Pod
Deployment
StatefulSet
DaemonSet
Service
EndpointSlice
Ingress
NetworkPolicy
ServiceAccount
Role
ClusterRole
RoleBinding
ClusterRoleBinding
Secret
ConfigMap
```

Azure/GCP 先保留 provider-neutral 接口和分类信号，不在本次实现中扩展完整资源采集器，避免把第一版范围扩大到不可验证。

### 7. 设计分层拓扑上下文，避免误解为“原始图被截断”

原始 DKG 不截断，保留完整图。`max_nodes`/`max_edges` 只约束发送给 LLM 的视图，不代表资源采集失败或原始关系被删除。

只有发送给 LLM 的视图需要有界。新增 topology context 查询接口：

```python
def topology_context(
    self,
    *,
    view: str = "cloud",
    anchors: list[str] | None = None,
    relation_types: list[str] | None = None,
    max_hops: int = 2,
    max_nodes: int = 48,
    max_edges: int = 96,
    since_revision: int | None = None,
) -> dict:
    ...
```

上下文采用三层结构，默认策略为“全局摘要 + 当前局部图 + 增量变化”：

1. **全局摘要**
   展示环境类型、账号/集群/Namespace 摘要、Host 身份列表、各类资源数量和 coverage；不展开所有资源属性。

2. **当前局部图**
   以当前 Session、目标 Host、活动任务和当前攻击路径为 anchors，只展开相关节点及其有限跳数关系。

3. **增量变化**
   只展示 `since_revision` 之后新增或变化的关系。

上下文选择规则：

- 当前 foothold 和活动攻击路径优先；
- 与当前任务目标相关的资源优先；
- `observed` 关系优先于 `inferred`；
- 不相关的资源只保留计数摘要；
- 超出上限时输出 `omitted_count` 和覆盖提示，而不是静默丢失。

新增字段：

```python
@dataclass
class TopologyCoverage:
    total_nodes: int
    total_edges: int
    included_nodes: int
    included_edges: int
    omitted_nodes: int
    omitted_edges: int
    view: str
    complete: bool
```

这样可以区分：

- 原始图是否完整；
- 当前 LLM 视图是否完整；
- 哪些内容因为上下文预算未展示。

超出上下文预算时必须显式输出 `omitted_count` 和覆盖提示；不得静默地让 Planner 误以为未展示资源不存在。

### 8. 统一各阶段的拓扑复用

复用策略：

- scan：建立资源和关系；
- research：只注入紧凑的云环境摘要、相关服务依赖和当前可达路径；
- analyze：注入完整的当前环境摘要、关键局部图和攻击路径；
- plan：注入当前 foothold 周围的局部图、候选路径和 coverage；
- exploit：任务执行前注入任务目标相关子图；
- replan：注入任务前后 topology diff、路径置信度变化和新增关系。

普通 Web/DB 场景不增加 topology 区块，或只保留现有轻量状态上下文。

Replan 行为：

- 单次失败不立即删除整条攻击路径；
- 由 Evaluator 根据结果降低路径或漏洞 confidence；
- 允许有限替代尝试；
- 连续失败或明确反证后将路径标记为 rejected/stale；
- 新关系出现时重新计算受影响路径，而不是重算所有无关路径。

### 9. 作用域与 DKG 生命周期

单个 benchmark 默认使用独立 DKG，不把跨目标污染作为主流程。

仍增加轻量运行作用域字段，用于 checkpoint 恢复和显式复用外部 DKG 时的基本校验：

```text
engagement_id
target_scope
environment_scope
```

作用：

- checkpoint 恢复时校验目标作用域；
- 显式复用外部 DKG 时避免不同 benchmark 资源混入；
- 不改变单 benchmark 的默认行为；
- 单 benchmark 默认仍使用独立 DKG，不引入复杂的跨任务图分片。

## Test Plan

### 单元测试

新增或扩展以下测试：

- `upsert_edge()` 重复写入只保留一条边；
- 重复写入相同属性不增加 revision；
- provenance/evidence 合并正确；
- 历史重复边 checkpoint 能被折叠；
- Host/Service/Endpoint 基础边自动建立；
- K8s selector 正确映射 Service → Pod；
- RBAC/IAM policy 关系正确；
- observed/inferred/hypothesized 状态正确；
- environment classifier 对 Web/DB、K8s、AWS、hybrid 场景分类正确；
- topology context 返回全局摘要、局部图和 coverage；
- `since_revision` 只返回增量关系；
- context 超限时报告 omitted counts；
- attack path 在失败后降低 confidence，而不是立即删除；
- cloud-only analyzer 在 Web/DB 场景不会执行。

### Integration 测试

使用本地 fixture 和 CLI stubs，禁止真实云 API、真实 IMDS、真实 kubectl 集群：

1. Web/DB 场景：
   - 不调用完整 CloudTopologyMapper；
   - 不产生 K8s/IAM 节点；
   - 现有路径行为保持不变。

2. K8s private cloud 场景：
   - 生成 Cluster、Node、Namespace、Pod、Service、SA、RBAC；
   - 验证 Service selector 和 Pod 归属关系；
   - 验证当前 Session 到 Pod/Role 的攻击路径。

3. AWS public cloud 场景：
   - mock IAM、VPC、Subnet、SecurityGroup、EC2、S3；
   - 验证 Role → Policy → Resource；
   - 验证网络可达性和跨账号路径。

4. Hybrid 场景：
   - 验证 K8s 与云 IAM 关系合并；
   - 验证同一资源不会被重复建模；
   - 验证关系 upsert 幂等。

5. Runtime 场景：
   - task 执行新增关系；
   - replan 收到 topology diff；
   - 失败任务触发有限替代策略；
   - 不相关路径不会被错误重建。

### 验收命令

```bash
conda run -n deeplearn python -m pytest -q
conda run --no-capture-output -n deeplearn python -m pytest -m integration -v
conda run -n deeplearn python -m pytest -m acceptance -v
conda run -n deeplearn python -m darwin.tools.manifest --out tools_manifest.json --check
conda run -n deeplearn python -m tools.audit_coverage
git diff --check
```

同时更新对应 `docs/darwin/**` 模块文档和拓扑上下文契约说明。

## Assumptions

- 第一版正式支持 AWS public cloud 和 Kubernetes private cloud；Azure/GCP 只保留扩展接口。
- 只有 scan 产生明确云/K8s 信号后，才执行深度资源采集和关系分析。
- 普通 Web/DB 流程、工具契约和现有 Planner/Runtime 接口保持兼容。
- 原始 DKG 保留完整图；有界限制只适用于 LLM 上下文视图。
- 单次 task 失败允许有限试错；路径通过 confidence 和 evidence 逐步淘汰。
- 关系上下文只展示与当前任务相关的内容，并对不确定关系使用简短状态标签。
- 作用域保护只用于 checkpoint 和显式外部 DKG 复用，不改变单 benchmark 默认行为。
- benchmark 的固定对外端口范围是环境分类的前置假设；轻量探针只在基础扫描出现云/K8s 信号后执行。


----------------------------------------------------------------------------------------------

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

-------------------------------------------------------------------------------------------
拓扑关系分析与完整 K8s 采集

## Summary

以当前工作区未提交改动为基线继续推进，不回滚已有 DKG、环境分类和拓扑上下文实现。当前相关测试及全量回归均通过（`575 passed`）；下一轮聚焦“确定性 RelationAnalyzer + 完整 K8s 资源关系”，AWS 资源采集延后。

## Implementation Changes

1. **先修当前隐藏回归**
   - 修复 `darwin/orchestration/execution.py` 中 `_apply_attack_path_feedback()` 对未定义 `matched/endpoint/delta` 的日志引用。
   - 增加带 `path_id` 的成功、失败、降级和终止状态测试，确保攻击路径反馈不会因日志代码抛异常。

2. **新增确定性 `RelationAnalyzer`**
   - 新增 `darwin/topology_analysis.py` 及对应文档。
   - 提供 `TopologyAnalysisResult`：`before_revision`、`after_revision`、新增/更新关系数、受影响路径、coverage、warnings。
   - `analyze(dkg, classification)` 只基于已采集事实推导关系，不调用 LLM；所有写入统一走 `DKG.upsert_edge()`。
   - 第一版覆盖：
     - Service selector/Pod labels；
     - Deployment、StatefulSet、DaemonSet ownerReferences；
     - EndpointSlice/Service/Ingress 后端关系；
     - Role、ClusterRole 与 Binding、ServiceAccount 的 RBAC 关系；
     - NetworkPolicy 的 allow/deny 关系。
   - 关系状态明确区分 `observed`、`inferred`、`hypothesized`；只有前两类关系可生成高优先级任务，弱推断只能作为低优先级候选。
   - 所有新增关系先登记到 DKG 的 `EDGE_TYPES`/`EDGE_SEMANTICS`，禁止同义关系双写。

3. **扩展 K8s 只读采集**
   - 扩展 `CloudTopology` 数据结构和 `CloudTopologyMapper`，采集：
     `Deployment`、`StatefulSet`、`DaemonSet`、`EndpointSlice`、`Ingress`、`NetworkPolicy`、`Role`、`ClusterRole`、`RoleBinding`、`ClusterRoleBinding`、`Secret`、`ConfigMap`。
   - 在 `cloud_discovery_command` allowlist 中加入对应固定命令，并重新生成、校验 `tools_manifest.json`。
   - 采集结果必须经 gateway tool port；发现失败记录 `discovery_failure` 和 `coverage=incomplete`，不得阻断普通 Web/DB 流程。
   - Secret/ConfigMap 默认只写元数据和 key 名称，不把完整敏感值注入拓扑上下文。

4. **接入编排与任务优先级**
   - `ReconCoordinator` 在 `PRIVATE_CLOUD`/`HYBRID` 分类下执行 K8s 采集后调用 `RelationAnalyzer`；`WEB_DB`/`UNKNOWN` 不执行完整云采集。
   - 将分析结果写入 DKG Analysis 节点，并让 research/plan/replan 继续复用现有 `topology_context()`。
   - 为由 `observed/inferred` 关系生成的任务保留稳定 `path_id`，执行结果通过 evaluator 更新路径 confidence/status；本轮只更新受影响路径状态，完整 AWS 路径重算留待后续阶段。

5. **同步文档**
   - 更新 `docs/darwin/cloud_topology.md`、新增分析器文档，并同步编排/recon 文档中的调用链、失败语义和覆盖率说明。
   - 保留 `DKG_TOPOLOGY_CONTEXT_PLAN_v1.md` 作为后续 AWS/Hybrid 阶段的边界说明。

## Test Plan

- 单元测试：每种 K8s 资源 JSON fixture 的解析、canonical 节点/关系、selector/owner/RBAC/Ingress/NetworkPolicy 推导、幂等 upsert、provenance/status。
- 编排测试：Web/DB 场景不调用云 discovery；K8s 场景调用完整 allowlist；单条 discovery 失败仍能继续运行。
- 路径测试：`path_id` 映射、成功增信、失败降级、连续失败后 `stale/rejected`。
- 验收命令：
  - `conda run -n deeplearn python -m pytest -q`
  - `conda run -n deeplearn python -m pytest -m integration -v`
  - `conda run -n deeplearn python -m pytest -m acceptance -v`
  - `conda run -n deeplearn python -m darwin.tools.manifest --out tools_manifest.json --check`
  - `conda run -n deeplearn python -m tools.audit_coverage`
  - `git diff --check`

## Assumptions

- 本轮不实现 AWS Account/VPC/IAM 资源采集；仅保留现有 provider-neutral 分类接口。
- 不调用真实云 API、真实 kubectl 集群或外网，全部使用本地 fixture、gateway stub 和确定性测试数据。
- 原始 DKG 保持完整，节点/边上限只限制 LLM 视图。
- 当前工作区已有改动视为用户上一轮成果，实施时按模块审阅后增量修改，不覆盖或重置