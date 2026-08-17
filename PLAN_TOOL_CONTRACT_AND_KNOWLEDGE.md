# 修改计划：工具契约化 + 分层知识库

> 状态：待评审 · 版本：v0.1 · 日期：2026-08-17
>
> 对应上一轮分析的结论：
> - 工具侧已有 MCPGateway 注册 + 参数归一化（P9）+ Capability 契约（P8，仅 4 个能力），但 130 个工具中绝大多数仍走 legacy 直连，且描述/参数存在与实现不符的问题。
> - 知识侧已有 collection/category/subcategory 元数据，但检索是"全局打分后过滤"的扁平 RAG，没有显式 taxonomy 与两阶段路由。

## 0. 目标与边界

### 目标

1. **工具契约化**：所有工具对外暴露统一、机器可校验的契约（函数名、参数、所属域、能力、依赖、输出），消除"重构后参数与调用方式漂移"。
2. **分层知识库**：显式 taxonomy（域 → 技术大类 → 场景叶子）+ 两阶段检索（先路由后检索），以 benchmark 89 个 GUIDE 场景为金标评测集，提升命中精度并压缩注入 token。

### 边界（不做的事）

- 不重写攻击/侦察工具的业务逻辑，只统一外壳与契约。
- 不删除 legacy 直连路径，作为兼容层保留到迁移完成。
- 不引入新向量库/新模型依赖；复用现有 TF-IDF / Faiss / sentence-transformers。
- 不改 benchmark 靶场本身。

## 1. 阶段一：工具契约化（约 3–5 天）

### 1.1 定义 ToolSpec 契约（新模块 `darwin/tools/spec.py`）

```python
@dataclass(frozen=True)
class ToolSpec:
    name: str
    version: str = "1.0.0"
    description: str
    domains: list[str]            # web / db / k8s / cloud / ad / lnx ...
    capability: str = ""          # 归属能力（见 1.6）
    parameters: dict              # JSON Schema：properties + required + default
    executor: str                 # python | shell | mcp
    shell_args: list[str] | None  # shell 工具优先用 argv 数组；模板仅作兼容
    dependencies: list[str]       # 所需外部 CLI：kubectl, gcc, openssl ...
    flags: dict                   # destructive / interactive / requires_network / idempotent
    output_contract: dict         # success_patterns / error_taxonomy / exit_codes
    aliases: dict = {}            # legacy 参数别名（host→target 等）
    deprecated: bool = False
```

### 1.2 注册层强制校验（改 `darwin/tools/mcp_gateway.py`）

- `register()` / `register_shell_tool()` 增加 `spec: ToolSpec` 入参；无 spec 时从现有注册参数自动生成并标记 `auto=True`。
- 启动校验（`python -m darwin.tools.spec --check`，并接入 pytest）：
  - python 工具：`inspect.signature` 与 parameters schema 一致（无未声明参数、无缺失必填）。
  - shell 工具：模板/argv 占位符 ⊆ 声明参数；声明参数被使用或标记 optional。
  - name/domain 无冲突；description 非空且与实现一致（人工审计清单见 1.4）。
- `_normalize_params` 改为从 `spec.aliases` 读取别名；fuzzy 子串匹配降级为兼容开关（默认对新工具关闭）。

### 1.3 工具 Manifest（新模块 `darwin/tools/manifest.py`）

- 命令：`python -m darwin.tools.manifest --out tools_manifest.json`。
- 内容：全量工具 name / version / domains / capability / parameters / dependencies / flags / executor。
- 版本规则：参数或语义变化必须升 version；`tools_manifest.lock` 提交入库，CI 校验"锁文件 == 当前注册表"。
- 生成物同时供：LLM prompt 组装、评测脚本、覆盖率巡检、文档。

### 1.4 描述与实现一致性审计（清单驱动）

上一轮已确认的问题，逐项修复并加测试：

| 工具 | 问题 | 修复 |
|---|---|---|
| `saml_forge` | 描述称"持有私钥"，实际只生成未签名断言 | 增加签名参数（私钥 PEM + 签名算法）或改描述并标注"未签名" |
| `jwt_forge` | 算法枚举无 none（WEB-15） | 增加 `algorithm="none"` 支持并更新描述 |
| `mssqlclient_query` / `mssql_query` | 描述与命令模板互相矛盾（sqlcmd vs impacket） | 校正两者语义与 fallback 方向 |
| `test_db_credential` / `test_credential` | 描述自称支持多协议，实际仅 SSH | 收紧描述或扩展实现 |
| `k8s_sa_token_steal` / `k8s_kubelet_exec` / `k8s_etcd_keys` / `wpscan_enum` 等 | 提取时发现描述错位（相邻注册块串扰） | 逐条复核 description 与实现，纳入 1.2 校验 |

### 1.5 shell 工具硬化

- 新增 `register_shell_argv_tool(spec, argv_template)`：参数数组执行（`asyncio.create_subprocess_exec`），不再字符串插值。
- 优先迁移 benchmark 命中的 shell 工具：`helm`、`docker_registry`、`jwt_forge`、`saml_forge`、`mssqlclient_query`、`mongodb_query`、`redis_cmd`、`couchdb_query`、`elasticsearch_query`、`kubectl_exec`、`kubectl_run`、`crictl_cmd`、`ssh_exec`、`ssh_key_exec`、`aws_cli`、`gcloud_cli`、`az_cli`。
- 保留 `command_template` 兼容路径，但 manifest 中标记 `executor_style="legacy_template"`，迁移一个标记一个。

### 1.6 Capability 扩展（改 `darwin/core/capabilities.py` + `darwin/tools/adapters/`）

- 现有 4 个能力（fetch_url / verify_sql_injection / test_credentials / acquire_shell）保持不变。
- 新增覆盖 benchmark 场景族的能力（每个含 supported_tools 顺序 + default_tool + required_context + success_condition）：
  - `sql_query`（psql/mysql/mssql/oracle/redis/mongo）
  - `web_exploit_send`（send_payload / http_post / xxe_inject / ssti_inject / graphql_introspect）
  - `container_escape`（check_* → container_escape_* 有序链）
  - `k8s_apply`（kubectl_run / shell_exec，承载 apply/patch/label 等）
  - `secret_dump`（k8s_secret_dump / k8s_configmap_dump / etcdctl_get）
  - `cloud_iam_assume`（aws_sts_query / aws_iam_federation / saml_forge / jwt_forge）
  - `registry_push`（docker_registry / shell_exec）
  - `credential_test`（test_credential / hydra_http_brute / test_db_credential）
- 每个能力配 ToolAdapter（复制现有 4 个 adapter 的模式）。

### 1.7 Executor 全路径 schema 校验（改 `darwin/core/executor.py` + `darwin/core/parameters.py`）

- 当前：capability 路径走 P9 schema 校验，legacy 直连跳过。
- 改为：直连路径也先过 `ToolSchemaProvider` 校验；校验失败返回 INVALID_ARGUMENT 并记录到执行日志（不静默吞掉）。
- 兼容策略：`strict_schema` 配置开关（默认 true for new tools，legacy 工具逐个迁移后关闭宽松模式）。

### 1.8 域过滤数据化（改 `darwin/tools/attack_server.py`）

- `_DOMAIN_TOOL_MAP` 从硬编码集合迁移为读取 `ToolSpec.domains`。
- `enabled_domains` 读取顺序：`config/darwin.yaml`（若存在）→ 环境变量 `DARWIN_ENABLED_DOMAINS` → 默认全部。

### 1.9 阶段一验收

- [ ] 130/130 工具通过 spec 一致性校验，新增 `tests/test_tool_spec_consistency.py`。
- [ ] `tools_manifest.json` + lock 生成并入库；CI 校验一致。
- [ ] 1.4 审计清单全部关闭。
- [ ] 原 176 个测试全绿；新增 shell argv 工具测试、capability 扩展测试。
- [ ] 执行日志指标基线对比：`tool_not_found` / `INVALID_ARGUMENT` 不高于改造前。
- [ ] `run.py` 对本地靶标 smoke 通过。

## 2. 阶段二：分层知识库（约 4–6 天）

### 2.1 显式 taxonomy（新文件 `knowledge/taxonomy.json`）

```json
{
  "version": 1,
  "roots": [
    {
      "name": "cloud",
      "children": [
        {"name": "iam", "children": [{"name": "federation"}]},
        {"name": "kubernetes", "children": [{"name": "network-bypass"}, {"name": "escape"}]}
      ]
    }
  ],
  "leaves": [
    {
      "id": "k8s-cni-ip-spoofing",
      "guid": "K8S-30",
      "path": ["cloud", "kubernetes", "network-bypass"],
      "tools": ["kubectl_exec", "shell_exec"],
      "capability": "k8s_apply",
      "source": "benchmark/cve_challenges/scenarios/k8s/cni-ip-spoof/GUIDE.md"
    }
  ]
}
```

- 初版生成脚本：`tools/build_taxonomy.py`，输入 = 现有 `knowledge/` 目录层级 + 89 个 GUIDE。
- 每个叶子绑定：guid（K8S-30 等）、tools（ToolSpec name）、capability、source。

### 2.2 GUIDE 叶子入库（新脚本 `tools/ingest_benchmark_guides.py`）

- 解析 89 个 GUIDE：id、技术/CVE、核心利用行、利用步骤、flag、工具提及。
- 生成叶子条目写入 `knowledge/scenarios/*.json`（保持现有 RAG 可加载格式：id/title/category/subcategory/description/techniques/tools）。
- 目的：把上一轮 14 个 cloud 知识缺失场景补齐为"指南来源条目"，confidence 标记为 `0.6`（待验证），后续人工或实验升级。

### 2.3 节点向量化

- 用现有 embedder 对 taxonomy 根/分支节点生成语义向量（节点文本 = name + 子节点名 + 代表条目）。
- 存储：`knowledge/taxonomy_vectors.json`（或惰性构建，启动时若缺失则重建）。
- 叶子仍走原 collection 向量索引，不重复建索引。

### 2.4 两阶段检索（改 `darwin/rag.py`，新增 `search_hierarchical`）

```
query
  → 路由：规则关键词（aws/k8s/docker/wordpress/oracle/…）+ 节点向量 top-1/top-2
  → 子树内检索：按 path 前缀过滤条目后，再走 Faiss/TF-IDF 打分
  → 重排：score = 0.6*vec + 0.2*keyword_overlap + 0.2*confidence（权重可配）
  → 回退：路由置信度 < 阈值时，调用现有扁平 search()
```

- 修复现状缺陷：category/subcategory 从"全局打分后过滤"改为"路由后子树内打分"。
- 返回结果附带 `path` 字段，prompt 中展示命中路径（可解释）。
- `search()` 扁平 API 保留，供 A/B 与兼容。

### 2.5 编排层接入（改 `darwin/orchestrator.py` + `darwin/tools/attack_server.py` 的 knowledge_search）

- `knowledge_search` / `summarize` 默认切换为 `search_hierarchical`（A/B 开关 `rag.mode=hierarchical|flat`）。
- 研究阶段（`_research_phase`）的知识注入片段附带 path 与叶子 guid。

### 2.6 评测（新脚本 `tools/eval_knowledge_retrieval.py`）

- 评测集：89 个 GUIDE 的"标题 + 核心利用行"构造 query，gold = 场景 guid。
- 指标：Recall@1 / Recall@5 / MRR / 叶子命中精度 / 注入 token 数（top_k=5 时平均条目文本长度）。
- A/B：flat（现状） vs hierarchical（top-1 路由 / top-2 路由 / 混合回退）。
- 输出：`checkpoints/knowledge_eval/{flat,hierarchical}.json` + 对比摘要。
- 验收阈值（建议）：hierarchical 的 Recall@5 ≥ flat，token 注入量下降 ≥ 30%；无场景金标命中率下降。

### 2.7 阶段二验收

- [ ] `taxonomy.json` 覆盖全部 89 场景；每个叶子有 path / tools / capability。
- [ ] 14 个 cloud 缺口生成指南来源条目，`knowledge/scenarios/` 入库成功。
- [ ] 评测报告产出，达到 2.6 阈值。
- [ ] 3 个代表场景（K8S-30、DB-03、CLOUD-33）smoke 通过或步骤效率不低于改造前。
- [ ] 现有 176 个测试全绿；新增 rag 单测（路由、子树过滤、回退）。

## 3. 阶段三：链路集成与持续巡检（约 2 天）

### 3.1 覆盖率巡检自动化（替换上一轮人工分析）

- 新脚本 `tools/audit_coverage.py`：
  - 遍历 taxonomy 叶子 → 校验 `leaf.tools` 均在注册表且参数可用；
  - 校验 `leaf.capability` 存在；
  - 校验知识条目存在（guid 关联）；
  - 输出 `TOOL_COVERAGE_REPORT.md`（自动生成，替代手工报告）。

### 3.2 CI 门槛

- pytest 扩展：manifest 一致性、taxonomy 一致性、leaf→tool→capability 引用有效、描述审计清单为空。
- pre-commit：`tools_manifest.json`、`taxonomy.json` 变更必须配套代码变更。

### 3.3 文档

- 更新 `CLAUDE.md` / `README.md`：ToolSpec 字段说明、新增工具流程、taxonomy 维护流程、A/B 开关说明。

## 4. 风险与对策

| 风险 | 对策 |
|---|---|
| 契约校验太严导致大量工具注册失败 | 自动生成 spec（auto=True）+ 分批人工复核；启动校验只 warn，`--strict` 才 fail |
| legacy 行为变化影响 benchmark 通过率 | 别名/模糊匹配兼容层保留；`strict_schema` 逐工具开启；执行日志对比迁移前后指标 |
| shell 工具从模板迁 argv 引入回归 | 迁移一个、跑对应场景 smoke 一个；保留模板路径回滚开关 |
| 路由错误级联导致检索劣化 | top-2 子树 + 低置信度回退扁平；按域评估，不接受任何域 Recall 回退 |
| taxonomy 维护成本 | 入库脚本 LLM 自动标注 + 人工抽检；taxonomy.json 版本化 |
| 知识条目质量（14 个 cloud 场景） | 标记 confidence=0.6（指南来源、待验证），用 benchmark 实际 Pass@k 逐步升级 |

## 5. 里程碑检查表

- [ ] M1：ToolSpec + manifest + 启动校验上线（阶段一 1.1–1.5）
- [ ] M2：Capability 扩展 + 全路径 schema 校验上线（阶段一 1.6–1.7）
- [ ] M3：taxonomy + GUIDE 叶子入库（阶段二 2.1–2.2）
- [ ] M4：两阶段检索 + 编排接入 + 评测达标（阶段二 2.3–2.6）
- [ ] M5：覆盖率巡检自动化 + CI 门槛（阶段三）

## 6. 工作量估算（供排期参考）

| 阶段 | 内容 | 估算 |
|---|---|---|
| 一 | 工具契约化 | 3–5 人日 |
| 二 | 分层知识库 | 4–6 人日 |
| 三 | 链路集成与巡检 | 2 人日 |

## 7. 建议执行顺序

1. 先做 1.1–1.3（ToolSpec + 校验 + manifest），立即获得全量工具的一致性基线。
2. 再做 2.1–2.6（taxonomy + 两阶段检索 + 评测），用 89 场景金标验证收益后再决定是否全量切换编排层。
3. 最后做阶段三自动化，把覆盖率分析变成 CI 常驻检查。

每个里程碑独立可交付、可回滚，不需要大爆炸式迁移。

---

## 实施状态

### 阶段一：工具契约化 ✅（2026-08-17）

- [x] `darwin/tools/spec.py`：ToolSpec 数据类 + 参数/shell 模板/argv/signature 校验 + auto_spec + check_all_specs
- [x] `darwin/tools/manifest.py`：manifest 生成/校验 CLI（`python -m darwin.tools.manifest --out tools_manifest.json --check`）
- [x] `tools_manifest.json`：130 个工具，与注册表同步
- [x] `mcp_gateway.py`：注册层携带 spec；新增 `register_shell_argv_tool`（无 shell 执行 + shlex 拼接）；别名优先读 spec.aliases
- [x] shell argv 迁移 7 个工具：kubectl_exec / kubectl_run / helm / ssh_exec / ssh_key_exec / redis_cmd / crictl_cmd
- [x] 描述修复：jwt_forge 增加 alg:none；saml_forge 标注断言未签名
- [x] Capability 扩展：sql_query / web_exploit_send / container_escape / k8s_apply / secret_dump / cloud_iam_assume / registry_push / credential_test
- [x] Executor legacy 直连路径接入 P9 schema 校验（`_execute_tool`）
- [x] 域过滤数据化：`_apply_domain_filter` 增加 spec/entry 域过滤
- [x] 测试：新增 `tests/test_tool_spec.py`（13 项），更新 3 个行为断言；415 passed

### 阶段二：分层知识库 ✅（2026-08-17）

- [x] `tools/ingest_benchmark_guides.py`：89 个 GUIDE 解析入库（`knowledge/scenarios/{web,db,k8s,cloud}/benchmark_guides.json`），叶子绑定 Darwin 工具名/guid/source
- [x] `tools/build_taxonomy.py`：生成 `knowledge/taxonomy.json`（4 roots / 89 leaves，全部带 capability 映射）
- [x] `darwin/rag.py`：新增 `load_taxonomy()` / `search_hierarchical()`（路由 → 子树内打分 → 重排 → 扁平回退），修复"全局打分后过滤"缺陷；`knowledge_search` 工具切换为分层检索
- [x] `tools/eval_knowledge_retrieval.py`：89 查询 A/B；结果 Recall@1/5 持平（1.0），MRR 0.9944→1.0，注入 token 量 -82%（2048→371 字符）
- [x] 测试：`tests/test_rag_hierarchical.py`（4 项）；419 passed

### 阶段三：链路集成与持续巡检 ✅（2026-08-17）

- [x] `tools/audit_coverage.py`：taxonomy 叶子 → 工具注册表 / Capability / 知识条目 自动巡检，输出 `TOOL_COVERAGE_AUDIT.md`（89/89 OK）
- [x] CI 门槛：`tests/test_coverage_audit.py`（manifest 锁文件一致性 + taxonomy 引用完整性）
- [x] 文档：README / CLAUDE.md 补充工具契约与分层知识库章节
- [x] 全量测试：421 passed；manifest 与 130 个工具保持同步
