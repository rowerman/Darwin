# AGENTS.md

本文件是面向 Codex（及任何读取 `AGENTS.md` 的编码代理）的 DARWIN 仓库工作说明，以当前代码为唯一事实来源。

## 1. 项目背景

DARWIN（Defense-Aware Adaptive Penetration Testing Agent Framework）是一个 LLM 驱动的自适应渗透测试代理框架，用于单目标渗透测试与 benchmark 评测。

核心能力：

- **Solo 单代理控制面（v2 起）**：LLM 规划结构化 `Task`，系统通过 Task/Capability/Executor 层执行
- **DKG 世界状态**：带 provenance（谁发现、依据、时间戳）的结构化世界模型，Planner/Replanner 通过类型化 `PipelineState` 快照读取。
- **DPM 防御感知**：WAF/Cloak/Honey/Trap 检测，三级级联：规则 → 签名 → LLM 分类器。
- **DAVE 四级验证**：L1 HTTP 响应、L2 Playwright 浏览器、L3 防御完整性、L4 影响确认（flag 提取 + 蜜罐拒绝）。
- **CTEG 跨任务经验**：跨挑战积累的动态利用/绕过模式，按半衰期衰减，持久化到 `cteg_state.json`。
- **DarwinRAG 静态知识**：约 8200 条精选条目，覆盖 web / windows_ad / cloud / network 四域；SentenceTransformer `all-MiniLM-L6-v2`（384 维）+ Faiss IndexFlatIP，TfidfVectorizer 回退；`search_hierarchical()` 先按 taxonomy 路由、再在子树内打分。
- **LangGraph 集成**：ReAct 循环（observe → plan → act → evaluate）带 checkpointing。

## 2. 项目主要结构

```
run.py                     CLI 入口（参数解析、LLM 配置加载、结果汇总）
darwin/
  orchestrator.py          主编排器：recon/analyze/exploit/defense/verify 全流程
  core/                    v2 控制面：task, task_graph, scheduler, runtime,
                           executor, evaluator, replan, capabilities,
                           parameters, memory, metrics, schemas, contracts,
                           events, belief
  dkg.py                   动态知识图谱（NetworkX MultiDiGraph，线程安全）
  dpm.py                   防御感知（规则 → WAF 签名 → LLM）
  dave.py                  四级验证（HTTP → Browser → Integrity → Impact）
  cteg.py                  跨任务经验图（动态模式，半衰期衰减）
  rag.py                   静态知识检索（Faiss + SentenceTransformer）
  cloud_topology.py        CTAGE：K8s 集群拓扑与 IAM 信任关系自动发现
  cloud_attack_path.py     AttackPath：攻击路径 BFS 推理
  knowledge_base.py        知识库加载与查询
  search_evidence.py       证据检索
  tools/
    mcp_gateway.py         工具注册表 + 统一调用（ToolResult）
    spec.py                ToolSpec 工具契约（校验、auto_spec）
    manifest.py            工具清单生成/校验 CLI
    attack_server.py       攻击域工具注册（约 130 个工具的主体）
    recon_server.py        侦察域工具注册
    mcp_client.py          可选 MCP 客户端池
  prompts/                 role prompts（orchestrator/planner/evaluator/memory/research/dpm_classifier）
  utils/                   llm.py（LiteLLM 封装）、http_client、thought_logger、phase_logger
experiments/               runner.py / parallel_runner.py / scenario_loader.py 等评测入口
tools/                     知识入库与审计脚本（ingest_*、build_taxonomy、audit_coverage、eval_knowledge_retrieval）
tests/                     pytest 测试（34 个测试文件）
knowledge/                 静态知识：web/ windows_ad/ cloud/ network/、scenarios/、taxonomy.json
config/                    darwin.yaml / llm.yaml / waf_fingerprints.yaml / mcp_servers.yaml（已 gitignore）
checkpoints/、log/、cteg_state.json   运行时产物（gitignore）
tools_manifest.json        130 个工具的机器可读契约（提交入库，作为锁文件）
```

### 关键设计决策（改动前必须保持的约束）

1. 所有工具执行都经过 `darwin/tools/mcp_gateway.py` 网关和 `darwin/core/executor.py`；编排器不得直接调用外部工具。
2. `core.Runtime` 是唯一执行路径：plan → schedule → execute → evaluate → replan。
3. 阶段间 LLM 输出必须走 `darwin/core/schemas.py` 的版本化 pydantic 模型；校验失败时记录 `schema_violation` 并回退 legacy 解析（零回归保证）。
4. 上下文接近阈值时用 `LLMSession.compress()` 压缩，不做硬重置；DKG 结构化状态跨阶段承载。
5. 工具计划需经 `_sanitize_plan_tools()` 清洗：黑名单、自动回退、凭据占位符解析、端口范围门控、`file://` 阻断。
6. 任务失败先分类再修复（`_analyze_and_fix_task()`，最多重试 2 次），部分成功也要提取部分价值。

## 3. 工作流

### 运行时数据流

```
Orchestrator.run()
  → bootstrap recon（nmap 端口发现 → HTTP 探测 → DKG）
  → Runtime loop：plan → schedule → execute → evaluate → replan
  → DPM 防御检测/绕过、DAVE flag 验证
```

内存四层：DKG（世界事实）、PlanMemory（任务 rationale）、ExecutionMemory（执行历史 + preserve/compress/discard 分级）、CTEG（跨任务经验）。

### 对 Codex 的开发工作流

- 修改工具：先读 `tools_manifest.json` 中该工具的 `ToolSpec` → 改注册（`attack_server.py` / `recon_server.py`）→ 重新生成 manifest 并 `--check` → 补/改测试。
- 修改知识库：`tools/ingest_*` 入库 → `tools/build_taxonomy.py` 重建 → `python -m tools.audit_coverage` 校验引用 → 补测试。
- 修改核心循环：对应 `tests/test_core_*.py` 或 `tests/test_runtime_path.py`，并跑 `pytest tests/ -m acceptance -v`。
- 任何改动完成前：全量 `pytest tests/ -v` 必须通过。

## 4. 依赖环境与配置

### Python 环境

要求 Python ≥ 3.10。RAG 依赖（`sentence-transformers`、`faiss-cpu`）**不在** `pyproject.toml` 中，需要时手动安装；其余依赖由 `pyproject.toml` 声明。

优先考虑激活conda环境

### 外部 CLI 工具

recon/attack 工具包装外部命令，启动时 Orchestrator 会校验并警告缺失：

- 必需：`nmap`、`dirb`、`whatweb`、`curl`、`sqlmap`、`ffuf`、`sshpass`
- 可选/按场景：`wpscan`、`netexec`、`impacket-*`、`ldapsearch`、`kubectl`、`capsh`、`msfconsole`（`msfinstall` 脚本在仓库根）


辅助：`WPSCAN_API_TOKEN`、`BRAVE_API_KEY`、`GITHUB_PERSONAL_ACCESS_TOKEN`。
 
### 运行命令

```bash
python run.py <target>                              # IP / hostname / URL 均可
python run.py example.com -u admin -p pass123
python run.py example.com --time-budget 1200 --token-budget 200000
python run.py example.com --port-range ""           # '' = 全端口扫描
```

注意：`--port-range` 默认是 `"10000-14000"`（benchmark 端口段），不是 README 里说的全端口自动发现；要全扫必须显式传 `''`。裸 IP/hostname 会自动补 `http://` 前缀并做 nmap 端口发现。

评测入口：

```bash
python experiments/runner.py                        # pilot 模式
python experiments/runner.py cve K8S-06 CLOUD-10    # 指定场景
python experiments/parallel_runner.py --parallelism 4
python -m tools.eval_knowledge_retrieval            # RAG A/B 评测
python -m tools.audit_coverage                      # taxonomy → 工具/能力/知识 覆盖审计
```

## 5. 接口格式

### Orchestrator.run → TaskResult

`Orchestrator.run(task_description, target_url, username=None, password=None, port_range=None) -> TaskResult`。

`TaskResult` 字段：`success`、`flag`、`steps`、`tokens_used`、`time_elapsed`、`phase_at_end`、`defense_detected`、`waf_bypassed`、`waf_type`、`defense_complexity`、`dkg_summary`、`error`。

### LLMSession.generate（LiteLLM 封装）

```python
def generate(prompt, system_prompt=None, tools=None, temperature=None,
             timeout=180.0, stage=None) -> tuple[str, list[dict] | None]
```

`tools` 为 OpenAI function-calling 定义列表；返回 `(content, tool_calls)`，`tool_calls` 为 `[{"name": ..., "arguments": {...}}]` 或 `None`。

### 阶段间 LLM 输出（`darwin/core/schemas.py`）

- `AnalyzeOutputV1`：`application_understanding` + `vulnerabilities[]`（`AnalyzeVulnV1`：`vuln_type/endpoint/param/confidence/evidence/suggested_tool/tool_args`）+ `attack_paths[]`（`AttackPathV1`）
- `PlanTaskV1`：`id/instruction/tool/params/reason/dependent_task_ids/priority`，兼容 `dependencies` 与 JSON 字符串 `params`；`status` 不在 LLM 契约内
- `ResearchFindingV1` / `ServiceResearchFindingV1`：漏洞与服务研究输出

解析契约：提取宽容（直接 JSON、围栏代码块、括号计数），校验严格（必填字段/类型）；失败返回 `(None, error)`，调用方记录 `schema_violation` 并回退 legacy 路径。新增阶段输出必须复用这套模式。

### Task 与状态机（`darwin/core/task.py`、`contracts.py`）

`TaskStatus`：`created / ready / running / success / failed / blocked / invalidated / needs_replan / abandoned`。

`Task` 关键字段：`id/type/goal/instruction/hypothesis/rationale/evidence/confidence/action/required_context/success_condition/failure_policy/dependencies/priority/status/attempt_count/result_summary`；`to_dict()/from_dict()` 是 JSON 持久化的唯一通道，状态存 `status.value`。

### 工具调用契约

`MCPGateway.call(name, params) -> ToolResult`。`ToolResult`：

```python
@dataclass
class ToolResult:
    tool_name: str
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    elapsed_ms: float
    parsed_output: dict = {}
```

未注册工具返回 `exit_code=-1`；异常被网关捕获并包装成失败的 `ToolResult`（stdout 携带错误信息供 LLM 修复）。参数在分发前经 `_normalize_params` 做语义别名映射（`url→target_url`、`host→target`、`username→user` 等，仅当目标参数已声明时生效）和子串修正。

### Flag 格式

`flag{...}`，匹配正则：`flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}`（大小写不敏感）。蜜罐 flag（如 `flag{test}`、`flag{example}`、`flag{honeypot}`）由 DAVE L4 拒绝。

## 6. 工具格式

### ToolSpec（`darwin/tools/spec.py`，CONTRACT_VERSION = 1.0.0）

每个注册工具都必须携带一个 `ToolSpec`（显式传入或由注册调用 `auto_spec` 派生，`auto=True` 标记）。字段：

| 字段 | 说明 |
|------|------|
| `name` / `version` | 工具名与契约版本 |
| `description` | 给 LLM 的工具描述（非空） |
| `domains` | 域标签（web/db/cloud/k8s/container/ad/network 等），用于 `tools.enabled_domains` 过滤 |
| `capability` | 能力名（如 `sql_query`、`container_escape`、`k8s_apply`） |
| `parameters` | OpenAI property 格式：`{name: {"type", "description", "default"}}`；无 `default` 即为必填 |
| `executor` | `python` / `shell` / `shell_argv` / `mcp` |
| `command_template` / `shell_args` / `split_params` | shell 模板或 argv 模板；`shell_argv` 不经 shell 执行，`split_params` 按 shlex 拆分注入 |
| `dependencies` / `flags` / `output_contract` | 外部依赖、flag 提取规则、输出契约 |
| `aliases` | 参数别名（方向：`alias → [canonical...]`，只指向已声明参数） |
| `deprecated` / `auto` | 废弃标记 / 是否自动派生 |

`validate_spec()` 返回违规列表（空 = 合法）：描述非空、executor 合法、参数 schema 是 dict 且含 `type`、模板占位符都已在参数中声明、alias 不能与 canonical 同名且必须指向已声明参数等。

### 注册方式（`darwin/tools/mcp_gateway.py`）

- `register(name, func, description, parameters, domain, spec=None)`：Python 函数工具。
- `register_shell_tool(name, command_template, description, parameters, parser=None, timeout=60, retries=1, ...)`：shell 命令模板（`{param}` 占位符），带超时重试（1.5 倍递增）。
- `register_shell_argv_tool(name, shell_args, description, parameters, split_params=None, ...)`：无 shell 的 argv 列表执行。
- 域过滤：`set_enabled_domains(...)` 后，注册时静默跳过不在集合内的工具；无域工具始终注册。

LLM 工具定义由 `get_tool_definitions()` 生成，格式为 OpenAI function-calling：

```json
{"type": "function", "function": {"name": "...", "description": "...",
  "parameters": {"type": "object", "properties": {...}, "required": [...]}}}
```

### 工具清单（manifest）

`tools_manifest.json` 是提交入库的锁文件：`{schema_version, generated_at, source, tool_count, tools[]}`，当前 132 个工具（130 个攻击/侦察工具 + `tool_registry_list` / `tool_registry_get` 两个注册表元工具）。所有注册表改动后必须：

```bash
python -m darwin.tools.manifest --out tools_manifest.json
python -m darwin.tools.manifest --out tools_manifest.json --check
```

参数或语义变化必须升 `version`。`tests/test_coverage_audit.py::test_committed_manifest_is_in_sync` 会以当前注册表重建并比对，不一致即测试失败。

### 注册表元工具与 prompt 的工具发现机制

unified / planner / analyze 等 LLM prompt **不再内嵌静态工具目录**。LLM 通过两个只读元工具按需获取工具信息：

- `tool_registry_list(domain="", capability="", keyword="")`：返回工具名 + 一句话描述 + 域 + 能力，用于发现候选。
- `tool_registry_get(name)`：返回单个工具的完整 `ToolSpec`（参数/必填/默认值/别名/executor 等），写任务参数前必须先查。

两者读取 `MCPGateway.get_tool_specs()`（与 manifest 同源），在 attack gateway 注册且无域标签，不受 `tools.enabled_domains` 过滤影响。plan 生成、plan_review、analyze 的 LLM 调用会先跑一个最多 3 轮的注册表查询循环，查询结果作为 tool result 进入上下文；若门面未暴露注册表工具（如测试用 fake），自动退化为单次普通生成。修改工具注册后，除了重新生成 manifest，还要确认这些 prompt 没有被重新塞回静态目录（`tests/test_prompts.py` 有契约断言）。

## 7. 测试标准

环境是通过conda创建的虚拟环境，具体env_name需要列举一下

```bash
conda run -n env_name python -m pytest -q
conda run --no-capture-output -n env_name python -m pytest -m integration -v
conda run -n env_name python -m pytest -m acceptance -v
```

后续测试按以下顺序执行：

1. 先在 `env_name` 环境运行与改动直接相关的单测；确认失败原因后再扩大范围。
2. 涉及多个模块或公共控制面的改动，运行 `pytest -m integration -v`。integration 测试必须使用本地靶场、确定性 LLM replay、CLI stubs 和临时目录，禁止外网、真实 LLM、真实 CLI 与 Docker。
3. 修改核心循环、工具注册、工具契约或知识库时，运行 `pytest -m acceptance -v`，并分别执行 manifest/taxonomy 校验：

   ```bash
   conda run -n deeplearn python -m darwin.tools.manifest --out tools_manifest.json --check
   conda run -n deeplearn python -m tools.audit_coverage
   ```

4. 在提交前运行全量回归 `conda run -n deeplearn python -m pytest -q`，同时检查 `git diff --check`。Windows 下涉及子进程或异步管道的测试应使用 `-W default`，不得遗留 transport、pipe 或 running subprocess 警告。
5. 只有在显式 live 联调时才运行 Docker/benchmark 场景；这类测试不纳入默认回归，必须记录所需外部工具、服务和命令结果。Mutation testing 仅在环境提供 `mutmut`、`cosmic-ray` 等 runner 时执行；没有 runner 时不得声称已完成，应记录为环境限制。

约定（`pyproject.toml` 已配置 `asyncio_mode = "auto"`、`acceptance` 和 `integration` marker）：

- 新增局部逻辑先补单元测试；涉及跨模块执行路径必须补 `integration`；修改核心循环、工具注册或知识库还要跑 `acceptance`；Docker/benchmark 行为另跑显式 live 测试。
- 未标记测试是隔离单测；`integration` 使用本地 HTTP 靶场、确定性 LLM replay 和 CLI stubs，必须经过 `Orchestrator.run()`、Runtime、MCPGateway、DPM/DAVE，禁止外网、真实 LLM 和 Docker。
- Docker/benchmark 联调属于显式 live 测试，不进入默认回归。
- 修改工具、知识库或核心循环后，跑全量测试及相关 `integration/acceptance`；manifest/taxonomy 必须同步校验。
- 复用 `tests/conftest.py` fixtures；未知工具必须失败，不得用默认成功的 fake 掩盖错误；不伪造或跳过失败测试。
