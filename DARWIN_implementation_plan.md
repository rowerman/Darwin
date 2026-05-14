# DARWIN 代码实施计划 (Phase 1 — 原型验证)

## 0. 目标

构建DARWIN最小可行原型，验证两个核心创新：
1. **DPM防御感知**：能在PACEBench D-CVE（WAF场景）上实现>0%成功率
2. **Solo Mode基础渗透能力**：在XBOW简单挑战上达到80%+成功率

## 1. 技术选型

| 选择 | 理由 | 参考来源 |
|------|------|---------|
| Python 3.11+ | LLM生态成熟，快速原型 | Cochise(576行Python)、AWE(~5000行Python) |
| LiteLLM | Provider-agnostic，支持100+LLM | Cochise使用litellm |
| NetworkX + JSON | 轻量图存储，无需外部数据库 | — |
| Pydantic | 配置管理和数据验证 | — |
| FastAPI + uvicorn | PACEBench HTTP协议 | PACEBench agent_server_protocol.md |
| aiohttp | 异步HTTP客户端 | — |
| playwright | 浏览器验证(DAVE L2) | AWE使用playwright |

## 2. Phase 1 实现清单

| # | 文件 | 行数 | 依赖 | 核心功能 |
|---|------|------|------|---------|
| 0 | `pyproject.toml` | ~30 | — | 项目配置、依赖声明 |
| 1 | `darwin/utils/llm.py` | ~150 | litellm | LLM统一调用接口（复用Cochise的LLMFunctionMapping模式） |
| 2 | `darwin/utils/http_client.py` | ~100 | aiohttp | HTTP客户端+WAF探针 |
| 3 | `darwin/dkg.py` | ~250 | networkx | DKG节点/边管理+JSON持久化 |
| 4 | `darwin/darwin_config.py` | ~80 | pydantic | 配置管理 |
| 5 | `config/darwin.yaml` | ~30 | — | 主配置 |
| 6 | `config/llm.yaml` | ~20 | — | LLM配置 |
| 7 | `config/waf_fingerprints.yaml` | ~80 | — | WAF指纹数据库 |
| 8 | `darwin/dpm.py` | ~300 | dkg, http_client | DPM：FilterDetector + WAF签名 + DefenseStateVector |
| 9 | `darwin/dave.py` | ~200 | dkg, dpm, http_client | DAVE：L1 HTTP + L2 Browser + L4 Impact验证 |
| 10 | `darwin/tools/mcp_gateway.py` | ~150 | — | MCP工具调用网关 |
| 11 | `darwin/tools/recon_server.py` | ~200 | mcp_gateway | 侦察工具（nmap, dirb, curl, whatweb） |
| 12 | `darwin/tools/attack_server.py` | ~250 | mcp_gateway | 攻击工具（sqlmap, ffuf, wfuzz, python-requests） |
| 13 | `darwin/orchestrator.py` | ~350 | dkg, dpm, dave, tools, llm | Orchestrator：Solo Mode主循环 |
| 14 | `benchmarks/pacebench_adapter.py` | ~200 | fastapi, uvicorn, orchestrator | PACEBench HTTP服务器适配器 |
| 15 | `experiments/runner.py` | ~200 | all | 实验运行器 |
| 16 | `experiments/metrics.py` | ~100 | — | 指标计算 |
| | **总计** | **~2,700行** | | |

## 3. 实现顺序（依赖驱动）

```
Step 0: pyproject.toml + config/ + darwin/__init__.py   [基础骨架]
Step 1: darwin/utils/llm.py                             [无依赖]
Step 2: darwin/utils/http_client.py                      [无依赖]
Step 3: darwin/dkg.py                                   [无依赖]
Step 4: darwin/darwin_config.py                         [无依赖]
Step 5: darwin/dpm.py                                   [依赖: dkg, http_client]
Step 6: darwin/dave.py                                  [依赖: dkg, dpm, http_client]
Step 7: darwin/tools/mcp_gateway.py                     [无依赖]
Step 8: darwin/tools/recon_server.py                    [依赖: mcp_gateway]
Step 9: darwin/tools/attack_server.py                   [依赖: mcp_gateway]
Step 10: darwin/orchestrator.py                          [依赖: dkg, dpm, dave, tools, llm]
Step 11: benchmarks/pacebench_adapter.py                 [依赖: orchestrator]
Step 12: experiments/runner.py                           [依赖: all]
```

## 4. 每个文件的设计规格

### 4.1 `darwin/utils/llm.py`
```
类: LLMSession
  - __init__(model: str, provider: str, api_key: str)
  - generate(prompt: str, system_prompt: str = None) -> str
  - generate_with_tools(prompt: str, tools: List[Dict], system_prompt: str) -> (str, List[Dict])
  
类: LLMFunctionMapping  (参考Cochise common.py:89)
  - register(func: Callable) -> Dict  # 自动转换Python函数为OpenAI tool definition
  - call(tool_call: Dict) -> Any     # 执行tool call并返回结果
```

### 4.2 `darwin/utils/http_client.py`
```
类: HTTPClient
  - get(url: str, headers: Dict = None) -> HTTPResponse
  - post(url: str, data: str, headers: Dict = None) -> HTTPResponse
  
类: ProbeClient(HTTPClient)  # WAF探针专用
  - send_probe(url: str, param: str, probe_value: str) -> ProbeResult
  - send_probe_batch(url: str, param: str, probes: List[str]) -> List[ProbeResult]
  - get_baseline(url: str) -> HTTPResponse  # 正常请求作为对比基线

类: HTTPResponse
  - status_code: int
  - headers: Dict[str, str]
  - body: str
  - elapsed_ms: float
```

### 4.3 `darwin/dkg.py`
```
类: DKG (参考Cochise knowledge.py + AWE MemoryStorage)
  节点类型: Host, Service, Vulnerability, Credential, Session, Flag
  边类型: host_has_service, service_has_vuln, credential_for, session_on_host
  
  - add_node(node_type: str, node_id: str, properties: Dict) -> None
  - add_edge(from_id: str, to_id: str, edge_type: str, **props) -> None
  - query_nodes(node_type: str, filters: Dict = None) -> List[Dict]
  - query_edges(from_type: str = None, edge_type: str = None) -> List[Tuple]
  - get_defense_context() -> Dict  # 提取防御相关上下文
  - to_dict() -> Dict  # JSON序列化
  - save(path: str) -> None
  - load(path: str) -> 'DKG'
```

### 4.4 `darwin/dpm.py`
```
类: DefensePerceptionModule (参考AWE filter_detector.py + CHeaT defense DB)
  
  - detect_defenses(responses: List[HTTPResponse], probes: List[ProbeResult]) -> DefenseStateVector
  - _match_waf_signatures(responses: List[HTTPResponse]) -> WAFMatch
  - _analyze_filter_behavior(probes: List[ProbeResult]) -> FilterProfile
  - _classify_defense(responses, filter_profile) -> DefenseCategory
  - _compute_defense_complexity(waf_match, filter_profile, defense_cat) -> float

类: DefenseStateVector
  字段: waf_type, waf_confidence, sanitization_strategy, sanitization_strictness,
        defense_category, defense_complexity, bypass_recommendations

类: FilterDetector (参考AWE xss_agent/analyzers/filter_detector.py)
  - analyze(probe_results: List[ProbeResult]) -> FilterProfile
  - _get_probe_sequence() -> List[str]  # A-E五类探针序列
```

### 4.5 `darwin/dave.py`
```
类: DAVE (Defense-Aware Verification Engine)
  
  四层验证:
  - L1: _verify_http_response(response: HTTPResponse) -> L1Result
  - L2: _verify_browser_execution(url: str, payload: str) -> L2Result  (使用playwright)
  - L3: _verify_defense_integrity(sent: str, reflected: str) -> L3Result  (简化版)
  - L4: _verify_impact(flag: str, expected_pattern: str) -> L4Result
  
  - verify(exploit_attempt: ExploitAttempt) -> VerificationResult
```

### 4.6 `darwin/tools/mcp_gateway.py`
```
类: MCPGateway
  - register_tool(name: str, func: Callable, description: str, parameters: Dict)
  - call_tool(name: str, params: Dict) -> ToolResult
  - list_tools() -> List[Dict]  # 返回OpenAI function calling格式
  - get_tool_definitions() -> List[Dict]  # for LLM tool_choice
```

### 4.7 `darwin/orchestrator.py`
```
类: Orchestrator (参考Cochise planner.py:131)
  
  Solo Mode主循环:
  1. 接收任务描述 → 初始化DKG + DPM
  2. 侦察阶段: 调用侦察工具 → 写入DKG
  3. 分析阶段: 从DKG读取漏洞线索 → LLM分析
  4. 利用阶段: 生成payload → 执行 → DAVE验证
  5. 如果有WAF → DPM检测 → 触发绕过策略 → 重试
  6. 循环直到捕获flag或预算耗尽
  
  - run(task_description: str, target_url: str) -> TaskResult
  - _recon_phase() -> None
  - _analyze_phase() -> List[VulnerabilityHypothesis]
  - _exploit_phase(vulns: List[VulnerabilityHypothesis]) -> ExploitResult
  - _defense_bypass_phase(exploit_result) -> ExploitResult
  
类: SoloAgent
  - __init__(orchestrator: Orchestrator)
  - run() -> TaskResult

类: TaskResult
  字段: success, flag, steps, tokens_used, time_elapsed, defense_detected, waf_bypassed
```

## 5. 关键参考代码文件

| 参考 | 文件路径 | 复用内容 |
|------|---------|---------|
| Cochise LLM调用 | `cochise/src/cochise/common.py:89` | LLMFunctionMapping自动工具转换 |
| Cochise Planner | `cochise/src/cochise/planner.py:131` | 持久化对话+知识累积+历史压缩 |
| Cochise Knowledge | `cochise/src/cochise/knowledge.py:73` | 增量知识累积模式 |
| AWE FilterDetector | `AWE/xss_agent/analyzers/filter_detector.py` | 过滤探针序列和分析逻辑 |
| AWE LLMPayloadEngine | `AWE/xss_agent/analyzers/llm_payload_engine.py` | 上下文感知的payload生成提示模板 |
| AWE Verifier | `AWE/xss_agent/agents/verifier.py` | Playwright浏览器验证 |
| AWE MemoryStorage | `AWE/src/core/memory_storage.py` | SQLite长期记忆schema |
| VulnBot Role | `multi_agents_pentest/roles/role.py:16-90` | Plan→Act→Observe循环 |
| PACEBench Protocol | `PACEbench/docs/agent_server_protocol.md` | 4端点HTTP服务器协议 |
| CHeaT Defenses | `CHeaT/cheat/database/` | 33种防御技术的JSON数据库 |
| CPA Classifier | `container-pentester-agent/internal/hub/agent/v2/classifier/hybrid.go` | 规则+LLM混合分类器 |
