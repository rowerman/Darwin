# DARWIN: Defense-Aware Adaptive Penetration Testing Agent Framework

## 0. 可实现性评估（基于9个开源代码库分析）

### 0.1 已分析的全部代码库

| # | 代码库 | 路径 | 论文 | 语言 | 规模 |
|---|--------|------|------|------|------|
| 1 | Cochise | `paper_analysis/AD_pt/cochise/` | AD_pt (ACM TOSEM) | Python | ~576行 |
| 2 | AWE | `paper_analysis/AWE/AWE/` | AWE (NDSS LAST-X 2026) | Python | ~5,000行 |
| 3 | CyberGym | `paper_analysis/CyberGYM/cybergym/` | CyberGym (ICLR 2026) | Python | ~3,000行 |
| 4 | HackWorld | `paper_analysis/Hackworld/HackWorld/` | HackWorld (arXiv 2025) | Python | ~4,000行 |
| 5 | PACEBench | `paper_analysis/PACEBench/PACEbench/` | PACEBench (ICLR 2026) | Python | ~2,500行 |
| 6 | RedTeamCUA | `paper_analysis/RedTeamCUA/RedTeamCUA/` | RedTeamCUA (ICLR 2026) | Python | ~6,000行 |
| 7 | CHeaT | `paper_analysis/Proactive_Defenses/CHeaT/` | Proactive_Defenses (USENIX 2025) | Python | ~2,000行 |
| 8 | CPA | `container-pentester-agent/` | CPA (容器安全) | Go | ~15,000行 |
| 9 | VulnBot | `multi_agents_pentest/` | VulnBot (课程项目) | Python | ~5,000行 |

### 0.2 每个DARWIN模块的可实现性评估（基于代码验证）

| DARWIN模块 | 可实现性 | 可直接复用的代码 | 需从零构建 | 风险 |
|-----------|---------|----------------|-----------|------|
| **Orchestrator** | **高** | Cochise的Planner+Executor分离模式、CPA的TaskEngine | B维度决策逻辑 | 低 |
| **DPM (防御感知)** | **高** | AWE的FilterDetector(字符级过滤分析) + CHeaT的33种防御技术数据库 + CPA的混合分类器(规则+LLM) | WAF类型→绕过策略的映射表 | 低 |
| **DKG (动态知识图谱)** | **高** | Cochise的Knowledge类(增量累积) + AWE的MemoryManager(SQLite持久化) + VulnBot的DB Schema | 图查询API、多Agent并发写入 | 低 |
| **CTEG (跨任务经验图)** | **中** | AWE的MemoryStorage(长期记忆SQLite表: payload_attempts, detected_filters, successful_bypasses, strategy_effectiveness) + VulnBot的RAG(Milvus+Embedding) | Pattern Abstraction算法、Graph Query、衰减机制 | 中 |
| **DAVE (防御感知验证)** | **高** | AWE的Playwright Verifier(浏览器验证) + CyberGym的PoC崩溃验证 + PACEBench的flag验证 | L3 Defense Integrity(payload对比) | 低 |
| **MCP工具集成** | **高** | Cochise的LLMFunctionMapping(Python函数→工具定义自动转换) + CPA的gRPC Tool Registry | MCP协议适配层 | 低 |
| **子Agent生命周期** | **高** | CPA的Task Lifecycle (Pending→Running→Completed) + VulnBot的Role.run()循环 | 动态孵化/销毁 | 低 |
| **基准适配器** | **高** | PACEBench的HTTP Server协议(4端点) + CyberGym的HTTP Client + HackWorld的Agent接口 | 统一适配层 | 低 |
| **Custom Defense基准** | **高** | CHeaT的33种防御技术 + 防御安装器(local_file/web_file/tool_wrapper) + RedTeamCUA的adversary评估框架 | 无（全部可复用） | 极低 |

### 0.3 关键发现（修正原计划的可行性判断）

1. **DPM远比预期可行**：AWE已有完整的FilterDetector实现（`xss_agent/analyzers/filter_detector.py`），它能检测"哪些字符被过滤、哪些标签被阻止、哪些事件处理器被ban"。CHeaT提供了33种防御技术的完整分类和部署代码。CPA的混合分类器提供了规则+LLM的双层检测模式。三者结合即可构建DPM。

2. **CTEG有现有基础**：AWE的MemoryStorage已经是跨会话的长期记忆系统（SQLite，含payload_attempts/detected_filters/successful_bypasses/strategy_effectiveness四张表）。需要扩展的是：从"单任务内记忆"变为"跨任务模式抽象"。

3. **Custom Defense基准有现成实现**：CHeaT的`defense_installer.py`可以直接部署Cloak/Honey/Trap防御。RedTeamCUA提供了完整的adversary评估框架（双度量体系+agent集成+CUA测试）。

4. **动态伸缩需要在两个现有模式间架桥**：Cochise（Planner+临时Executor，极简）和CPA（Hub+多Spoke，完整）代表了简单和复杂两端。DARWIN需要的是在这两端之间按B维度动态切换。

5. **PACEBench的集成最简单**：只需实现4个REST端点的HTTP服务器。比HackWorld（需要VMware）和CyberGym（需要130GB+数据）的门槛低得多。

---

## 一、Agent框架设计

### 1.0 设计哲学：为什么"动态伸缩"是正确的第三条路

现有两种极端设计的失败分析（基于真实代码验证）：

| 设计 | 代表系统(代码已验证) | 简单场景 | 复杂场景 | 根本问题 |
|------|-------------------|---------|---------|---------|
| 固定单Agent | Cochise(576行, Planner+临时Executor) | 极简有效（单域AD $2以下攻陷） | GOAD多域失败（Knowledge类过于简单） | 内存字典知识无法承载多域多主机的并行状态 |
| 固定单Agent | VulnBot实验的BaseGPT | 简单CTF可用 | 无任务分解、认知负荷过高 | 单LLM上下文无法承载多主机/多域并行状态 |
| 固定多Agent(顺序) | VulnBot (Collector→Scanner→Exploiter) | 中 | LLM摘要传递损失信息 | 摘要压缩丢失关键信息（SQL参数名、WAF行为等） |
| 固定多Agent(集中) | CPA (Hub+Spoke, 5 Agent类型) | 仅覆盖容器场景 | 仅覆盖容器场景 | Agent类型固定、无动态伸缩 |
| 专用单Agent | AWE (~5000行, 8种漏洞Agent) | XSS 87%，注入类极致 | 非注入类完全无效 | 架构绑定漏洞类型，无通用探索能力 |

**动态伸缩的核心洞察**（基于代码验证）：
- **Cochise证明了极简可行**：576行即可完成AD域渗透。但Knowledge类是简单内存字典，无法扩展到多域。
- **AWE证明了专业化价值**：8种漏洞Agent+上下文感知+过滤检测+记忆系统=87% XSS。但架构绑定注入类。
- **CPA证明了集中协调可行**：Hub-and-Spoke + gRPC + 工具注册表 + HITL = 生产级架构。但Agent类型固定。
- **正确的做法**：Cochise的极简Planner+Executor作为Solo Mode → CPA的Hub-and-Spoke作为Distributed Mode → B维度驱动在两者间切换 → DKG替代Cochise的简单字典和VulnBot的LLM摘要。

### 1.1 总体架构（六层）

```
Layer 0: System Prompts (Orchestrator + 3 Sub-Agent Types)
Layer 1: Orchestration (TaskDecomposer + ResourceGovernor + DefenseMonitor)
Layer 2: Dynamic Scaling Engine (B维度 + TDA + 伸缩状态机)
Layer 3: Execution (MCP Gateway + Tool Router + Skill Composer + 30 Tools)
Layer 4: Memory & Knowledge (Shared DKG + Action History + CTEG)
Layer 5: Verification (DAVE: L1 HTTP → L2 Browser → L3 Defense Integrity → L4 Impact)
```

### 1.2 实现架构（与概念架构的代码级映射）

```
概念层                 实现组件                    直接复用来源
──────────────────────────────────────────────────────────────
Orchestrator Agent  →  orchestrator.py             Cochise planner.py (Planner+临时Executor)
Sub-Agent Pool      →  sub_agents/                 VulnBot roles/ + CPA hub/agent/v2/
DKG                 →  dkg.py (NetworkX + JSON)    Cochise knowledge.py + AWE MemoryStorage
CTEG                →  cteg.py (JSON图 + Embedding) AWE MemoryStorage(长期) + VulnBot rag/
DPM                 →  dpm.py                       AWE filter_detector.py + CHeaT defenses DB + CPA classifier
DAVE                →  dave.py                      AWE verifier.py(Playwright) + PACEBench flag验证
MCP Gateway         →  mcp_gateway.py               Cochise LLMFunctionMapping + CPA gRPC Tool Registry
Benchmark Adapters  →  benchmarks/                  PACEBench 4-endpoint HTTP protocol
Custom Defense      →  custom_defense/              CHeaT defense_installer.py + RedTeamCUA adversary eval
```

### 1.3 Dynamic Scaling Engine — 最终实现设计

#### 1.3.1 Orchestrator Agent (`orchestrator.py`)

**直接复用Cochise的Planner+Executor模式**（`cochise/planner.py` 131行 + `cochise/executor.py` 129行）：

```python
class Orchestrator:
    """
    Solo Mode: 直接复用Cochise的Planner+临时Executor模式
    Coordinated/Distributed: 扩展为CPA的Hub-and-Spoke模式
    
    参考:
    - Cochise planner.py:131 — 持久化LLM对话+知识累积+历史压缩
    - CPA hub/task/engine.go:70-121 — TaskEngine状态机
    """
    
    def __init__(self, config: DarwinConfig):
        self.dkg = DKG()
        self.dpm = DefensePerceptionModule()  # 复用AWE FilterDetector + CHeaT DB
        self.cteg = CTEG()  # 扩展AWE MemoryStorage
        self.dave = DAVE()  # 复用AWE Playwright Verifier
        self.sub_agents = SubAgentPool()
        self.knowledge = KnowledgeBase()  # 参考Cochise Knowledge类
        
    def run(self, task_description: str) -> TaskResult:
        """主循环 — 参考Cochise planner.engage()模式"""
        self._init_from_task(task_description)
        
        while not self._termination_condition():
            # 计算B维度（从DKG实时提取目标拓扑）
            B = compute_task_breadth(self.dkg)
            
            if B < 0.3:  # Solo Mode — 直接复用Cochise的Planner+临时Executor
                result = self._run_solo_cycle()  # 参考cochise/planner.py:engage()
            elif B < 0.6:  # Coordinated Mode
                result = self._run_coordinated_cycle()
            else:  # Distributed Mode — 参考CPA Hub-and-Spoke
                result = self._run_distributed_cycle()
            
            # DKG监控 → 检测协同机会 → 可能重新分配子Agent
            self._scan_collaboration_opportunities()
            
            # 更新TDA + B
            self._update_tda()
        
        return self._aggregate_results()
```

**B维度计算方法**（从DKG实时提取，参考Cochise knowledge.py的模式）：

```python
def compute_task_breadth(dkg: DKG) -> float:
    """
    从DKG实时感知目标拓扑范围
    
    参考:
    - Cochise knowledge.py:73 — 从内存字典提取实体信息
    - CPA internal/hub/k8s/perceptor.go — 实时感知集群拓扑
    """
    hosts = dkg.query_nodes("Host")
    domains = dkg.query_nodes("Domain")
    credentials = dkg.query_nodes("Credential")
    
    n_targets = len(hosts)
    is_multi_domain = len(domains) > 1
    
    # 检测横向移动需求：有内网可达主机 + 已有凭证
    internal_hosts = [h for h in hosts if h.get('is_internal')]
    needs_lateral = len(internal_hosts) > 0 and len(credentials) > 0
    
    N_norm = min(n_targets / 5.0, 1.0)
    M_domain = 1.0 if is_multi_domain else 0.0
    L_move = 1.0 if needs_lateral else 0.0
    
    return 0.4 * N_norm + 0.3 * M_domain + 0.3 * L_move
```

#### 1.3.2 Sub-Agent 实现（`sub_agents/`）

**直接复用VulnBot的Role模式**（`roles/role.py:16-90`）和**CPA的Agent实现**：

```python
class BaseSubAgent:
    """
    参考: VulnBot Role._plan() + Role._react() 模式 (role.py:38-82)
          Cochise Executor (executor.py:129) — 临时实例、独立LLM会话
    
    关键设计:
    - 独立LLM会话（参考VulnBot per-agent chat_id）
    - 独立上下文窗口（不污染Orchestrator上下文）
    - 仅通过DKG与Orchestrator和其他子Agent通信
    - 无自然语言Agent间对话（消除SoK批评的信息传递损失）
    """
    
    def __init__(self, agent_type: str, task_scope: TaskScope,
                 dkg: DKG, llm_session: LLMSession, budget: TokenBudget):
        self.agent_type = agent_type
        self.task_scope = task_scope
        self.dkg = dkg
        self.llm = llm_session
        self.budget = budget
        self.memory = SubAgentMemory()  # 参考AWE MemoryManager(短期)
        
    def run(self) -> SubAgentResult:
        """参考VulnBot Role.run() — Plan→Act→Observe循环"""
        self.plan = self._generate_plan()
        
        while self.budget.remaining() > 0:
            task = self._select_next_task()
            if not task: break
            
            # 参考VulnBot WriteCode + ExecuteTask 模式
            # 但结果写入DKG而非LLM摘要
            command = self._generate_command(task)
            result = self._execute(command)
            
            # 写入DKG — 替代VulnBot的LLM摘要
            self._write_findings_to_dkg(task, result)
            
            # 参考VulnBot check_success (planner.py:35-67)
            if self._evaluate_success(task, result):
                self.plan = self._update_plan_success(task)
            else:
                self.plan = self._replan_after_failure(task, result)
        
        return self._build_result()
```

**三种Sub-Agent的代码复用来源**：

| Sub-Agent | 直接复用来源 | 关键参考文件 |
|-----------|------------|------------|
| ReconAgent | VulnBot Collector (`roles/collector.py`) | 工具列表、侦察提示模板 |
| ExploitAgent | AWE XSS/SQLi Agent (`xss_agent/`, `sqli_agent/`) | FilterDetector、ContextAnalyzer、LLMPayloadEngine |
| PivotAgent | Cochise Executor (`executor.py`) | SSH命令执行、凭证复用模式 |

### 1.4 DPM — 基于AWE FilterDetector + CHeaT Defense DB的防御感知模块

**核心复用**：
- AWE `xss_agent/analyzers/filter_detector.py` — 字符级/标签级/事件级过滤检测
- CHeaT `cheat/database/` — 33种防御技术的完整JSON数据库
- CPA `classifier/hybrid.go` — 规则+LLM混合分类器模式

```python
class DefensePerceptionModule:
    """
    三层检测架构（基于已验证的代码模式）:
    
    Layer 1 (规则匹配): 复用AWE的FilterDetector
      - 发送Probe Class A-E探针序列（同AWE的5类35+探针）
      - 检测字符级过滤（哪些字符被删除/编码）
      - 检测标签级过滤（script/img/svg/iframe是否被阻止）
      - 检测事件处理器过滤（onerror/onclick等）
      - 检测协议过滤（javascript:/data:等）
      
    Layer 2 (WAF指纹匹配): 基于CHeaT的33种防御技术数据库
      - 响应头特征匹配（ModSecurity/Cloudflare/Naxsi/Coraza）
      - 响应体模式匹配（拦截页面特征）
      - 状态码异常检测（403/406/429/999）
      - 复用CHeaT的defense_technique.json格式
      
    Layer 3 (LLM分类器): 参考CPA混合分类器
      - 当规则置信度<0.8时触发LLM分类（参考CPA的gpt-5-nano用法）
      - 输入: 异常HTTP事务的完整上下文
      - 输出: 防御类型 + 置信度 + 推荐绕过策略
    """
    
    def __init__(self):
        # 复用AWE的FilterDetector实现
        self.filter_detector = FilterDetector()
        
        # 加载CHeaT的防御技术数据库
        self.defense_db = self._load_cheat_defenses()
        
        # WAF指纹数据库（初始10条规则，可动态扩展）
        self.waf_signatures = self._load_waf_signatures()
        
        # LLM分类器（低成本模型，参考CPA的gpt-5-nano）
        self.llm_classifier = LLMClassifier(model="gpt-5-nano")
    
    def detect(self, http_transaction: HTTPTransaction) -> DPMReport:
        """
        混合检测流程:
        1. FilterDetector: 确定性探针结果（0 cost）
        2. WAF Signature Match: 规则匹配（0 cost）
        3. LLM Classifier: 仅在置信度<0.8时调用（low cost）
        
        参考: CPA classifier/hybrid.go:24-60
        """
        filter_result = self.filter_detector.analyze(http_transaction)
        waf_result = self._match_waf_signatures(http_transaction)
        
        confidence = self._rule_confidence(filter_result, waf_result)
        if confidence < 0.8:
            llm_result = self.llm_classifier.classify(http_transaction, filter_result)
            return self._merge_and_build_report(filter_result, waf_result, llm_result)
        
        return self._build_report(filter_result, waf_result)
```

### 1.5 CTEG — 基于AWE MemoryStorage扩展的跨任务经验图

**核心复用**：
- AWE `MemoryStorage` — SQLite长期记忆（payload_attempts, detected_filters, successful_bypasses, strategy_effectiveness四张表）
- VulnBot `rag/` — Milvus向量数据库 + Embedding + Reranker

```python
class CTEG:
    """
    扩展AWE的MemoryStorage从"单任务内记忆"到"跨任务模式抽象"
    
    AWE MemoryStorage已有:
    - payload_attempts: (session_id, target_domain, payload, strategy, success, detected_filters)
    - detected_filters: (target_domain, filter_type, filter_signature, detection_count)
    - successful_bypasses: (filter_type, bypass_technique, effectiveness_score)
    - strategy_effectiveness: (strategy_name, success_count, failure_count, effectiveness_score)
    
    DARWIN CTEG新增:
    - 剥离session_id和target_domain → 跨任务泛化
    - 新增Pattern节点: 抽象绕过/利用模式（非具体payload）
    - 新增图查询: 基于防御特征检索有效模式
    - 衰减机制: 基于时间的置信度衰减
    """
    
    def __init__(self, storage_path: str = "cteg_state.json"):
        self.graph = nx.MultiDiGraph()  # 同DKG
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
        self.storage_path = storage_path
        
    def abstract_patterns(self, task_record: TaskRecord) -> List[Pattern]:
        """
        从具体任务记录提取抽象模式
        
        关键差异 vs AWE MemoryStorage:
        AWE存储: (session_123, "target.com", "<script>alert(1)</script>", "encoding", True, ...)
        CTEG存储: BypassPattern("双URL编码", "绕过ModSecurity黑名单过滤", applicable_defenses=[...])
        
        即: 剥离session/domain/specific payload → 保留抽象机制
        """
        prompt = f"""
        Extract ABSTRACT patterns from this task. Strip ALL specific values.
        Task: {task_record.summary()}
        AWE MemoryStorage записи: {task_record.memory_entries}
        
        Output JSON with:
        - abstract_mechanism (the general technique)
        - applicable_defense_types (WAF/Cloak/Honey/Trap)
        - preconditions (what must be true for this to work)
        """
        return self._parse_and_store(llm.generate(prompt))
    
    def query(self, defense_state: DefenseStateVector, top_k: int = 5) -> List[Pattern]:
        """
        查询有效的绕过/利用模式
        参考: VulnBot RAG的Milvus similarity search + reranker
        """
        query_vec = self.embedder.encode(defense_state.to_query_text())
        
        # Vector similarity over pattern nodes
        candidates = []
        for node_id, data in self.graph.nodes(data=True):
            if data.get('type') in ['BypassPattern', 'ExploitPattern']:
                node_vec = self.embedder.encode(data.get('abstract_description', ''))
                similarity = cosine_similarity(query_vec, node_vec)
                candidates.append((node_id, similarity, data))
        
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[:top_k]
```

### 1.6 DAVE — 基于AWE Playwright Verifier的四层验证

```python
class DAVE:
    """
    四层验证引擎 — 每层都有现有代码基础
    
    L1 (HTTP Response): 参考PACEBench的flag提取逻辑
    L2 (Browser): 直接复用AWE verifier.py (Playwright + alert/console/DOM监控)
    L3 (Defense Integrity): 参考AWE ContextAnalyzer的反射分析逻辑
    L4 (Impact): 参考CyberGym的PoC崩溃验证 + PACEBench的flag验证
    """
```

---

## 二、基准集成方案（基于实际代码接口）

### 2.1 每个基准的具体集成方式

#### PACEBench（最优先）
**接口**：4个REST端点的HTTP服务器（最简单）
**复用**：`PACEBench/docs/agent_server_protocol.md` 已定义完整协议
**适配器**：`benchmarks/pacebench_adapter.py` (~150行FastAPI服务器)

```python
# 直接参考PACEBench的协议定义
# 端点: POST /model, POST /chat, GET /result, POST /stop
# DARWIN Orchestrator.run() = /chat的处理逻辑
```

#### XBOW
**接口**：Docker容器 + Flag文件读取
**复用**：XBOW的Docker Compose部署
**适配器**：`benchmarks/xbow_adapter.py` (~100行)

#### XBOW
**接口**：Docker容器 + Flag文件读取
**复用**：XBOW的Docker Compose部署
**适配器**：`benchmarks/xbow_adapter.py` (~100行)

### 2.2 Custom Defense基准构建方案

**直接复用CHeaT的33种防御技术 + RedTeamCUA的评估框架**：

```python
# custom_defense/build_challenge.py
"""
构建流程 (参考CHeaT的defense_installer.py + RedTeamCUA的prepare_injection):

1. 基于XBOW的Web挑战模板，部署基础漏洞应用 (Docker)
2. 使用CHeaT defense_installer.py部署防御层:
   - Cloak: 端口随机化 | Banner混淆 | 响应混淆 | 动态指纹 | 会话门控
   - Honey: 虚假凭证文件 | 蜜罐数据库 | 伪漏洞 | 假flag | 行为蜜罐
   - Trap: 慢速响应 | 无限数据流 | 语义混淆 | 连接陷阱 | 资源耗尽
3. 每个挑战注入验证flag (参考PACEBench的flag注入模式)
4. 部署到Docker Compose (参考PACEBench docker_manager.py)
"""
```

---

## 三、实验设计

### 3.0 关键设计原则

1. **两个外部基线，各有适用范围**：
   - **Claude Code**：能覆盖全部3个基准的通用基线。AWE/Cochise/VulnBot各自只能适配部分基准，已被移除。
   - **PentestAgent**（AsiaCCS 2025, arXiv:2411.05185）：多Agent框架（Recon/Search/Planning/Execution四Agent），使用RAG+CoT，在VulHub+HTB 67目标上达74.2%成功率。可适配Web类基准（XBOW/PACEBench/CustomDef），但无法适配CyberGym（无二进制能力）和GOADv3（无AD专用工具链）。引入它作为"已发表的多Agent框架"对照，增强RQ1和RQ4的说服力。

2. **消融实验不做跨基准汇总**：每个消融变体只在其适用的基准上与DARWIN(full)做配对per-benchmark对比。

3. **所有对比都是配对的**：在同一组挑战上运行两种配置，用配对统计检验。

### 3.1 基准概述

| 基准 | 挑战数 | 特点 | 适用场景 |
|------|--------|------|---------|
| **XBOW** | 104 | Web漏洞利用(26种漏洞类型) | 通用Web能力基线 |
| **PACEBench** | 32 | A:17(单CVE), B:7(多主机), C:5(链式), D:3(WAF) | 递进难度 + WAF防御 |
| **Custom Defense** | 20 | Cloak:5, Honey:5, Trap:5, Combined:5 | 主动防御场景 |
| **总计** | **156** | | |

> CyberGym(二进制PoC)和GOADv3(AD渗透)已移除：PentestAgent无法处理这两类挑战，仅DARWIN vs Claude Code在两个额外基准上对比缺乏说服力。聚焦Web基准确保三个配置(DARWIN/PentestAgent/Claude Code)都能运行全量挑战，实验对比更公平。

### 3.2 RQ1: 防御感知能否突破WAF场景零成功率？

| 项目 | 内容 |
|------|------|
| **核心问题** | DPM + Defense Bypass能否让Agent首次在有WAF/主动防御的场景下取得成功？ |
| **基准** | PACEBench D-CVE(3个WAF挑战) + Custom Defense(20个Cloak/Honey/Trap挑战) = **23挑战** |
| **为什么只选这两个** | 只有这两个基准包含主动防御机制。XBOW不含防御层 |
| **对比配置** | (a) **DARWIN(full)** vs (b) **DARWIN\DPM** (移除防御感知) vs (c) **Claude Code** (通用基线) vs (d) **PentestAgent** (多Agent框架基线, AsiaCCS 2025) |
| **为什么引入PentestAgent** | PentestAgent是已发表的多Agent渗透测试框架（Recon/Search/Planning/Execution四Agent + RAG + CoT），在VulHub+HTB 67目标上达74.2%。但它的架构中不含防御感知模块——DPM和Defense Bypass是其设计中不存在的概念。将其与DARWIN在防御基准上对比，可以验证一个关键命题：**多Agent架构 + RAG知识检索 ≠ 防御感知**。即使有搜索Agent和规划Agent，缺乏DPM的框架仍会在WAF/蜜罐前失败 |
| **核心指标** | TSR、WAF检测Precision/Recall/F1、Honey Detection Rate、Bypass Strategy Success Rate |
| **统计方法** | McNemar's test (配对二元, DARWIN vs each)、Cohen's g (效应量) |
| **重复** | 每挑战3次 (Pass@3) |
| **运行数** | 4配置 × 23挑战 × 3次 = **276次** |
| **关键假设** | PACEBench D-CVE从当前SOTA的0%首次破零 |
| **注** | 如需要加深分析，可在PACEBench A/B/C(无WAF的三个场景，共29挑战)上额外运行DARWIN(full) vs DARWIN\DPM，验证DPM在无防御场景下是否产生负收益(null effect check)。额外运行数：2配置 × 29 × 3 = 174次 |

### 3.3 RQ2: 动态伸缩是否保持简单场景效率+提升复杂场景性能？

| 项目 | 内容 |
|------|------|
| **核心问题** | B维度驱动的动态伸缩能否做到：简单场景零子Agent开销(Solo Mode) → 复杂场景自动扩展(Distributed Mode)？ |
| **基准** | 全部三个基准(156挑战)，按B计算值分成三级 |
| **B级别分组** | B<0.3(单点): XBOW部分 + PACEBench A-CVE 17 ≈ 80挑战；0.3≤B<0.6(中等): PACEBench B-CVE 7 + Custom Defense Combined 5 = 12挑战；B≥0.6(高广度): PACEBench C-CVE 5 + D-CVE 3 + Custom Defense部分 15 = 23挑战 |
| **对比配置** | **DARWIN(full)** vs **DARWIN\B** (永远Solo Mode, 无论B值多大都不孵化子Agent) vs **Claude Code** |
| **为什么\B在所有基准上都能运行** | DARWIN\B只是锁定在Solo Mode——它仍然是一个完整的功能Agent，只是不使用多Agent协作。它在任何基准上都可以运行 |
| **核心指标** | 按B级别分组的TSR、token效率、子Agent孵化数(vs B值) |
| **统计方法** | Two-way ANOVA (配置 × B级别)；Cochran's Q test (三层B级别内的配对比较) |
| **重复** | 每挑战3次 |
| **运行数** | 复用RQ4中DARWIN(full) + DARWIN\B + Claude Code在全部261挑战上的数据。不额外运行 |
| **关键假设** | B<0.3: full ≈ \B (无差异, 零开销)；B≥0.6: full >> \B (显著提升) |
| **注** | DARWIN\B在全基准上运行=156×3=468次，这部分成本已计入RQ4 |

### 3.4 RQ3: CTEG跨任务经验迁移能否随时间提升性能？

| 项目 | 内容 |
|------|------|
| **核心问题** | CTEG能否通过任务间累积经验来持续提升Agent的性能？ |
| **基准** | XBOW子集100挑战（按漏洞类型均匀采样：XSS:20, SQLi:20, SSTI:15, CMDi:15, SSRF:10, XXE:5, LFI:5, 其他:10）。不使用全部104个——因为需要控制挑战难度和类型的分布均匀性 |
| **为什么只用XBOW** | CTEG的学习效果需要在同质场景序列上测量——XBOW是同类(Web)挑战的最大集合。XBOW是同质性最高的Web挑战集合，最利于测量学习效果 |
| **对比配置** | **DARWIN(full)** (CTEG启用) vs **DARWIN\CTEG** (任务间重置, 等价于现有所有框架的行为) |
| **实验方案** | 两个变体各按相同顺序运行100个挑战。CTEG变体：经验跨任务累积。\CTEG变体：每任务后清空记忆。重复5次，每次使用不同的随机挑战顺序（控制顺序效应） |
| **核心指标** | 学习曲线(EMA, α=0.1)、前25 vs 后25 TSR差异、BypassPattern/ExploitPattern节点增长数 |
| **统计方法** | Paired t-test (前25 vs 后25 TSR)、Bootstrap 95% CI (1000 resamples over 5 orders) |
| **重复** | 每变体5次(不同随机顺序) |
| **运行数** | 2变体 × 100挑战 × 5顺序 = **1,000次** |
| **关键假设** | DARWIN(full)后25任务的TSR显著高于前25任务；DARWIN\CTEG前后无显著差异 |

### 3.5 RQ4: DARWIN在全部基准上的综合性能如何？

| 项目 | 内容 |
|------|------|
| **核心问题** | DARWIN在三个基准上的整体表现，与Claude Code(通用基线)和PentestAgent(多Agent框架基线)的对比 |
| **基准** | 全部三个基准 = **156挑战** |
| **对比配置** | (a) **DARWIN(full)** vs (b) **Claude Code** vs (c) **PentestAgent** |
| **三个配置覆盖一致** | 移除CyberGym和GOADv3后，三个配置在全部156个挑战上都能运行。对比不再需要N/A行 |
| **呈现方式** | per-benchmark对比表，每行一个基准，三列TSR对比 |
| **核心指标** | Per-benchmark TSR、Pass@3、Token效率(TSR/1K tokens)、时间效率、API成本 |
| **统计方法** | Per-benchmark: McNemar's test (配对二元TSR)；跨基准排名：Friedman + Nemenyi |
| **重复** | 每挑战3次 |
| **运行数** | 3配置 × 156挑战 × 3次 = **1,404次** |

#### RQ4 结果表示例（论文Table格式）

| 基准 | 挑战数 | DARWIN TSR | PentestAgent TSR | Claude Code TSR | Δ(DARWIN-PA) | Δ(DARWIN-CC) |
|------|--------|-----------|-----------------|-----------------|---------------|---------------|
| XBOW | 104 | — | — | — | — | — |
| PACEBench A-CVE | 17 | — | — | — | — | — |
| PACEBench B-CVE | 7 | — | — | — | — | — |
| PACEBench C-CVE | 5 | — | — | — | — | — |
| PACEBench D-CVE | 3 | — | — | — | — | — |
| Custom Defense | 20 | — | — | — | — | — |
| **综合/加权** | **156** | — | — | — | — | — |

### 3.6 RQ5: 结构化DKG通信是否优于LLM摘要通信？

| 项目 | 内容 |
|------|------|
| **核心问题** | DKG(Schema约束的结构化写入/读取) vs LLM摘要(自然语言压缩, 参考VulnBot的PlannerSummary模式) vs 自然语言对话(MAPTA式Agent间聊天)——哪种通信方式信息损失最小？ |
| **基准** | 仅选**需要Agent间通信的场景**（单Agent Solo Mode不需要通信）：PACEBench B-CVE(7, 多主机需要协作) + PACEBench C-CVE(5, 链式需要传递凭证/会话) + Custom Defense Combined(5, 组合防御需要传递防御信息) = **17挑战** |
| **为什么不包含XBOW简单挑战** | XBOW大部分是单主机单漏洞——Solo Mode就能处理，不涉及Agent间通信。包含它们只会稀释信号 |
| **对比配置** | (a) **DARWIN(full)** (DKG通信) vs (b) **DARWIN\DKG** (替换为VulnBot式LLM摘要通信：每个子Agent完成后→LLM将其DKG写入压缩为自然语言摘要→Orchestrator将摘要注入下一个子Agent) vs (c) **DARWIN\DKG+Chat** (替换为MAPTA式自然语言对话：子Agent间直接通过聊天消息通信) |
| **为什么\DKG变体只能在这些基准上运行** | \DKG变体需要多Agent通信场景才有意义——在单Agent Solo场景中通信路径为空 |
| **核心指标** | 信息保留率(自动提取发送方DKG写入的关键字段，与接收方DKG读取的对应字段对比，计算保留率)、误传率(信息被扭曲的比例)、TSR差异 |
| **统计方法** | McNemar's test (配对TSR)；人工标注(信息保留率，200条采样, Kappa) |
| **重复** | 每挑战3次 |
| **运行数** | 3变体 × 17挑战 × 3次 = **153次** |
| **关键假设** | DKG的信息保留率 > 90%；LLM摘要 < 70%；自然语言对话 < 50% |

### 3.7 RQ6: 失败模式分析

| 项目 | 内容 |
|------|------|
| **核心问题** | DARWIN及其消融变体各自以什么方式失败？与Claude Code的失败模式有何不同？ |
| **数据来源** | 复用RQ1-RQ5所有实验的全部失败案例日志(预计2000+案例) |
| **对比** | DARWIN(full) vs DARWIN\DPM vs DARWIN\B vs DARWIN\CTEG vs DARWIN\DKG vs Claude Code |
| **方法** | 两名安全研究人员独立编码200个随机采样失败案例(从全部系统中均匀采样)、计算Cohen's κ。达到κ>0.7后，其中一人编码剩余案例 |

**失败分类编码框架**：

| Level | 类别 | 编码 | 示例 |
|-------|------|------|------|
| L1: 能力缺陷 | 工具参数错误 | CD-TOOL | nmap缺少-p-参数 |
| L1: 能力缺陷 | 结果解析失败 | CD-PARSE | 未从dirb输出中提取URL |
| L1: 能力缺陷 | 上下文溢出 | CD-CTX | token超限导致关键信息截断 |
| L1: 能力缺陷 | 过早终止 | CD-EARLY | 获取一个flag后即停止 |
| L1: 能力缺陷 | 重复无效行动 | CD-LOOP | 反复执行相同的失败命令 |
| L2: 策略推理 | 规划不足 | SR-PLAN | 无法构建多步攻击链 |
| L2: 策略推理 | 路径切换失败 | SR-STUCK | 主路径受阻后不探索备选 |
| L2: 策略推理 | 信息整合失败 | SR-INTEG | 拥有全部线索但无法关联 |
| L3: 防御相关 | 防御未检测 | DR-NODETECT | 未识别WAF/蜜罐存在 |
| L3: 防御相关 | 绕过策略耗尽 | DR-EXHAUST | 所有绕过尝试均失败 |
| L3: 防御相关 | 蜜罐误判 | DR-HONEY | 将蜜罐数据误作真实flag |
| L3: 防御相关 | 陷阱触发 | DR-TRAP | 被无限数据流耗尽资源 |
| L3: 防御相关 | 对抗性提示中招 | DR-PROMPT | 被语义混淆内容误导 |
| L4: 幻觉 | Flag幻觉 | HAL-FLAG | 编造不存在的flag字符串 |
| L4: 幻觉 | 漏洞幻觉 | HAL-VULN | 报告不存在的漏洞 |

**运行数**: 0次（纯分析现有数据）

### 3.8 消融实验汇总：谁在哪个基准上运行

这是最关键的一张表——回答"消融变体去掉某组件后能适配哪些基准，以及怎么和full做对比"：

| 消融变体 | 可运行的基准 | 挑战数 | 为什么只能在这些基准上运行 | 与full对比的方式 |
|---------|------------|--------|------------------------|---------------|
| **DARWIN(full)** | 全部3个 | 156 | 完整功能 | — |
| **DARWIN\B** (永远Solo) | 全部3个 | 156 | \B只是锁定Solo Mode，不影响任何功能模块。子Agent孵化被禁用但Orchestrator/DPM/DAVE/CTEG/DKG均完整 | Per-benchmark配对TSR对比。是唯一能在全部基准上与full对比的消融 |
| **DARWIN\DPM** (无防御感知) | PACEBench(32) + CustomDef(20) = 52 | 只有这两个基准包含需要DPM检测的防御层。XBOW不含WAF/Cloak/Honey/Trap——DPM在该基准上不发挥作用，移除与否无差异 | 只在PACEBench(D-CVE重点)和CustomDef上配对对比TSR。预期：full >> \DPM在D-CVE上；\DPM在无防御基准上=full |
| **DARWIN\CTEG** (任务间重置) | XBOW(104) + PACEBench(32) + CustomDef(20) = 156 | CTEG仅在连续运行多个同类任务时才可能产生收益。纯Web挑战的同质性确保跨任务迁移有意义 | 在RQ3的XBOW 100子集上做专门的学习曲线对比。在PACEBench和CustomDef上可以做辅助验证 |
| **DARWIN\DKG** (LLM摘要通信) | PACEBench B-CVE(7)+C-CVE(5) + CustomDef Combined(5) = 17 | 仅在需要Agent间通信的多主机/链式/组合防御场景中有意义。单主机场景中无Agent间通信——\DKG和full的行为完全一致 | 仅在RQ5的17个挑战上配对对比。在其他基准上\DKG ≡ full（无通信路径） |

**消融实验运行量汇总**：

| 消融变体 | 基准范围 | 挑战数 | 重复 | 运行数 |
|---------|---------|--------|------|--------|
| DARWIN\B | 全部3基准 | 156 | 3 | 468 |
| DARWIN\DPM | PACEBench + CustomDef | 52 | 3 | 156 |
| DARWIN\CTEG (RQ3专门实验) | XBOW 100子集 | 100 | 5顺序 | 500 |
| DARWIN\CTEG (辅助验证, 可选) | PACEBench + CustomDef | 52 | 3 | 156 |
| DARWIN\DKG (RQ5专门实验) | B-CVE+C-CVE+Combined | 17 | 3 | 51 |
| **消融合计** | | | | **1,646次** |

### 3.9 实验总规模汇总

| RQ | 配置 | 基准 | 挑战数 | 重复 | 运行数 |
|----|------|------|--------|------|--------|
| RQ4 | DARWIN(full) + Claude Code + PentestAgent | 全部3基准 | 156 | 3 | 1,404 |
| RQ1 | DARWIN(full) + \DPM + Claude Code + PentestAgent | PACEBench D-CVE + CustomDef | 23 | 3 | 276 |
| RQ1 (辅助) | DARWIN(full) + \DPM | PACEBench A/B/C | 29 | 3 | 174 |
| RQ2 | 复用RQ4数据(增加B维度分析) | — | — | — | 0 (纯分析) |
| RQ2补充 | DARWIN\B | 全部3基准 | 156 | 3 | 468 |
| RQ3 | DARWIN(full) + \CTEG | XBOW 100子集 | 100 | 5 | 1,000 |
| RQ5 | DARWIN(full) + \DKG + \DKG+Chat | B-CVE+C-CVE+Combined | 17 | 3 | 153 |
| RQ6 | 复用全部失败案例 | — | — | — | 0 (纯分析) |
| **总计** | | | | | **3,475次** |

### 3.10 实验执行顺序

```
Phase 1 — Pilot (3-4周, ~800次运行):
  RQ4 (XBOW子集20 + PACEBench A-CVE 5) → 验证DARWIN基本功能
  RQ1 (PACEBench D-CVE 3 + CustomDef子集 5) → 验证DPM核心创新
  成功标准: DARWIN D-CVE > 0%, DPM检测率 > 60%

Phase 2 — Core (4-5周, ~2,500次运行):
  RQ4完整 (全部156挑战 × 3配置) → 综合性能
  RQ1完整 (23+29挑战) → 防御感知完整验证
  RQ2 (含DARWIN\B在156挑战上) → 动态伸缩验证
  RQ5 (17挑战) → DKG通信验证

Phase 3 — Extended (2-3周, ~1,000次运行):
  RQ3 (XBOW 100子集, 5顺序) → CTEG学习曲线
  RQ6 (失败编码+统计) → 定性分析

论文撰写与Phase 2/3并行进行
```

---

## 四、实现路线图

### Phase 0: 项目骨架 (当前)
- [x] 9个参考代码库分析完成
- [x] 框架设计完成
- [ ] 创建Python项目骨架 (`pyproject.toml`, 目录结构)
- [ ] 配置LiteLLM (参考Cochise的provider-agnostic模式)

### Phase 1: Pilot — 核心创新验证 (3-4周)

**目标**：在PACEBench D-CVE上实现>0%，验证DPM可行

| Step | 任务 | 直接复用 | 工作量 |
|------|------|---------|--------|
| 1.1 | 实现DKG (`dkg.py`) | Cochise knowledge.py + AWE MemoryStorage schema | 3天 |
| 1.2 | 实现DPM (`dpm.py`) — 静态规则版 | AWE filter_detector.py + CHeaT defense DB | 3天 |
| 1.3 | 实现DAVE (`dave.py`) — L1+L4 | PACEBench flag验证 + AWE verifier.py | 2天 |
| 1.4 | 实现Orchestrator — Solo Mode | Cochise planner.py模式 | 3天 |
| 1.5 | 实现PACEBench适配器 | PACEBench agent_server_protocol.md | 2天 |
| 1.6 | Pilot实验 (PACEBench 32 + XBOW 15) | — | 5天 |

**Pilot成功标准**：
- PACEBench D-CVE > 0% (当前SOTA=0%)
- DPM WAF检测率 > 60% (规则版)
- Solo Mode在XBOW简单挑战上 ≈ 现有SOTA (80%+)

### Phase 2: Core — 动态伸缩+CTEG (4-5周)

| Step | 任务 | 直接复用 | 工作量 |
|------|------|---------|--------|
| 2.1 | 实现B维度 + 伸缩状态机 | — | 3天 |
| 2.2 | 实现3种子Agent (Recon/Exploit/Pivot) | VulnBot Role + AWE Agent | 5天 |
| 2.3 | 实现DKG多Agent并发读写 | — | 2天 |
| 2.4 | 实现CTEG (`cteg.py`) | AWE MemoryStorage + VulnBot RAG | 5天 |
| 2.5 | 实现Custom Defense基准 | CHeaT defense_installer.py | 3天 |
| 2.6 | 全量实验 (156挑战 × 3配置 × 3次 + 消融) | — | 10天 |

### Phase 3: Extended — CTEG+论文 (2-3周)

| Step | 任务 |
|------|------|
| 3.1 | CTEG学习曲线实验 (RQ3) |
| 3.2 | 失败分析 + 统计分析 (RQ6) |
| 3.3 | 论文撰写 |

---

## 五、学术规范声明

### 5.1 创新点声明

| 创新 | 新颖性 | 与现有工作的具体区别 |
|------|--------|-------------------|
| **B维度驱动的动态伸缩** | 新 | 所有现有系统(Cochise/AWE/VulnBot/CPA)使用固定Agent数量。DARWIN是首个根据DKG中的实时目标拓扑自动决定Agent数量的框架 |
| **DKG作为唯一Agent间通信媒介** | 新(组合) | PTFusion用DKG但Agent固定3个。VulnBot用LLM摘要。CPA用集中Session。Cochise用内存字典。DARWIN首次将DKG作为动态数量Agent的唯一结构化通信媒介 |
| **DPM (防御感知)** | 新 | AWE有FilterDetector但仅用于payload生成，不用于决策Agent行为。CHeaT有防御技术但不检测。DARWIN首次将防御检测作为Agent的感知能力 |
| **CTEG (跨任务经验)** | 新 | AWE MemoryStorage跨会话但限于单任务类型。DARWIN首次跨任务+跨漏洞类型抽象模式 |
| **DAVE L3 (防御完整性验证)** | 新 | AWE验证浏览器执行但不验证payload是否穿透WAF |

### 5.2 外部代码引用规范

| 参考元素 | 来源 | 引用方式 |
|---------|------|---------|
| Planner+临时Executor模式 | Cochise (`cochise/planner.py`) | 引用happe2025论文，说明"受Cochise的单Planner多临时Executor架构启发" |
| FilterDetector探针序列 | AWE (`xss_agent/analyzers/filter_detector.py`) | 引用jaswal2026论文，说明"扩展了AWE的过滤检测方法" |
| MemoryStorage四表设计 | AWE (SQLite schema) | 引用论文，说明"CTEG将AWE的单任务记忆扩展为跨任务经验图" |
| CHeaT 33种防御技术 | CHeaT (`cheat/database/`) | 引用ayzenshteyn2025论文，说明"Custom Defense基准基于CHeaT的防御分类法" |
| PACEBench HTTP协议 | PACEBench (`docs/agent_server_protocol.md`) | 引用liu2026论文，说明"采用PACEBench定义的agent-server协议" |

**所有DARWIN代码将独立编写。不直接复制任何现有代码库的代码行。复用仅限于：架构模式参考、算法思路借鉴、协议规范遵循。**

### 5.3 论文写作规范

1. **禁止**直接翻译任何参考论文的段落
2. **禁止**使用参考论文的图表（所有图表重新设计）
3. **禁止**在实验中引用非开源或不可复现的基准数据
4. Related Work中客观描述每个参考系统的贡献和局限性（包括其开源代码状态）
5. 消融实验的具体数值必须在实际运行后填入（不可预估伪造）

---

## 六、风险与应对（基于代码分析的更新）

| 风险 | 等级 | 实际依据 | 应对 |
|------|------|---------|------|
| DPM检测率不达标 | **→低** | AWE FilterDetector已验证可检测过滤行为；CHeaT提供33种防御的完整实现 | 聚焦top-5最常见WAF |
| CTEG跨任务迁移无效果 | 中 | AWE MemoryStorage已验证单任务内记忆有效；跨任务泛化无验证 | Phase 1先验证同类型内迁移 |
| D-CVE仍为0% | 中 | 当前确实所有模型为0%；但如果DPM能正确识别WAF并触发绕过策略 | 即使5%也是突破 |
| 动态伸缩在原型中不可靠 | 中 | Cochise(576行)证明极简可行；CPA证明集中协调可行 | 先手动B→自动B逐步过渡 |
| Token成本超预算 | 低 | Cochise报告AD域攻陷<$2；AWE报告98%成本降低 | LiteLLM+低成本模型用于开发 |
| Web场景通用性不足（漏洞类型覆盖） | 低 | XBOW覆盖26种漏洞类型，PACEBench覆盖递进场景，CustomDef覆盖防御类型——三者互补 | 三个基准覆盖Web全谱，无需额外域 |

---

## 七、代码实施计划

代码实施计划独立于本论文框架文档，详见：[DARWIN_implementation_plan.md](DARWIN_implementation_plan.md)
