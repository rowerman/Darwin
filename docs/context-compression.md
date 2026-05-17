# DARWIN 上下文压缩机制

## 设计来源

来自 Cochise planner.py 参考模式：持久化 LLM 对话 + 知识累积 + 历史压缩。设计文档 `plan/DARWIN_framework.md` 第107行明确引用了这个模式。

## 配置文件

`config/darwin.yaml` 中定义了两个关键参数：
- `max_context_tokens: 180000` — 视为 100% 上下文负载的 token 数
- `context_compression_threshold: 0.4` — 触发压缩的负载比例（0.4 = 40%，即约 72K tokens）

## 实现文件

- `darwin/utils/llm.py` — 核心压缩引擎（`LLMSession.compress()`, `_serialize_messages()`, `_fallback_truncate()`, `SYSTEM_PROMPT_COMPRESS`）
- `darwin/orchestrator.py` — 编排器端（`_maybe_compress()`, `_tokens_exceeded()` 更新，`__init__` 中的 `max_context_tokens` 和 `compression_threshold` 参数）
- `darwin/sub_agents/base.py` — 子代理端（`BaseSubAgent._maybe_compress()`, `_should_continue()` 更新）

## 触发条件

`LLMSession.context_load >= compression_threshold` 且 conversation_history 中消息数 > keep_recent + 2 时才执行压缩。`context_load` = token_count / max_context_tokens。

## 压缩流程

```
conversation_history
  ├── [旧消息1, 旧消息2, ..., 旧消息N-6]  ← 压缩对象
  └── [最近6条消息]                      ← 完整保留
              ↓
  旧消息通过 _serialize_messages() 序列化为紧凑文本
  （处理 tool_calls 和 tool_result 两种特殊消息格式）
              ↓
  专用 LLM 调用（使用 SYSTEM_PROMPT_COMPRESS 作为 system prompt）
              ↓
  生成结构化摘要，包含5类信息：
  1. Key Facts Discovered（主机、IP、端口、服务、端点、参数、凭证）
  2. Actions Taken（工具、命令、payload 及其结果）
  3. Current State（活跃会话、已捕获 flag、已检测防御、已知漏洞）
  4. Failed Attempts（尝试了什么、为什么失败，避免重复）
  5. Defense Intelligence（WAF/IDS/蜜罐行为）
              ↓
  conversation_history
  ├── [system: [COMPRESSED CONTEXT — X messages summarized] + 摘要]  ← 单条消息替代 N 条
  └── [最近6条消息]                                                   ← 完整保留
```

压缩后 `_compressed_count += 1`，返回节省的 token 数。

## 容错设计

如果压缩 LLM 调用抛出异常，自动降级为 `_fallback_truncate()`：按关键词（flag, port, service, endpoint, vuln, waf, host, ip, 192., 10., sql, xss, cmdi, error, blocked, 403, 401, 200）从旧消息中提取包含这些关键词的行，保留最多 40 行。确保 LLM 不可用时压缩机制不会导致上下文完全丢失。

## 调用点

| 位置 | 调用时机 | 方法 |
|------|---------|------|
| `Orchestrator._analyze_phase()` | `generate()` 调用前 | `_maybe_compress()` |
| `Orchestrator._defense_bypass_attempt()` | `generate()` 调用前（reset 后） | `_maybe_compress()` |
| `Orchestrator._exploit_phase()` | `_tokens_exceeded()` 返回 True 前 | `_tokens_exceeded()` → `_maybe_compress()` |
| `BaseSubAgent.run()` | `_generate_plan()` 前 | `_maybe_compress()` |
| `BaseSubAgent.run()` | 每次 replanning（`_replan_after_failure`/`_update_plan`）前 | `_maybe_compress()` |
| `BaseSubAgent._should_continue()` | `budget.tokens_exceeded()` 返回 True 前 | `_maybe_compress()` → 仍超限才终止为 `BUDGET_EXHAUSTED` |

## 与 Phase 切换的关系

阶段边界（recon → analyze → exploit → bypass）仍保留 `reset()` 清空 LLM 对话历史，因为每个阶段使用不同的 system prompt（分析师 vs 绕过专家 vs 编排者）。压缩处理的是**阶段内**的工具调用链增长——例如 bypass 阶段中反复尝试多种绕过策略，或者子代理 Plan→Act→Observe 循环中累积的大量工具调用结果。

## 与 DKG / CTEG 的分工

```
LLM conversation_history  ← compress() 管理（阶段内工具调用链上下文）
DKG                       ← 任务内结构化状态（主机/服务/漏洞/flag），跨 phase 传递
CTEG                      ← 跨任务抽象模式（绕过/利用），commit_task()/get_suggestions()
```

三者各司其职，不重叠：LLM 对话负责阶段内的推理连贯性，DKG 负责跨阶段的结构化事实传递，CTEG 负责跨任务的经验迁移。
