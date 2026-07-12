# DARWIN Cloud K8S Benchmark 测试结果 (Round 2)

日期: 2026-07-08 ~ 2026-07-11 (已完成)

## 总览

| 场景 | 结果 | 尝试 | Flag | Steps | 诊断 |
|------|------|------|------|-------|------|
| CLOUD-10 | ✅ PASS | 1 | `flag{cloud-10-7e5e9f4272067ea0}` | 22 | X-Forwarded-For 绕过，单步 HTTP header exploit |
| CLOUD-11 | ❌ FAILED | 3 | - | 9-12 | OIDC 多步链 (4-5步)，Solo 无法完成 |
| CLOUD-12 | ✅ PASS* | 1 | `flag{cloud-12-step2-cross-account}` | 11 | ⚠️ S3 flag 硬编码(已修复)；DARWIN 完成 AssumeRole→S3 链 |
| CLOUD-14 | ❌ FAILED | 3 | - | - | PassRole 链(2步)，plan loop 未执行利用任务 |
| CLOUD-15 | ❌ FAILED | 3 | - | - | SCP bypass(2步)，利用任务未被优先执行 |

**总成功率: 2/5 (40%)**，但 CLOUD-12 的 flag 为硬编码默认值。

## DARWIN 框架修复 (4 个)

1. **`curl_get` headers dict 支持** (`recon_server.py`) — LLM function calling 传入 dict 时不再崩溃
2. **`ssh_key_exec` key_path 默认值** (`attack_server.py`) — 添加 `~/.ssh/id_rsa` 默认值
3. **`gobuster_dir` 超时优化** (`recon_server.py`) — 90s→45s，加速 bootstrap
4. **`ssh_key_exec` user 参数默认值** (`attack_server.py`) — 修复 Template format error

## Benchmark 基础设施修复 (2 个)

5. **CLOUD-12 S3 硬编码 FLAG** (`cross-account-trust/docker-compose.yml`) — `$CVE_FLAG` 替代硬编码
6. **CLOUD-14 Lambda 硬编码 FLAG** (`passrole-abuse/docker-compose.yml`) — `$CVE_FLAG` 替代硬编码

## 系统性发现 (根因分析)

### 核心问题：Solo 模式无法执行云原生多步 API 链

| 场景 | 攻击步数 | LLM 置信度 | 实际完成 | 根本原因 |
|------|----------|-----------|---------|---------|
| CLOUD-10 | 1 | - | ✅ 22 steps | 单步 HTTP header 注入 — simple |
| CLOUD-11 | 4-5 | 80-90% | ❌ 9-12 steps | OIDC→JWT→AssumeRole 链太长 |
| CLOUD-12 | 3-4 | 80-90% | ✅ 11 steps | AssumeRole 链成功(但 flag 硬编码) |
| CLOUD-14 | 2 | 70-95% | ❌ - | Plan loop 优先执行无关任务 |
| CLOUD-15 | 2 | 85-95% | ❌ - | 利用任务 task-scp-step2 从未执行 |

**所有 5 个场景的 LLM analyze 阶段都正确识别了攻击路径 (70-95% 置信度)！问题不在分析能力，在编排执行。**

### 三大故障模式

1. **Plan-driven loop 任务优先级错误**：利用任务 (http_post/send_payload) 被排到侦察任务 (gobuster/curl_get) 和 SSH 爆破之后
2. **失败任务阻塞循环**：一个无关任务失败后，loop 终止而非跳过继续尝试下一个
3. **VULN_TOOL_MAP 覆盖不足**：cloud 原生漏洞类型 (OIDC/IAM/PassRole/SCP bypass) 不在映射表中，systematic pass 跳过或使用错误工具
