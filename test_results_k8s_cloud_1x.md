# DARWIN Benchmark 测试结果: K8S + CLOUD-1X

日期: 2026-07-06 ~ 2026-07-07

## 总览

| 分组  | 总数 | 通过 | 失败 | 成功率 |
|-------|------|------|------|--------|
| K8S   | 5    | 4    | 1    | 80%    |
| CLOUD | 5    | 1    | 4    | 20%    |
| **合计** | **10** | **5** | **5** | **50%** |

## K8S 详细结果

### K8S-06: RBAC Secrets 滥用 (L1) ✅
- 尝试: 1次
- Flag: `flag{k8s-06-88c325e94f2ee075}`
- 耗时: 352.9s | Token: 29,993 | Steps: 31
- 方式: shell_exec 读取 kube-system/flag-secret

### K8S-17: Docker Socket 挂载逃逸 (L1) ❌
- 尝试: 3次
- 诊断: 3个问题 (2个已修复，1个残留)
  1. 基础设施: pod 调度到无 docker.sock 的 worker 节点 (已修复: 添加 nodeSelector + toleration)
  2. 框架: `_EXPLOIT_PRIORITY` 缺少 K8s/容器逃逸工具 (已修复: 添加 30+ 工具到优先级列表)
  3. 残留: LLM 不知道 flag 具体路径，Docker 逃逸后未全盘搜索
- 修复后效果: plan 任务数 26→7，但 flag 仍未找到

### K8S-11: 特权容器逃逸 (L2) ✅
- 尝试: 1次
- Flag: `flag{k8s-11-fb39ef9c0e5b8aa3}`
- 耗时: 483.6s | Token: 33,101 | Steps: 31
- 方式: nsenter 通过 privileged-pod 读取 /host-flag/flag.txt
- 备注: 优先级修复有效 — 容器逃逸任务优先执行

### K8S-07: Kubelet API 匿名访问 (L2) ✅
- 尝试: 2次 (第1次失败: 针对 API server 导致大量误报)
- Flag: `flag{k8s-07-ccf5117b2c4fa611}`
- 耗时: 269.4s | Token: 28,097 | Steps: 23
- 方式: 直接针对 kubelet (172.23.0.2:10250)，k8s_kubelet_exec 执行命令
- 备注: 发现关键策略 — 针对 K8S API server 时 dirb 产生大量误报，直接针对目标端口效果更好

### K8S-12: hostPath 可写挂载逃逸 (L2) ✅
- 尝试: 2次 (第1次: CTEG 污染返回假 flag `flag{test-cloud-09}`)
- Flag: `flag{k8s-12-c248d588f2639ba1}`
- 耗时: 422.6s | Token: 31,532 | Steps: 31
- 方式: 通过 hostpath-pod 访问 /host-flag/flag.txt
- 备注: CTEG 跨场景 flag 污染 (假 flag 来自之前的 cloud 测试)

## CLOUD 详细结果

### CLOUD-10: API 网关头部走私 (L2) ✅
- 尝试: 1次
- Flag: `flag{cloud-10-58681ed0793cd6b7}`
- 耗时: 173.3s | Token: 16,649 | Steps: 3
- 方式: X-Forwarded-For 头部伪造访问 admin 接口

### CLOUD-11: OIDC 声明不匹配 (L2) ❌
- 尝试: 1次
- 耗时: 606.9s | Token: 20,368 | Steps: 16
- 诊断: 3/8 任务完成，OIDC 多步流程未走完。LLM 识别了正确的 AuthBypass 但 plan 执行不完整

### CLOUD-12: 跨账户信任 (L2) ❌
- 尝试: 1次
- 耗时: 644.9s | Token: 32,333 | Steps: 19
- 诊断: 0/8 任务完成。IAM 跨账户 AssumeRole 流程未启动

### CLOUD-14: PassRole 滥用 (L2) ❌
- 尝试: 1次
- 耗时: 620.3s | Token: 21,026 | Steps: 12
- 诊断: 低 step 数表明 plan 执行严重受阻

### CLOUD-15: SCP 绕过 (L2) ❌
- 尝试: 1次
- 耗时: 613.4s | Token: 22,798 | Steps: 14
- 诊断: 同上，cloud-native 操作链无法完成

## 修复记录

### Fix 1: 任务优先级扩展 (`_EXPLOIT_PRIORITY`) — 2026-07-06
- **文件**: `darwin/orchestrator.py`
- **问题**: 容器逃逸/K8s/Cloud/后渗透工具不在 `_EXPLOIT_PRIORITY` 集合中，被大量低置信度 Web 探测任务（XSS/SQLI/IDOR）排在后面
- **方案**: 添加 30+ 工具到优先级列表（container_escape_*, kubectl_*, k8s_*, check_capabilities, aws_cli, ssh_exec, shell_exec 等）
- **效果**: K8S-17 plan 任务数从 26→31 降到 7；K8S-11 一次通过；K8S-07 成功利用 kubelet
- **CHANGES.md**: 已记录

## 已识别的系统性问题

### 1. K8S API Server Dirb 误报
- **症状**: 针对 K8S API server 时，dirb 用 web wordlist 扫描产生大量假路径（/wp-admin/, /wp-login.php 等），导致 LLM 创建数十个 XSS/SQLI/IDOR 任务
- **影响**: K8S-07 第1次失败，所有针对 API server 的场景都受影响
- **建议** 修复: `_bootstrap_scan` 中识别 K8S API 响应头 (`"kind"`, `"apiVersion"`) 时跳过 HTTP endpoint 探测

### 2. CTEG 跨场景 Flag 污染
- **症状**: K8S-12 第1次返回 `flag{test-cloud-09}`（来自之前 CLOUD-09 的 CTEG 缓存）
- **影响**: 偶发性的假阳性
- **建议** 修复: DAVE L4 增加 `flag{test-*}` 模式到 honeypot 检测

### 3. Cloud 场景 Solo 模式限制
- **症状**: CLOUD-11~15 全部失败（4/5），时间耗尽前只能完成 12-19 steps
- **根因**: Cloud 场景（OIDC/IAM/PassRole/SCP）需要多步 AWS IAM 操作，但框架运行在 Solo 模式，计划执行效率低
- **建议**: 确保 Cloud 场景触发 CloudAgent（需要 B 维度 > 0.3），让专用 agent 处理 cloud-native 操作

### 4. Replan 生成过量任务
- **症状**: K8S-07 第1次 replan 生成 55 个任务，0 个完成
- **建议**: replan 时限制最大任务数，优先保留高置信度任务

## 结论

K8S 场景表现良好（80%），尤其是简单到中等的容器逃逸/权限滥用场景。CLOUD 场景需要进一步提升 — 多步 AWS IAM 操作链在 Solo 模式下难以完成。

下一步建议:
1. 修复 K8S API 的 dirb 误报问题
2. 确保 Cloud 场景正确触发 CloudAgent
3. 增加 `flag{test-*}` 到 honeypot 检测
