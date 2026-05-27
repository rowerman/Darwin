# GOAD & Kubernetes Goat Benchmark 清单

只聚焦两个 Benchmark：GOAD（Windows AD）和 Kubernetes Goat（K8s/云原生）。

---

## 一、环境配置清单

### 1. GOAD（已 clone 则可跳过 clone 步骤）

如果已 clone，直接从步骤 2 开始。

| 步骤 | 命令/操作 | 说明 |
|------|----------|------|
| 1 | `git clone https://github.com/Orange-Cyberdefense/GOAD.git && cd GOAD` | 已 clone 则跳过 |
| 2 | `python3 -m venv .venv && source .venv/bin/activate` | Python 虚拟环境 |
| 3 | `pip install ansible-core==2.12.6 pywinrm` | Ansible + WinRM |
| 4 | `ansible-galaxy install -r requirements.yml` | Ansible 依赖角色 |
| 5 | **选择 Provider** | 三选一 |

**Provider 选项：**

| Provider | 额外依赖 | 硬件要求 |
|----------|---------|---------|
| VirtualBox | VirtualBox 7.0 + Vagrant 2.2.19+ + `vagrant-vbguest` 等插件 | 8+ cores, 24-32 GB RAM, 115 GB+ SSD |
| VMware | VMware Workstation/Fusion + Vagrant + `vagrant-vmware-desktop` | 同上 |
| AWS | Terraform + AWS CLI + AWS 账号 | 按需付费 |

| 步骤 | 命令/操作 | 说明 |
|------|----------|------|
| 6 | `./goad.sh -t check -l GOAD -p virtualbox -m local` | 检查依赖 |
| 7 | `./goad.sh -t install -l GOAD -p virtualbox -m local` | 安装（提供 VM + Ansible 配置），约 1-2 小时 |

**可选：** 如果需要轻量化版本，可使用 `GOAD-Light`（6 cores/20 GB RAM/90 GB）或 `GOAD-Mini`（4 cores/16 GB RAM/60 GB）。

GOAD 共有 5 台 Windows VM，部署 3 个域 2 个森林，默认子网 `192.168.56.0/24`，Windows Server 评估版（180 天试用）。

### 2. Kubernetes Goat

| 步骤 | 命令/操作 | 说明 |
|------|----------|------|
| 1 | 安装 Docker | 运行时 |
| 2 | 安装 kubectl | K8s CLI |
| 3 | 安装 KIND | `go install sigs.k8s.io/kind@latest` 或直接二进制下载 |
| 4 | `git clone https://github.com/madhuakula/kubernetes-goat.git && cd kubernetes-goat` | Clone 仓库 |
| 5 | `bash setup-kubernetes-goat.sh` | 自动部署 KIND 集群 + 22 个场景 |
| 6 | `bash access-kubernetes-goat.sh` | 暴露 Playground 到 `http://127.0.0.1:1234` |

硬件要求较低（单机 Docker 即可），约 30 分钟内完成。22 个场景覆盖 OWASP Kubernetes Top 10 + MITRE ATT&CK 映射。

---

## 二、相关论文清单

### 使用 GOAD 进行测试验证的论文

| # | 论文 | 来源 | 关键结果 |
|---|------|------|----------|
| 1 | **"Can LLMs Hack Enterprise Networks? Autonomous Assumed Breach Penetration-Testing Active Directory Networks"** (Happe & Cito, 2025) | ACM TOSEM, arXiv:2502.04227 | Cochise 框架，首个全自主 LLM 攻破 GOAD。评估 5 个 LLM（GPT-4o, DeepSeek-V3, Gemini-2.5-Flash, o1-preview, Qwen3）。**7 个域账户被攻破**，平均 **$17.47/账户**。35.9% 无效命令率。代码、traces、logs 全部开源。**DARWIN 可直接对比的论文。** |
| 2 | **"Cochise: A Reference Harness for Autonomous Penetration Testing"** (Happe & Cito, 2026) | arXiv:2605.11671 | Cochise 的后续 refinement，精简到 597 LOC 的参考框架，定位为 reusable experimental infrastructure 而非 SOTA agent。提供 standardized 对比方法。 |
| 3 | **"Can LLMs Hack Enterprise Networks? — RCR Report"** (2025) | arXiv:2603.01789 | Cochise 的复现性验证报告，确认论文结果可复现。 |
| 4 | **NodeZero vs GOAD 技术报告** (Horizon3.ai, 2025) | 工业界（非学术论文，但结果被行业广泛引用） | NodeZero **14 分钟**完全攻克 GOAD（人类 12-16 小时）。首次 AI 完成多域全主机妥协。已被 NSA CAPT 项目采用。 |

**附加参考论文：**

| # | 论文 | 来源 | 内容 |
|---|------|------|------|
| 5 | **"Penetration Testing in Active Directory"** (Fougias, 2025) | University of Piraeus MSc Thesis | 使用 GOAD MINILAB 覆盖完整 AD 攻击链（Pass-the-Hash, DCSync, Golden/Silver Ticket, ADCS, Kerberoasting），全 MITRE ATT&CK 映射。 |
| 6 | **CMU 研究** (2025) | Carnegie Mellon University | 证明 GPT-4o/Gemini 2.5 Pro/Sonnet 3.7 无法可靠执行多主机入侵（捕获不到 30% 攻击图状态），凸显 GOAD 的难度和 benchmark 价值。 |

### 使用 Kubernetes Goat 进行测试验证的论文

**目前没有找到任何学术论文直接使用 Kubernetes Goat 作为 LLM 或自动化渗透测试的 Benchmark。** 这个领域存在明确的空白。

Kubernetes Goat 目前主要用于：
- 安全培训/教学
- 安全工具能力演示（Falco, Tetragon, Kyverno 等）
- 个人练习和 CTF

这意味着 **DARWIN 有机会成为第一个使用 Kubernetes Goat 进行系统化 LLM pentest 评估的框架**，可以在这个方向上建立先发优势。

### 相关但不直接使用 K8s Goat 的 K8s/Cloud 论文

| # | 论文 | 来源 | 内容 |
|---|------|------|------|
| 7 | **"Comparative Analysis of eBPF-Based Runtime Security Monitoring Tools on Kubernetes"** (Syairozi & Arizal, 2025) | SciTePress RITECH | 对比 Falco/Tetragon/Tracee 在 OWASP K8s Top 10 场景下的检测性能（检测率 100%，零误报）。场景与 K8s Goat 高度重叠，可用于指导 DARWIN 的评估指标设计。 |
| 8 | **"Brewing the Kubernetes Storm Center"** (Roedig & Callaghan, 2024) | KubeCon EU | "Honeyclusters" 方法论：基于威胁模型生成带 trip-wire 的 K8s 环境并暴露于真实攻击以量化攻击路径。可参考其 benchmark 生成方法论。 |
| 9 | **"Offensive Strategies for Identifying Cloud Security Weaknesses in Multi-Cloud Environments"** (Guliev & Tiihonen, 2025) | Kristianstad University, IKEA 合作 | 多云自动化 pentest 框架（AWS/Azure/GCP），基于 AttackForge 测试套件。方法论可借鉴。 |
| 10 | **"CloudLens: Modeling and Detecting Cloud Security Vulnerabilities"** (2024) | arXiv:2402.10985 | AI Planning 驱动的云 IAM 攻击路径发现。 |

---

## 三、关键对比数据（DARWIN vs 现有工作）

### GOAD 场景

| 系统 | 时间 | 账户妥协数 | 全域妥协 | 代码开源 |
|------|------|-----------|---------|---------|
| Cochise (GPT-4o) | 未报告确切时间 | 7 | 未完全 | ✅ |
| Cochise (o1-preview) | 未报告确切时间 | 7 | 未完全 | ✅ |
| Cochise (Gemini-3-Flash, 2026) | 未报告 | 全部 | ✅ (€2) | ✅ |
| NodeZero | 14 分钟 | 全部 | ✅ | ❌ |
| **DARWIN** | **TBD** | **TBD** | **TBD** | ✅ |

### K8s Goat 场景

| 系统 | 场景数 | 自动化程度 | 开源 |
|------|--------|-----------|------|
| **DARWIN** | **TBD** | **全自主 LLM** | ✅ |
| (无其他公开的 LLM pentest 结果) | - | - | - |
