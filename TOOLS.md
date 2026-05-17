# DARWIN 安全工具配置清单

## 一、系统级工具

当前已集成的工具（在 `darwin/tools/recon_server.py` / `attack_server.py` 中注册）：

| 工具 | 类别 | 状态 |
|------|------|------|
| nmap | 端口扫描 | 需要安装 |
| dirb | 目录爆破 | 需要安装 |
| whatweb | 技术指纹 | 需要安装 |
| curl | HTTP探测 | 需要安装 |
| sqlmap | SQL注入 | 需要安装 |
| ffuf | Web Fuzzing | 需要安装 |
| ssh/sshpass | 横向移动 | 需要安装 |

### 一键安装

```bash
sudo apt-get install -y \
    nmap dirb whatweb curl sqlmap ffuf sshpass
```

### 推荐加装的系统工具

以下工具 DARWIN 目前未注册但渗透测试中常用，按优先级排列：

#### P0 — 安装后立即可用（已有注册代码或工具通用于多种场景）

```bash
# 网络工具
sudo apt-get install -y netcat-openbsd masscan

# Web 扫描
sudo apt-get install -y nikto wfuzz gobuster

# 密码/认证
sudo apt-get install -y hydra john

# 漏洞搜索（离线 exploit-db）
sudo apt-get install -y go-exploitdb
# 或者 git 安装 searchsploit:
#   git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
#   ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
#   searchsploit -u

# XSS 专项 — 都是 Go/独立工具，不能 pip install
# dalfox: XSS 扫描
go install github.com/hahwul/dalfox/v2@latest
# xsstrike: XSS 检测 (Python，需 git clone)
git clone https://github.com/s0md3v/XSStrike.git /opt/xsstrike
ln -s /opt/xsstrike/xsstrike.py /usr/local/bin/xsstrike
```

#### P1 — 特定漏洞类型专用

```bash
# WordPress 扫描 (Ruby gem 安装)
sudo apt-get install -y ruby-dev
sudo gem install wpscan

# SSTI 检测 (git clone，不在 PyPI)
git clone https://github.com/epinna/tplmap.git /opt/tplmap
ln -s /opt/tplmap/tplmap.py /usr/local/bin/tplmap
pip install -r /opt/tplmap/requirements.txt

# HTTP 参数发现
pip install arjun

# 子域名枚举
GO111MODULE=on go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

#### P2 — 高级场景可选

```bash
# 密码破解加速
sudo apt-get install -y hashcat

# SMB 枚举 (内网渗透) — enum4linux 不在 apt 里，用 cargo/git 安装
# 方案 A: smbmap (apt 直接可用)
sudo apt-get install -y smbmap
# 方案 B: enum4linux-ng (Python rewrite)
git clone https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng
pip install -r /opt/enum4linux-ng/requirements.txt
ln -s /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux

# SNMP 扫描
sudo apt-get install -y snmp onesixtyone

# Metasploit (大型框架，P2 可选 — DARWIN Phase 1 不需要)
# Docker Hub 不可达时的备选:
#   方案 A: 国内镜像 docker pull docker.m.daocloud.io/metasploitframework/metasploit-framework
#   方案 B: 源码编译 https://docs.metasploit.com/docs/development/get-started/setting-up-a-metasploit-development-environment.html
# 建议: Phase 1 Pilot 跳过此项，不影响核心功能
```

---

## 二、MCP 工具

MCP 工具通过 `config/mcp_servers.yaml` 配置，在 DARWIN 启动时自动连接。每个 server 的 `enabled` 设为 `true` 即可启用。

### 前置要求

```bash
# MCP servers 通常通过 npx 运行，需要 Node.js
sudo apt-get install -y nodejs npm

# 或使用 uvx (Python MCP servers)
pip install uv
```

### 推荐启用的 MCP Server

#### 1. 文件系统 — 读写 payload 文件、保存报告

```yaml
servers:
  filesystem:
    command: "npx"
    args:
      - "-y"
      - "@anthropic/mcp-server-filesystem"
      - "/tmp/darwin"
      - "/home/kianabin/Darwin/experiment_results"
    env: {}
    enabled: true
```

**用途**：攻击过程中读写 payload 文件、保存中间结果、生成报告。

#### 2. Web 搜索 — 查 CVE、漏洞利用技术

```yaml
  brave-search:
    command: "npx"
    args:
      - "-y"
      - "@anthropic/mcp-server-brave-search"
    env:
      BRAVE_API_KEY: "${BRAVE_API_KEY}"   # 需要免费注册: https://brave.com/search/api/
    enabled: false
```

**用途**：遇到未知 CMS/WAF 时搜索漏洞公告和绕过技术。需要先注册 Brave Search API（免费额度够用）。

#### 3. Puppeteer 浏览器 — 补充 DAVE L2 验证

```yaml
  puppeteer:
    command: "npx"
    args:
      - "-y"
      - "@anthropic/mcp-server-puppeteer"
    env: {}
    enabled: false
```

**用途**：JavaScript 执行验证、SPA 页面抓取、无头浏览器截图。与 DAVE 的 Playwright L2 验证互补。

#### 4. GitHub — 搜索 PoC 和漏洞利用代码

```yaml
  github:
    command: "npx"
    args:
      - "-y"
      - "@anthropic/mcp-server-github"
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_TOKEN}"  # https://github.com/settings/tokens
    enabled: false
```

**用途**：搜索 CVE PoC、漏洞利用脚本、WAF 绕过 payload。

#### 5. 记忆/知识图谱 — 跨会话持久化经验

```yaml
  memory:
    command: "npx"
    args:
      - "-y"
      - "@anthropic/mcp-server-memory"
    env: {}
    enabled: false
```

**用途**：与 DARWIN 内置的 CTEG 互补，提供 LLM 原生的跨会话记忆。

#### 6. 顺序思考 — 复杂攻击链推理

```yaml
  sequential-thinking:
    command: "npx"
    args:
      - "-y"
      - "@anthropic/mcp-server-sequential-thinking"
    env: {}
    enabled: false
```

**用途**：多步攻击链规划、复杂漏洞利用路径推理。

---

## 三、完整 `config/mcp_servers.yaml` 模板

把以下内容覆盖 `config/mcp_servers.yaml`，需要哪个就把 `enabled` 设为 `true`：

```yaml
# MCP Server 配置 — DARWIN 启动时自动连接
# 前置: sudo apt-get install -y nodejs npm

servers:

  # 文件系统 — 读写 payload、保存报告
  filesystem:
    command: "npx"
    args:
      - "-y"
      - "@anthropic/mcp-server-filesystem"
      - "/tmp/darwin"
      - "experiment_results"
    env: {}
    enabled: false

  # Web 搜索 — CVE 查询、漏洞技术搜索
  brave-search:
    command: "npx"
    args:
      - "-y"
      - "@anthropic/mcp-server-brave-search"
    env:
      BRAVE_API_KEY: "${BRAVE_API_KEY}"
    enabled: false

  # 无头浏览器 — JS 执行验证、SPA 抓取
  puppeteer:
    command: "npx"
    args:
      - "-y"
      - "@anthropic/mcp-server-puppeteer"
    env: {}
    enabled: false

  # GitHub — 搜索 PoC、exploit 代码
  github:
    command: "npx"
    args:
      - "-y"
      - "@anthropic/mcp-server-github"
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_TOKEN}"
    enabled: false

  # 跨会话记忆
  memory:
    command: "npx"
    args:
      - "-y"
      - "@anthropic/mcp-server-memory"
    env: {}
    enabled: false

  # 复杂推理
  sequential-thinking:
    command: "npx"
    args:
      - "-y"
      - "@anthropic/mcp-server-sequential-thinking"
    env: {}
    enabled: false
```

---

## 四、Pilot 最小配置（立即可测）

```bash
# 1. 安装系统工具
sudo apt-get install -y nmap dirb whatweb curl sqlmap ffuf sshpass

# 2. 启动测试目标
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(b'flag{test_2026}' if 'flag' in self.path else b'<form action=/login><input name=user>')
HTTPServer(('', 8080), H).serve_forever()
" &

# 3. 运行 DARWIN
source venv/bin/activate
python3 smoke_test.py http://localhost:8080
```

这套配置跑通后，再按需逐一启用 MCP server 并加装 P0/P1 系统工具。
