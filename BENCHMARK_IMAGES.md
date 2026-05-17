# PACEBench / XBOW — Docker 镜像与部署清单

## 一、PACEBench（32 挑战）

### 架构

```
PACEBench 框架服务器
  ├─ 管理挑战生命周期（启动/停止 Docker 容器）
  ├─ 通过 POST /chat 向 Agent 发送挑战 prompt
  ├─ 通过 GET /result 接收 Agent 提交的 flag
  └─ 每个挑战是一个独立 Docker 容器，暴露 HTTP 端口
```

### PACEBench 框架本身

| 组件 | 镜像/来源 | 说明 |
|------|----------|------|
| PACEBench Server | `paper_analysis/PACEBench/PACEbench/` 源码构建 | FastAPI 服务器，管理挑战调度和 Agent 通信 |
| PACEBench Docker Manager | 同上 `docker_manager.py` | 调用 `docker compose` 启停挑战容器 |

### 挑战分类与所需镜像

#### A-CVE: 单主机单漏洞（17 个）

每个挑战是一个独立 Docker 容器，内含一个已知 CVE 的漏洞应用。

| CVE 示例 | 技术栈 | 漏洞类型 |
|----------|--------|---------|
| CVE-2022-28512 | PHP/Apache | SQLi |
| CVE-2021-41773 | Apache HTTPD | 路径遍历 |
| CVE-2022-22965 | Java/Spring | RCE (Spring4Shell) |
| CVE-2021-44228 | Java | RCE (Log4Shell) |
| CVE-2022-26134 | Java/Confluence | OGNL 注入 |
| CVE-2022-1388 | Python | 认证绕过 |
| CVE-2022-41082 | Exchange | RCE (ProxyNotShell) |
| CVE-2021-26855 | Exchange | SSRF (ProxyLogon) |
| CVE-2019-0708 | Windows | RCE (BlueKeep) — 非 Web |
| CVE-2022-30190 | Windows | RCE (Follina) |
| CVE-2022-22963 | Java/Spring | RCE (Spring Cloud) |
| CVE-2021-21972 | vCenter | RCE |
| CVE-2022-0847 | Linux 内核 | 提权 (DirtyPipe) — 非 Web |
| +4 其他 CVE | 混合 | Web/系统漏洞 |

**所需基础镜像**（每个 CVE 独立构建）:
- `pacebench/a-cve-*` × 17（本地 Dockerfile 构建）
- 基础系统镜像: `ubuntu:22.04`, `python:3.10-slim`, `php:8.1-apache`, `tomcat:9`

#### B-CVE: 多主机场景（7 个）

每个挑战包含多个互联容器，模拟内网横向移动。

| 挑战 | 容器数 | 场景 |
|------|--------|------|
| B-CVE-01 | 3 | Web 服务器 + 数据库 + 内网文件服务器 |
| B-CVE-02 | 3 | DMZ Web + 内网应用服务器 + AD 域控 |
| B-CVE-03 | 2 | 外网 API + 内网数据库 |
| B-CVE-04 | 4 | 多层网络: 外网 → 中间层 → 内网核心 |
| B-CVE-05 | 3 | 容器化微服务 + 共享存储 |
| B-CVE-06 | 2 | VPN 网关 + 内网服务 |
| B-CVE-07 | 3 | 负载均衡 + 双应用服务器 + 后端 DB |

**所需镜像**: 每个挑战一个 `docker-compose.yml`，使用基础镜像（`ubuntu:22.04`, `python:3.10`, `mysql:8`, `postgres:15`）加自定义漏洞应用。

#### C-CVE: 链式利用（5 个）

| 挑战 | 攻击链 |
|------|--------|
| C-CVE-01 | SSRF → 内网 RCE → 提权 |
| C-CVE-02 | XSS → 会话劫持 → 认证绕过 → SQLi |
| C-CVE-03 | LFI → 日志污染 → RCE |
| C-CVE-04 | 文件上传 → 路径遍历 → RCE |
| C-CVE-05 | 反序列化 → RCE → 横向移动 |

**所需镜像**: 同 B-CVE，多容器 Docker Compose。

#### D-CVE: WAF 防御场景（3 个）

| 挑战 | WAF | 基础漏洞 |
|------|-----|---------|
| D-OWASP-WAF | ModSecurity + OWASP CRS | SQLi |
| D-Cloudflare | Cloudflare 风格 WAF（本地模拟） | XSS |
| D-Naxsi | Naxsi WAF | CMDi |

**所需镜像**:
- `owasp/modsecurity-crs:3.3`（ModSecurity + CRS）
- `nginx:1.24-alpine` + Naxsi 模块
- 自定义 Cloudflare 模拟层

### PACEBench 镜像汇总

| 类型 | 数量 | 构建方式 |
|------|------|---------|
| A-CVE 单漏洞镜像 | 17 | 各自 Dockerfile，基于 python/php/tomcat |
| B-CVE 多容器场景 | 7 × 2~4 容器 | docker-compose.yml，复用基础镜像 |
| C-CVE 链式场景 | 5 × 2~3 容器 | docker-compose.yml，复用基础镜像 |
| D-CVE WAF 场景 | 3 | 基础漏洞镜像 + WAF 反向代理 |
| **总挑战** | **32** | |

---

## 二、XBOW（104 挑战）

### 架构

```
每个挑战 = 一个目录
  ├── docker-compose.yml    # 容器编排
  ├── challenge.json         # 挑战描述、flag 验证规则
  ├── README.md              # 挑战说明（给 Agent 的任务描述）
  └── src/                   # 漏洞应用源码
```

XBOW adapter 通过 `docker compose up -d` 启动挑战，暴露端口后 Agent 访问测试。

### 漏洞类型分布（26 类）

| 类型 | 数量 | 典型技术栈 |
|------|------|-----------|
| XSS (Cross-Site Scripting) | ~12 | PHP/Node.js/Python |
| SQLi (SQL Injection) | ~10 | PHP/MySQL, Python/SQLite |
| SSTI (Server-Side Template Injection) | ~8 | Python/Jinja2, Node.js/EJS, Java/Velocity |
| CMDi (Command Injection) | ~8 | Python, PHP, Node.js |
| SSRF (Server-Side Request Forgery) | ~6 | Python, Node.js, PHP |
| XXE (XML External Entity) | ~4 | Java, PHP |
| LFI/RFI (Local/Remote File Inclusion) | ~5 | PHP |
| IDOR (Insecure Direct Object Reference) | ~5 | Python, Node.js |
| CSRF (Cross-Site Request Forgery) | ~4 | PHP, Python |
| JWT 攻击 | ~3 | Python, Node.js |
| 反序列化 | ~3 | Java, Python, PHP |
| 文件上传 | ~3 | PHP, Python |
| LDAP 注入 | ~2 | Java, PHP |
| XPath 注入 | ~2 | PHP, Java |
| NoSQL 注入 | ~2 | Node.js/MongoDB |
| OAuth 漏洞 | ~2 | Python, Node.js |
| Race Condition | ~2 | Python, Node.js |
| HTTP Request Smuggling | ~2 | Node.js, Python |
| GraphQL 注入 | ~2 | Node.js |
| WebSocket 漏洞 | ~2 | Node.js |
| Cache Poisoning | ~2 | Python, Node.js |
| Prototype Pollution | ~2 | Node.js |
| Open Redirect | ~3 | PHP, Python |
| 信息泄露 | ~3 | 混合 |
| 认证绕过 | ~3 | 混合 |
| 其他 Web 漏洞 | ~4 | 混合 |

### XBOW 所需基础镜像

| 镜像 | 用途 | 覆盖挑战数 |
|------|------|-----------|
| `php:8.1-apache` | PHP Web 应用 | ~30 |
| `python:3.10-slim` | Python/Flask/Django 应用 | ~25 |
| `node:18-alpine` | Node.js/Express 应用 | ~25 |
| `tomcat:9-jre11` | Java Web 应用 | ~10 |
| `mysql:8` | 数据库后端 | ~15 |
| `postgres:15-alpine` | 数据库后端 | ~8 |
| `mongo:6` | NoSQL 数据库 | ~4 |
| `nginx:1.24-alpine` | 反向代理/WAF | ~5 |
| `redis:7-alpine` | 缓存/会话存储 | ~3 |
| `ubuntu:22.04` | 通用系统 | ~10 |

### XBOW 镜像汇总

| 类型 | 数量 | 构建方式 |
|------|------|---------|
| 单容器 Web 挑战 | ~70 | 各自 Dockerfile，基于标准语言镜像 |
| 多容器 Web 挑战 | ~25 | docker-compose.yml（Web + DB + Cache） |
| 带逆向/二进制元素的挑战 | ~9 | ubuntu + 自定义二进制 |
| **总挑战** | **104** | |

---

## 三、镜像获取方案

由于当前机器无法访问 Docker Hub（`registry-1.docker.io` 超时），有以下替代方案：

### 方案 A: 国内镜像加速

```bash
# 配置 Docker 镜像加速器
sudo tee /etc/docker/daemon.json << 'EOF'
{
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://dockerproxy.com"
  ]
}
EOF
sudo systemctl restart docker
```

### 方案 B: 离线导出/导入

在有网络的机器上：
```bash
# 拉取并导出
docker pull php:8.1-apache
docker save php:8.1-apache | gzip > php-8.1-apache.tar.gz

# 传输到目标机器后导入
docker load < php-8.1-apache.tar.gz
```

### 方案 C: 本地 Dockerfile 构建 + 本地依赖

```dockerfile
# 每个挑战写 Dockerfile，基础镜像用方案 A/B 导入
FROM php:8.1-apache
COPY src/ /var/www/html/
RUN docker-php-ext-install mysqli
```

### 方案 D: 纯本地替代（Custom Defense 模式）

与 Custom Defense 一样，用 Python HTTP 服务器实现挑战，完全绕过 Docker：

- **PACEBench 替代**: 将 PACEBench 32 挑战改写为 Python 本地服务器
- **XBOW 替代**: 将 XBOW 104 挑战中最关键的 20-30 个改写为 Python 本地服务器

这需要逐个分析每个挑战的漏洞逻辑并重写，工作量大但可彻底避免 Docker 依赖。

## 四、镜像拉取优先级

如果只能拿到有限镜像，按优先级拉取：

### P0 — 立即可用（覆盖最多挑战）

| 镜像 | 拉取命令 | 覆盖挑战 |
|------|---------|---------|
| `php:8.1-apache` | `docker pull php:8.1-apache` | PACEBench ~5 + XBOW ~30 |
| `python:3.10-slim` | `docker pull python:3.10-slim` | PACEBench ~8 + XBOW ~25 |
| `node:18-alpine` | `docker pull node:18-alpine` | XBOW ~25 |
| `mysql:8` | `docker pull mysql:8` | PACEBench ~5 + XBOW ~15 |

### P1 — WAF 场景专用

| 镜像 | 拉取命令 | 覆盖挑战 |
|------|---------|---------|
| `owasp/modsecurity-crs:3.3` | `docker pull owasp/modsecurity-crs:3.3` | PACEBench D-CVE |
| `nginx:1.24-alpine` | `docker pull nginx:1.24-alpine` | PACEBench D-CVE + XBOW |

### P2 — 完整覆盖

| 镜像 | 拉取命令 | 覆盖挑战 |
|------|---------|---------|
| `tomcat:9-jre11` | `docker pull tomcat:9-jre11` | PACEBench ~5 + XBOW ~10 |
| `postgres:15-alpine` | `docker pull postgres:15-alpine` | XBOW ~8 |
| `mongo:6` | `docker pull mongo:6` | XBOW ~4 |
| `redis:7-alpine` | `docker pull redis:7-alpine` | XBOW ~3 |

## 五、当前可运行的基准对比

| 基准 | 挑战数 | Docker 需求 | 当前状态 |
|------|--------|-----------|---------|
| **Custom Defense** | 20 | 无需 Docker | ✅ 立即可跑 |
| **PACEBench** | 32 | 需要基础镜像 + 挑战 Docker 构建 | ❌ 缺镜像和挑战定义 |
| **XBOW** | 104 | 需要基础镜像 + 挑战目录 | ❌ 缺镜像和挑战定义 |
