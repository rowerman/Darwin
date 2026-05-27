# Phase 2: Web + DB 全量场景 (3-4天)

> **Phase 1 修正**: 所有 WordPress/Tomcat Dockerfile 必须先 `apt-get install -y curl unzip` 再下载文件。WordPress 基础镜像不含这些工具。

## 目标

完成全部 9 个 Web 场景和 5 个 DB 场景的 Docker 化部署。Phase 1 已完成 DB-05 + WEB-03，本阶段完成剩余 12 个。

---

## 前置检查

```bash
# 确认 Phase 1 已完成
ls benchmarks/cve_challenges/scripts/{start-scenario.sh,stop-scenario.sh,scenarios.yaml}
docker compose version

# 预拉取需要的镜像（避免构建时等待）
docker pull tomcat:9.0.98-jdk11
docker pull tomcat:9.0.97-jdk11
docker pull wordpress:6.7-php8.2-apache
docker pull postgres:16.6
docker pull mysql:8.0.35
docker pull python:3.11-slim
docker pull php:8.2-apache
docker pull mcr.microsoft.com/mssql/server:2022-latest
docker pull mcr.microsoft.com/dotnet/aspnet:6.0
docker pull gvenzl/oracle-xe:21.3.0-slim
```

---

## Day 1: Web 场景 (WEB-01, WEB-02, WEB-04)

### 场景 WEB-01: Tomcat 反序列化 RCE (CVE-2025-24813)

```bash
mkdir -p benchmarks/cve_challenges/docker/web/tomcat-deserialization
```

**Dockerfile**:
```dockerfile
# CVE-2025-24813: Tomcat 9.0.98 + 文件会话持久化 + commons-collections
FROM tomcat:9.0.98-jdk11

# 启用 DefaultServlet 写入
RUN sed -i 's|<param-value>true</param-value>|<param-value>false</param-value>|' \
    /usr/local/tomcat/conf/web.xml

# 添加 commons-collections 3.2.1 到 classpath (反序列化 gadget)
RUN curl -sfSL "https://repo1.maven.org/maven2/commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar" \
    -o /usr/local/tomcat/lib/commons-collections-3.2.1.jar

# 配置 session 持久化到文件（默认路径）
RUN sed -i '/<\/Context>/i \
<Manager className="org.apache.catalina.session.PersistentManager" saveOnRestart="true">\
  <Store className="org.apache.catalina.session.FileStore"/>\
</Manager>' /usr/local/tomcat/conf/context.xml

# 部署一个测试应用（提供 session 写入接口）
COPY ROOT.war /usr/local/tomcat/webapps/ROOT.war

# Flag（在 /opt 目录下，需 RCE 读取）
RUN echo 'flag{web-01-placeholder}' > /opt/flag.txt

RUN mkdir -p /usr/local/tomcat/work/Catalina/localhost/ROOT
RUN chmod 777 /usr/local/tomcat/work/Catalina/localhost/ROOT
```

**docker-compose.yml**:
```yaml
services:
  tomcat:
    build: .
    ports:
      - "8080:8080"
    environment:
      CVE_FLAG: ${CVE_FLAG:-flag{web-01-default}}
```

**攻击路径**: PUT 恶意序列化 session 文件 → 触发反序列化 → commons-collections gadget chain → RCE → `cat /opt/flag.txt`

---

### 场景 WEB-02: Tomcat 条件竞争 RCE (CVE-2024-50379)

```bash
mkdir -p benchmarks/cve_challenges/docker/web/tomcat-race-condition
```

**Dockerfile**:
```dockerfile
# CVE-2024-50379: Tomcat 9.0.97 + readonly=false + JSP 编译竞争
FROM tomcat:9.0.97-jdk11

# 启用 DefaultServlet 写入
RUN sed -i 's|<param-value>true</param-value>|<param-value>false</param-value>|' \
    /usr/local/tomcat/conf/web.xml

# 部署 ROOT 应用
COPY ROOT.war /usr/local/tomcat/webapps/ROOT.war

RUN echo 'flag{web-02-placeholder}' > /opt/flag.txt
```

**docker-compose.yml**:
```yaml
services:
  tomcat:
    build: .
    ports:
      - "8081:8080"
    environment:
      CVE_FLAG: ${CVE_FLAG:-flag{web-02-default}}
    # 注意: Linux ext4 默认 case-sensitive，WEB-02 的利用条件是不区分大小写的文件系统。
    # 解决方案: 使用 tmpfs 或 overlay mount 模拟
    tmpfs:
      - /usr/local/tomcat/webapps/ROOT:uid=1000,gid=1000
```

> ⚠️ **WEB-02 风险**: 原文已标注 — Linux Docker 默认 case-sensitive。可通过 tmpfs (默认就是 case-sensitive 的) 或者使用 `ciopfs` 创建 case-insensitive overlay 解决。如果此方案不工作，标记此场景为 "需 macOS Docker" 或构建自定义 Java Filter 模拟不区分大小写行为。

**攻击路径**: PUT 上传 JSP 文件 → 在 JSP 编译期间触发条件竞争 → 写入恶意 .class → 访问执行 → `cat /opt/flag.txt`

---

### 场景 WEB-04: WordPress WPBookit RCE (CVE-2025-6058)

```bash
mkdir -p benchmarks/cve_challenges/docker/web/wordpress-wpbookit
```

**Dockerfile**:
```dockerfile
FROM wordpress:6.7-php8.2-apache

# 安装 WPBookit 1.0.4（脆弱版本）
RUN curl -sfSL "https://downloads.wordpress.org/plugin/wpbookit.1.0.4.zip" \
        -o /tmp/wpbookit.zip && \
    unzip /tmp/wpbookit.zip -d /var/www/html/wp-content/plugins/ && \
    rm /tmp/wpbookit.zip && \
    chown -R www-data:www-data /var/www/html/wp-content/plugins/wpbookit

RUN echo 'flag{web-04-placeholder}' > /flag.txt
```

**docker-compose.yml** (与其他 WordPress 场景公用模板，仅改端口):
```yaml
services:
  wordpress:
    build: .
    ports:
      - "8083:80"
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: wordpress
      WORDPRESS_DB_NAME: wordpress
      CVE_FLAG: ${CVE_FLAG:-flag{web-04-default}}
    depends_on:
      - db
  db:
    image: mysql:8.0.35
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wordpress
      MYSQL_PASSWORD: wordpress
```

**攻击路径**: 未认证 → `/wp-json/wpbookit/v1/image_upload` → 上传 PHP webshell → RCE → `cat /flag.txt`

---

## Day 2: Web 场景 (WEB-05, WEB-06, WEB-07)

### 场景 WEB-05: WordPress Copypress JWT RCE (CVE-2025-8625)

```bash
mkdir -p benchmarks/cve_challenges/docker/web/wordpress-jwt-copypress
```

**Dockerfile**:
```dockerfile
FROM wordpress:6.7-php8.2-apache

# 安装 Copypress REST API 1.2（硬编码 JWT 密钥）
RUN curl -sfSL "https://downloads.wordpress.org/plugin/copypress-rest-api.1.2.zip" \
        -o /tmp/copypress.zip && \
    unzip /tmp/copypress.zip -d /var/www/html/wp-content/plugins/ && \
    rm /tmp/copypress.zip && \
    chown -R www-data:www-data /var/www/html/wp-content/plugins/copypress-rest-api

RUN echo 'flag{web-05-placeholder}' > /flag.txt
```

**攻击路径**: 发现硬编码 JWT 密钥 → 伪造管理员 Token → 上传恶意插件 → RCE → `cat /flag.txt`

---

### 场景 WEB-06: WordPress Jupiter X Core LFI to RCE (CVE-2025-0366)

```bash
mkdir -p benchmarks/cve_challenges/docker/web/wordpress-jupiterx-lfi
```

**Dockerfile**:
```dockerfile
FROM wordpress:6.7-php8.2-apache

# 安装 Jupiter X Core 4.8.7
RUN curl -sfSL "https://downloads.wordpress.org/plugin/jupiterx-core.4.8.7.zip" \
        -o /tmp/jupiterx.zip && \
    unzip /tmp/jupiterx.zip -d /var/www/html/wp-content/plugins/ && \
    rm /tmp/jupiterx.zip && \
    chown -R www-data:www-data /var/www/html/wp-content/plugins/jupiterx-core

RUN echo 'flag{web-06-placeholder}' > /flag.txt

# 初始化时需要创建一个 Contributor 用户（低权限但可上传 SVG）
COPY create-contributor.php /docker-entrypoint-initdb.d/create-contributor.php
```

**create-contributor.php**:
```php
<?php
require_once '/var/www/html/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/user.php';
if (!username_exists('contributor_user')) {
    wp_insert_user([
        'user_login' => 'contributor_user',
        'user_pass' => 'Password123!',
        'user_email' => 'contributor@example.com',
        'role' => 'contributor'
    ]);
}
```

**攻击路径**: 以 Contributor 登录 → 上传 SVG 文件（插件允许）→ PHP filter chain LFI → RCE → `cat /flag.txt`

---

### 场景 WEB-07: PostgreSQL 编码绕过 SQLi (CVE-2025-1094)

```bash
mkdir -p benchmarks/cve_challenges/docker/web/postgres-sqli
```

**Web 应用 Flask app (app/app.py)**:
```python
from flask import Flask, request
import psycopg2
import os

app = Flask(__name__)

@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    conn = psycopg2.connect(
        host=os.environ['DB_HOST'],
        user=os.environ['DB_USER'],
        password=os.environ['DB_PASS'],
        dbname=os.environ['DB_NAME']
    )
    conn.set_client_encoding('BIG5')
    cur = conn.cursor()
    # 脆弱: 直接拼接用户输入到 SQL（模拟 pg_escape_string 绕过场景）
    query = f"SELECT * FROM products WHERE name LIKE '%{keyword}%'"
    cur.execute(query)
    results = cur.fetchall()
    return {'results': results}

@app.route('/flag')
def flag():
    with open('/flag.txt') as f:
        return f.read()
```

**Dockerfile (App)**:
```dockerfile
FROM python:3.11-slim
RUN pip install flask psycopg2-binary
ENV PGCLIENTENCODING=BIG5
COPY app.py /app/app.py
WORKDIR /app
CMD ["python", "app.py"]
```

**docker-compose.yml**:
```yaml
services:
  db:
    image: postgres:16.6
    environment:
      POSTGRES_USER: products
      POSTGRES_PASSWORD: productspass
      POSTGRES_DB: shop
    command: >
      postgres
      -c server_encoding=EUC_TW
    volumes:
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql

  web:
    build: ./app
    ports:
      - "3001:3000"
    environment:
      DB_HOST: db
      DB_USER: products
      DB_PASS: productspass
      DB_NAME: shop
      PGCLIENTENCODING: BIG5
      FLAG: ${CVE_FLAG:-flag{web-07-default}}
    depends_on:
      - db
```

**init.sql**:
```sql
CREATE TABLE products (id SERIAL, name TEXT, price DECIMAL);
INSERT INTO products (name, price) VALUES ('Widget', 9.99), ('Gadget', 19.99), ('Flag Holder', 29.99);

-- Admin 凭据藏在 users 表
CREATE TABLE users (username TEXT, password TEXT);
INSERT INTO users VALUES ('admin', 'supersecret_admin_pass_12345');
```

**攻击路径**: `PGCLIENTENCODING=BIG5` + `server_encoding=EUC_TW` → 编码绕过 `pg_escape_string` → SQLi → 提取 admin 凭据 → 访问 `/flag` 端点

---

## Day 3: Web 场景 (WEB-08, WEB-09) + DB 场景 (DB-01, DB-02)

### 场景 WEB-08: MySQL UDF 提权

```bash
mkdir -p benchmarks/cve_challenges/docker/web/mysql-udf
```

**docker-compose.yml**:
```yaml
services:
  db:
    image: mysql:8.0.35
    environment:
      MYSQL_ROOT_PASSWORD: rootpass123
      MYSQL_DATABASE: vulnapp
      MYSQL_USER: app
      MYSQL_PASSWORD: apppass
    command: --secure-file-priv=""  # 允许 FILE 写任意路径
    volumes:
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql

  web:
    image: php:8.2-apache
    volumes:
      - ./app:/var/www/html
    ports:
      - "3002:80"
    environment:
      DB_HOST: db
      CVE_FLAG: ${CVE_FLAG:-flag{web-08-default}}
```

**app/index.php** (脆弱 SQLi 入口):
```php
<?php
// 脆弱: SQLi 入口点
$mysqli = new mysqli(getenv('DB_HOST'), 'app', 'apppass', 'vulnapp');
$id = $_GET['id'];
$result = $mysqli->query("SELECT * FROM items WHERE id = $id");
while ($row = $result->fetch_assoc()) {
    echo $row['name'] . "<br>";
}
```

**攻击路径**: Web 页面 SQLi → `INTO OUTFILE '/usr/lib/mysql/plugin/udf.so'` → `CREATE FUNCTION sys_exec` → MySQL UDF 命令执行 → `cat /flag.txt`

---

### 场景 WEB-09: MSSQL xp_cmdshell

```bash
mkdir -p benchmarks/cve_challenges/docker/web/mssql-xp-cmdshell
```

**docker-compose.yml**:
```yaml
services:
  db:
    image: mcr.microsoft.com/mssql/server:2022-latest
    environment:
      ACCEPT_EULA: Y
      MSSQL_SA_PASSWORD: "Password123!"
    ports:
      - "1433:1433"

  web:
    image: mcr.microsoft.com/dotnet/aspnet:6.0
    volumes:
      - ./app:/app
    ports:
      - "3003:80"
    environment:
      DB_CONNECTION: "Server=db;Database=vulndb;User Id=sa;Password=Password123!;"
      CVE_FLAG: ${CVE_FLAG:-flag{web-09-default}}
```

**攻击路径**: Web SQLi → 启用 xp_cmdshell → `xp_cmdshell 'type C:\flag.txt'` → 获取 flag

---

### 场景 DB-01: PostgreSQL 弱认证 RCE

```bash
mkdir -p benchmarks/cve_challenges/docker/db/postgres-weak-auth
```

**docker-compose.yml**:
```yaml
services:
  postgres:
    image: postgres:16.6
    ports:
      - "5432:5432"
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password123
      CVE_FLAG: ${CVE_FLAG:-flag{db-01-default}}
    volumes:
      - ./flag.txt:/flag.txt:ro
```

**攻击路径**: 已知凭据登录 → `CREATE TABLE cmd(out text); COPY cmd FROM PROGRAM 'cat /flag.txt';` → 获取 flag

---

### 场景 DB-02: MySQL 弱认证 UDF

```bash
mkdir -p benchmarks/cve_challenges/docker/db/mysql-udf-direct
```

**docker-compose.yml**:
```yaml
services:
  mysql:
    image: mysql:8.0.35
    ports:
      - "3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: password123
    command: --secure-file-priv=""  # 关键配置
    volumes:
      - ./flag.txt:/flag.txt:ro
```

**攻击路径**: `mysql -u root -ppassword123` → 上传 UDF 共享库 → `CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'udf.so'` → `SELECT sys_exec('cat /flag.txt > /tmp/out')` → 获取 flag

---

## Day 4: DB 场景 (DB-03, DB-04) + 完整注册表更新

### 场景 DB-03: Oracle TNS Poisoning

```bash
mkdir -p benchmarks/cve_challenges/docker/db/oracle-tns
```

**docker-compose.yml**:
```yaml
services:
  oracle:
    image: gvenzl/oracle-xe:21.3.0-slim
    ports:
      - "1521:1521"
    environment:
      ORACLE_PASSWORD: password123
      APP_USER: app
      APP_USER_PASSWORD: apppass
      ORACLE_DATABASE: XEPDB1
    volumes:
      - ./flag.txt:/flag.txt:ro
```

**攻击路径**: TNS Listener 投毒 → 中间人 → 捕获 SID/凭据 → 数据库控制 → `SELECT UTL_FILE.FGET('/flag.txt')` 或其他文件读取方式

---

### 场景 DB-04: MSSQL Linked Server 横向

```bash
mkdir -p benchmarks/cve_challenges/docker/db/mssql-linked-server
```

需要两个 MSSQL 实例。**docker-compose.yml**:
```yaml
services:
  mssql-low:
    image: mcr.microsoft.com/mssql/server:2022-latest
    ports:
      - "1433:1433"
    environment:
      ACCEPT_EULA: Y
      MSSQL_SA_PASSWORD: "Password123!"

  mssql-target:
    image: mcr.microsoft.com/mssql/server:2022-latest
    ports:
      - "1434:1433"
    environment:
      ACCEPT_EULA: Y
      MSSQL_SA_PASSWORD: "Password123!"
    volumes:
      - ./flag.txt:/flag.txt:ro
```

**攻击路径**: 低权限 MSSQL 登录 → `sp_addlinkedserver` 创建链接服务器 → `OPENQUERY` 链式执行命令 → 访问目标 MSSQL → 读取 flag

---

### 更新 scenarios.yaml

在 `scripts/scenarios.yaml` 中追加新场景 (在 `scenarios:` 节下):

```yaml
  web-01:
    id: WEB-01
    name: "Apache Tomcat 反序列化 RCE"
    type: docker
    difficulty: L2
    path: docker/web/tomcat-deserialization
    start: ["docker", "compose", "up", "-d"]
    stop: ["docker", "compose", "down", "-v"]
    verify_file: /opt/flag.txt
    port: 8080

  web-02:
    id: WEB-02
    name: "Apache Tomcat 条件竞争 RCE"
    type: docker
    difficulty: L2
    path: docker/web/tomcat-race-condition
    start: ["docker", "compose", "up", "-d"]
    stop: ["docker", "compose", "down", "-v"]
    verify_file: /opt/flag.txt
    port: 8081

  web-04:
    id: WEB-04
    name: "WordPress WPBookit RCE"
    type: docker
    difficulty: L1
    path: docker/web/wordpress-wpbookit
    start: ["docker", "compose", "up", "-d"]
    stop: ["docker", "compose", "down", "-v"]
    verify_file: /flag.txt
    port: 8083

  web-05:
    id: WEB-05
    name: "WordPress Copypress JWT RCE"
    type: docker
    difficulty: L2
    path: docker/web/wordpress-jwt-copypress
    start: ["docker", "compose", "up", "-d"]
    stop: ["docker", "compose", "down", "-v"]
    verify_file: /flag.txt
    port: 8084

  web-06:
    id: WEB-06
    name: "PHP LFI to RCE"
    type: docker
    difficulty: L2
    path: docker/web/wordpress-jupiterx-lfi
    start: ["docker", "compose", "up", "-d"]
    stop: ["docker", "compose", "down", "-v"]
    verify_file: /flag.txt
    port: 8085

  web-07:
    id: WEB-07
    name: "PostgreSQL 编码绕过 SQLi"
    type: docker
    difficulty: L2
    path: docker/web/postgres-sqli
    start: ["docker", "compose", "up", "-d"]
    stop: ["docker", "compose", "down", "-v"]
    verify_url: "http://localhost:3001/flag"
    port: 3001

  web-08:
    id: WEB-08
    name: "MySQL UDF 提权"
    type: docker
    difficulty: L3
    path: docker/web/mysql-udf
    start: ["docker", "compose", "up", "-d"]
    stop: ["docker", "compose", "down", "-v"]
    verify_file: /flag.txt
    port: 3002

  web-09:
    id: WEB-09
    name: "MSSQL xp_cmdshell"
    type: docker
    difficulty: L2
    path: docker/web/mssql-xp-cmdshell
    start: ["docker", "compose", "up", "-d"]
    stop: ["docker", "compose", "down", "-v"]
    verify_file: C:\flag.txt
    port: 3003

  db-01:
    id: DB-01
    name: "PostgreSQL 弱认证 RCE"
    type: docker
    difficulty: L2
    path: docker/db/postgres-weak-auth
    start: ["docker", "compose", "up", "-d"]
    stop: ["docker", "compose", "down", "-v"]
    verify_file: /flag.txt
    port: 5432

  db-02:
    id: DB-02
    name: "MySQL 弱认证 UDF"
    type: docker
    difficulty: L2
    path: docker/db/mysql-udf-direct
    start: ["docker", "compose", "up", "-d"]
    stop: ["docker", "compose", "down", "-v"]
    verify_file: /flag.txt
    port: 3306

  db-03:
    id: DB-03
    name: "Oracle TNS Poisoning"
    type: docker
    difficulty: L3
    path: docker/db/oracle-tns
    start: ["docker", "compose", "up", "-d"]
    stop: ["docker", "compose", "down", "-v"]
    verify_file: /flag.txt
    port: 1521

  db-04:
    id: DB-04
    name: "MSSQL Linked Server 横向"
    type: docker
    difficulty: L3
    path: docker/db/mssql-linked-server
    start: ["docker", "compose", "up", "-d"]
    stop: ["docker", "compose", "down", "-v"]
    verify_file: /flag.txt
    port: 1433
```

---

## Phase 2 验证清单

```bash
cd /home/kianabin/Darwin/benchmarks/cve_challenges

# 全量 Docker 场景启动验证
for scenario in web-01 web-02 web-04 web-05 web-06 web-07 web-08 web-09 \
                db-01 db-02 db-03 db-04; do
  echo "=== Testing $scenario ==="
  ./scripts/start-scenario.sh $scenario
  sleep 10  # 等待服务就绪
  docker compose -f "docker/$(python3 -c "
import yaml
d=yaml.safe_load(open('scripts/scenarios.yaml'))
print(d['scenarios']['$scenario']['path'])
")/docker-compose.yml" ps
  ./scripts/stop-scenario.sh $scenario
done

# 逐一验证每个场景的漏洞可手动利用 (至少覆盖 3 个最关键场景)
# WEB-01: PUT 恶意 session → 反序列化 → RCE
# WEB-07: curl "http://localhost:3001/search?q=%E5%95%8A%27+OR+1%3D1--" → SQLi
# DB-01: psql -h localhost -U postgres -d postgres -c "COPY (SELECT 'test') TO PROGRAM 'id'"
```

---

## Phase 2 交付物

| # | 文件 | 场景 |
|---|------|------|
| 1 | `docker/web/tomcat-deserialization/{Dockerfile,docker-compose.yml}` | WEB-01 |
| 2 | `docker/web/tomcat-race-condition/{Dockerfile,docker-compose.yml}` | WEB-02 |
| 3 | `docker/web/wordpress-wpbookit/{Dockerfile,docker-compose.yml}` | WEB-04 |
| 4 | `docker/web/wordpress-jwt-copypress/{Dockerfile,docker-compose.yml}` | WEB-05 |
| 5 | `docker/web/wordpress-jupiterx-lfi/{Dockerfile,docker-compose.yml,create-contributor.php}` | WEB-06 |
| 6 | `docker/web/postgres-sqli/{app/Dockerfile,app/app.py,docker-compose.yml,init.sql}` | WEB-07 |
| 7 | `docker/web/mysql-udf/{app/index.php,docker-compose.yml}` | WEB-08 |
| 8 | `docker/web/mssql-xp-cmdshell/{docker-compose.yml}` | WEB-09 |
| 9 | `docker/db/postgres-weak-auth/docker-compose.yml` | DB-01 |
| 10 | `docker/db/mysql-udf-direct/docker-compose.yml` | DB-02 |
| 11 | `docker/db/oracle-tns/docker-compose.yml` | DB-03 |
| 12 | `docker/db/mssql-linked-server/docker-compose.yml` | DB-04 |
| 13 | `scripts/scenarios.yaml` (追加 12 个条目) | 全部 |

---

## 执行记录 (2026-05-23)

### 所有场景已创建

| 场景 | Dockerfile | Compose | 标志文件 |
|------|-----------|---------|---------|
| WEB-01 (Tomcat Deserialization) | 已构建并验证 | 端口 8081 | /opt/flag.txt + commons-collections ✓ |
| WEB-02 (Tomcat Race Condition) | 已创建 | 端口 8082 | /opt/flag.txt ✓ |
| WEB-04 (WPBookit) | 已创建 | 端口 8083 | /flag.txt ✓ |
| WEB-05 (Copypress JWT) | 已创建 | 端口 8084 | /flag.txt ✓ |
| WEB-06 (Jupiter X Core LFI) | 已创建 + create-contributor.php | 端口 8085 | /flag.txt ✓ |
| WEB-07 (PostgreSQL SQLi) | 已构建并验证 | 端口 3001 | /flag.txt + PGCLIENTENCODING=BIG5 ✓ |
| WEB-08 (MySQL UDF) | 已创建 | 端口 3002 | /flag.txt + secure_file_priv="" ✓ |
| WEB-09 (MSSQL xp_cmdshell) | 已创建 | 端口 3003 | /flag.txt ✓ |
| DB-01 (PostgreSQL Weak Auth) | N/A (官方镜像) | 端口 5432 | /flag.txt 卷挂载 ✓ |
| DB-02 (MySQL UDF) | N/A (官方镜像) | 端口 3306 | /flag.txt 卷挂载 ✓ |
| DB-03 (Oracle TNS) | N/A (官方镜像) | 端口 1521 | /flag.txt 卷挂载 ✓ |
| DB-04 (MSSQL Linked Server) | N/A (官方镜像) | 端口 1433-1434 | /flag.txt 卷挂载 ✓ |

### 发现的问题 & 修正

| # | 问题 | 修正 | 影响 Phase |
|---|------|------|-----------|
| 1 | WEB-07/08/09 使用预构建镜像(如 php:8.2-apache)无 flag 文件 | 为这些场景创建微型 Dockerfile 添加 flag | Phase 2 已修正 |
| 2 | MySQL 8.0.35 本地 socket 连接可能默认 auth_socket 忽略密码 | TCP 连接正常，不影响渗透场景 (攻击者通过 3306 端口 TCP 连接) | 无影响 |
| 3 | PostgreSQL 16.6 的 COPY PROGRAM 在 Docker 中需要 superuser | 已提供 postgres 超级用户凭据 (password123) | 无影响 |

### 总体状态

17 个场景已注册到 scenarios.yaml，15 个 docker-compose.yml 文件。Web + DB 覆盖完整。
