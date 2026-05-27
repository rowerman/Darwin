# Phase 1: 基础设施 + 5 MVP 场景 (2-3天)

## 目标

搭建 CVE Benchmark 的底板：目录结构、通用脚本、Flag 管理系统。完成 5 个最简单的场景验证全流程可行性。

---

## 前置检查

```bash
# 确认依赖已安装
docker --version         # >= 24.0
docker compose version   # >= 2.0
python3 --version        # >= 3.10
kind version             # >= 0.20 (安装: go install sigs.k8s.io/kind@latest)
kubectl version          # >= 1.27

# 确认 DARWIN 虚拟环境已激活
source venv/bin/activate

# 确认 GOAD 已 clone
ls ~/GOAD/
```

---

## Step 1: 目录结构 (30分钟)

```bash
cd /home/kianabin/Darwin

# 根目录
mkdir -p benchmarks/cve_challenges/{docker/{web,db,linux},k8s,ad,chains,scripts}

# Web 场景子目录 (Phase 1 只建需要的)
mkdir -p benchmarks/cve_challenges/docker/web/{wordpress-simple-file-list}
mkdir -p benchmarks/cve_challenges/docker/db/{redis-unauth}
mkdir -p benchmarks/cve_challenges/docker/linux/{sudo-chroot}

# K8s 场景子目录
mkdir -p benchmarks/cve_challenges/k8s/{rbac-secrets}

# AD 场景子目录
mkdir -p benchmarks/cve_challenges/ad/scenarios

# 攻击链子目录
mkdir -p benchmarks/cve_challenges/chains/{web-to-da,container-to-admin,wordpress-to-k8s}

# 创建 .gitignore
cat > benchmarks/cve_challenges/.gitignore << 'EOF'
# Flag 文件
flag*.txt
*.flag

# 数据库数据
*.db
*.sqlite
data/

# Vagrant
.vagrant/
*.box

# K8s
kubeconfig*
*.kubeconfig

# 临时文件
*.tmp
*.log
EOF
```

---

## Step 2: 通用脚本 (1小时)

### 2.1 场景注册表 `scripts/scenarios.yaml`

```bash
cat > benchmarks/cve_challenges/scripts/scenarios.yaml << 'EOF'
# CVE Benchmark 场景注册表
# 每个场景定义: ID, 名称, 类型, 难度, 启动命令, 验证命令

scenarios:
  # === MVP Phase 1 ===
  db-05:
    id: DB-05
    name: "Redis 未授权访问"
    type: docker
    difficulty: L1
    path: docker/db/redis-unauth
    start: ["docker", "compose", "up", "-d"]
    stop: ["docker", "compose", "down", "-v"]
    verify_url: null
    verify_file: /flag.txt
    port: 6379

  web-03:
    id: WEB-03
    name: "WordPress Simple File List RCE"
    type: docker
    difficulty: L1
    path: docker/web/wordpress-simple-file-list
    start: ["docker", "compose", "up", "-d"]
    stop: ["docker", "compose", "down", "-v"]
    verify_url: "http://localhost:8080/wp-content/plugins/simple-file-list/ee-list/flag.txt"
    port: 8080

  lnx-05:
    id: LNX-05
    name: "Sudo Chroot 提权"
    type: docker
    difficulty: L2
    path: docker/linux/sudo-chroot
    start: ["docker", "compose", "up", "-d"]
    stop: ["docker", "compose", "down", "-v"]
    ssh_user: attacker
    ssh_password: password123
    ssh_port: 2222
    verify_file: /root/flag.txt

  k8s-06:
    id: K8S-06
    name: "K8s RBAC 权限滥用"
    type: k8s
    difficulty: L1
    path: k8s/rbac-secrets
    start: ["bash", "deploy.sh"]
    stop: ["bash", "teardown.sh"]
    verify_secret: "flag-secret"

  ad-01:
    id: AD-01
    name: "Kerberoasting 基础"
    type: ad
    difficulty: L1
    path: ad/scenarios/ad-01-kerberoasting
    start: ["vagrant", "snapshot", "restore", "ad-01-base"]
    stop: ["vagrant", "halt"]
    target_host: 192.168.56.10
    attacker_user: lowpriv
    attacker_pass: Password123!
    flag_location: "AD user 'svc_sql' description attribute"
EOF
```

### 2.2 `start-scenario.sh`

```bash
cat > benchmarks/cve_challenges/scripts/start-scenario.sh << 'SCRIPT'
#!/bin/bash
# 用法: ./start-scenario.sh <场景ID>  例如: ./start-scenario.sh db-05
set -euo pipefail

SCENARIO_ID="${1:?Usage: $0 <scenario-id>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SCENARIOS_FILE="$SCRIPT_DIR/scenarios.yaml"

echo "[*] Starting scenario: $SCENARIO_ID"

# 确定场景类型
TYPE=$(python3 -c "
import yaml
with open('$SCENARIOS_FILE') as f:
    data = yaml.safe_load(f)
print(data['scenarios']['$SCENARIO_ID']['type'])
")

case "$TYPE" in
  docker)
    SCENARIO_PATH="$ROOT_DIR/$(python3 -c "import yaml; d=yaml.safe_load(open('$SCENARIOS_FILE')); print(d['scenarios']['$SCENARIO_ID']['path'])")"
    cd "$SCENARIO_PATH"
    # 生成随机 flag
    FLAG="flag{${SCENARIO_ID}-$(openssl rand -hex 8)}"
    export CVE_FLAG="$FLAG"
    echo "[+] Flag: $FLAG"
    docker compose up -d
    echo "[+] Scenario $SCENARIO_ID started"
    ;;

  k8s)
    SCENARIO_PATH="$ROOT_DIR/$(python3 -c "import yaml; d=yaml.safe_load(open('$SCENARIOS_FILE')); print(d['scenarios']['$SCENARIO_ID']['path'])")"
    cd "$SCENARIO_PATH"
    FLAG="flag{${SCENARIO_ID}-$(openssl rand -hex 8)}"
    export CVE_FLAG="$FLAG"
    echo "[+] Flag: $FLAG"
    bash deploy.sh
    ;;

  ad)
    SCENARIO_PATH="$ROOT_DIR/$(python3 -c "import yaml; d=yaml.safe_load(open('$SCENARIOS_FILE')); print(d['scenarios']['$SCENARIO_ID']['path'])")"
    cd "$SCENARIO_PATH"
    vagrant snapshot restore "${SCENARIO_ID}-base"
    vagrant up
    echo "[+] AD scenario $SCENARIO_ID restored and started"
    ;;
esac
SCRIPT
chmod +x benchmarks/cve_challenges/scripts/start-scenario.sh
```

### 2.3 `stop-scenario.sh`

```bash
cat > benchmarks/cve_challenges/scripts/stop-scenario.sh << 'SCRIPT'
#!/bin/bash
set -euo pipefail

SCENARIO_ID="${1:?Usage: $0 <scenario-id>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SCENARIOS_FILE="$SCRIPT_DIR/scenarios.yaml"

echo "[*] Stopping scenario: $SCENARIO_ID"

TYPE=$(python3 -c "
import yaml
with open('$SCENARIOS_FILE') as f:
    data = yaml.safe_load(f)
print(data['scenarios']['$SCENARIO_ID']['type'])
")

case "$TYPE" in
  docker)
    SCENARIO_PATH="$ROOT_DIR/$(python3 -c "import yaml; d=yaml.safe_load(open('$SCENARIOS_FILE')); print(d['scenarios']['$SCENARIO_ID']['path'])")"
    cd "$SCENARIO_PATH"
    docker compose down -v
    echo "[+] Scenario $SCENARIO_ID stopped and cleaned"
    ;;
  k8s)
    SCENARIO_PATH="$ROOT_DIR/$(python3 -c "import yaml; d=yaml.safe_load(open('$SCENARIOS_FILE')); print(d['scenarios']['$SCENARIO_ID']['path'])")"
    cd "$SCENARIO_PATH"
    bash teardown.sh
    ;;
  ad)
    SCENARIO_PATH="$ROOT_DIR/$(python3 -c "import yaml; d=yaml.safe_load(open('$SCENARIOS_FILE')); print(d['scenarios']['$SCENARIO_ID']['path'])")"
    cd "$SCENARIO_PATH"
    vagrant halt
    ;;
esac
SCRIPT
chmod +x benchmarks/cve_challenges/scripts/stop-scenario.sh
```

### 2.4 `list-scenarios.sh`

```bash
cat > benchmarks/cve_challenges/scripts/list-scenarios.sh << 'SCRIPT'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
python3 -c "
import yaml
with open('$SCRIPT_DIR/scenarios.yaml') as f:
    data = yaml.safe_load(f)
print(f'{\"ID\":<10} {\"Type\":<10} {\"Difficulty\":<10} {\"Name\"}')
print('-' * 60)
for sid, s in sorted(data['scenarios'].items()):
    print(f'{s[\"id\"]:<10} {s[\"type\"]:<10} {s[\"difficulty\"]:<10} {s[\"name\"]}')
"
SCRIPT
chmod +x benchmarks/cve_challenges/scripts/list-scenarios.sh
```

### 2.5 `verify-flag.sh`

```bash
cat > benchmarks/cve_challenges/scripts/verify-flag.sh << 'SCRIPT'
#!/bin/bash
# 验证 flag 是否被获取
# 用法: echo "flag{xxx}" | ./verify-flag.sh
set -euo pipefail

FLAG="${1:-$(cat)}"
FLAG_PATTERN='^flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}$'

# 1. 格式检查
if [[ ! "$FLAG" =~ $FLAG_PATTERN ]]; then
  echo "[FAIL] Invalid flag format: $FLAG"
  exit 1
fi

# 2. 蜜罐检查 (DAVE L4 - honeypot flag detection)
HONEYPOT_KEYWORDS="test|example|honeypot|demo|fake|sample|placeholder|dummy|123456|admin|password"
FLAG_CONTENT=$(echo "$FLAG" | sed 's/flag{//;s/}//')
if echo "$FLAG_CONTENT" | grep -qiE "$HONEYPOT_KEYWORDS"; then
  echo "[FAIL] Honeypot flag detected: $FLAG"
  exit 1
fi

echo "[OK] Valid flag: $FLAG"
exit 0
SCRIPT
chmod +x benchmarks/cve_challenges/scripts/verify-flag.sh
```

---

## Step 3: 场景 1 — DB-05 Redis 未授权 (30分钟)

```bash
cd /home/kianabin/Darwin/benchmarks/cve_challenges/docker/db/redis-unauth
```

### docker-compose.yml

```yaml
services:
  ssh-target:
    image: ubuntu:22.04
    container_name: db05-ssh-target
    command: >
      bash -c "
        apt-get update && apt-get install -y openssh-server &&
        useradd -m -s /bin/bash victim &&
        echo 'victim:password123' | chpasswd &&
        mkdir -p /home/victim/.ssh &&
        chmod 700 /home/victim/.ssh &&
        touch /home/victim/.ssh/authorized_keys &&
        chmod 600 /home/victim/.ssh/authorized_keys &&
        chown -R victim:victim /home/victim/.ssh &&
        echo '${CVE_FLAG:-flag{db-05-default}}' > /flag.txt &&
        chmod 644 /flag.txt &&
        service ssh start &&
        tail -f /dev/null
      "
    networks:
      - redis-net

  redis:
    image: redis:7.2.4
    container_name: db05-redis
    command: redis-server --requirepass ""
    ports:
      - "6379:6379"
    networks:
      - redis-net

networks:
  redis-net:
    driver: bridge
```

### 验证

```bash
docker compose up -d
# 从攻击者视角验证：无密码连接 Redis → config set dir /home/victim/.ssh → config set dbfilename authorized_keys → 写入 SSH 公钥 → SSH 登录 → cat /flag.txt
docker compose down -v
```

---

## Step 4: 场景 2 — WEB-03 WordPress Simple File List (45分钟)

```bash
cd /home/kianabin/Darwin/benchmarks/cve_challenges/docker/web/wordpress-simple-file-list
```

### Dockerfile

```dockerfile
FROM wordpress:6.7-php8.2-apache

# 安装脆弱插件 Simple File List 4.2.2
RUN curl -sfSL "https://downloads.wordpress.org/plugin/simple-file-list.4.2.2.zip" \
        -o /tmp/sfl.zip && \
    unzip /tmp/sfl.zip -d /var/www/html/wp-content/plugins/ && \
    rm /tmp/sfl.zip && \
    chown -R www-data:www-data /var/www/html/wp-content/plugins/simple-file-list

# Flag 注入（在 web root 外部，攻击者需 RCE 才能读）
RUN echo 'flag{web-03-placeholder}' > /flag.txt && chmod 644 /flag.txt

# WordPress 自动安装脚本
COPY auto-install.sh /docker-entrypoint-initdb.d/
```

### docker-compose.yml

```yaml
services:
  wordpress:
    build: .
    ports:
      - "8080:80"
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: wordpress
      WORDPRESS_DB_NAME: wordpress
      CVE_FLAG: ${CVE_FLAG:-flag{web-03-default}}
    depends_on:
      - db
    volumes:
      - wp-data:/var/www/html

  db:
    image: mysql:8.0.35
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wordpress
      MYSQL_PASSWORD: wordpress

volumes:
  wp-data:
```

### 攻击路径说明

1. 未认证攻击者访问 `http://localhost:8080/wp-content/plugins/simple-file-list/`
2. 上传恶意 PHP 文件（利用文件上传无验证漏洞）
3. 访问上传的文件 → PHP RCE
4. `cat /flag.txt` 获取 flag

---

## Step 5: 场景 3 — LNX-05 Sudo Chroot 提权 (45分钟)

```bash
cd /home/kianabin/Darwin/benchmarks/cve_challenges/docker/linux/sudo-chroot
```

### Dockerfile

```dockerfile
FROM ubuntu:24.04

# 安装 SSH + 固定脆弱 sudo 版本
RUN apt-get update && apt-get install -y openssh-server wget dpkg && \
    # 安装 sudo 1.9.16p2 (脆弱版本)
    wget -q "https://github.com/sudo-project/sudo/releases/download/SUDO_1_9_16p2/sudo_1.9.16p2-1_amd64.deb" \
         -O /tmp/sudo.deb && \
    dpkg -i /tmp/sudo.deb || apt-get install -f -y && \
    rm /tmp/sudo.deb && \
    # 禁止升级 sudo
    apt-mark hold sudo && \
    # 创建低权限用户
    useradd -m -s /bin/bash attacker && \
    echo 'attacker:password123' | chpasswd && \
    # 创建低权限组
    groupadd lowpriv && usermod -aG lowpriv attacker && \
    # 配置 SSH
    mkdir /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    # 注入 flag
    echo 'flag{lnx-05-placeholder}' > /root/flag.txt && \
    chmod 600 /root/flag.txt && \
    # 确保 sudo --chroot 可用
    echo "attacker ALL=(ALL) NOPASSWD: /usr/bin/sudo" >> /etc/sudoers

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
```

### docker-compose.yml

```yaml
services:
  sudo-chroot:
    build: .
    ports:
      - "2222:22"
    environment:
      CVE_FLAG: ${CVE_FLAG:-flag{lnx-05-default}}
    # 不需要 privileged，这是用户态漏洞
```

### 攻击路径说明

```bash
ssh attacker@localhost -p 2222  # password: password123
# 创建 chroot 环境 + 恶意 libnss 库 → sudo -R /tmp/evil woot → root shell → cat /root/flag.txt
```

---

## Step 6: 场景 4 — K8S-06 RBAC 滥用 (45分钟)

```bash
cd /home/kianabin/Darwin/benchmarks/cve_challenges/k8s/rbac-secrets
```

### kind-config.yaml

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3@sha256:3966ac761ae0136263ffdb6cfd4db23ef8a83cba8a463690e98317add2c9ba72
```

### deploy.sh

```bash
#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-k8s-06-rbac"

cd "$SCRIPT_DIR"

# 1. 创建 KIND 集群
kind create cluster --name "$CLUSTER_NAME" --config kind-config.yaml

# 2. 注入 flag
FLAG="${CVE_FLAG:-flag{k8s-06-default}}"
kubectl create namespace kube-system --dry-run=client -o yaml | kubectl apply -f -

# 在 kube-system 中创建 flag secret
kubectl create secret generic flag-secret \
  --namespace=kube-system \
  --from-literal=flag="$FLAG" \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. 创建攻击者 ServiceAccount
kubectl create serviceaccount attacker-sa --namespace=default
kubectl create namespace attacker-ns --dry-run=client -o yaml | kubectl apply -f -

# 4. 创建 RBAC（允许 attacker-sa 读取所有 namespace 的 secrets）
kubectl apply -f - << 'K8S_RBAC'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secrets-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: attacker-secrets-binding
subjects:
  - kind: ServiceAccount
    name: attacker-sa
    namespace: default
roleRef:
  kind: ClusterRole
  name: secrets-reader
  apiGroup: rbac.authorization.k8s.io
K8S_RBAC

# 5. 创建低权限 bot pod 并绑定 attacker SA
kubectl apply -f - << 'K8S_POD'
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: default
spec:
  serviceAccountName: attacker-sa
  containers:
    - name: kubectl
      image: bitnami/kubectl:1.27
      command: ["sleep", "3600"]
K8S_POD

# 等待 Pod ready
kubectl wait --for=condition=Ready pod/attacker-pod --timeout=60s

echo "[+] K8S-06 cluster ready"
echo "[+] Attacker pod: kubectl exec -it attacker-pod -- /bin/bash"
echo "[+] Flag stored in: secret/flag-secret in kube-system namespace"
```

### teardown.sh

```bash
#!/bin/bash
set -euo pipefail
kind delete cluster --name cve-k8s-06-rbac
```

### 攻击路径说明

```bash
kubectl exec -it attacker-pod -- /bin/bash
# 1. 检查当前 SA 权限: kubectl auth can-i list secrets --all-namespaces
# 2. 读取 flag: kubectl get secret flag-secret -n kube-system -o jsonpath='{.data.flag}' | base64 -d
# 3. 可选：提取高权限 SA token 进一步横向
```

---

## Step 7: 场景 5 — AD-01 Kerberoasting (60分钟)

### 前提：GOAD 已配置完成

```bash
cd /home/kianabin/GOAD
source .venv/bin/activate
```

### AD-01 场景配置 `benchmarks/cve_challenges/ad/scenarios/ad-01-kerberoasting/config.yaml`

```yaml
scenario:
  id: AD-01
  name: "Kerberoasting 基础"
  difficulty: L1
  technique: "Kerberoasting (ATT&CK T1558.003)"

network:
  dc_ip: 192.168.56.10
  domain: north.sevenkingdoms.local
  dc_hostname: winterfell

attacker:
  entry_point: "Kali jump host (192.168.56.50)"
  credentials:
    username: "lowpriv"
    password: "Password123!"
    domain: "north"
  tools:
    - impacket-GetUserSPNs
    - hashcat
    - john

target:
  service_account: "svc_sql"
  spn: "MSSQLSvc/castelblack.north.sevenkingdoms.local:1433"
  password_hint: "weak password (rockyou.txt crackable)"

flag:
  location: "AD user 'svc_sql' description attribute"
  format: "flag{ad-01-xxxxxxxx}"

defense:
  windows_defender: on
  smb_signing: enabled  # Kerberoasting 不受 SMB signing 影响
  patch_level: "Jan 2024"  # 不含最新补丁

setup_commands:
  - "vagrant snapshot restore ad-01-base"
  - "vagrant up winterfell"
  - "vagrant up kali"
```

### GOAD Ansible 修改 (为 AD-01 注入 flag)

```bash
cd /home/kianabin/GOAD

# 创建 AD-01 专用 playbook
cat > ansible/ad01_setup.yml << 'EOF'
---
- name: AD-01 Kerberoasting scenario setup
  hosts: winterfell
  tasks:
    - name: Create vulnerable service account with weak password
      win_shell: |
        Import-Module ActiveDirectory
        $password = ConvertTo-SecureString "Summer2024!" -AsPlainText -Force
        New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" `
          -UserPrincipalName "svc_sql@north.sevenkingdoms.local" `
          -AccountPassword $password -Enabled $true `
          -PasswordNeverExpires $true `
          -Description "flag{ad-01-kerberoast-$(Get-Random -Min 100000 -Max 999999)}"

    - name: Register SPN for service account
      win_shell: |
        setspn -S MSSQLSvc/castelblack.north.sevenkingdoms.local:1433 north\svc_sql

    - name: Create low-privilege domain user for attacker
      win_shell: |
        Import-Module ActiveDirectory
        $password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
        New-ADUser -Name "lowpriv" -SamAccountName "lowpriv" `
          -AccountPassword $password -Enabled $true `
          -PasswordNeverExpires $true
EOF

# 运行 playbook (GOAD 需先启动)
# ansible-playbook -i inventory ansible/ad01_setup.yml
```

---

## Step 8: Flag 管理系统 (30分钟)

### `scripts/flag_manager.py`

```python
#!/usr/bin/env python3
"""Flag generation, injection, and verification for CVE benchmarks."""
import hashlib
import secrets
import re
from pathlib import Path

FLAG_PATTERN = re.compile(r'flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}')
HONEYPOT_KEYWORDS = [
    'test', 'example', 'honeypot', 'demo', 'fake',
    'sample', 'placeholder', 'dummy', '123456'
]

def generate_flag(scenario_id: str, salt: str = "") -> str:
    """生成格式统一的随机 flag"""
    rand = secrets.token_hex(8)
    return f"flag{{{scenario_id}-{rand}}}"

def is_valid_flag(flag: str) -> bool:
    """验证 flag 格式并排除蜜罐"""
    if not FLAG_PATTERN.fullmatch(flag):
        return False
    content = flag[5:-1].lower()
    return not any(kw in content for kw in HONEYPOT_KEYWORDS)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <scenario-id>")
        sys.exit(1)
    print(generate_flag(sys.argv[1]))
```

---

## Step 9: 验证清单 (Phase 1 收尾)

对 5 个 MVP 场景逐一验证：

```bash
cd /home/kianabin/Darwin/benchmarks/cve_challenges

# DB-05: 验证 Redis 未授权
./scripts/start-scenario.sh db-05
redis-cli -h localhost -p 6379 PING
# 预期: PONG (无需认证)
./scripts/stop-scenario.sh db-05

# WEB-03: 验证 WordPress 插件可用
./scripts/start-scenario.sh web-03
curl -s http://localhost:8080/wp-content/plugins/simple-file-list/ | head -5
# 预期: 插件目录可访问 (非 404)
# 使用 PoC 上传 webshell 后验证 RCE
./scripts/stop-scenario.sh web-03

# LNX-05: 验证 Sudo Chroot
./scripts/start-scenario.sh lnx-05
sshpass -p password123 ssh -o StrictHostKeyChecking=no attacker@localhost -p 2222 'sudo --version'
# 预期: sudo 版本 1.9.16p2
./scripts/stop-scenario.sh lnx-05

# K8S-06: 验证 RBAC
cd k8s/rbac-secrets/ && bash deploy.sh
kubectl exec attacker-pod -- kubectl auth can-i list secrets -n kube-system
# 预期: yes
bash teardown.sh

# AD-01: 验证 Kerberoasting (需 GOAD 已启动)
# vagrant up
# impacket-GetUserSPNs north.sevenkingdoms.local/lowpriv:Password123! -dc-ip 192.168.56.10
# 预期: 列出 svc_sql 的 SPN
```

---

## Phase 1 交付物

| # | 文件 | 说明 |
|---|------|------|
| 1 | `benchmarks/cve_challenges/.gitignore` | Git 排除规则 |
| 2 | `benchmarks/cve_challenges/scripts/scenarios.yaml` | 场景注册表 |
| 3 | `benchmarks/cve_challenges/scripts/start-scenario.sh` | 通用启动 |
| 4 | `benchmarks/cve_challenges/scripts/stop-scenario.sh` | 通用停止 |
| 5 | `benchmarks/cve_challenges/scripts/list-scenarios.sh` | 场景列表 |
| 6 | `benchmarks/cve_challenges/scripts/verify-flag.sh` | Flag 格式/蜜罐校验 |
| 7 | `benchmarks/cve_challenges/scripts/flag_manager.py` | Flag 生成器 |
| 8 | `docker/db/redis-unauth/docker-compose.yml` | DB-05 |
| 9 | `docker/web/wordpress-simple-file-list/{Dockerfile,docker-compose.yml}` | WEB-03 |
| 10 | `docker/linux/sudo-chroot/{Dockerfile,docker-compose.yml}` | LNX-05 |
| 11 | `k8s/rbac-secrets/{kind-config.yaml,deploy.sh,teardown.sh}` | K8S-06 |
| 12 | `ad/scenarios/ad-01-kerberoasting/config.yaml` | AD-01 |

---

## 执行记录 (2026-05-23)

### 已验证的场景

| 场景 | 状态 | 备注 |
|------|------|------|
| DB-05 (Redis) | **PASS** | Redis 无密码访问确认，flag 动态注入正常 |
| WEB-03 (WordPress) | **PASS** | 插件安装成功，flag 在 /flag.txt |
| LNX-05 (Sudo Chroot) | **PASS** | sudo 1.9.16p2 编译成功，`sudo -R /tmp/woot woot` 返回 "No such file" (确认漏洞存在) |
| K8S-06 (RBAC) | **PASS** | SA Token 成功读取 kube-system 中的 flag-secret |
| AD-01 (Kerberoasting) | **CONFIG-ONLY** | Vagrant 未安装，仅创建了配置文件 |

### 发现的问题 & 修正

| # | 问题 | 影响 Phase | 修正方案 |
|---|------|-----------|---------|
| 1 | Docker base 镜像 (wordpress, ubuntu) 默认不含 curl/unzip | Phase 2 所有 Web 场景 | Dockerfile 必须先 `apt-get install -y curl unzip` |
| 2 | Ubuntu 24.04 apt 包已 backport 安全补丁，sudo 1.9.15p5-3ubuntu5.24.04.2 不受 CVE-2025-32463 影响 | Phase 3 LNX-05 | 改为从源码编译 sudo-1.9.16p2 (URL: https://www.sudo.ws/dist/sudo-1.9.16p2.tar.gz) |
| 3 | KIND 集群内无法从 Docker Hub 拉取镜像 (网络超时) | Phase 4 所有 K8s 场景 | 使用 `kind load docker-image` 预加载或使用 Docker Hub 直接可用的镜像 |
| 4 | `mkdir -p` 中大括号 `{}` 被当成字面量 | 所有 Phase | 用完整路径替代 brace expansion |
| 5 | Bash `=~` regex 中 `!` 和 `$` 有兼容性问题 | 所有 Phase | verify-flag.sh 改用 Python re 模块 |

### 对后续 Phase 计划的更新

- **Phase 2**: WEB-01~06 Dockerfile 需添加 `apt-get install -y curl unzip`
- **Phase 3**: LNX-05 不需要 VM(x), 已用 Docker + 源码编译完成。其余 4 个内核漏洞仍需要 Vagrant
- **Phase 4**: 所有 `deploy.sh` 需要 `kind load docker-image` 步骤或改用 Docker Hub 可拉取的镜像
- **Phase 5**: AD 环境需要 Vagrant + VirtualBox（当前主机不支持）
