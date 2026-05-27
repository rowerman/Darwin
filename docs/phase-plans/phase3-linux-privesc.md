# Phase 3: Linux 提权场景 (2天)

> **Phase 1 修正**: LNX-05 (Sudo Chroot) 已在 Phase 1 用 Docker + 源码编译完成，本 Phase 只需做 LNX-01~04 四个内核漏洞。
> 另：Ubuntu apt 包包含 backport 补丁，依赖特定二进制版本的场景应从源码编译。

## 目标

完成 4 个 Linux 内核提权场景（LNX-01~04），使用 Vagrant + VirtualBox。LNX-05 已在 Phase 1 完成。

---

## 前置检查

```bash
# 确认 Vagrant + VirtualBox
vagrant --version      # >= 2.3
vboxmanage --version   # VirtualBox 7.0+

# 确认有足够磁盘空间
df -h ~  # 每个 VM 约 5-10 GB，4 个共 40 GB

# LNX-05 已在 Phase 1 完成
ls benchmarks/cve_challenges/docker/linux/sudo-chroot/
```

---

## 通用 Vagrant 模板

所有 Linux 提权场景共用以下结构：

```
docker/linux/<scenario>/
  Vagrantfile
  provision.sh         # 安装脆弱内核/组件 + 创建用户 + 注入 flag
  README.md            # 攻击者场景描述
```

---

## Day 1: LNX-01 + LNX-02

### 场景 LNX-01: nftables UAF (CVE-2024-1086)

```bash
mkdir -p benchmarks/cve_challenges/docker/linux/nftables-cve-2024-1086
```

**Vagrantfile**:
```ruby
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"  # Ubuntu 22.04

  config.vm.provider "virtualbox" do |vb|
    vb.memory = 2048
    vb.cpus = 2
    vb.name = "cve-lnx-01-nftables"
  end

  config.vm.network "private_network", ip: "192.168.57.101"
  
  config.ssh.username = "attacker"
  config.ssh.password = "password123"

  config.vm.provision "shell", inline: <<-SHELL
    set -e
    # ===== 1. 安装脆弱内核 6.6.14 =====
    KERNEL="6.6.14"
    KERNEL_URL="https://kernel.ubuntu.com/mainline/v${KERNEL}/amd64"
    
    wget -q "${KERNEL_URL}/linux-headers-${KERNEL}-generic_${KERNEL}.amd64.deb"
    wget -q "${KERNEL_URL}/linux-image-unsigned-${KERNEL}-generic_${KERNEL}.amd64.deb"
    wget -q "${KERNEL_URL}/linux-modules-${KERNEL}-generic_${KERNEL}.amd64.deb"
    
    dpkg -i linux-*.deb
    rm -f linux-*.deb
    
    # 启用 nf_tables + user namespaces
    sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="user_namespace.enable=1"/' /etc/default/grub
    update-grub

    # ===== 2. 创建低权限用户 =====
    useradd -m -s /bin/bash attacker
    echo 'attacker:password123' | chpasswd
    usermod -aG sudo attacker  # sudo 仅用于查看 flag，攻击前不需要

    # ===== 3. 注入 flag =====
    FLAG="${CVE_FLAG:-flag{lnx-01-default}}"
    echo "$FLAG" > /root/flag.txt
    chmod 600 /root/flag.txt

    # ===== 4. 安装 SSH 并配置密码登录 =====
    apt-get update -qq && apt-get install -y -qq openssh-server
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
    systemctl enable ssh

    # ===== 5. 确认模块可用 =====
    modprobe nf_tables 2>/dev/null || echo "nf_tables built-in"

    echo "[+] LNX-01 CVE-2024-1086 ready. Reboot required for new kernel."
    reboot
  SHELL
end
```

**关键 PoC**: `https://github.com/Notselwyn/CVE-2024-1086` (99.4% 成功率)

**攻击路径**:
```
SSH attacker@192.168.57.101 (password123)
git clone https://github.com/Notselwyn/CVE-2024-1086
cd CVE-2024-1086 && make
./exploit
# → root shell → cat /root/flag.txt
```

---

### 场景 LNX-02: nftables pipapo Double-Free (CVE-2024-26809)

```bash
mkdir -p benchmarks/cve_challenges/docker/linux/nftables-cve-2024-26809
```

**Vagrantfile** (基于通用模板，仅改内核版本和 IP):
```ruby
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.provider "virtualbox" do |vb|
    vb.memory = 2048
    vb.cpus = 2
    vb.name = "cve-lnx-02-nftables-pipapo"
  end

  config.vm.network "private_network", ip: "192.168.57.102"
  config.ssh.username = "attacker"
  config.ssh.password = "password123"

  config.vm.provision "shell", inline: <<-SHELL
    set -e
    # 安装脆弱内核 6.6.22 (＜6.6.23 受影响)
    KERNEL="6.6.22"
    KERNEL_URL="https://kernel.ubuntu.com/mainline/v${KERNEL}/amd64"
    
    for pkg in linux-headers-${KERNEL}-generic_${KERNEL}.amd64.deb \
               linux-image-unsigned-${KERNEL}-generic_${KERNEL}.amd64.deb \
               linux-modules-${KERNEL}-generic_${KERNEL}.amd64.deb; do
      wget -q "${KERNEL_URL}/${pkg}"
    done
    
    dpkg -i linux-*.deb
    rm -f linux-*.deb
    
    sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="user_namespace.enable=1"/' /etc/default/grub
    update-grub

    useradd -m -s /bin/bash attacker
    echo 'attacker:password123' | chpasswd

    FLAG="${CVE_FLAG:-flag{lnx-02-default}}"
    echo "$FLAG" > /root/flag.txt
    chmod 600 /root/flag.txt

    apt-get update -qq && apt-get install -y -qq openssh-server
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
    systemctl enable ssh

    echo "[+] LNX-02 CVE-2024-26809 ready"
    reboot
  SHELL
end
```

---

## Day 2: LNX-03 + LNX-04

### 场景 LNX-03: Kernel cgroup PrivEsc (CVE-2024-50264)

```bash
mkdir -p benchmarks/cve_challenges/docker/linux/kernel-cve-2024-50264
```

**Vagrantfile**:
```ruby
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.provider "virtualbox" do |vb|
    vb.memory = 2048
    vb.cpus = 2
    vb.name = "cve-lnx-03-kernel-cgroup"
  end

  config.vm.network "private_network", ip: "192.168.57.103"
  config.ssh.username = "attacker"
  config.ssh.password = "password123"

  config.vm.provision "shell", inline: <<-SHELL
    set -e
    # CVE-2024-50264: 使用 Ubuntu 22.04 自带内核并添加 setup 条件
    # 备选: 如果 22.04 HWE 内核不可用，使用 kernel 6.11.0
    # Ubuntu 24.04 默认内核可能已修复，需要 22.04 + HWE 6.8 内核
    
    # 安装 HWE 6.8 内核 (Ubuntu 22.04 可选硬件启用栈)
    apt-get update -qq
    apt-get install -y -qq linux-image-6.8.0-31-generic linux-headers-6.8.0-31-generic || {
      # 如果 HWE 不可用，尝试从 mainline 下载 6.11.0
      KERNEL="6.11.0"
      URL="https://kernel.ubuntu.com/mainline/v${KERNEL}/amd64"
      wget -q "${URL}/linux-headers-${KERNEL}-generic_${KERNEL}.amd64.deb"
      wget -q "${URL}/linux-image-unsigned-${KERNEL}-generic_${KERNEL}.amd64.deb"
      wget -q "${URL}/linux-modules-${KERNEL}-generic_${KERNEL}.amd64.deb"
      dpkg -i linux-*.deb
      rm -f linux-*.deb
    }
    
    update-grub

    useradd -m -s /bin/bash attacker
    echo 'attacker:password123' | chpasswd

    FLAG="${CVE_FLAG:-flag{lnx-03-default}}"
    echo "$FLAG" > /root/flag.txt
    chmod 600 /root/flag.txt

    apt-get install -y -qq openssh-server
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
    systemctl enable ssh

    echo "[+] LNX-03 kernel ready"
    reboot
  SHELL
end
```

> ⚠️ **LNX-03 风险提示**: CVE-2024-50264 的 PoC 在特定内核版本的兼容性尚待验证。如果 Ubuntu 22.04 HWE 内核不可用，备选方案是使用在计划中标记的 Kernel 6.11.0 手动编译路径。如果 PoC 无法在选定内核上运行，替换为其他 Linux 提权 CVE 场景。

---

### 场景 LNX-04: vsock UAF (CVE-2025-21756)

```bash
mkdir -p benchmarks/cve_challenges/docker/linux/kernel-cve-2025-21756
```

**Vagrantfile**:
```ruby
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.provider "virtualbox" do |vb|
    vb.memory = 2048
    vb.cpus = 2
    vb.name = "cve-lnx-04-vsock"
  end

  config.vm.network "private_network", ip: "192.168.57.104"
  config.ssh.username = "attacker"
  config.ssh.password = "password123"

  config.vm.provision "shell", inline: <<-SHELL
    set -e
    # 安装脆弱内核 6.6.75 (PoC 已验证在此版本工作)
    KERNEL="6.6.75"
    KERNEL_URL="https://kernel.ubuntu.com/mainline/v${KERNEL}/amd64"
    
    for pkg in linux-headers-${KERNEL}-generic_${KERNEL}.amd64.deb \
               linux-image-unsigned-${KERNEL}-generic_${KERNEL}.amd64.deb \
               linux-modules-${KERNEL}-generic_${KERNEL}.amd64.deb; do
      wget -q "${KERNEL_URL}/${pkg}"
    done
    
    dpkg -i linux-*.deb
    rm -f linux-*.deb
    update-grub

    # 加载 vsock 模块
    modprobe vmw_vsock_virtio_transport 2>/dev/null || true

    # 创建低权限用户
    useradd -m -s /bin/bash attacker
    echo 'attacker:password123' | chpasswd

    # 注入 flag
    FLAG="${CVE_FLAG:-flag{lnx-04-default}}"
    echo "$FLAG" > /root/flag.txt
    chmod 600 /root/flag.txt

    # SSH
    apt-get update -qq && apt-get install -y -qq openssh-server
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
    systemctl enable ssh

    echo "[+] LNX-04 CVE-2025-21756 ready"
    reboot
  SHELL
end
```

**攻击路径**: SSH → vsock UAF PoC → KASLR bypass → 覆写 modprobe_path → root shell → `cat /root/flag.txt`

---

## 更新 scenarios.yaml

```yaml
  lnx-01:
    id: LNX-01
    name: "nftables Use-After-Free PrivEsc"
    type: vagrant
    difficulty: L2
    path: docker/linux/nftables-cve-2024-1086
    start: ["vagrant", "up"]
    stop: ["vagrant", "halt"]
    ssh_user: attacker
    ssh_password: password123
    ssh_host: 192.168.57.101
    verify_file: /root/flag.txt

  lnx-02:
    id: LNX-02
    name: "nftables pipapo Double-Free PrivEsc"
    type: vagrant
    difficulty: L2
    path: docker/linux/nftables-cve-2024-26809
    start: ["vagrant", "up"]
    stop: ["vagrant", "halt"]
    ssh_user: attacker
    ssh_password: password123
    ssh_host: 192.168.57.102
    verify_file: /root/flag.txt

  lnx-03:
    id: LNX-03
    name: "Kernel cgroup PrivEsc"
    type: vagrant
    difficulty: L3
    path: docker/linux/kernel-cve-2024-50264
    start: ["vagrant", "up"]
    stop: ["vagrant", "halt"]
    ssh_user: attacker
    ssh_password: password123
    ssh_host: 192.168.57.103
    verify_file: /root/flag.txt

  lnx-04:
    id: LNX-04
    name: "vsock UAF PrivEsc"
    type: vagrant
    difficulty: L2
    path: docker/linux/kernel-cve-2025-21756
    start: ["vagrant", "up"]
    stop: ["vagrant", "halt"]
    ssh_user: attacker
    ssh_password: password123
    ssh_host: 192.168.57.104
    verify_file: /root/flag.txt
```

> 注意：`start-scenario.sh` 需要添加 `vagrant` 类型支持。在 Phase 3 中修改脚本，增加 vagrant 分支：
> ```bash
> vagrant)
>   cd "$SCENARIO_PATH"
>   vagrant up
>   ;;
> ```

---

## 验证清单

```bash
# LNX-01
cd benchmarks/cve_challenges/docker/linux/nftables-cve-2024-1086
vagrant up
# 等 VM 启动后:
sshpass -p password123 ssh -o StrictHostKeyChecking=no attacker@192.168.57.101 'uname -r'
# 预期: 6.6.14-generic

# LNX-02
cd benchmarks/cve_challenges/docker/linux/nftables-cve-2024-26809
vagrant up
sshpass -p password123 ssh attacker@192.168.57.102 'cat /proc/version'
# 预期: Linux version 6.6.22

# LNX-03
cd benchmarks/cve_challenges/docker/linux/kernel-cve-2024-50264
vagrant up
sshpass -p password123 ssh attacker@192.168.57.103 'uname -r'

# LNX-04
cd benchmarks/cve_challenges/docker/linux/kernel-cve-2025-21756
vagrant up
sshpass -p password123 ssh attacker@192.168.57.104 'zcat /proc/config.gz | grep CONFIG_VSOCKETS'
```

---

## Phase 3 交付物

| # | 文件 | 场景 |
|---|------|------|
| 1 | `docker/linux/nftables-cve-2024-1086/Vagrantfile` | LNX-01 |
| 2 | `docker/linux/nftables-cve-2024-26809/Vagrantfile` | LNX-02 |
| 3 | `docker/linux/kernel-cve-2024-50264/Vagrantfile` | LNX-03 |
| 4 | `docker/linux/kernel-cve-2025-21756/Vagrantfile` | LNX-04 |
| 5 | `scripts/scenarios.yaml` (追加 4 个条目) | 全部 |
| 6 | `scripts/start-scenario.sh` (添加 vagrant 类型支持) | 全部 |
