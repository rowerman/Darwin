# MITRE ATT&CK: T1611 - Escape to Host

**技术 ID**: T1611
**战术**: Privilege Escalation
**平台**: Containers
**描述**: 攻击者可能会突破容器隔离以获得对底层宿主操作系统的访问权限。这可以通过利用容器运行时漏洞、错误配置（如特权容器、危险挂载点）或内核漏洞来实现。成功逃逸后，攻击者可以访问宿主机上的所有容器和敏感数据。

**常见方法**:
1. **特权容器逃逸**: 利用 `--privileged` 标志获取宿主机权限
2. **Docker Socket 挂载**: 挂载 `/var/run/docker.sock` 以控制 Docker Daemon
3. **HostPath 挂载**: 挂载宿主机敏感目录（如 `/etc`, `/root`）
4. **Capabilities 滥用**: 利用 `CAP_SYS_ADMIN` 等危险权限
5. **内核漏洞**: 利用 DirtyPipe、DirtyCOW 等内核漏洞

**检测方法**:
- 监控容器以特权模式运行（`securityContext.privileged: true`）
- 检测 Docker Socket 挂载（`/var/run/docker.sock`）
- 监控异常的 Capabilities（`CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`）
- 检测 HostPath 挂载到敏感目录
- 监控容器内执行的系统调用（`execve`, `mount`, `ptrace`）
- 检测容器内访问宿主机进程（`/proc/1/root`）

**缓解措施**:
1. **禁用特权容器**: 使用 Pod Security Standards 限制特权容器
2. **限制 Capabilities**: 使用 `drop: [ALL]` 并仅添加必需的权限
3. **禁止危险挂载**: 限制 Docker Socket 和 HostPath 挂载
4. **使用安全 Contexts**: 配置 `runAsNonRoot`, `readOnlyRootFilesystem`
5. **应用 SELinux/AppArmor**: 启用强制访问控制
6. **及时修补内核**: 保持宿主机内核为最新版本
7. **使用运行时安全工具**: Falco、Aqua、Sysdig 等

**真实案例**:

**案例 1 - TeamTNT（2020-2023）**:
TeamTNT 是一个臭名昭著的云原生攻击团伙，专门针对容器和 Kubernetes 环境。他们通过扫描暴露的 Docker API 和 Kubernetes API，部署恶意容器并挂载 Docker Socket (`/var/run/docker.sock`)，从而逃逸到宿主机。一旦获得宿主机权限，TeamTNT 会安装加密货币挖矿软件、窃取 AWS 凭证，并横向移动到其他容器。

**参考**: https://unit42.paloaltonetworks.com/teamtnt-operations-cloud-environments/

**案例 2 - Siloscape（2021）**:
Siloscape 是首个针对 Windows 容器的恶意软件，能够逃逸容器并获取 Kubernetes 集群访问权限。攻击者利用 Windows 容器的漏洞实现逃逸，然后窃取 Kubernetes ServiceAccount Token 以访问集群 API。Siloscape 主要用于部署后门和数据窃取。

**参考**: https://unit42.paloaltonetworks.com/siloscape/

**参考**: https://attack.mitre.org/techniques/T1611/

**元数据**:
- category: "attack_technique"
- source: "MITRE"
- technique_id: "T1611"
- tactics: "Privilege Escalation"
- platform: "Containers"