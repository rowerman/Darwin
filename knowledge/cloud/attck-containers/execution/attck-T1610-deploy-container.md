# MITRE ATT&CK: T1610 - Deploy Container

**技术 ID**: T1610
**战术**: Execution
**平台**: Containers
**描述**: 攻击者可能会在环境中部署容器，以促进执行操作或规避防御措施。在某些情况下，攻击者可能会部署新的容器来执行与特定镜像或部署相关的进程，例如执行或下载恶意软件的进程。在其他情况下，攻击者可能会部署一个未配置网络规则、用户限制等的新容器，以绕过环境中现有的防御措施。在 Kubernetes 环境中，攻击者可能会尝试将特权容器或易受攻击的容器部署到特定节点，以便逃逸到主机并访问该节点上运行的其他容器。
容器可以通过多种方式部署，例如通过 Docker 的 create 和 start API，或者通过 Kubernetes 仪表板、Kubeflow 等 Web 应用程序。在 Kubernetes 环境中，容器可以通过 ReplicaSets 或 DaemonSets 等工作负载进行部署，这些工作负载能够让容器在多个节点上部署。攻击者可能会基于获取或构建的恶意镜像，或者从在运行时下载并执行恶意有效负载的良性镜像来部署容器。

**常见方法**:
1. 部署一个未配置网络规则、用户限制等的新容器，以绕过环境中现有的防御措施。
2. 将特权容器或易受攻击的容器部署到特定节点，以便逃逸到主机并访问该节点上运行的其他容器。
3. 通过 Docker 的 create 和 start API，或者通过 Kubernetes 仪表板、Kubeflow 等 Web 应用程序。
4. 通过 ReplicaSets 或 DaemonSets 等工作负载进行部署，这些工作负载能够让容器在多个节点上部署。

**检测方法**:
- 通过远程/API驱动的方式创建并启动容器，该容器的镜像不在允许列表中（或者被标记为latest），由非管理员主体执行，和/或使用危险的运行时属性启动（例如，--privileged、主机PID/NET命名空间、敏感的主机路径挂载、添加权限）。在短时间窗口内将该容器的创建➜启动➜首次网络。

**缓解措施**:
1. 在部署前扫描镜像，并阻止那些不符合安全策略的镜像。在 Kubernetes 环境中，可以使用准入控制器在容器部署请求通过认证后、但容器部署前对镜像进行验证。
2. 将与容器服务的通信限制在受管理和安全的通道上，例如本地Unix套接字或通过SSH进行的远程访问。通过禁用对Docker API、Kubernetes API服务器和容器编排Web应用程序的未认证访问，要求通过TLS使用安全端口访问来与API通信。在部署于云环境中的Kubernetes集群中，使用原生云平台功能来限制被允许访问API服务器的IP范围。在可能的情况下，考虑为Kubernetes API启用即时（JIT）访问，以对访问施加额外限制。
3. 通过使用网络代理、网关和防火墙，拒绝对内部系统的直接远程访问。
4. 通过将容器仪表板的访问权限限制在仅必要的用户范围内，来执行最小权限原则。使用Kubernetes时，应避免向用户授予通配符权限或将用户添加到system:masters组，并且要使用RoleBindings而非ClusterRoleBindings，以将用户权限限制在特定的命名空间中。

**真实案例**:

**案例 1 - TeamTNT（2021-2022）**:

TeamTNT已在受害者环境中部署了不同类型的容器以促进执行。
TeamTNT还向在本地IP地址范围内发现的Kubernetes集群传输了加密货币挖矿软件

**参考**: 
- https://www.intezer.com/blog/cloud-security/attackers-abusing-legitimate-cloud-monitoring-tools-to-conduct-cyber-attacks/
- https://documents.trendmicro.com/assets/white_papers/wp-tracking-the-activities-of-teamTNT.pdf
- https://blog.talosintelligence.com/teamtnt-targeting-aws-alibaba-2/

**案例 2 - Peirates（2022）**:

Peirates可以部署一个挂载其节点根文件系统的Pod，然后执行命令在该节点上创建反向shell。

**参考**: https://github.com/inguardians/peirates

**参考**: https://attack.mitre.org/techniques/T1610/

**元数据**:
- category: "attack_technique"
- source: "MITRE"
- technique_id: "T1610"
- tactics: "Execution"
- platform: "Containers"
