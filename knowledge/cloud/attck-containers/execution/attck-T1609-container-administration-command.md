# MITRE ATT&CK: T1609 - Container Administration Command

**技术 ID**: T1609
**战术**: Execution
**平台**: Containers
**描述**: 攻击者可能会滥用容器管理服务在容器内执行命令。诸如Docker守护进程、Kubernetes API服务器或kubelet之类的容器管理服务可能允许对环境中的容器进行远程管理。在Docker中，攻击者可能会在容器部署期间指定一个执行脚本或命令的入口点，或者他们可能会使用诸如docker exec之类的命令在运行中的容器内执行命令。在Kubernetes中，如果攻击者拥有足够的权限，他们可能通过与Kubernetes API服务器、kubelet交互，或者通过运行诸如kubectl exec之类的命令，在集群中的容器中获得远程执行权限。

**常见方法**:
1. 在Docker中，攻击者可能会在容器部署期间指定一个执行脚本或命令的入口点，或者他们可能会使用诸如docker exec之类的命令在运行中的容器内执行命令。
2. 在Kubernetes中，如果攻击者拥有足够的权限，他们可能通过与Kubernetes API服务器、kubelet交互，或者通过运行诸如kubectl exec之类的命令，在集群中的容器中获得远程执行权限。

**检测方法**:
- 防御者可以通过观察管理工具的异常使用（docker exec、kubectl exec或对kubelet的API调用）与容器内意外的进程创建之间的关联，来检测容器管理命令的滥用情况。行为链包括未授权的API请求，随后是在运行的Pod或容器内执行命令，这些行为通常源自不常见的用户账户、自动化脚本或预期集群管理平面之外的IP地址。

**缓解措施**:
1. 从容器中移除不必要的工具和软件。
2. 尽可能使用只读容器、只读文件系统和最小化镜像来防止命令执行。只要有可能，还应考虑使用应用程序控制和软件限制工具（如SELinux提供的工具）来限制对容器中文件、进程和系统调用的访问。
3. 将与容器服务的通信限制在受管理和安全的通道上，例如本地Unix套接字或通过SSH进行的远程访问。通过禁用对Docker API和Kubernetes API服务器的未认证访问，要求通过TLS使用安全端口访问来与API通信。在部署于云环境中的Kubernetes集群中，使用原生云平台功能来限制被允许访问API服务器的IP范围。在可能的情况下，考虑启用对Kubernetes API的即时（JIT）访问，以对访问施加额外限制。
4. 确保容器默认不以root用户运行。在Kubernetes环境中，考虑定义Pod安全标准以防止Pod运行特权容器，并使用NodeRestriction准入控制器来阻止kubelet访问其所属节点之外的节点和Pod。
5. 对容器服务实施身份验证和基于角色的访问控制，以将用户权限限制在所需的最小范围内。使用Kubernetes时，应避免向用户授予通配符权限或将用户添加到 system:masters 组中，并且应使用
RoleBindings 而非 ClusterRoleBindings 来将用户权限限制在特定的命名空间内。

**真实案例**:

**案例 1 - Hildegard（2021）**:

Hildegard 是通过kubelet API的run命令以及在运行的容器上执行命令来运行的

**参考**: https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/

**案例 2 - Kinsing（2021）**:

Kinsing 通过一个运行shell脚本的Ubuntu容器入口点被执行

**参考**: https://blog.aquasec.com/threat-alert-kinsing-malware-container-vulnerability

**参考**: https://attack.mitre.org/techniques/T1609/

**元数据**:
- category: "attack_technique"
- source: "MITRE"
- technique_id: "T1609"
- tactics: "Execution"
- platform: "Containers"
