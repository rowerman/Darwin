# MITRE ATT&CK: T1613 - Container and Resource Discovery

**技术 ID**: T1613
**战术**: Discovery
**平台**: Containers
**描述**: 攻击者可能会尝试发现容器环境中可用的容器和其他资源。其他资源可能包括镜像、部署、 pods、节点以及集群状态等其他信息。这些资源可以在Kubernetes仪表板等Web应用程序中查看，也可以通过Docker和Kubernetes API进行查询。在Docker中，日志可能会泄露有关环境的信息，例如环境配置、可用的服务以及受害者可能使用的云提供商。对这些资源的发现可能会为攻击者在该环境中的下一步行动提供信息，例如如何进行横向移动以及使用哪些方法来执行操作。

**常见方法**:
1. 使用Kubernetes仪表板或kubectl命令行工具来查看容器环境中的资源。
2. 使用Docker命令行工具来查看Docker环境中的资源。
3. 使用Kubernetes和Docker API来查询资源。

**检测方法**:
- 检测攻击者在容器化环境中枚举容器、Pod、节点及相关资源的尝试。防御者可能会观察到对Docker或Kubernetes的异常API调用（例如，“docker ps”“kubectl get pods”“kubectl get nodes”）、针对Kubernetes仪表板的异常账户活动，或对容器元数据端点的意外查询。这些事件应与用户上下文和网络活动相关联，以揭示资源探测尝试。

**缓解措施**:
1. 将与容器服务的通信限制在受管理和安全的渠道，例如本地Unix套接字或通过SSH进行的远程访问。通过禁用对Docker API和Kubernetes API服务器的未认证访问，要求通过TLS使用安全端口访问来与API通信。在云环境中部署的Kubernetes集群中，使用原生云平台功能来限制被允许访问API服务器的IP范围。在可能的情况下，考虑启用对Kubernetes API的即时（JIT）访问，以对访问施加额外限制
2. 通过使用网络代理、网关和防火墙，拒绝对内部系统的直接远程访问。
3. 通过将仪表板可见性限制为仅必要用户，来执行最小权限原则。使用Kubernetes时，避免向用户授予通配符权限或将用户添加到system:masters组，并且使用RoleBindings而非ClusterRoleBindings，以将用户权限限制在特定命名空间内。

**真实案例**:

**案例 1 - TeamTNT（2021-2022）**:

TeamTNT已使用docker ps检查运行中的容器，并使用docker inspect检查特定的容器名称。
TeamTNT还搜索了在本地网络中运行的Kubernetes pods。

**参考**: 
- https://documents.trendmicro.com/assets/white_papers/wp-tracking-the-activities-of-teamTNT.pdf
- https://blog.talosintelligence.com/teamtnt-targeting-aws-alibaba-2/

**案例 2 - Peirates（2022）**:

Peirates能够枚举特定命名空间中的Kubernetes pods。

**参考**: https://github.com/inguardians/peirates

**参考**: https://attack.mitre.org/techniques/T1613/

**元数据**:
- category: "attack_technique"
- source: "MITRE"
- technique_id: "T1613"
- tactics: "Discovery"
- platform: "Containers"
