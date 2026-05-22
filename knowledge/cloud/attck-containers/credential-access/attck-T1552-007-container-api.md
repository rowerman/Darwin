# MITRE ATT&CK: T1552.007 - Container API

**技术 ID**: T1552.007
**战术**: Credential Access
**平台**: Containers
**描述**: 攻击者可能会通过容器环境中的API收集凭证。这些环境中的API，如Docker API和Kubernetes API，允许用户远程管理其容器资源和集群组件。攻击者可能会访问Docker API来收集日志，这些日志中包含云、容器以及环境中其他各种资源的凭证。拥有足够权限的攻击者（例如通过Pod的服务账户）也可能使用Kubernetes API从Kubernetes API服务器检索凭证。这些凭证可能包括Docker API认证所需的凭证或Kubernetes集群组件的密钥。

**常见方法**:
1. 攻击者可能会使用Docker API来收集日志，这些日志中包含云、容器以及环境中其他各种资源的凭证。
2. 攻击者可能会使用Kubernetes API从Kubernetes API服务器检索凭证。这些凭证可能包括Docker API认证所需的凭证或Kubernetes集群组件的密钥。

**检测方法**:
- 检测会将异常的Docker或Kubernetes API请求与对日志、密钥或服务账户的访问相关联。它会监控对docker logs、kubectl get secrets的未授权使用，或对Kubernetes API服务器端点的直接API调用。该检测能识别攻击者从基本的Pod/容器交互升级到可暴露敏感凭证材料的特权API调用的行为模式。

**缓解措施**:
1. 将与容器服务的通信限制在受管理和安全的通道上，例如本地Unix套接字或通过SSH进行的远程访问。通过禁用对Docker API和Kubernetes API服务器的未认证访问，要求通过TLS使用安全端口访问来与这些API进行通信。在云环境中部署的Kubernetes集群中，使用原生云平台功能来限制被允许访问API服务器的IP范围。在可能的情况下，考虑启用对Kubernetes API的即时（JIT）访问，以对访问施加额外限制
2. 通过使用网络代理、网关和防火墙，拒绝对内部系统的直接远程访问。
3. 对Kubernetes中的服务账户等特权账户采用最小权限原则。例如，如果某个Pod不需要访问Kubernetes API，可考虑完全禁用该服务账户。
4. 对容器API实施身份验证和基于角色的访问控制，以将用户限制在所需的最小权限范围内。
使用Kubernetes时，应避免向用户授予通配符权限或把用户添加到 system:masters 组中，并且要使用
RoleBindings 而非 ClusterRoleBindings，以将用户权限限制在特定的命名空间内。

**真实案例**:

**案例 1 - Peirates（2022）**:

Peirates可以查询Kubernetes API以获取密钥。

**参考**: https://github.com/inguardians/peirates

**参考**: https://attack.mitre.org/techniques/T1552.007/

**元数据**:
- category: "attack_technique"
- source: "MITRE"
- technique_id: "T1552.007"
- tactics: "Credential Access"
- platform: "Containers"
