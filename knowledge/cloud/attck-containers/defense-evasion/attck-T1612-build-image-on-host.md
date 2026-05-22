# MITRE ATT&CK: T1612 - Build Image on Host

**技术 ID**: T1612
**战术**: Defense Evasion
**平台**: Containers
**描述**: 攻击者可能会直接在主机上构建容器镜像，以绕过那些监控从公共注册表获取恶意镜像的防御措施。可能会向Docker API发送远程build请求，其中包含一个Dockerfile，该文件会从公共或本地注册表中拉取一个原始基础镜像（如alpine），然后在此基础上构建自定义镜像。攻击者可能会利用该buildAPI在主机上构建包含从其命令与控制（C2）服务器下载的恶意软件的自定义镜像，然后他们可能会使用该自定义镜像来实施部署容器操作。如果基础镜像是从公共注册表拉取的，防御措施可能不会将该镜像检测为恶意镜像，因为它是一个原始镜像。如果基础镜像已存在于本地注册表中，那么拉取操作可能会被认为更不可疑，因为该镜像已经在环境中了。

**常见方法**:
1. 攻击者可能会利用Docker API发送远程build请求，其中包含一个Dockerfile，该文件会从公共或本地注册表中拉取一个原始基础镜像（如alpine），然后在此基础上构建自定义镜像。
2. 攻击者可能会在Dockerfile中包含恶意软件的下载指令，以便在构建过程中从C2服务器下载恶意软件。
3. 攻击者可能会利用自定义镜像来部署容器，其中包含恶意软件。

**检测方法**:
- 利用Docker或Kubernetes的编程接口（API）检测直接在主机上进行的容器镜像构建活动。防御者可能会观察到Docker构建请求、异常的Dockerfile指令（例如从未知IP下载代码），或者新镜像创建后立即部署的情况。这种行为链通常包括意外的镜像创建事件，以及与非标准或不可信目标的出站网络通信相关联。

**缓解措施**:
1. 对环境中部署的镜像进行审计，以确保它们不包含任何恶意组件。
2. 将与容器服务的通信限制在本地Unix套接字或通过SSH进行的远程访问。通过禁用对2375端口上Docker API的未认证访问，要求通过TLS使用安全端口访问来与API通信。相反，应通过2376端口上的TLS与Docker API进行通信。
3. 通过使用网络代理、网关和防火墙，拒绝对内部系统的直接远程访问。
4. 确保容器默认不以root用户身份运行。在Kubernetes环境中，考虑定义Pod安全标准，以防止Pod运行特权容器。

**真实案例**:

**案例 1 - Team Nautilus（2021）**:

自我们之前发布威胁报告以来，恶意行为者持续改进和调整其策略，既针对云原生应用的软件供应链，也针对其基础设施。

**参考**: https://info.aquasec.com/hubfs/Threat%20reports/AquaSecurity_Cloud_Native_Threat_Report_2021.pdf?utm_campaign=WP%20-%20Jun2021%20Nautilus%202021%20Threat%20Research%20Report&utm_medium=email&_hsmi=132931006&_hsenc=p2ANqtz-_8oopT5Uhqab8B7kE0l3iFo1koirxtyfTehxF7N-EdGYrwk30gfiwp5SiNlW3G0TNKZxUcDkYOtwQ9S6nNVNyEO-Dgrw&utm_content=132931006&utm_source=hs_automation

**参考**: https://attack.mitre.org/techniques/T1612/

**元数据**:
- category: "attack_technique"
- source: "MITRE"
- technique_id: "T1612"
- tactics: "Defense Evasion"
- platform: "Containers"
