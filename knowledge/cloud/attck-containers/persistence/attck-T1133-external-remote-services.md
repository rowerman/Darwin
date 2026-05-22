# MITRE ATT&CK: T1133 - External Remote Services

**技术 ID**: T1133
**战术**: Persistence, Initial Access
**平台**: Containers
**描述**: 攻击者可能会利用面向外部的远程服务来初始访问网络和 / 或在网络中保持持久存在。虚拟专用网络（VPN）、思杰（Citrix）等远程服务以及其他访问机制允许用户从外部位置连接到企业内部网络资源。通常存在远程服务网关，用于管理这些服务的连接和凭据认证。Windows 远程管理和虚拟网络计算（VNC）等服务也可在外部使用。使用这些服务通常需要获取有效账户的访问权限，这可以通过凭据钓鱼获得，或者在攻陷企业网络后从用户那里获取凭据。在一次攻击行动中，对远程服务的访问可能会被用作一种冗余或持久的访问机制。
也可能通过不需要认证的暴露服务获得访问权限。在容器化环境中，这可能包括暴露的 Docker API、Kubernetes API 服务器、kubelet，或者像 Kubernetes 仪表板这样的 Web 应用程序。攻击者还可能通过在受感染的系统上配置Tor隐藏服务来在网络上建立持久化。攻击者可能会利用工具ShadowLink来协助安装和配置Tor隐藏服务。由于ShadowLink会在受感染的系统上设置一个.onion地址，因此Tor隐藏服务可以通过Tor网络访问。ShadowLink可用于将任何入站连接转发到RDP，使攻击者能够进行远程访问。攻击者可能通过将ShadowLink伪装成微软 Defender 应用程序，使其在系统上保持持久化。

**常见方法**:
1. 利用暴露的远程服务网关来获取对企业内部网络资源的访问权限。
2. 利用暴露的 Docker API、Kubernetes API 服务器、kubelet 等服务来获取对容器化环境的访问权限。
3. 利用暴露的 Web 应用程序（如 Kubernetes 仪表板）来获取对容器化环境的访问权限。

**检测方法**:
- 异常或未授权的外部远程访问尝试（例如，RDP、VPN、Citrix）→ 多次登录失败，随后从非常见地理位置或在工作时间之外出现成功的会话→ 后续的内部横向移动或数据泄露活动。
- 来自外部IP的重复SSH、VPN或RDP网关认证尝试→后续成功登录→远程shell或横向移动活动（例如，scp/sftp）。
- 来自外部来源的意外VNC/SSH/屏幕共享传入或传出连接→多次登录失败后成功→远程交互式会话或异常文件传输。
- 来自未授权外部IP与暴露的容器服务（例如，Docker API、Kubernetes API服务器）的连接→异常的容器创建/启动→集群节点内的横向活动。

**缓解措施**:
1. 禁用或阻断可能不必要的可远程访问服务。
2. 通过VPN等集中管理的集中器和其他受管理的远程访问系统限制对远程服务的访问。
3. 对远程服务账户使用强大的双因素或多因素认证，以降低攻击者利用被盗凭据的能力，但要注意某些双因素认证实施中的多因素认证拦截技术。
4. 通过使用网络代理、网关和防火墙，拒绝对内部系统的直接远程访问。
5. 限制所有与公共Tor节点之间的来往流量。

**真实案例**:

**案例 1 - Sandworm Team（2015）**:
在2015年乌克兰电力攻击期间，沙虫团队（Sandworm Team）安装了一个经过修改的Dropbear SSH客户端作为针对目标系统的后门。

**参考**: https://www.boozallen.com/content/dam/boozallen/documents/2016/09/ukraine-report-when-the-lights-went-out.pdf

**案例 2 - Doki（2020）**:
Doki是通过开放的Docker守护进程API端口执行的。

**参考**: https://www.intezer.com/blog/cloud-security/watch-your-containers-doki-infecting-docker-servers-in-the-cloud/

**参考**: https://attack.mitre.org/techniques/T1133/

**元数据**:
- category: "attack_technique"
- source: "MITRE"
- technique_id: "T1133"
- tactics: "Persistence"
- platform: "Containers"
