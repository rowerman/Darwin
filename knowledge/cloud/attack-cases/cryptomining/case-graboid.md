# 攻击案例: Graboid Docker 挖矿蠕虫攻击

Project: Graboid Docker Cryptojacking Worm
Date: 2019-10-16
Severity: High

**攻击者**: 未公开
**时间**: 2019 年（披露时）
**目标**: 公网暴露且未认证的 Docker Engine API（Docker daemon）
**攻击类型**: 通过容器传播的挖矿蠕虫、资源劫持（Monero）

## 案例概述

Graboid 被认为是首个通过 Docker 容器传播的加密货币挖矿蠕虫。其主要入口是“未做认证/授权暴露到互联网的 Docker daemon”，攻击者通过远程下发 Docker 命令拉起恶意容器，随后容器内脚本从 C2 拉取易受害主机列表并随机扩散，同时部署矿工进行 Monero 挖矿。公开分析指出该活动感染超过 2,000 台未加固的 Docker 主机，并且矿工呈现随机启停的行为模式。

**关键事实**:
- 传播入口: 未认证暴露的 Docker Engine API（常见为 TCP `2375`）可被远程完全控制主机/容器运行
- 恶意镜像: `pocosow/centos:7.6.1810`（投递/扩散容器）与 `gakeaws/nginx`（内含矿工并伪装为 nginx）
- 脚本链: 典型脚本包括 `live.sh`、`worm.sh`、`cleanxmr.sh`、`xmr.sh`，并从 C2 下载包含 2000+ IP 的列表文件

## 攻击链分析

### 1. 初始访问 (Initial Access)

**技术**: 利用暴露的容器管理接口
**MITRE ATT&CK**: T1190 - Exploit Public-Facing Application

攻击者通过互联网发现未加固的 Docker daemon，并直接在远端执行 Docker 命令在受害主机上拉起恶意容器。

### 2. 执行 (Execution)

**技术**: 部署恶意容器并执行脚本链
**MITRE ATT&CK**: T1610 - Deploy Container

投递容器（`pocosow/centos`）启动后会执行入口脚本，并从 C2 拉取多段 shell 脚本与 IP 列表，完成扩散与矿工控制。

**执行命令示例**:
```bash
docker -H tcp://victim:2375 run -d --restart=always pocosow/centos:7.6.1810
```

### 3. 持久化 (Persistence)

**技术**: 依赖集群内其他感染节点对矿工进行随机控制
**MITRE ATT&CK**: T1562.001 - Disable or Modify Tools

Graboid 的设计会在每轮迭代随机选择目标：向一个目标传播、停止另一个目标的矿工、启动第三个目标的矿工，导致矿工呈现“随机启停”的现象；公开材料未披露稳定的宿主级持久化机制。

### 4. 权限提升 (Privilege Escalation)

**技术**: 通过暴露的 Docker daemon 扩大控制面（依赖环境配置）
**MITRE ATT&CK**: T1611 - Escape to Host

在“Docker daemon 公网暴露且允许创建高权限容器”的情况下，攻击者通常可以通过挂载宿主机文件系统、进入宿主命名空间等方式进一步扩大控制面；公开分析未披露 Graboid 必然包含该步骤，但该风险与入口配置强相关。

### 5. 凭证访问 (Credential Access)

**技术**: 访问容器/宿主机内的敏感配置（依赖环境配置）
**MITRE ATT&CK**: T1552 - Unsecured Credentials

公开分析重点在蠕虫传播与挖矿控制；在真实环境中，一旦攻击者能创建容器并获得更高权限，可能进一步读取宿主机或运行时中的敏感配置与凭证。

### 6. 横向移动 (Lateral Movement)

**技术**: 通过 Docker 客户端对其他暴露 daemon 发起远程拉起
**MITRE ATT&CK**: T1613 - Container and Resource Discovery

投递镜像包含 Docker 客户端工具，用于与其他 Docker 主机通信并远程拉起同类容器，实现蠕虫式传播。

### 7. 影响 (Impact)

**技术**: 资源劫持（挖矿）
**MITRE ATT&CK**: T1496 - Resource Hijacking

攻击者部署矿工进行 Monero 挖矿，造成 CPU 资源被占用、业务性能下降与云成本上升。

## TTP 映射

| MITRE ATT&CK ID | 技术名称 | 描述 |
|-----------------|---------|------|
| T1190 | Exploit Public-Facing Application | 利用暴露的 Docker daemon 作为入口 |
| T1610 | Deploy Container | 远程拉起容器并执行脚本链 |
| T1613 | Container and Resource Discovery | 发现并选择可传播的 Docker 主机 |
| T1496 | Resource Hijacking | 挖矿导致资源消耗与成本增加 |

## 威胁指标 (IoC)

**镜像/仓库**:
- `pocosow/centos:7.6.1810`
- `gakeaws/nginx`
- `gakeaws/mysql`（与 `gakeaws/nginx` 内容相同的另一个镜像）

**脚本名**:
- `live.sh`
- `worm.sh`
- `cleanxmr.sh`
- `xmr.sh`

## 检测方法

### 主机/Docker 层检测

```bash
# 检查 Docker daemon 是否对外监听高风险端口（示例）
ss -lntp | grep -E ":2375|:2376"

# 检查是否存在可疑镜像/容器（示例）
docker images | grep -E "pocosow/centos|gakeaws/nginx|gakeaws/mysql"
docker ps -a | grep -E "pocosow/centos|gakeaws/nginx|gakeaws/mysql"
```

### 网络层检测

```bash
# 查找容器/主机对未知外部 C2 的周期性出站连接（需结合实际日志源）
# 重点关注：容器新建后短时间内的大量外联与对随机 IP 的 2375 探测
```

## 防护建议

### 预防措施

1. **禁止 Docker daemon 直接暴露公网**：优先使用本地 socket；如必须开放，启用 TLS/mTLS 并配合网络 ACL 进行访问控制。
2. **镜像来源治理**：对拉取的镜像进行签名校验/漏洞与恶意扫描，限制从公共仓库直接拉取到生产环境。
3. **运行时检测与告警**：对异常容器创建、异常 CPU 飙升、以及 `curl|bash` 等脚本化投递行为建立告警联动。

## 参考资料

- [Unit 42: Graboid: First-Ever Cryptojacking Worm Found in Images on Docker Hub](https://unit42.paloaltonetworks.com/graboid-first-ever-cryptojacking-worm-found-in-images-on-docker-hub/)
