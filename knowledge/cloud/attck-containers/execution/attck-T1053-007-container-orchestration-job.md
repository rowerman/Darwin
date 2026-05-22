# MITRE ATT&CK: T1053.007 - Container Orchestration Job

**技术 ID**: T1053.007
**战术**: Execution、Persistence、Privilege Escalation
**平台**: Containers
**描述**: 攻击者可能会滥用 Kubernetes 等容器编排工具提供的任务调度功能，来调度配置为执行恶意代码的容器的部署。容器编排作业会在特定的日期和时间运行这些自动化任务，类似于 Linux 系统上的 cron 作业。这种类型的部署还可以配置为随时间维持一定数量的容器，从而自动完成在集群中保持持久性的过程。在 Kubernetes 中，CronJob 可用于调度运行一个或多个容器以执行特定任务的 Job。因此，攻击者可能会利用 CronJob 来调度 Job 的部署，以便在集群内的各个节点中执行恶意代码。

**常见方法**:
1. 攻击者可能会创建一个 CronJob，配置为在特定的时间间隔内运行一个或多个容器。这些容器可能会执行恶意代码，例如在目标系统上安装后门或窃取敏感数据。
2. 攻击者可能会修改 CronJob 的配置，以改变其运行时间或触发条件。例如，攻击者可能会将 CronJob 配置为在每天凌晨运行，以隐藏其活动。
3. 攻击者可能会利用 CronJob 来执行特权操作，例如在目标系统上安装新的容器运行时或配置网络策略。

**检测方法**:
- 检测对容器编排平台（例如Kubernetes）的滥用行为，即攻击者创建定时任务（CronJobs）以维持持久化存在或在整个集群中执行恶意任务（Jobs）。

**缓解措施**:
1. 确保容器默认不以 root 用户身份运行。在 Kubernetes 环境中，考虑定义 Pod 安全标准，以防止 Pod 运行特权容器。
2. 限制用户账户的权限并修复权限提升途径，以便只有授权的管理员能够创建容器编排作业。

**真实案例**:

**参考**: https://attack.mitre.org/techniques/T1053.007/

**元数据**:
- category: "attack_technique"
- source: "MITRE"
- technique_id: "T1053.007"
- tactics: "Execution"
- platform: "Containers"
