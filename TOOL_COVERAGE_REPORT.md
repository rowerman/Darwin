# Darwin 工具/知识覆盖分析报告（benchmark 全部单点场景）

- 统计基准：`..\benchmark\cve_challenges\scenarios` 共 **89** 个带 GUIDE.md 的单点场景（web 18 / db 9 / k8s 29 / cloud 33）。
- Darwin 侧核对：`darwin/tools/attack_server.py` 实际注册 **115** 个攻击工具 + `recon_server.py` **15** 个侦察工具；`knowledge/` 目录按场景直接对应条目见下表。
- 结论分布：直接覆盖 **43**、组合覆盖 **21**、部分覆盖 **11**、工具可组合但专项知识缺失 **14**。

## 判定口径
- 直接覆盖：存在对口/专用工具，且知识库有对应条目，可开箱执行。
- 组合覆盖：知识条目在库，但无单一专用工具；利用流程由 `kubectl_exec`/`shell_exec`/`curl`/`http_post` 等通用原语完成。
- 部分覆盖：工具存在但关键环节缺失，或依赖环境二进制/参数描述未覆盖（见备注）。
- 知识缺失：HTTP/DB/云通用工具可发出请求，但知识库无该场景专项条目，成功率依赖 LLM 先验。

| 域 | 场景 | 技术 | 判定 | Darwin 工具 | 知识条目 | 备注 |
|---|---|---|---|---|---|---|
| web | web/graphql-idor | GraphQL introspection + IDOR | 直接覆盖 | graphql_introspect / http_post | web_supplement:graphql-introspection-idor |  |
| web | web/jwt-alg-none | JWT alg:none | 部分覆盖 | jwt_forge | jwt-manipulation（通用） | jwt_forge 算法参数描述未列出 none，模板传 algorithm=none+空 secret 可生成，但依赖 LLM 试出 |
| web | web/mssql-xp-cmdshell | MSSQL xp_cmdshell | 直接覆盖 | mssqlclient_query / mssql_query | db_exploitation:mssql-xp-cmdshell-enable |  |
| web | web/mysql-udf | MySQL UDF Abuse | 直接覆盖 | mysql_query / mysql_file_write | db_exploitation:mysql-udf-privesc |  |
| web | web/php-deserialization | Insecure PHP deserialization | 直接覆盖 | php_serialize_generate / send_payload | web_supplement:php-deserialization-auth-bypass |  |
| web | web/postgres-sqli | CVE-2025-1094 | 部分覆盖 | sqlmap_test / psql_query / send_payload | sqli 通用条目；无 CVE-2025-1094 编码绕过专项 | 编码绕过参数需手工构造，sqlmap 不一定自动命中 |
| web | web/ssrf-internal | N/A (SSRF misconfiguration) | 直接覆盖 | ssrf_probe / send_payload | web_supplement:ssrf-internal-probe |  |
| web | web/ssrf-localhost | N/A (SSRF misconfiguration) | 组合覆盖 | ssrf_probe / http_post / send_payload | ssrf-internal-probe（通用） | localhost 过滤绕过需构造 host 解析/重定向参数 |
| web | web/ssti-jinja2 | N/A (SSTI vulnerability) | 直接覆盖 | ssti_inject | web_supplement:ssti-jinja2-rce | 工具内置 jinja2 检测与 RCE payload |
| web | web/tomcat-deserialization | CVE-2025-24813 | 直接覆盖 | tomcat_exploit / ysoserial_generate / file_upload / send_payload | web_vulnerabilities:tomcat-deserialization-rce; nuclei:CVE-2025-24813 | 需环境中存在 ysoserial-all.jar（工具自动探测 /opt、/usr/share 等路径） |
| web | web/tomcat-race-condition | CVE-2024-50379 | 直接覆盖 | parallel_request / send_payload | web_vulnerabilities:tomcat-race-condition-rce | 并发 PUT 由 parallel_request 直接支持 |
| web | web/wordpress-jupiterx-lfi | CVE-2025-0366 | 部分覆盖 | php_filter_chain / curl_get / send_payload | lfi-path-traversal（通用）；无 CVE-2025-0366 专项 | LFI→log/session 投毒 RCE 需 LLM 组合多步 |
| web | web/wordpress-jwt-copypress | CVE-2025-8625 | 部分覆盖 | jwt_forge / http_post / send_payload | jwt-manipulation（通用）；无 CVE-2025-8625 专项模板 | 插件私有 JWT 校验与特权端点参数需从页面/提示中探测 |
| web | web/wordpress-simple-file-list | CVE-2025-34085 | 直接覆盖 | file_upload / send_payload | nuclei:CVE-2025-34085 |  |
| web | web/wordpress-wpbookit | CVE-2025-6058 | 直接覆盖 | file_upload / send_payload | nuclei:CVE-2025-6058 |  |
| web | web/xss-stored | Stored XSS | 组合覆盖 | xss_reflection_test / curl_get / DAVE L2 浏览器 | xss-reflected（通用） | 存储型 XSS 需投递后等待 admin bot 访问并轮询 /steal |
| web | web/xxe-basic | XXE (XML External Entity) | 直接覆盖 | xxe_inject | web_supplement:xxe-file-read |  |
| web | web/xxe-svg | XXE (XML External Entity) | 直接覆盖 | xxe_inject(custom_xml) / file_upload | xxe-file-read（通用） | SVG 内容通过 custom_xml 参数注入 |
| db | db/couchdb-rce | N/A (Erlang native view RCE) | 直接覆盖 | couchdb_query | network:couchdb-replication-privesc | 工具内置 /_replicate 提权链 |
| db | db/elasticsearch-script | N/A (script injection) | 直接覆盖 | elasticsearch_query | network:elasticsearch-script-injection |  |
| db | db/mongodb-nosqli | N/A (NoSQL injection) | 直接覆盖 | nosql_inject / mongodb_query | network:mongodb-nosqli-regex |  |
| db | db/mongodb-unauth | N/A (misconfiguration) | 直接覆盖 | mongodb_query | network:mongodb-unauth-access |  |
| db | db/mssql-linked-server | MSSQL Linked Server | 直接覆盖 | mssqlclient_query / mssql_query | db_exploitation:mssql-linked-server-lateral |  |
| db | db/mysql-udf-direct | MySQL UDF Abuse | 直接覆盖 | mysql_query / mysql_file_write | db_exploitation:mysql-udf-privesc |  |
| db | db/oracle-tns | TNS Poisoning | 部分覆盖 | oracle_tns_poison / oracle_query | network:oracle-tns-poisoning; oracle-utl-file-exploitation | TNS 工具覆盖 SID/连接包探测，MITM 代理环节需 shell/python；凭据已知时 oracle_query 可直接取 flag |
| db | db/postgres-weak-auth | N/A (misconfiguration) | 直接覆盖 | psql_query / test_db_credential | network:postgresql-copy-program-rce-weak-auth |  |
| db | db/redis-unauth | N/A (misconfiguration) | 直接覆盖 | redis_cmd / ssh_key_exec | unauth_services:redis-unauth-exploit / redis-unauth-ssh-keygen |  |
| k8s | k8s/cap-sys-admin-cgroup | CAP_SYS_ADMIN abuse | 直接覆盖 | container_escape_cgroup | k8s_escape:cgroup-release-agent | 工具内置 release_agent 逃逸链 |
| k8s | k8s/cap-sys-ptrace-inject | CAP_SYS_PTRACE abuse | 组合覆盖 | kubectl_exec(gdb) / shell_exec | k8s-escape-supplement:ptrace-host-injection | gdb 位于 pod 镜像内，经 kubectl_exec 可用 |
| k8s | k8s/cni-ip-spoof | N/A (IP spoofing) | 组合覆盖 | kubectl_exec(ip addr add) / shell_exec | k8s-network-bypass:cni-ip-spoofing |  |
| k8s | k8s/cri-socket-escape | CRI socket abuse | 直接覆盖 | crictl_cmd | k8s_escape:cri-socket-escape |  |
| k8s | k8s/docker-socket-escape | Docker socket abuse | 直接覆盖 | container_escape_docker_sock | k8s_escape:docker-socket-escape |  |
| k8s | k8s/etcd-unauth | N/A (misconfiguration) | 直接覆盖 | etcdctl_get / k8s_etcd_keys | k8s_escape:etcd-navigation |  |
| k8s | k8s/externalip-hijack | CVE-2020-8554 | 组合覆盖 | shell_exec(kubectl apply Service) / kubectl_exec(nc 监听) | k8s-networking:externalip-hijack |  |
| k8s | k8s/gitrepo-cve-2024-10220 | CVE-2024-10220 | 组合覆盖 | kubectl_run / shell_exec / kubectl_exec | k8s-misconfig:gitrepo-volume + post-checkout-hook | 需攻击者可控 git 仓库 + 创建 gitRepo 卷 Pod |
| k8s | k8s/helm-tiller | N/A (misconfiguration) | 直接覆盖 | helm | k8s-misconfig:helm-tiller-unauth | helm 工具描述直接面向 Tiller 44134 |
| k8s | k8s/hostpath-escape | N/A (hostPath mount) | 直接覆盖 | container_escape_procfs / container_escape_mount_disk / nsenter_exec | k8s_escape:hostpath-symlink-escape |  |
| k8s | k8s/ingress-nginx-rce | CVE-2025-1974 | 部分覆盖 | send_payload / http_post + shell_exec | k8s-networking:ingress-nginx-rce | 需 gcc 编译 .so、openssl；无专用 exploit 工具 |
| k8s | k8s/ingress-snippet | CVE-2021-25742 | 组合覆盖 | shell_exec(kubectl annotate) / curl / kubectl logs | k8s-networking:ingress-snippet-injection |  |
| k8s | k8s/kubelet-unauth | N/A (misconfiguration) | 直接覆盖 | kubelet_probe / k8s_kubelet_exec | k8s_escape:kubelet-anonymous-api |  |
| k8s | k8s/localhost-bypass | CVE-2020-8558 | 组合覆盖 | kubectl_exec(wget/curl) | k8s-networking:kube-proxy-localhost-bypass |  |
| k8s | k8s/mutable-image-tag | N/A (image tag mutation) | 组合覆盖 | docker_registry(push) / kubectl_run / shell_exec(重启) | k8s-escape-supplement:mutable-image-tag | containerd mirror 拉取需环境配合 |
| k8s | k8s/networkpolicy-bypass | N/A (network policy bypass) | 组合覆盖 | kubectl_exec(label) / shell_exec | k8s-networking:networkpolicy-bypass + label-spoof |  |
| k8s | k8s/node-redirect | CVE-2020-8559 | 组合覆盖 | kubectl_exec / curl(节点代理) | k8s-networking:node-api-redirect | CVE-2020-8559 知识在库 |
| k8s | k8s/node-selector-evasion | N/A (scheduling bypass) | 组合覆盖 | kubectl_run / shell_exec(改 label/selector) | k8s-scheduling:node-selector-evasion |  |
| k8s | k8s/privileged-breakout | N/A (privileged pod) | 直接覆盖 | nsenter_exec / container_escape_* / check_capabilities / check_mounts | k8s escape 通用（cesc-001 / hacktricks） |  |
| k8s | k8s/rbac-secrets | N/A (misconfiguration) | 直接覆盖 | kubectl_get_secrets / k8s_secret_dump | k8s 通用条目（kubernetes_attacks） | 工具直接覆盖跨命名空间 secret dump |
| k8s | k8s/registry-poison | N/A (misconfiguration) | 直接覆盖 | docker_registry | k8s-misconfig:docker-registry-poisoning |  |
| k8s | k8s/runc-cve-2024-21626 | CVE-2024-21626 | 组合覆盖 | kubectl_run / kubectl_exec / shell_exec | k8s_runC:workdir-container-escape | 无专用工具（container_escape_runc 仅 CVE-2019-5736） |
| k8s | k8s/runc-cve-2025-31133 | CVE-2025-31133 | 组合覆盖 | kubectl_run / kubectl_exec / shell_exec | k8s_runC:devnull-container-escape | 同上 |
| k8s | k8s/runc-cve-2025-52881 | CVE-2025-52881 | 组合覆盖 | kubectl_run / kubectl_exec / shell_exec | k8s_runC:lsm-bypass-container-escape | 同上 |
| k8s | k8s/sa-cluster-admin | RBAC misconfiguration | 直接覆盖 | sa_token_read / k8s_secret_dump / kubectl_exec | k8s 通用条目 |  |
| k8s | k8s/sa-cross-ns | N/A (RBAC lateral) | 直接覆盖 | sa_token_read / kubectl_get_secrets / k8s_secret_dump | k8s_escape:sa-token-lateral |  |
| k8s | k8s/seccomp-bypass | N/A (misconfiguration) | 直接覆盖 | container_escape_procfs | k8s-hostpid-procfs | hostPID+procfs 主路径 |
| k8s | k8s/toleration-abuse | N/A (taint bypass) | 组合覆盖 | shell_exec(apply 带 toleration Pod) / kubectl_run | k8s-scheduling:toleration-abuse |  |
| k8s | k8s/webhook-inject | N/A (admission control abuse) | 组合覆盖 | kubectl_run / kubectl_exec / k8s_secret_dump | k8s-networking:webhook-injection |  |
| cloud | cloud/actor-token | N/A (actor/tenant validation bug, case #246) | 知识缺失 | curl / http_post / jwt_forge | 无专项条目 | tenant claim 校验缺失 |
| cloud | cloud/attachme-volume | N/A (control-plane ownership check missing) | 知识缺失 | curl / http_post | 无专项条目 | ocid.vol 枚举 + attach 属主绕过 |
| cloud | cloud/beta-endpoint | N/A (non-production endpoint skips audit, case #154) | 部分覆盖 | curl / http_post / aws_cli | 无专项条目 | SigV4 签名需自行构造或借助 aws_cli endpoint |
| cloud | cloud/buildfleet-registry | N/A (unauth internal registry, case #260 lineage) | 组合覆盖 | http_post(PUT /images) / send_payload / docker_registry | k8s-docker-registry-poisoning（近似） | 构建舰队专属 API 无专项条目 |
| cloud | cloud/cap-netraw-metadata | N/A (CAP_NET_RAW + ARP spoofing) | 部分覆盖 | kubectl_exec / tcpdump_capture / shell_exec | k8s-networking:cap-net-raw-arp-spoof | ARP 双向欺骗需 arpspoof/ettercap 或手工 raw socket |
| cloud | cloud/cf-injection | N/A (CF Fn::Sub injection) | 直接覆盖 | send_payload / http_post(YAML) | cloudformation_injection:cf-injection-001..003; aws-cfn-ssm-parameter |  |
| cloud | cloud/ci-poisoning | N/A (CI/CD script injection) | 组合覆盖 | http_post(提交 workflow) / shell_exec | cicd-pipeline-script-injection |  |
| cloud | cloud/cloudsql-index-rce | N/A (ATExecChangeOwner patch + ANALYZE, case #052) | 知识缺失 | psql_query | 无专项条目 | ATExecChangeOwner 补丁链需专项知识 |
| cloud | cloud/composer-depconf | N/A (global namespace dependency confusion, case #270) | 知识缺失 | http_post(PUT 包 + /resolve) | 无专项条目 | 依赖混淆发布链 |
| cloud | cloud/cosmiss-notebook | N/A (forwardingId authz bypass, case #073) | 知识缺失 | curl / http_post / send_payload | 无专项条目 | forwardingId 替换为纯 HTTP 组合，依赖 LLM 先验 |
| cloud | cloud/cross-account-trust | N/A (overly permissive trust policy) | 直接覆盖 | aws_sts_query / aws_iam_federation | aws-cross-account-assumerole |  |
| cloud | cloud/dataform-pt | N/A (cross-tenant path traversal, case #267) | 知识缺失 | http_post / curl | 无专项条目 | dataset_ref ../ 穿越 |
| cloud | cloud/extrareplica-repl | N/A (internal subnet + mis-anchored cert regex, case #061) | 部分覆盖 | psql_query / shell_exec(pg_basebackup) | 无专项条目 | pg_basebackup 未在工具/依赖清单，依赖环境二进制 |
| cloud | cloud/global-s3-squatting | N/A (global namespace resource squatting) | 直接覆盖 | aws_cli(s3 mb/put) / object_store_get | cloud-s3-bucket-monopoly |  |
| cloud | cloud/golden-saml | N/A (SAML signing key exposure) | 部分覆盖 | saml_forge / aws_iam_federation | cloud-golden-saml | saml_forge 只生成未签名断言；若服务端验签需补充签名步骤（python/xmlsec/openssl） |
| cloud | cloud/iam-enum-oracle | N/A (uncovered service error oracle, case #134/#137) | 知识缺失 | aws_sts_query / curl | 无专项条目 | 未记录 AccessDenied oracle 枚举 |
| cloud | cloud/lambda-passrole | N/A (command injection + IAM privesc) | 直接覆盖 | send_payload(注入代码) / aws_iam_federation / aws_cli | aws-iam-passrole-lambda |  |
| cloud | cloud/lowcode-secrets | N/A (connector store tenant-scope missing, case #249/#197) | 知识缺失 | curl / http_post | 无专项条目（nuclei 中 low-code 命中为无关模板） |  |
| cloud | cloud/multi-tenant-k8s | N/A (privileged container + hostPID escape) | 直接覆盖 | nsenter_exec / kubectl_exec / sa_token_read | k8s escape 通用条目 |  |
| cloud | cloud/notebook-escape | N/A (notebook escape + SA token) | 直接覆盖 | container_escape_docker_sock / check_cloud_metadata | cloud-ai-notebook-escape |  |
| cloud | cloud/oidc-federation | N/A (OIDC federation misconfiguration) | 直接覆盖 | jwt_forge / aws_iam_federation | cloud-oidc-claim-forge |  |
| cloud | cloud/omigod-agent | N/A (auth bypass in provider agent, CVE-2021-38647 lineage) | 组合覆盖 | send_payload / http_post(WSMan) | nuclei:CVE-2021-38647 |  |
| cloud | cloud/persistence-as-a-service | N/A (automation-runbook persistence, case #149) | 知识缺失 | http_post / curl | 无专项条目 | runbook 持久化后门 |
| cloud | cloud/pickle-model | N/A (pickle deserialization, case #091) | 知识缺失 | shell_exec(生成 pickle) / file_upload / check_cloud_metadata | 无专项条目（仅通用 pickle 资料） |  |
| cloud | cloud/rds-logfdw | N/A (log_fdw path traversal, case #015) | 知识缺失 | psql_query | 无 log_fdw 专项条目 | CREATE EXTENSION file_fdw + 读 grover_volume.conf 需 LLM 推导 |
| cloud | cloud/resource-explorer | N/A (unlogged search API, case #148) | 知识缺失 | curl / http_post | 无专项条目 | 无日志 search API 枚举 |
| cloud | cloud/sa-cross-namespace | N/A (overly permissive RBAC) | 直接覆盖 | sa_token_read / kubectl_get_secrets | k8s_escape:sa-token-lateral |  |
| cloud | cloud/scp-bypass | N/A (SCP enforcement gap) | 直接覆盖 | aws_sts_query(api_version=2010-05-08) / aws_cli | cloud-scp-legacy-bypass | 工具参数显式支持旧版 API 绕过 SCP |
| cloud | cloud/serverless-sa | N/A (over-scoped default SA, case #266/#272) | 知识缺失 | curl / http_post | 无专项条目 | 默认服务账号越权 |
| cloud | cloud/shared-nat | N/A (service-tag source-IP trust, case #259) | 组合覆盖 | http_post(egress 代理) / curl | cloud-service-tag-spoof（近似） |  |
| cloud | cloud/ssrf-to-imds | N/A (SSRF → IMDS) | 直接覆盖 | ssrf_probe / check_cloud_metadata / aws_cli | aws-imds-ssrf |  |
| cloud | cloud/synlapse-ir | N/A (ODBC driver injection, CVE-2022-29972 lineage, case #062) | 知识缺失 | send_payload / http_post | 无 CVE-2022-29972 模板/条目 | ODBC LOGIN_URL 注入依赖专项知识 |
| cloud | cloud/wireserver-bootstrap | N/A (unvalidated transport cert, case #255/#184) | 部分覆盖 | curl / http_post / shell_exec(openssl 解密) | cloud_metadata_proxy（wireserver 提及，弱） | RSA-OAEP/AES-GCM 解密与 CSR 流程需手工组合 |

## 主要缺口
1. 新增云厂商定制场景（CLOUD-23/24/25/26/30/31/32/34/36/37/38/40/41/42）无专项知识条目，纯依赖 HTTP 组合 + LLM 先验，是当前最大不确定区。
2. `saml_forge` 不生成 XML 签名（golden-saml 关键步骤）；`jwt_forge` 参数描述未覆盖 alg:none。
3. 编排层无 `kubectl apply/patch/delete/label`、`docker build`、`openssl`、`pg_basebackup` 专用工具；K8S-20/21/22/24/25/26/27/28/29/30 等依赖 `shell_exec` + 环境内二进制。
4. runC 三个新 CVE（2024-21626/2025-31133/2025-52881）与 ingress-nginx RCE 只有知识条目、无专用 exploit 工具。
5. 依赖清单（`_check_tool_dependencies`）未覆盖 kubectl/docker/helm/etcdctl/crictl/gcc/gdb/openssl/pg_basebackup/arpspoof 等，缺失时只会静默失败。