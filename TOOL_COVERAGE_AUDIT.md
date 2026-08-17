# Darwin 覆盖率自动巡检（taxonomy 叶子 → 工具/能力/知识）

- 叶子总数：89
- 完全 OK：89
- 存在问题：0

| id | guid | path | capability | tools | status |
|---|---|---|---|---|---|
| scenario-actor-token |  | cloud/n-a-actor-tenant-validation-bug-case-246 | cloud_iam_assume | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-attachme-volume |  | cloud/n-a-control-plane-ownership-check-missin | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-beta-endpoint |  | cloud/n-a-non-production-endpoint-skips-audit- | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec, aws_cli, aws_sts_query, aws_iam_federation | OK |
| scenario-buildfleet-registry |  | cloud/n-a-unauth-internal-registry-case-260-li | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec, send_payload, php_serialize_generate | OK |
| scenario-cap-netraw-metadata |  | cloud/n-a-cap-net-raw-arp-spoofing | web_exploit_send | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-cap-sys-admin-cgroup | K8S-14 | k8s/cap-sys-admin-abuse | container_escape | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-cap-sys-ptrace-inject | K8S-19 | k8s/cap-sys-ptrace-abuse | container_escape | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-cf-injection |  | cloud/n-a-cf-fn-sub-injection | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-ci-poisoning |  | cloud/n-a-ci-cd-script-injection | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-cloudsql-index-rce |  | cloud/n-a-atexecchangeowner-patch-analyze-case | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-cni-ip-spoof | K8S-30 | k8s/n-a-ip-spoofing | k8s_apply | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-composer-depconf |  | cloud/n-a-global-namespace-dependency-confusio | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-cosmiss-notebook |  | cloud/n-a-forwardingid-authz-bypass-case-073 | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-couchdb-rce | DB-08 | db/n-a-erlang-native-view-rce | sql_query | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-cri-socket-escape | K8S-16 | k8s/cri-socket-abuse | container_escape | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, docker_registry, container_escape_docker_sock, shell_exec, crictl_cmd | OK |
| scenario-cross-account-trust | CLOUD-12 IAM 信任策略 Principal | cloud/n-a-overly-permissive-trust-policy | cloud_iam_assume | docker_registry, container_escape_docker_sock, shell_exec, aws_cli, aws_sts_query, aws_iam_federation | OK |
| scenario-dataform-pt |  | cloud/n-a-cross-tenant-path-traversal-case-267 | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-docker-socket-escape | K8S-17 | k8s/docker-socket-abuse | container_escape | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-elasticsearch-script | DB-07 | db/n-a-script-injection | sql_query | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-etcd-unauth | K8S-08 | k8s/n-a-misconfiguration | secret_dump | curl_get, http_post, send_payload, kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, etcdctl_get, k8s_etcd_keys, shell_exec | OK |
| scenario-externalip-hijack | K8S-22 | k8s/cve-2020-8554 | k8s_apply | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-extrareplica-repl |  | cloud/n-a-internal-subnet-mis-anchored-cert-re | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-gitrepo-cve-2024-10220 | K8S-05 | k8s/cve-2024-10220 | container_escape | curl_get, http_post, send_payload, kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, docker_registry, container_escape_docker_sock, shell_exec, php_serialize_generate | OK |
| scenario-global-s3-squatting |  | cloud/n-a-global-namespace-resource-squatting | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-golden-saml |  | cloud/n-a-saml-signing-key-exposure | cloud_iam_assume | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-graphql-idor | WEB-16 | web/graphql-introspection-idor | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-helm-tiller | K8S-10 | k8s/n-a-misconfiguration | k8s_apply | curl_get, http_post, send_payload, kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, helm, shell_exec | OK |
| scenario-hostpath-escape | K8S-12 | k8s/n-a-hostpath-mount | container_escape | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-iam-enum-oracle |  | cloud/n-a-uncovered-service-error-oracle-case- | cloud_iam_assume | docker_registry, container_escape_docker_sock, shell_exec, oracle_query, oracle_tns_poison | OK |
| scenario-ingress-nginx-rce | K8S-20 | k8s/cve-2025-1974 | k8s_apply | curl_get, http_post, send_payload, kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec, php_serialize_generate | OK |
| scenario-ingress-snippet | K8S-21 | k8s/cve-2021-25742 | secret_dump | curl_get, http_post, send_payload, kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-jwt-alg-none | WEB-15 | web/jwt-alg-none | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-kubelet-unauth | K8S-07 | k8s/n-a-misconfiguration | secret_dump | curl_get, http_post, send_payload, kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-lambda-passrole |  | cloud/n-a-command-injection-iam-privesc | cloud_iam_assume | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-localhost-bypass | K8S-24 | k8s/cve-2020-8558 | k8s_apply | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-lowcode-secrets |  | cloud/n-a-connector-store-tenant-scope-missing | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-mongodb-nosqli | DB-09 | db/n-a-nosql-injection | sql_query | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec, php_serialize_generate | OK |
| scenario-mongodb-unauth | DB-06 | db/n-a-misconfiguration | sql_query | docker_registry, container_escape_docker_sock, shell_exec, mongodb_query, nosql_inject | OK |
| scenario-mssql-linked-server | DB-04 | db/mssql-linked-server | sql_query | docker_registry, container_escape_docker_sock, shell_exec, mssqlclient_query, mssql_query | OK |
| scenario-mssql-xp-cmdshell | WEB-09 | web/mssql-xp-cmdshell | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec, mssqlclient_query, mssql_query | OK |
| scenario-multi-tenant-k8s |  | cloud/n-a-privileged-container-hostpid-escape | web_exploit_send | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-mutable-image-tag | K8S-15 | k8s/n-a-image-tag-mutation | k8s_apply | curl_get, http_post, send_payload, kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-mysql-udf | WEB-08 | web/mysql-udf-abuse | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec, mysql_query, mysql_file_write, php_serialize_generate, php_filter_chain | OK |
| scenario-mysql-udf-direct | DB-02 | db/mysql-udf-abuse | sql_query | docker_registry, container_escape_docker_sock, shell_exec, mysql_query, mysql_file_write | OK |
| scenario-networkpolicy-bypass | K8S-27 | k8s/n-a-network-policy-bypass | k8s_apply | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-node-redirect | K8S-26 | k8s/cve-2020-8559 | k8s_apply | curl_get, http_post, send_payload, kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-node-selector-evasion | K8S-28 | k8s/n-a-scheduling-bypass | k8s_apply | curl_get, http_post, send_payload, kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-notebook-escape |  | cloud/n-a-notebook-escape-sa-token | cloud_iam_assume | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-oidc-federation |  | cloud/n-a-oidc-federation-misconfiguration | cloud_iam_assume | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-omigod-agent |  | cloud/n-a-auth-bypass-in-provider-agent-cve-20 | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-oracle-tns | DB-03 | db/tns-poisoning | sql_query | docker_registry, container_escape_docker_sock, shell_exec, oracle_query, oracle_tns_poison | OK |
| scenario-persistence-as-a-service |  | cloud/n-a-automation-runbook-persistence-case- | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec, aws_cli, aws_sts_query, aws_iam_federation | OK |
| scenario-php-deserialization | WEB-17 | web/insecure-php-deserialization | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec, php_serialize_generate, php_filter_chain | OK |
| scenario-pickle-model |  | cloud/n-a-pickle-deserialization-case-091 | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec, send_payload, php_serialize_generate, kubectl_exec | OK |
| scenario-postgres-sqli | WEB-07 | web/cve-2025-1094 | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-postgres-weak-auth | DB-01 | db/n-a-misconfiguration | sql_query | docker_registry, container_escape_docker_sock, shell_exec, psql_query | OK |
| scenario-privileged-breakout | K8S-11 | k8s/n-a-privileged-pod | container_escape | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-rbac-secrets | K8S-06 | k8s/n-a-misconfiguration | secret_dump | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-rds-logfdw |  | cloud/n-a-log-fdw-path-traversal-case-015 | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec, aws_cli, aws_sts_query, aws_iam_federation | OK |
| scenario-redis-unauth | DB-05 | db/n-a-misconfiguration | sql_query | docker_registry, container_escape_docker_sock, shell_exec, redis_cmd | OK |
| scenario-registry-poison | K8S-09 | k8s/n-a-misconfiguration | k8s_apply | curl_get, http_post, send_payload, kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-resource-explorer |  | cloud/n-a-unlogged-search-api-case-148 | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec, aws_cli, aws_sts_query, aws_iam_federation | OK |
| scenario-runc-cve-2024-21626 | K8S-01 | k8s/cve-2024-21626 | container_escape | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-runc-cve-2025-31133 | K8S-02 | k8s/cve-2025-31133 | container_escape | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-runc-cve-2025-52881 | K8S-03 | k8s/cve-2025-52881 | container_escape | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-sa-cluster-admin | K8S-18 | k8s/rbac-misconfiguration | secret_dump | curl_get, http_post, send_payload, kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-sa-cross-namespace |  | cloud/n-a-overly-permissive-rbac | cloud_iam_assume | curl_get, http_post, send_payload, kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-sa-cross-ns | K8S-13 | k8s/n-a-rbac-lateral | secret_dump | curl_get, http_post, send_payload, kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-scp-bypass |  | cloud/n-a-scp-enforcement-gap | cloud_iam_assume | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-seccomp-bypass | K8S-23 | k8s/n-a-misconfiguration | k8s_apply | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-serverless-sa |  | cloud/n-a-over-scoped-default-sa-case-266-272 | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-shared-nat |  | cloud/n-a-service-tag-source-ip-trust-case-259 | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-ssrf-internal | WEB-10 | web/n-a-ssrf-misconfiguration | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-ssrf-localhost | WEB-11 | web/n-a-ssrf-misconfiguration | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec, php_serialize_generate | OK |
| scenario-ssrf-to-imds |  | cloud/n-a-ssrf-imds | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-ssti-jinja2 | WEB-12 | web/n-a-ssti-vulnerability | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec, php_serialize_generate | OK |
| scenario-synlapse-ir |  | cloud/n-a-odbc-driver-injection-cve-2022-29972 | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-toleration-abuse | K8S-29 | k8s/n-a-taint-bypass | k8s_apply | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-tomcat-deserialization | WEB-01 | web/cve-2025-24813 | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec, ysoserial_generate, tomcat_exploit | OK |
| scenario-tomcat-race-condition | WEB-02 | web/cve-2024-50379 | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-webhook-inject | K8S-25 | k8s/n-a-admission-control-abuse | k8s_apply | kubectl_exec, kubectl_run, kubectl_get_pods, k8s_secret_dump, shell_exec | OK |
| scenario-wireserver-bootstrap |  | cloud/n-a-unvalidated-transport-cert-case-255- | web_exploit_send | docker_registry, container_escape_docker_sock, shell_exec, kubectl_exec | OK |
| scenario-wordpress-jupiterx-lfi | WEB-06 | web/cve-2025-0366 | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec, php_serialize_generate, php_filter_chain | OK |
| scenario-wordpress-jwt-copypress | WEB-05 | web/cve-2025-8625 | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec, php_serialize_generate, php_filter_chain | OK |
| scenario-wordpress-simple-file-list | WEB-03 | web/cve-2025-34085 | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec, php_serialize_generate, php_filter_chain | OK |
| scenario-wordpress-wpbookit | WEB-04 | web/cve-2025-6058 | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec, php_serialize_generate, php_filter_chain | OK |
| scenario-xss-stored | WEB-18 | web/stored-xss | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-xxe-basic | WEB-13 | web/xxe-xml-external-entity | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec | OK |
| scenario-xxe-svg | WEB-14 | web/xxe-xml-external-entity | web_exploit_send | curl_get, http_post, send_payload, docker_registry, container_escape_docker_sock, shell_exec | OK |
