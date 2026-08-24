"""ParityScheduler — exact replica of the legacy plan-task selection.

The v2 Runtime owns the loop; this scheduler reproduces the legacy
``_select_next_plan_task`` ordering semantics so the cutover is behavior
equivalent:

- topological order (Kahn's algorithm over task-ID dependencies);
- skip ABANDONED tasks and ids in the session exhausted set;
- only READY/CREATED tasks are considered;
- dependencies are satisfied when the dep task exists and is
  SUCCESS / FAILED / ABANDONED; when ALL deps failed, the dependent task
  is marked ABANDONED (can never succeed);
- ready tasks are classified exploit-first (tool whitelist, instruction
  keywords, or ``source == "credential-hint"``), then probe, then
  low-priority (hydra brute-force) — first of each bucket wins.
"""

from __future__ import annotations

from darwin.core.contracts import TaskStatus
from darwin.core.task import Task
from darwin.core.task_graph import TaskGraph, dependency_task_ids


_EXPLOIT_PRIORITY = {
    "command_injection_test", "sqlmap_test", "send_payload",
    "xss_reflection_test", "ffuf_fuzz",
    # HTTP exploitation (form-based API exploits, auth bypass, etc.)
    "http_post", "form_extract",
    "redis_cmd", "mysql_query", "psql_query", "mssql_query", "mssqlclient_query",
    "oracle_query", "tomcat_exploit", "php_filter_chain",
    "jwt_forge", "impacket_psexec", "impacket_wmiexec",
    "impacket_pth", "impacket_ticketer", "impacket_silver_ticket",
    "impacket_secretsdump", "impacket_secretsdump_dcsync",
    "impacket_GetUserSPNs", "impacket_GetNPUsers",
    # Container escape tools
    "container_escape_docker_sock", "container_escape_docker_api",
    "container_escape_cgroup", "container_escape_mount_disk",
    "container_escape_cap_dac", "container_escape_procfs",
    "container_escape_runc", "nsenter_exec", "crictl_cmd",
    # Container recon (prerequisite for escape)
    "check_capabilities", "check_mounts",
    "container_find_sockets", "container_find_docker", "container_recon_env",
    # K8s exploitation and post-exploitation
    "kubectl_exec", "kubectl_run",
    "k8s_secret_dump", "k8s_configmap_dump", "k8s_sa_token_steal",
    "k8s_kubelet_exec", "k8s_etcd_keys", "etcdctl_get",
    "k8s_backdoor_daemonset", "k8s_backdoor_cronjob",
    # K8s enumeration (prerequisite for exploitation)
    "kubectl_get_pods", "kubectl_get_secrets",
    "kubectl_get_clusterrolebindings", "kubectl_auth_check",
    "sa_token_read", "kubelet_probe",
    # Cloud exploitation
    "aws_cli", "aws_iam_federation", "check_cloud_metadata",
    "ssrf_probe",
    # Post-exploitation and lateral movement
    "ssh_exec", "shell_exec", "ssh_key_exec",
    "linux_priv_check", "file_upload",
    # Additional exploit tools
    "xxe_inject", "ssti_inject", "graphql_introspect",
    "wpscan_enum", "oracle_tns_poison", "smbmap_enum",
    "gpp_decrypt", "hash_crack", "smb_client",
    "test_credential",
}

_LOW_PRIORITY = {
    "hydra_http_brute", "hydra_ssh_brute",
}

_EXPLOIT_KEYWORDS = [
    "bypass", "exploit", "assume", "escalat",
    "inject", "takeover", "token", "flag",
    " privilege", "admin role", "forgery",
]


class ParityScheduler:
    """Picks the next ready Task with legacy plan-loop ordering."""

    def __init__(self, exhausted_ids: set[str] | None = None) -> None:
        self._exhausted_ids = exhausted_ids if exhausted_ids is not None else set()

    @staticmethod
    def _has_exploit_semantics(task: Task) -> bool:
        inst = (task.instruction or "").lower()
        return any(kw in inst for kw in _EXPLOIT_KEYWORDS)

    def next_ready(self, graph: TaskGraph, budget=None, world: dict | None = None) -> Task | None:
        """Return the next ready Task, mirroring the legacy selector."""
        if world and "attack_paths" in world:
            graph.refresh_states(world)
        ready_exploit: list[Task] = []
        ready_probe: list[Task] = []
        ready_low: list[Task] = []

        for task in graph.topological_order():
            if task.status is TaskStatus.ABANDONED or task.id in self._exhausted_ids:
                continue
            if task.status not in (TaskStatus.READY, TaskStatus.CREATED):
                continue
            dep_ids = dependency_task_ids(task)
            deps_met = True
            all_deps_failed = True if dep_ids else False
            for dep_id in dep_ids:
                dep_task = graph.get(dep_id)
                if not dep_task or dep_task.status not in (
                    TaskStatus.SUCCESS,
                    TaskStatus.FAILED,
                    TaskStatus.ABANDONED,
                ):
                    deps_met = False
                    break
                if dep_task.status is not TaskStatus.FAILED:
                    all_deps_failed = False
            # When ALL credential-test dependencies failed, the dependent
            # task cannot succeed (legacy "skipped" semantics → ABANDONED).
            if deps_met and all_deps_failed:
                try:
                    graph.transition(task.id, TaskStatus.ABANDONED)
                except ValueError:
                    task.status = TaskStatus.ABANDONED
                continue
            if deps_met:
                tool = str((task.action or {}).get("tool", "") or "")
                if (
                    task.source == "credential-hint"
                    or tool in _EXPLOIT_PRIORITY
                    or self._has_exploit_semantics(task)
                ):
                    ready_exploit.append(task)
                elif tool in _LOW_PRIORITY:
                    ready_low.append(task)
                else:
                    ready_probe.append(task)

        if ready_exploit:
            return ready_exploit[0]
        if ready_probe:
            return ready_probe[0]
        if ready_low:
            return ready_low[0]
        return None
