"""Cloud-native and Kubernetes penetration testing agent.

Capabilities:
- Container enumeration (pods, services, secrets, service accounts)
- Container escape (Docker socket, privileged, hostPath, capabilities)
- RBAC abuse (impersonation, role binding, cluster-admin escalation)
- Cloud metadata access (AWS/GCP/Azure IMDS)

Reference: container-pentester-agent's spoke/tools architecture
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from darwin.dkg import DKG
from darwin.sub_agents.base import BaseSubAgent, SubAgentResult, TokenBudget, AgentType
from darwin.tools.attack_server import create_attack_gateway
from darwin.utils.llm import LLMSession


class CloudAgent(BaseSubAgent):
    """Cloud-native penetration testing agent for Kubernetes and container environments."""

    def __init__(
        self,
        agent_id: str,
        task_scope: Any = None,
        dkg: DKG | None = None,
        budget: TokenBudget | None = None,
        llm_session: LLMSession | None = None,
        cloud_context: dict | None = None,
    ):
        from darwin.prompts.cloud_agent import (
            SYSTEM_PROMPT_CLOUD,
            SYSTEM_PROMPT_CLOUD_EVALUATE,
            SYSTEM_PROMPT_CLOUD_REPLAN,
        )

        tools = create_attack_gateway()
        super().__init__(
            agent_id=agent_id,
            agent_type=AgentType.CLOUD,
            task_scope=task_scope,
            dkg=dkg,
            budget=budget or TokenBudget(),
            tools=tools,
            llm_session=llm_session or LLMSession.from_config("default"),
        )
        self.cloud_context = cloud_context or {}
        self._system_prompt = SYSTEM_PROMPT_CLOUD
        self._evaluate_prompt = SYSTEM_PROMPT_CLOUD_EVALUATE
        self._replan_prompt = SYSTEM_PROMPT_CLOUD_REPLAN

    async def _generate_plan(self) -> List[Dict[str, Any]]:
        tools = sorted(self.tools.get_tool_names()) if self.tools else []

        # ── CTAGE: enrich plan prompt with cloud topology & attack paths ──
        ctage_context = self._build_ctage_context()

        prompt = f"""Cloud Context: {self.cloud_context}
Targets: {self.task_scope.target_hosts if self.task_scope else []}
Tools: {', '.join(tools)}
{ctage_context}
Generate a cloud/K8s attack plan as JSON array. Each task: id, instruction, tool, params, dependent_task_ids, reason.
If pod_info shows "Not yet enumerated" (Docker cloud, no K8s): 1) check_cloud_metadata, 2) aws_cli for S3/IAM/STS, 3) curl_get for cloud APIs.
If K8s environment: 1) capability/mounts, 2) SA enumeration, 3) RBAC, 4) escape.
{('CRITICAL: Use the attack path analysis above to prioritize tasks. Focus on high-risk pods and confirmed escape vectors first.' if ctage_context else '')}
Output ONLY valid JSON array. 3-6 tasks."""
        self._maybe_compress()
        content, _ = self.llm.generate(prompt=prompt, system_prompt=self._system_prompt.format(
            cluster_info=self.cloud_context.get("cluster_info", "unknown"),
            pod_info=self.cloud_context.get("pod_info", "unknown"),
            sa_info=self.cloud_context.get("sa_info", "none"),
            resources=str(self.cloud_context.get("resources", [])),
            tools=", ".join(tools),
        ))
        try:
            import re, json
            match = re.search(r'\[.*\]', content, re.DOTALL)
            plan = json.loads(match.group(0)) if match else []
            if plan: return plan
        except Exception: pass
        # For non-K8s environments (pod_info not enumerated = Docker cloud),
        # prioritize cloud API tasks over container escape checks.
        _pod_info = self.cloud_context.get("pod_info", "")
        if _pod_info and "not yet" in _pod_info.lower():
            return [{"id": "check-1", "instruction": "Check for cloud metadata access (IMDS)",
                     "tool": "check_cloud_metadata", "params": {}, "dependent_task_ids": [],
                     "reason": "Non-K8s cloud environment — IMDS may expose AWS credentials"},
                    {"id": "check-2", "instruction": "Enumerate cloud services with aws_cli",
                     "tool": "aws_cli", "params": {"service": "sts", "action": "get-caller-identity",
                     "resource": "", "payload_json": ""}, "dependent_task_ids": ["check-1"],
                     "reason": "Cloud credentials from IMDS enable AWS service access"}]
        return [{"id": "check-1", "instruction": "Check container capabilities and mounts",
                 "tool": "check_capabilities", "params": {}, "dependent_task_ids": [],
                 "reason": "Assess container escape potential"},
                {"id": "check-2", "instruction": "Check for cloud metadata access",
                 "tool": "check_cloud_metadata", "params": {}, "dependent_task_ids": ["check-1"],
                 "reason": "IMDS access enables cloud credential theft"}]

    def _build_ctage_context(self) -> str:
        """Build CTAGE-enriched context from DKG cloud topology data.

        Extracts high-risk pods with escape vectors, lateral movement
        opportunities (cross-namespace RBAC), and IAM privilege escalation
        paths from structured DKG nodes. Returns empty string if no
        CTAGE data is available.
        """
        if not self.dkg:
            return ""

        parts = []

        # ── High-risk pods with escape vectors ──
        pods = self.dkg.query_nodes("K8sPod")
        if pods:
            high_risk = []
            for pod in pods:
                # Determine risk from pod properties
                host_pid = pod.get("host_pid", False)
                namespace = pod.get("namespace", "")
                pod_name = pod.get("name", "")
                sa = pod.get("service_account", "default")

                # Find SA → Role bindings for this pod
                escape_hints = []
                if host_pid:
                    escape_hints.append("hostPID_procfs_escape")

                # Check for pod_mounts_sa → sa_bound_to_role chains
                pod_id = f"k8s-pod-{namespace}-{pod_name}"
                if pod_id in self.dkg.graph:
                    for target_id, edge_type in self._get_outgoing_edges(pod_id):
                        if edge_type == "pod_mounts_sa":
                            sa_node = self.dkg.graph.nodes.get(target_id, {})
                            sa_name = sa_node.get("name", "")
                            # Check if SA has role bindings
                            for role_id, rb_edge in self._get_outgoing_edges(target_id):
                                if rb_edge == "sa_bound_to_role":
                                    role = self.dkg.graph.nodes.get(role_id, {})
                                    role_name = role.get("name", "")
                                    role_ns = role.get("namespace", "")
                                    if role_ns and role_ns != namespace:
                                        escape_hints.append(
                                            f"cross-ns RBAC: {sa_name}→{role_name} ({role_ns})"
                                        )
                                    else:
                                        escape_hints.append(
                                            f"RBAC: {sa_name}→{role_name}"
                                        )

                if escape_hints:
                    high_risk.append(
                        f"- {namespace}/{pod_name}: {', '.join(escape_hints)}, sa={sa}"
                    )

            if high_risk:
                parts.append("## High-Risk Pods (prioritize these)")
                parts.extend(high_risk[:8])  # Top 8 to avoid prompt bloat
                parts.append("")

        # ── Lateral movement: SA → cross-namespace RBAC ──
        sas = self.dkg.query_nodes("K8sSA")
        lateral = []
        for sa in sas:
            sa_name = sa.get("name", "")
            sa_ns = sa.get("namespace", "")
            said = f"k8s-sa-{sa_ns}-{sa_name}"
            if said in self.dkg.graph:
                for target_id, edge_type in self._get_outgoing_edges(said):
                    if edge_type == "sa_bound_to_role":
                        role = self.dkg.graph.nodes.get(target_id, {})
                        role_ns = role.get("namespace", "")
                        if role_ns not in ("", "cluster", sa_ns):
                            lateral.append(
                                f"- SA {sa_ns}/{sa_name} → role {role.get('name','')} in {role_ns}"
                            )

        if lateral:
            parts.append("## Lateral Movement Opportunities (cross-namespace)")
            parts.extend(lateral[:5])
            parts.append("")

        # ── IAM privilege escalation paths ──
        iam_roles = self.dkg.query_nodes("IAMRole")
        if len(iam_roles) > 1:
            parts.append(f"## IAM Roles ({len(iam_roles)} discovered)")
            for role in iam_roles[:5]:
                parts.append(f"- {role.get('name','')} ({role.get('source','')})")
            parts.append("Check role_can_assume chains for privilege escalation.")
            parts.append("")

        # ── Cross-account trust relationships ──
        trusts = self.dkg.query_nodes("TrustRelationship")
        if trusts:
            parts.append(f"## Cross-Account Trusts ({len(trusts)} discovered)")
            for trust in trusts[:3]:
                parts.append(
                    f"- {trust.get('principal','')} → "
                    f"effect={trust.get('effect','Allow')}"
                )
            parts.append("Use aws_iam_federation for cross-account AssumeRole.")
            parts.append("")

        if parts:
            parts.insert(0, "## CTAGE Attack Path Analysis (structured topology data)")

        return "\n".join(parts)

    @staticmethod
    def _get_outgoing_edges(dkg: DKG, node_id: str) -> list[tuple[str, str]]:
        """Get (target_id, edge_type) for outgoing edges from node_id."""
        if not dkg or node_id not in dkg.graph:
            return []
        return [
            (target, dkg.graph.edges[node_id, target, key].get("type", ""))
            for (src, target, key) in dkg.graph.out_edges(node_id, keys=True)
        ]

    async def _execute_task(self, task: Dict[str, Any]) -> Any:
        """Execute a cloud/K8s task — delegates to the LLM for tool selection."""
        tool_names = sorted(self.tools.get_tool_names()) if self.tools else []
        creds = self.dkg.query_nodes("Credential")
        pods = self.dkg.query_nodes("Service")

        ctx = (
            f"Services: {len(pods)}, Credentials: {len(creds)}"
        )

        prompt = (
            f"Task: {task['instruction']}\n"
            f"DKG Context: {ctx}\n"
            f"Params: {task.get('params', {})}\n"
            f"Available tools: {', '.join(tool_names)}\n\n"
            f"Execute this cloud/K8s task. Choose ONE tool, call it with appropriate params.\n"
            f"Output ONLY: {{\"tool\": \"tool_name\", \"params\": {{...}}}}"
        )
        self._maybe_compress()
        content, _ = self.llm.generate(prompt=prompt)
        import re, json
        try:
            match = re.search(r'\{.*\}', content, re.DOTALL)
            if match:
                spec = json.loads(match.group(0))
                tool_name = spec.get("tool", "")
                params = spec.get("params", {})
                if tool_name and tool_name in tool_names:
                    return await self.tools.call(tool_name, params)
        except Exception:
            pass
        _tool = task.get("tool", "")
        if _tool and _tool in tool_names:
            return await self.tools.call(_tool, task.get("params", {}))
        from darwin.tools.mcp_gateway import ToolResult
        return ToolResult(success=False, stdout=f"Cloud agent: no tool found for {task.get('instruction', '')}",
                         parsed={})
