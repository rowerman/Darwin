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
            llm_session=llm_session,
        )
        self.cloud_context = cloud_context or {}
        self._system_prompt = SYSTEM_PROMPT_CLOUD
        self._evaluate_prompt = SYSTEM_PROMPT_CLOUD_EVALUATE
        self._replan_prompt = SYSTEM_PROMPT_CLOUD_REPLAN

    async def _generate_plan(self) -> List[Dict[str, Any]]:
        tools = sorted(self.tools.get_tool_names()) if self.tools else []
        prompt = f"""Cloud Context: {self.cloud_context}
Targets: {self.task_scope.target_hosts if self.task_scope else []}
Tools: {', '.join(tools)}

Generate a cloud/K8s attack plan as JSON array. Each task: id, instruction, tool, params, dependent_task_ids, reason.
Prioritize: 1) capability/mount checks, 2) service account enumeration, 3) RBAC analysis, 4) escape attempts.
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
        return [{"id": "check-1", "instruction": "Check container capabilities and mounts",
                 "tool": "check_capabilities", "params": {}, "dependent_task_ids": [],
                 "reason": "Assess container escape potential"},
                {"id": "check-2", "instruction": "Check for cloud metadata access",
                 "tool": "check_cloud_metadata", "params": {}, "dependent_task_ids": ["check-1"],
                 "reason": "IMDS access enables cloud credential theft"}]
