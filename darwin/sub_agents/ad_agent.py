"""Active Directory penetration testing agent.

Capabilities:
- Domain enumeration (users, groups, computers, trusts, GPOs)
- Credential-based attacks (Kerberoasting, AS-REP roasting)
- Lateral movement (Pass-the-Hash, PsExec, WMI, WinRM)
- Privilege escalation (DCSync, ACL abuse)
- Persistence (Golden Ticket, Silver Ticket)

Reference: Cochise planner/executor architecture
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from darwin.dkg import DKG
from darwin.sub_agents.base import BaseSubAgent, SubAgentResult, TokenBudget, AgentType
from darwin.tools.attack_server import create_attack_gateway
from darwin.utils.llm import LLMSession


class ADAgent(BaseSubAgent):
    """Active Directory penetration testing agent for Windows domain environments."""

    def __init__(
        self,
        agent_id: str,
        task_scope: Any = None,
        dkg: DKG | None = None,
        budget: TokenBudget | None = None,
        llm_session: LLMSession | None = None,
        domain_context: dict | None = None,
    ):
        from darwin.prompts.ad_agent import (
            SYSTEM_PROMPT_AD,
            SYSTEM_PROMPT_AD_EVALUATE,
            SYSTEM_PROMPT_AD_REPLAN,
        )

        tools = create_attack_gateway()
        super().__init__(
            agent_id=agent_id,
            agent_type=AgentType.AD,
            task_scope=task_scope,
            dkg=dkg,
            budget=budget or TokenBudget(),
            tools=tools,
            llm_session=llm_session,
        )
        self.domain_context = domain_context or {}
        self._system_prompt = SYSTEM_PROMPT_AD
        self._evaluate_prompt = SYSTEM_PROMPT_AD_EVALUATE
        self._replan_prompt = SYSTEM_PROMPT_AD_REPLAN

    async def _generate_plan(self) -> List[Dict[str, Any]]:
        tools = sorted(self.tools.get_tool_names()) if self.tools else []
        dc_ip = self.domain_context.get("dc_ip", "") or (
            self.task_scope.target_hosts[0] if self.task_scope and self.task_scope.target_hosts else "")
        prompt = f"""Domain: {self.domain_context.get('domain_name', 'unknown')}
DC: {dc_ip}
Credentials: {self.domain_context.get('credentials', 'none')}
Hosts: {self.task_scope.target_hosts if self.task_scope else []}
Tools: {', '.join(tools)}

Generate an AD attack plan as JSON array. Each task: id, instruction, tool, params, dependent_task_ids, reason.
Output ONLY valid JSON array. 3-6 tasks."""
        self._maybe_compress()
        content, _ = self.llm.generate(prompt=prompt, system_prompt=self._system_prompt.format(
            domain_name=self.domain_context.get("domain_name", ""),
            dc_ip=dc_ip,
            credentials=str(self.domain_context.get("credentials", "")),
            hosts=str(self.task_scope.target_hosts if self.task_scope else []),
            tools=", ".join(tools),
        ))
        try:
            import re, json
            match = re.search(r'\[.*\]', content, re.DOTALL)
            plan = json.loads(match.group(0)) if match else []
            if plan: return plan
        except Exception: pass
        return [{"id": "enum-1", "instruction": f"Enumerate {dc_ip} via SMB and LDAP",
                 "tool": "netexec_enum", "params": {"target": dc_ip},
                 "dependent_task_ids": [], "reason": "Initial domain enumeration"}]
