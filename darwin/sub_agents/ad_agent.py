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
            llm_session=llm_session or LLMSession.from_config("default"),
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

    async def _execute_task(self, task: Dict[str, Any]) -> Any:
        """Execute an AD task — delegates to the LLM for tool selection."""
        tool_names = sorted(self.tools.get_tool_names()) if self.tools else []
        dc_ip = self.domain_context.get("dc_ip", "")
        domain = self.domain_context.get("domain_name", "")

        # Gather current DKG context
        creds = self.dkg.query_nodes("Credential")
        hosts = self.dkg.query_nodes("Host")
        sess = self.dkg.query_nodes("Session")

        ctx = (
            f"Domain: {domain}, DC: {dc_ip}, "
            f"Credentials: {len(creds)}, Hosts: {len(hosts)}, Sessions: {len(sess)}"
        )

        prompt = (
            f"Task: {task['instruction']}\n"
            f"DKG Context: {ctx}\n"
            f"Params: {task.get('params', {})}\n"
            f"Available tools: {', '.join(tool_names)}\n\n"
            f"Execute this AD task. Choose ONE tool, call it with appropriate params,\n"
            f"and report the result. Output ONLY the tool name and params as JSON.\n"
            f'{{"tool": "tool_name", "params": {{...}}}}'
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
        # Fallback: execute with task-provided tool
        _tool = task.get("tool", "")
        if _tool and _tool in tool_names:
            return await self.tools.call(_tool, task.get("params", {}))
        from darwin.tools.mcp_gateway import ToolResult
        return ToolResult(success=False, stdout=f"AD agent: no tool found for {task.get('instruction', '')}",
                         parsed={})
