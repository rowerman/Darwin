"""ReconAgent — focused reconnaissance on a specific target.

Reference: VulnBot roles/collector.py — Collector agent tool list and workflow
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from darwin.dkg import DKG
from darwin.sub_agents.base import (
    AgentType, BaseSubAgent, SubAgentResult, TaskScope, TokenBudget,
)
from darwin.tools.mcp_gateway import MCPGateway
from darwin.tools.recon_server import create_recon_gateway
from darwin.utils.llm import LLMSession


class ReconAgent(BaseSubAgent):
    """Focused reconnaissance agent.

    Scans a specific target (host/service) to discover endpoints,
    technologies, and potential attack surface. All decision-making
    (tool selection, result evaluation, replanning) is LLM-driven.

    Reference: VulnBot roles/collector.py — Collector agent
    """

    def __init__(
        self,
        agent_id: str,
        task_scope: TaskScope,
        dkg: DKG,
        llm_session: LLMSession | None = None,
        budget: TokenBudget | None = None,
    ):
        tools = create_recon_gateway()
        super().__init__(
            agent_id=agent_id,
            agent_type=AgentType.RECON,
            task_scope=task_scope,
            dkg=dkg,
            llm_session=llm_session or LLMSession(),
            budget=budget or TokenBudget(max_tokens=32000, max_iterations=15),
            tools=tools,
        )

    async def _generate_plan(self) -> List[Dict[str, Any]]:
        """Generate recon plan — LLM-driven using the ReconAgent system prompt."""
        if not self.task_scope.target_hosts:
            raise ValueError("ReconAgent requires at least one target host")
        target = self.task_scope.target_hosts[0]

        tools = self.tools.get_tool_names() if self.tools else ["whatweb_scan", "dirb_scan", "curl_get", "nmap_vulners_scan"]
        from darwin.prompts.recon_agent import SYSTEM_PROMPT_RECON

        prompt = f"""Target: {target}

Available recon tools: {', '.join(sorted(tools))}

Create a reconnaissance plan with 3-5 steps. Each step should specify:
- id: unique step ID
- instruction: what to do
- tool: which tool to use
- params: tool parameters

Output as JSON array:
[{{"id": "recon-1", "instruction": "...", "tool": "tool_name", "params": {{...}}, "dependent_task_ids": []}}]"""

        self._maybe_compress()
        content, _ = self.llm.generate(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT_RECON.format(target=target, tools=", ".join(sorted(tools))),
        )
        try:
            match = re.search(r'\[.*\]', content, re.DOTALL)
            plan = json.loads(match.group(0)) if match else []
            if isinstance(plan, list) and len(plan) > 0:
                return plan
        except Exception:
            pass

        # Fallback: hardcoded plan if LLM fails
        return [
            {"id": "recon-1", "instruction": f"Identify web technologies on {target}",
             "tool": "whatweb_scan", "params": {"target_url": target}, "dependent_task_ids": []},
            {"id": "recon-2", "instruction": f"Enumerate directories on {target}",
             "tool": "dirb_scan", "params": {"target_url": target}, "dependent_task_ids": ["recon-1"]},
            {"id": "recon-3", "instruction": "Probe endpoints",
             "tool": "curl_get", "params": {"url": target, "follow_redirects": True}, "dependent_task_ids": ["recon-2"]},
        ]

    async def _execute_task(self, task: Dict[str, Any]) -> Any:
        """Execute a recon task — LLM decides which tool and parameters to use.

        The LLM receives the task instruction, available tool definitions, and
        DKG context to make an informed decision about which reconnaissance
        action to take next.
        """
        tool_defs = self.tools.get_tool_definitions()
        tool_names = self.tools.get_tool_names()

        # Build context from DKG for the LLM
        endpoints = self.dkg.query_nodes("Endpoint")
        services = self.dkg.query_nodes("Service")
        ctx = f"Discovered endpoints: {len(endpoints)}, services: {len(services)}"

        prompt = (
            f"Task: {task['instruction']}\n"
            f"DKG Context: {ctx}\n"
            f"Available tools: {', '.join(sorted(tool_names))}\n"
            f"Choose the best reconnaissance tool and parameters for this task."
        )

        self._maybe_compress()
        content, tool_calls = self.llm.generate(
            prompt=prompt,
            system_prompt="You are a reconnaissance specialist. Select the best tool for the task. "
                          "Prefer targeted tools over generic ones. Output a tool call.",
            tools=tool_defs,
        )

        if tool_calls:
            call = tool_calls[0]
            tool_name = call.get("name", "whatweb_scan")
            params = call.get("arguments", {})
        else:
            # Fallback: use whatweb as default recon tool
            tool_name = "whatweb_scan"
            if not self.task_scope.target_hosts:
                raise ValueError("ReconAgent requires at least one target host")
            target = self.task_scope.target_hosts[0]
            params = {"target_url": target}

        result = await self.tools.call(tool_name, params)
        self.budget.tokens_used += len(json.dumps(params)) // 4 + 500
        # Record what was actually used for evaluation context
        task["_tool_used"] = tool_name
        task["_params_used"] = params
        return result

    async def _evaluate_result(
        self, task: Dict[str, Any], result: Any
    ) -> tuple[bool, List[Dict[str, Any]]]:
        """Evaluate recon results — LLM-driven extraction of structured findings.

        Uses the ReconAgent evaluate prompt to extract endpoints, services,
        technologies, and flags from tool output. Falls back to regex parsing
        if LLM evaluation fails.
        """
        findings = []

        if not hasattr(result, "success") or not result.success:
            self.findings.extend(findings)
            return False, findings

        stdout = getattr(result, "stdout", "")
        tool_name = task.get("_tool_used", task.get("tool", ""))

        # LLM-driven evaluation
        from darwin.prompts.recon_agent import SYSTEM_PROMPT_RECON_EVALUATE
        try:
            self._maybe_compress()
            content, _ = self.llm.generate(
                prompt=SYSTEM_PROMPT_RECON_EVALUATE.format(
                    tool_name=tool_name,
                    task_instruction=task.get("instruction", ""),
                    tool_output=stdout[:4000],
                ),
                system_prompt="You are a reconnaissance result evaluator. Output ONLY valid JSON.",
            )
            match = re.search(r'\[.*\]', content, re.DOTALL)
            if match:
                llm_findings = json.loads(match.group(0))
                if isinstance(llm_findings, list):
                    for f in llm_findings[:20]:
                        if isinstance(f, dict):
                            findings.append(f)
        except Exception:
            pass

        # Always regex-parse for flags (most reliable signal)
        flags = re.findall(r"flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}", stdout, re.IGNORECASE)
        for flag in flags:
            findings.append({"type": "flag", "value": flag, "source": "stdout_regex"})

        # Fallback: extract from parsed_output if LLM produced nothing
        if not findings and hasattr(result, "parsed_output") and result.parsed_output:
            findings.append({
                "type": "parsed",
                "data": result.parsed_output,
                "source": tool_name,
            })
            # Also extract URLs from stdout as last resort
            urls = re.findall(r"https?://[^\s\"'<>]+", stdout)
            for url in urls[:10]:
                findings.append({
                    "type": "endpoint",
                    "url": url.rstrip(".,;:'\""),
                    "source": "stdout_parse",
                })

        self.findings.extend(findings)
        return len(findings) > 0, findings

    async def _replan_after_failure(
        self, failed_task: Dict[str, Any], result: Any
    ) -> List[Dict[str, Any]]:
        """LLM-driven replanning after a failed reconnaissance task.

        Analyzes what went wrong and proposes alternative reconnaissance approaches.
        """
        stdout = getattr(result, "stdout", "") if hasattr(result, "stdout") else ""
        tool_name = failed_task.get("_tool_used", failed_task.get("tool", ""))
        tools = self.tools.get_tool_names()

        try:
            self._maybe_compress()
            content, _ = self.llm.generate(
                prompt=(
                    f"Reconnaissance task FAILED: '{failed_task['instruction']}'\n"
                    f"Tool used: {tool_name}\n"
                    f"Output: {stdout[:1500]}\n"
                    f"Available tools: {', '.join(sorted(tools))}\n\n"
                    f"Suggest alternative reconnaissance approaches. "
                    f"Output a JSON array of new tasks (max 4):\n"
                    f'[{{"id": "recon-alt-1", "instruction": "...", "tool": "...", '
                    f'"params": {{...}}, "dependent_task_ids": []}}]'
                ),
                system_prompt="You are a reconnaissance strategist. Output ONLY valid JSON array.",
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

        # Fallback: mark failed task as done and continue
        self._mark_task_done(failed_task)
        return self.plan

    async def _update_plan(
        self, completed_task: Dict[str, Any], result: Any
    ) -> List[Dict[str, Any]]:
        """LLM-driven plan update after a successful reconnaissance task.

        Analyzes what was discovered and decides whether to add follow-up tasks.
        """
        stdout = getattr(result, "stdout", "") if hasattr(result, "stdout") else ""
        tool_name = completed_task.get("_tool_used", completed_task.get("tool", ""))
        tools = self.tools.get_tool_names()

        # Mark completed task as done
        self._mark_task_done(completed_task)

        # Check if remaining tasks exist
        remaining = [t for t in self.plan if not t.get("done", False)]
        if not remaining:
            return self.plan

        # Ask LLM if we should add follow-up tasks based on what we learned
        try:
            self._maybe_compress()
            content, _ = self.llm.generate(
                prompt=(
                    f"Reconnaissance task COMPLETED: '{completed_task['instruction']}'\n"
                    f"Tool used: {tool_name}\n"
                    f"Key output: {stdout[:1500]}\n"
                    f"Remaining plan: {json.dumps(remaining[:3], indent=2)}\n\n"
                    f"Based on what was discovered, should we add any follow-up tasks? "
                    f"Output a JSON array of additional tasks, or [] if no additions needed:\n"
                    f'[{{"id": "recon-followup-1", "instruction": "...", "tool": "...", '
                    f'"params": {{...}}, "dependent_task_ids": []}}]'
                ),
                system_prompt="You are a reconnaissance strategist. Output ONLY valid JSON array.",
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
        """Write recon discoveries to DKG."""
        for finding in findings:
            ftype = finding.get("type", "")

            if ftype == "endpoint":
                url = finding.get("url", "")
                self.dkg.add_node("Endpoint", f"ep-{url[:50]}", {
                    "url": url,
                    "method": "GET",
                    "params": "",
                    "discovered_by": self.agent_id,
                })

            elif ftype == "parsed":
                data = finding.get("data", {})
                for tech in data.get("technologies", []):
                    self.dkg.add_node("Service", f"tech-{tech[:30]}", {
                        "port": 0, "protocol": "HTTP",
                        "version": tech, "banner": tech,
                        "discovered_by": self.agent_id,
                    })
                for path_info in data.get("discovered_paths", []):
                    path = path_info.get("path", "")
                    target = self.task_scope.target_hosts[0] if self.task_scope.target_hosts else ""
                    full_url = f"{target.rstrip('/')}{path}" if target else path
                    self.dkg.add_node("Endpoint", f"ep-{path[:40]}", {
                        "url": full_url, "method": "GET", "params": "",
                        "code": path_info.get("code", ""),
                        "discovered_by": self.agent_id,
                    })
                for port_info in data.get("open_ports", []):
                    port = port_info.get("port", 0)
                    self.dkg.add_node("Service", f"svc-{port}", {
                        "port": port, "protocol": "tcp",
                        "version": port_info.get("service", ""),
                        "discovered_by": self.agent_id,
                    })

            elif ftype == "flag":
                self.dkg.add_node("Flag", f"flag-{finding.get('value', '')[:20]}", {
                    "value": finding.get("value", ""),
                    "location": finding.get("source", ""),
                    "verified": False,
                    "discovered_by": self.agent_id,
                })

            elif ftype in ("service", "technology"):
                self.dkg.add_node("Service", f"svc-{finding.get('detail', '')[:30]}", {
                    "port": 0, "protocol": "HTTP",
                    "version": finding.get("detail", ""),
                    "discovered_by": self.agent_id,
                })
