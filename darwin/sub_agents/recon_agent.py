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


SYSTEM_PROMPT_RECON = """You are a reconnaissance specialist agent. Your goal is to discover
the attack surface of your assigned target.

## Available Tools
- whatweb_scan: Identify web technologies
- dirb_scan: Enumerate directories and files
- curl_get: Make HTTP requests and inspect responses

## Workflow
1. Start with whatweb_scan to identify the technology stack
2. Use dirb_scan to discover hidden endpoints
3. Use curl_get to probe interesting endpoints
4. Report ALL discovered endpoints, services, and technologies

## Output
After each tool execution, summarize what you found.
When done, output a JSON summary of all discoveries."""


class ReconAgent(BaseSubAgent):
    """Focused reconnaissance agent.

    Scans a specific target (host/service) to discover endpoints,
    technologies, and potential attack surface.

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
        """Generate recon plan: technology fingerprint → directory enum → endpoint probe."""
        target = self.task_scope.target_hosts[0] if self.task_scope.target_hosts else "http://localhost"

        plan = [
            {
                "id": "recon-1",
                "instruction": f"Identify web technologies on {target}",
                "action": "whatweb",
                "tool": "whatweb_scan",
                "params": {"target_url": target},
                "dependent_task_ids": [],
            },
            {
                "id": "recon-2",
                "instruction": f"Enumerate directories on {target}",
                "action": "dirb",
                "tool": "dirb_scan",
                "params": {"target_url": target},
                "dependent_task_ids": ["recon-1"],
            },
            {
                "id": "recon-3",
                "instruction": "Probe discovered endpoints for additional info",
                "action": "curl",
                "tool": "curl_get",
                "params": {"url": target, "follow_redirects": True},
                "dependent_task_ids": ["recon-2"],
            },
        ]
        return plan

    async def _execute_task(self, task: Dict[str, Any]) -> Any:
        """Execute a recon task using registered tools."""
        tool_name = task.get("tool", "")
        params = task.get("params", {})

        if not tool_name:
            # Use LLM to decide which tool to call
            content, tool_calls = self.llm.generate(
                prompt=f"Task: {task['instruction']}\nAvailable tools: {', '.join(self.tools.get_tool_names())}\nWhich tool should I use?",
                tools=self.tools.get_tool_definitions(),
            )
            if tool_calls:
                call = tool_calls[0]
                tool_name = call["name"]
                params = call["arguments"]
            else:
                # fallback: use whatweb as default recon tool
                tool_name = "whatweb_scan"
                target = self.task_scope.target_hosts[0] if self.task_scope.target_hosts else "http://localhost"
                params = {"target_url": target}

        result = await self.tools.call(tool_name, params)
        self.budget.tokens_used += len(json.dumps(params)) // 4 + 500  # rough token estimate
        return result

    async def _evaluate_result(
        self, task: Dict[str, Any], result: Any
    ) -> tuple[bool, List[Dict[str, Any]]]:
        """Evaluate recon results — extract discovered services/endpoints/technologies."""
        findings = []

        if hasattr(result, "success") and result.success:
            # Extract from parsed output
            if hasattr(result, "parsed_output") and result.parsed_output:
                findings.append({
                    "type": "parsed",
                    "data": result.parsed_output,
                    "source": getattr(result, "tool_name", task.get("tool", "")),
                })

            # Extract URLs from stdout
            if hasattr(result, "stdout"):
                urls = re.findall(r"https?://[^\s\"'<>]+", result.stdout)
                for url in urls[:10]:
                    findings.append({
                        "type": "endpoint",
                        "url": url.rstrip(".,;:'\""),
                        "source": "stdout_parse",
                    })

            success = len(findings) > 0
        else:
            success = False

        self.findings.extend(findings)
        return success, findings

    def _write_findings_to_dkg(
        self, task: Dict[str, Any], result: Any, findings: List[Dict[str, Any]]
    ) -> None:
        """Write recon discoveries to DKG."""
        for finding in findings:
            ftype = finding.get("type", "")

            if ftype == "endpoint":
                url = finding["url"]
                self.dkg.add_node("Endpoint", f"ep-{url[:50]}", {
                    "url": url,
                    "method": "GET",
                    "params": "",
                    "discovered_by": self.agent_id,
                })

            elif ftype == "parsed":
                data = finding.get("data", {})
                # Technologies
                for tech in data.get("technologies", []):
                    self.dkg.add_node("Service", f"tech-{tech[:30]}", {
                        "port": 0, "protocol": "HTTP",
                        "version": tech,
                        "banner": tech,
                        "discovered_by": self.agent_id,
                    })
                # Discovered paths
                for path_info in data.get("discovered_paths", []):
                    path = path_info.get("path", "")
                    target = self.task_scope.target_hosts[0] if self.task_scope.target_hosts else ""
                    full_url = f"{target.rstrip('/')}{path}" if target else path
                    self.dkg.add_node("Endpoint", f"ep-{path[:40]}", {
                        "url": full_url,
                        "method": "GET",
                        "params": "",
                        "code": path_info.get("code", ""),
                        "discovered_by": self.agent_id,
                    })
                # Open ports (from nmap integration)
                for port_info in data.get("open_ports", []):
                    port = port_info.get("port", 0)
                    self.dkg.add_node("Service", f"svc-{port}", {
                        "port": port,
                        "protocol": "tcp",
                        "version": port_info.get("service", ""),
                        "discovered_by": self.agent_id,
                    })
