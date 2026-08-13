"""P15 2b: mock behavior-parity tests for the Runtime-driven main loop.

The same mock scenario must produce the same result through the legacy
loop and the Runtime-driven path (DARWIN_USE_RUNTIME=1). Real benchmark
parity is deferred until real scenarios are available.
"""

import pytest

from darwin.data_model import ExploitationPlan
from darwin.tools.mcp_gateway import ToolResult


FLAG = "flag{runtime-path-ok}"


def plan_task(tool, params):
    return {
        "id": f"t-{tool}",
        "instruction": f"Run {tool}",
        "tool": tool,
        "params": params,
        "status": "pending",
        "dependent_task_ids": [],
        "attempts": 0,
        "result_summary": "",
    }


def make_plan(task):
    return ExploitationPlan(plan_id="runtime", phase="exploit", goal="g", tasks=[task])


@pytest.mark.asyncio
async def test_runtime_path_llm_driven_flag_matches_legacy(
    fake_llm, fake_gateway, make_orchestrator
):
    recon_gw = fake_gateway(
        {
            "curl_get": ToolResult(
                tool_name="curl_get",
                success=True,
                stdout=f"page\n{FLAG}\n",
                stderr="",
                exit_code=0,
                elapsed_ms=1.0,
            )
        }
    )
    attack_gw = fake_gateway({})
    llm = fake_llm(
        tool_calls=[
            {
                "name": "curl_get",
                "arguments": {"url": "http://target:8000/"},
                "id": "tc-1",
            }
        ]
    )
    orch = make_orchestrator(llm, recon_gw, attack_gw)
    orch.exploitation_plan = make_plan(
        plan_task("curl_get", {"url": "http://target:8000/"})
    )

    result = await orch._run_with_runtime("http://target:8000/")

    assert result is not None
    assert result.success is True
    assert result.flag == FLAG
    assert recon_gw.calls == [("curl_get", {"url": "http://target:8000/"})]


@pytest.mark.asyncio
async def test_runtime_path_direct_task_matches_legacy(
    fake_llm, fake_gateway, make_orchestrator
):
    attack_gw = fake_gateway(
        {
            "shell_exec": ToolResult(
                tool_name="shell_exec",
                success=True,
                stdout=FLAG,
                stderr="",
                exit_code=0,
                elapsed_ms=1.0,
            )
        }
    )
    recon_gw = fake_gateway({})
    # The direct path must not consult the LLM for tool selection; plan
    # review is skipped too because the verified flag terminates the run.
    llm = fake_llm(fail_on_generate=True)
    orch = make_orchestrator(llm, recon_gw, attack_gw)
    orch.exploitation_plan = make_plan(
        plan_task("shell_exec", {"command": f"echo {FLAG}"})
    )

    result = await orch._run_with_runtime("http://target:8000/")

    assert result is not None
    assert result.success is True
    assert result.flag == FLAG
    assert all(c[0] != "generate" for c in llm.calls)
    assert attack_gw.calls == [("shell_exec", {"command": f"echo {FLAG}"})]


@pytest.mark.asyncio
async def test_runtime_path_records_memory_and_metrics(
    fake_llm, fake_gateway, make_orchestrator
):
    recon_gw = fake_gateway(
        {
            "curl_get": ToolResult(
                tool_name="curl_get",
                success=True,
                stdout=f"page\n{FLAG}\n",
                stderr="",
                exit_code=0,
                elapsed_ms=1.0,
            )
        }
    )
    attack_gw = fake_gateway({})
    llm = fake_llm(
        tool_calls=[
            {
                "name": "curl_get",
                "arguments": {"url": "http://target:8000/"},
                "id": "tc-1",
            }
        ]
    )
    orch = make_orchestrator(llm, recon_gw, attack_gw)
    orch.exploitation_plan = make_plan(
        plan_task("curl_get", {"url": "http://target:8000/"})
    )

    await orch._run_with_runtime("http://target:8000/")

    assert orch.memory.plan.get("t-curl_get") is not None
    assert len(orch.memory.execution.for_task("t-curl_get")) == 1
    report = orch.metrics_report()
    assert report.total_executions == 1
    assert report.adherence_rate == 1.0


@pytest.mark.asyncio
async def test_runtime_path_failure_reviews_plan_and_returns_none(
    fake_llm, fake_gateway, make_orchestrator
):
    recon_gw = fake_gateway(
        {
            "curl_get": ToolResult(
                tool_name="curl_get",
                success=False,
                stdout="",
                stderr="connection refused",
                exit_code=7,
                elapsed_ms=1.0,
            )
        }
    )
    attack_gw = fake_gateway({})
    llm = fake_llm(
        tool_calls=[
            {
                "name": "curl_get",
                "arguments": {"url": "http://target:8000/"},
                "id": "tc-1",
            }
        ],
        content="[]",  # plan review adds nothing
    )
    orch = make_orchestrator(llm, recon_gw, attack_gw)
    orch.exploitation_plan = make_plan(
        plan_task("curl_get", {"url": "http://target:8000/"})
    )

    result = await orch._run_with_runtime("http://target:8000/")

    assert result is None
    # The per-task plan review ran (mirrors legacy), then the plan
    # exhausted and the loop stopped.
    assert any(c[0] == "generate" for c in llm.calls)
    assert orch.metrics_report().total_executions == 1
    assert orch.memory.plan.get("t-curl_get") is not None
